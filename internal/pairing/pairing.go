package pairing

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/tudiapps/portlight-cli/internal/agents"
	"github.com/tudiapps/portlight-cli/internal/discovery"
	"github.com/tudiapps/portlight-cli/internal/enroll"
	"github.com/tudiapps/portlight-cli/internal/envelope"
	"github.com/tudiapps/portlight-cli/internal/i18n"
	"github.com/tudiapps/portlight-cli/internal/putty"
	"github.com/tudiapps/portlight-cli/internal/relay"
	"github.com/tudiapps/portlight-cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// PayloadVersion is the schema version of Payload.
const PayloadVersion = 1

// Payload is what the phone receives, sealed, after the SAS is confirmed.
type Payload struct {
	Version    int                    `json:"version"`
	CreatedAt  int64                  `json:"created_at"`
	Hosts      []sshconfig.HostConfig `json:"hosts"`
	Keys       []sshconfig.Key        `json:"keys"`
	KnownHosts []string               `json:"known_hosts"`
	Agents     []agents.Agent         `json:"agents"`
	// Enroll offers the enroll extension; absent in protocol v1.
	Enroll *EnrollOfferPayload `json:"enroll,omitempty"`
}

// Redacted returns p without private key material, for previews.
func (p Payload) Redacted() Payload {
	keys := make([]sshconfig.Key, len(p.Keys))
	for i, k := range p.Keys {
		keys[i] = k.Redacted()
	}
	p.Keys = keys
	return p
}

// puttySessions reads PuTTY's saved sessions; tests replace it so they do
// not depend on the machine's registry.
var puttySessions = putty.Sessions

// BuildPayload gathers hosts (~/.ssh/config, then PuTTY's saved sessions),
// keys and known_hosts from this machine.
// opts decides whether passphrase-protected PuTTY keys are unlocked
// (pairing) or only listed (preview).
func BuildPayload(configPath string, opts sshconfig.LoadOptions) (Payload, []string, error) {
	hosts, warnings, err := sshconfig.ParseConfigFile(configPath)
	if err != nil {
		return Payload{}, warnings, fmt.Errorf("parsing ssh config: %w", err)
	}
	// PuTTY's saved sessions (Windows only), after the ssh config so a
	// host defined in both keeps its ssh config entry.
	sessions, err := puttySessions()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("PuTTY sessions: %v", err))
	}
	hosts, puttyWarnings := putty.Merge(hosts, sessions)
	warnings = append(warnings, puttyWarnings...)
	keys, keyWarnings := sshconfig.LoadKeys(hosts, "", opts)
	warnings = append(warnings, keyWarnings...)
	knownHosts, err := sshconfig.ReadKnownHosts("")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("known_hosts: %v", err))
	}
	if keys == nil {
		keys = []sshconfig.Key{}
	}
	if knownHosts == nil {
		knownHosts = []string{}
	}
	return Payload{
		Version:    PayloadVersion,
		CreatedAt:  time.Now().Unix(),
		Hosts:      hosts,
		Keys:       keys,
		KnownHosts: knownHosts,
		Agents:     agents.Detect(),
	}, warnings, nil
}

// RelayEnv names the environment variable that sets the relay URL when
// --relay is not given.
const RelayEnv = "PORTLIGHT_RELAY"

// PairOptions configure RunInteractive.
type PairOptions struct {
	// ConfigPath is the ssh config to read; empty means ~/.ssh/config.
	ConfigPath string
	// Port is the LAN port to try first.
	Port int
	// RelayURL, if not empty, is a mailbox relay (https://, or http:// on
	// loopback) served alongside the LAN server as the last fallback.
	RelayURL string
	// Enroll chooses whether, and how, the phone may add a key of its own.
	Enroll EnrollMode
}

// RunInteractive pairs with a phone over the local network: it shows the
// QR, waits for the phone, asks the user to compare codes and only then
// sends the sealed payload. Nothing is written to disk.
//
// Unless opts.Enroll is EnrollOff, the session then waits (EnrollTTL) for
// the phone to send a public key of its own; after the desktop user
// approves the host list, the key is added to those servers' authorized_keys
// with this machine's SSH access. Nothing is written locally then either.
func RunInteractive(opts PairOptions, in io.Reader, out io.Writer) error {
	configPath, port := opts.ConfigPath, opts.Port
	var relayClient *relay.Client
	if opts.RelayURL != "" {
		c, err := relay.New(opts.RelayURL)
		if err != nil {
			return err
		}
		relayClient = c
	}
	stdin := bufio.NewReader(in)
	payload, warnings, err := BuildPayload(configPath, sshconfig.LoadOptions{
		Passphrase: func(path string, attempt int) ([]byte, error) {
			if attempt > 1 {
				fmt.Fprintln(out, i18n.S("Wrong passphrase.", "Passphrase yanlış."))
			}
			fmt.Fprintf(out, i18n.S("The PuTTY key %s is passphrase protected.\n", "%s PuTTY anahtarı passphrase korumalı.\n"), filepath.Base(path))
			fmt.Fprint(out, i18n.S("Passphrase (leave empty to skip): ", "Passphrase (atlamak için boş bırakın): "))
			return readSecret(in, stdin, out)
		},
	})
	if err != nil {
		return err
	}

	var serverOpts Options
	writeTimeout := DecisionTTL + 10*time.Second
	if opts.Enroll != EnrollOff {
		ek, err := envelope.Random(envelope.EnrollKeySize)
		if err != nil {
			return err
		}
		// The distributor logs in with the keys read above; they stay here.
		desktop := &desktopEnroll{in: in, stdin: stdin, out: out}
		desktop.dist = &enroll.Distributor{
			Hosts:      slices.Clone(payload.Hosts),
			Keys:       payload.Keys,
			Passphrase: desktop.passphrase,
			Progress:   desktop.progress,
		}
		serverOpts.Enroll = &EnrollHandler{Key: ek, Handle: desktop.handle}
		payload.Enroll = &EnrollOfferPayload{Key: b64.EncodeToString(ek), Only: opts.Enroll == EnrollOnly}
		if opts.Enroll == EnrollOnly {
			// No private key leaves this machine; the phone makes its own.
			payload.Keys = []sshconfig.Key{}
			hosts := slices.Clone(payload.Hosts)
			for i := range hosts {
				hosts[i].Key = ""
			}
			payload.Hosts = hosts
		}
		// The enroll result long-polls through the decision and the work.
		writeTimeout = EnrollDecisionTTL + EnrollWorkTTL + 30*time.Second
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	confirm := func(sas string) bool {
		fmt.Fprintf(out, i18n.S("\nCode shown on the phone:  %s\n", "\nTelefonda görünen kod:  %s\n"), sas)
		fmt.Fprint(out, i18n.S(
			"Is it the same code on both screens? If so, type \"y\" and press Enter [y/N]: ",
			"İki ekrandaki kod aynı mı? Aynıysa \"e\" yazıp Enter'a basın [e/H]: "))
		line, _ := stdin.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "e" || answer == "evet" || answer == "y" || answer == "yes"
	}

	server, err := NewServer(body, confirm, serverOpts)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		listener, err = net.Listen("tcp", ":0")
		if err != nil {
			return fmt.Errorf("failed to open listener: %w", err)
		}
	}
	port = listener.Addr().(*net.TCPAddr).Port
	ips := discovery.LocalAddrs()
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}
	if len(addrs) == 0 && relayClient == nil {
		return fmt.Errorf("no local network address found; is this machine on Wi-Fi/LAN?")
	}
	// mDNS is a fallback for when the QR's addresses are unreachable; if
	// multicast is unavailable pairing still works without it.
	if len(ips) > 0 {
		if ad, err := discovery.Advertise(server.SessionID(), port, ips); err != nil {
			warnings = append(warnings, fmt.Sprintf(i18n.S("mDNS announcement failed: %v", "mDNS ilanı yapılamadı: %v"), err))
		} else {
			defer ad.Stop()
		}
	}
	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		// The envelope call long-polls through the user's decision.
		WriteTimeout: writeTimeout,
	}
	go func() { _ = httpServer.Serve(listener) }()
	// Keep serving until the phone has seen the outcome, then shut down.
	defer server.Close(httpServer)

	endpoints := Endpoints{Addrs: addrs}
	if relayClient != nil {
		endpoints.Relay = relayClient.URL()
		healthCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := relayClient.Health(healthCtx); err != nil {
			warnings = append(warnings, fmt.Sprintf(i18n.S("relay not responding (%v); will retry", "relay şu an yanıt vermiyor (%v); yeniden denenecek"), err))
		}
		cancel()
		relayCtx, stopRelay := context.WithCancel(context.Background())
		relayDone := make(chan struct{})
		go func() {
			defer close(relayDone)
			err := server.ServeRelay(relayCtx, relayClient, RelayOptions{
				Warn: func(msg string) { fmt.Fprintf(out, "  ! %s\n", msg) },
			})
			if err != nil {
				fmt.Fprintf(out, i18n.S("  ! relay off, the local network path goes on: %v\n", "  ! relay devre dışı, yerel ağ yolu sürüyor: %v\n"), err)
			}
		}()
		// Runs before server.Close. The relay loop ends by itself once the
		// phone has seen the outcome; this only bounds it on early return.
		defer func() {
			select {
			case <-relayDone:
			case <-time.After(ReportGrace + 15*time.Second):
			}
			stopRelay()
			relayClient.CloseIdle()
		}()
	}

	fmt.Fprintln(out, "\n========================================================")
	fmt.Fprintln(out, i18n.S(
		"                    PORTLIGHT PAIRING                   ",
		"                  PORTLIGHT EŞLEŞTİRME                  "))
	fmt.Fprintln(out, "========================================================")
	fmt.Fprintf(out, i18n.S("Hosts: %d · Keys: %d · known_hosts: %d\n", "Host: %d · Anahtar: %d · known_hosts: %d\n"),
		len(payload.Hosts), len(payload.Keys), len(payload.KnownHosts))
	printWarnings(out, warnings)
	if opts.Enroll == EnrollOnly {
		fmt.Fprintln(out, i18n.S(
			"Phone key mode: no private key is sent. The phone makes its own key and,\nonce you approve the list here, this computer adds it to those servers.",
			"Telefon anahtarı modu: hiçbir özel anahtar gönderilmez. Telefon kendi anahtarını\nüretir; listeyi burada onaylarsanız bu bilgisayar onu o sunuculara ekler."))
	}
	fmt.Fprintln(out, "--------------------------------------------------------")
	fmt.Fprintln(out, i18n.S(
		"Your phone and this computer must be on the same Wi-Fi network.",
		"Telefon ve bu bilgisayar aynı Wi-Fi ağında olmalı."))
	fmt.Fprintln(out, i18n.S(
		"Scan the QR code with the Portlight app on your phone:",
		"Telefonunuzdaki Portlight uygulamasından QR kodu tarayın:"))
	fmt.Fprintln(out)
	qr, err := qrcode.New(server.QRURI(endpoints), qrcode.Medium)
	if err != nil {
		return fmt.Errorf("rendering QR: %w", err)
	}
	fmt.Fprintln(out, qr.ToSmallString(false))
	fmt.Fprintf(out, i18n.S("Address: %s\n", "Adres: %s\n"), strings.Join(addrs, ", "))
	if relayClient != nil {
		fmt.Fprintf(out, i18n.S(
			"Relay: %s — used only if the local network cannot reach the phone; the relay sees "+
				"mailbox IDs, sizes, timing and IP addresses, never the QR secret, the 6-digit code "+
				"or what the envelope holds.\n",
			"Relay: %s — yalnız yerel ağ ulaşamazsa kullanılır; relay kutu kimliklerini, "+
				"boyutları, zamanlamayı ve IP adreslerini görür, QR sırrını, 6 haneli kodu ve "+
				"zarfın içeriğini göremez.\n"), relayClient.Host())
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out, i18n.S(
			"If Windows Firewall asks, choose \"Allow\"; otherwise the phone cannot connect.",
			"Windows Güvenlik Duvarı sorarsa \"İzin ver\" deyin; yoksa telefon bağlanamaz."))
	}
	fmt.Fprintf(out, i18n.S(
		"Waiting (%d s)... Nothing is sent until the codes match.\n",
		"Bekleniyor (%d sn)... Kod eşleşmeden hiçbir şey gönderilmez.\n"),
		int(HandshakeTTL.Seconds()))

	if serverOpts.Enroll != nil {
		go func() {
			select {
			case <-server.Delivered():
				fmt.Fprintf(out, i18n.S(
					"\n✓ Encrypted envelope delivered to the phone.\nIf the phone adds a key of its own to your servers, you will be asked here first.\nWaiting up to %d min (Ctrl+C to finish)...\n",
					"\n✓ Şifreli zarf telefona teslim edildi.\nTelefon sunucularınıza kendi anahtarını eklemek isterse önce burada sorulacak.\nEn çok %d dk bekleniyor (bitirmek için Ctrl+C)...\n"),
					int(EnrollTTL.Minutes()))
			case <-server.finished:
			}
		}()
	}

	if err := server.Wait(); err != nil {
		return err
	}
	if outcome, results := server.Enrollment(); outcome != EnrollNotOffered {
		printEnrollOutcome(out, outcome, results)
		return nil
	}
	fmt.Fprintln(out, i18n.S(
		"\n✓ Encrypted envelope delivered to the phone. Session closed.",
		"\n✓ Şifreli zarf telefona teslim edildi. Oturum kapandı."))
	return nil
}

// ExportConfig prints what pairing would send, without private key
// material, and sends nothing.
func ExportConfig(configPath string, asJSON bool, out, errOut io.Writer) error {
	payload, warnings, err := BuildPayload(configPath, sshconfig.LoadOptions{})
	if err != nil {
		return err
	}
	payload = payload.Redacted()

	if asJSON {
		// Warnings go to stderr so stdout stays valid JSON.
		printWarnings(errOut, warnings)
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	if configPath == "" {
		configPath = sshconfig.DefaultConfigPath()
	}
	fmt.Fprintln(out, "\n========================================================")
	fmt.Fprintln(out, i18n.S(
		"                 PORTLIGHT EXPORT PREVIEW               ",
		"              PORTLIGHT SSH AKTARIM ÖNİZLEMESİ          "))
	fmt.Fprintln(out, "========================================================")
	fmt.Fprintf(out, i18n.S("SSH config: %s\n", "SSH config yolu: %s\n"), configPath)
	printWarnings(out, warnings)
	fmt.Fprintf(out, i18n.S("%d hosts found:\n\n", "Toplam %d host bulundu:\n\n"), len(payload.Hosts))
	for i, h := range payload.Hosts {
		fmt.Fprintf(out, " [%d] %-15s -> %s@%s:%d\n", i+1, h.Alias, h.User, h.HostName, h.Port)
		if h.Key != "" {
			fmt.Fprintf(out, i18n.S("     Key: %s\n", "     Anahtar: %s\n"), h.Key)
		}
		if h.ProxyJump != "" {
			fmt.Fprintf(out, "     ProxyJump: %s\n", h.ProxyJump)
		}
	}

	fmt.Fprintf(out, i18n.S("\nPrivate keys to send (%d):\n", "\nGönderilecek özel anahtarlar (%d):\n"), len(payload.Keys))
	for _, k := range payload.Keys {
		protection := i18n.S("no passphrase", "passphrase yok")
		if k.Encrypted {
			protection = i18n.S("passphrase protected", "passphrase korumalı")
		}
		if k.FromPPK {
			protection += i18n.S(", converted from PuTTY to OpenSSH", ", PuTTY'den OpenSSH'e dönüştürülecek")
		}
		fmt.Fprintf(out, " - %-14s %s, %s\n", k.Name, k.Algorithm, protection)
	}

	fmt.Fprintf(out, i18n.S("\nKnown hosts (known_hosts) entries: %d\n", "\nBilinen sunucu (known_hosts) kayıtları: %d\n"), len(payload.KnownHosts))
	fmt.Fprintln(out, "--------------------------------------------------------")
	fmt.Fprintln(out, i18n.S(
		"Private keys are not shown here; `portlight pair` sends them\nencrypted, and only once the codes on both screens match.",
		"Özel anahtarlar burada gösterilmez; `portlight pair` onları\nyalnızca iki ekrandaki kod eşleştikten sonra, şifreli gönderir."))
	return nil
}

// readSecret reads one line without echoing it when in is a terminal.
func readSecret(in io.Reader, buffered *bufio.Reader, out io.Writer) ([]byte, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		secret, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(out)
		return secret, err
	}
	line, err := buffered.ReadString('\n')
	if err != nil && line == "" {
		return nil, nil
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// printWarnings lists what was skipped while reading the ssh setup.
func printWarnings(w io.Writer, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintf(w, i18n.S("Skipped (%d):\n", "Atlananlar (%d):\n"), len(warnings))
	for _, warning := range warnings {
		fmt.Fprintf(w, "  ! %s\n", warning)
	}
}

// ErrKeyOptions is returned for an authorized_keys line that carries
// options such as command="..." — enroll only adds plain keys.
var ErrKeyOptions = enroll.ErrKeyOptions

// EnrollKey adds a phone-generated public key to authorized_keys in sshDir
// (default ~/.ssh). The input must be exactly one plain public key: no
// options, no second line. It is re-encoded before writing, so nothing
// but the key and a fixed comment reaches the file.
func EnrollKey(publicKey, sshDir string, out io.Writer) error {
	pub, err := enroll.ParsePublicKey(publicKey)
	if err != nil {
		return err
	}

	if sshDir == "" {
		sshDir = sshconfig.DefaultSshDir()
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", sshDir, err)
	}
	authPath := filepath.Join(sshDir, "authorized_keys")

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if existing, err := os.ReadFile(authPath); err == nil {
		for _, l := range strings.Split(string(existing), "\n") {
			if p, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil &&
				string(p.Marshal()) == string(pub.Marshal()) {
				fmt.Fprintf(out, i18n.S("This key is already in %s.\n", "Bu anahtar zaten %s dosyasında.\n"), authPath)
				return nil
			}
		}
	}

	f, err := os.OpenFile(authPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening authorized_keys: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "\n%s portlight-mobile\n", line); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	fmt.Fprintf(out, i18n.S("✓ Key added to %s (%s).\n", "✓ Anahtar %s dosyasına eklendi (%s).\n"), authPath, ssh.FingerprintSHA256(pub))
	return nil
}
