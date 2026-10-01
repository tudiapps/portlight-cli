package pairing

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/tudiapps/portlight-cli/internal/agents"
	"github.com/tudiapps/portlight-cli/internal/discovery"
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

// RunInteractive pairs with a phone over the local network: it shows the
// QR, waits for the phone, asks the user to compare codes and only then
// sends the sealed payload. Nothing is written to disk.
//
// relayURL, if not empty, is a mailbox relay (https://, or http:// on
// loopback) served alongside the LAN server as the last fallback.
func RunInteractive(configPath string, port int, relayURL string, in io.Reader, out io.Writer) error {
	var relayClient *relay.Client
	if relayURL != "" {
		c, err := relay.New(relayURL)
		if err != nil {
			return err
		}
		relayClient = c
	}
	stdin := bufio.NewReader(in)
	payload, warnings, err := BuildPayload(configPath, sshconfig.LoadOptions{
		Passphrase: func(path string, attempt int) ([]byte, error) {
			if attempt > 1 {
				fmt.Fprintln(out, "Passphrase yanlış.")
			}
			fmt.Fprintf(out, "%s PuTTY anahtarı passphrase korumalı.\n", filepath.Base(path))
			fmt.Fprint(out, "Passphrase (atlamak için boş bırakın): ")
			return readSecret(in, stdin, out)
		},
	})
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	confirm := func(sas string) bool {
		fmt.Fprintf(out, "\nTelefonda görünen kod:  %s\n", sas)
		fmt.Fprint(out, "İki ekrandaki kod aynı mı? Aynıysa \"e\" yazıp Enter'a basın [e/H]: ")
		line, _ := stdin.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "e" || answer == "evet" || answer == "y" || answer == "yes"
	}

	server, err := NewServer(body, confirm, Options{})
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
			warnings = append(warnings, fmt.Sprintf("mDNS ilanı yapılamadı: %v", err))
		} else {
			defer ad.Stop()
		}
	}
	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		// The envelope call long-polls through the user's decision.
		WriteTimeout: DecisionTTL + 10*time.Second,
	}
	go func() { _ = httpServer.Serve(listener) }()
	// Keep serving until the phone has seen the outcome, then shut down.
	defer server.Close(httpServer)

	endpoints := Endpoints{Addrs: addrs}
	if relayClient != nil {
		endpoints.Relay = relayClient.URL()
		healthCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := relayClient.Health(healthCtx); err != nil {
			warnings = append(warnings, fmt.Sprintf("relay şu an yanıt vermiyor (%v); yeniden denenecek", err))
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
				fmt.Fprintf(out, "  ! relay devre dışı, yerel ağ yolu sürüyor: %v\n", err)
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
	fmt.Fprintln(out, "              PORTLIGHT PAIRING (EŞLEŞTİRME)            ")
	fmt.Fprintln(out, "========================================================")
	fmt.Fprintf(out, "Host: %d · Anahtar: %d · known_hosts: %d · Ajan: %d\n",
		len(payload.Hosts), len(payload.Keys), len(payload.KnownHosts), len(payload.Agents))
	printWarnings(out, warnings)
	fmt.Fprintln(out, "--------------------------------------------------------")
	fmt.Fprintln(out, "Telefonunuzdaki Portlight uygulamasından QR kodu tarayın:")
	fmt.Fprintln(out)
	qr, err := qrcode.New(server.QRURI(endpoints), qrcode.Medium)
	if err != nil {
		return fmt.Errorf("rendering QR: %w", err)
	}
	fmt.Fprintln(out, qr.ToSmallString(false))
	fmt.Fprintf(out, "Adres: %s\n", strings.Join(addrs, ", "))
	if relayClient != nil {
		fmt.Fprintf(out, "Relay: %s — yalnız yerel ağ ulaşamazsa kullanılır; relay kutu kimliklerini, "+
			"boyutları, zamanlamayı ve IP adreslerini görür, QR sırrını, 6 haneli kodu ve "+
			"zarfın içeriğini göremez.\n", relayClient.Host())
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out, "Windows Güvenlik Duvarı sorarsa \"İzin ver\" deyin; yoksa telefon bağlanamaz.")
	}
	fmt.Fprintf(out, "Bekleniyor (%d sn)... Kod eşleşmeden hiçbir şey gönderilmez.\n",
		int(HandshakeTTL.Seconds()))

	if err := server.Wait(); err != nil {
		return err
	}
	fmt.Fprintln(out, "\n✓ Şifreli zarf telefona teslim edildi. Oturum kapandı.")
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
	fmt.Fprintln(out, "              PORTLIGHT SSH AKTARIM ÖNİZLEMESİ          ")
	fmt.Fprintln(out, "========================================================")
	fmt.Fprintf(out, "SSH Config Yolu: %s\n", configPath)
	printWarnings(out, warnings)
	fmt.Fprintf(out, "Toplam %d Host bulundu:\n\n", len(payload.Hosts))
	for i, h := range payload.Hosts {
		fmt.Fprintf(out, " [%d] %-15s -> %s@%s:%d\n", i+1, h.Alias, h.User, h.HostName, h.Port)
		if h.Key != "" {
			fmt.Fprintf(out, "     Anahtar: %s\n", h.Key)
		}
		if h.ProxyJump != "" {
			fmt.Fprintf(out, "     ProxyJump: %s\n", h.ProxyJump)
		}
	}

	fmt.Fprintf(out, "\nGönderilecek özel anahtarlar (%d):\n", len(payload.Keys))
	for _, k := range payload.Keys {
		protection := "passphrase yok"
		if k.Encrypted {
			protection = "passphrase korumalı"
		}
		if k.FromPPK {
			protection += ", PuTTY'den OpenSSH'e dönüştürülecek"
		}
		fmt.Fprintf(out, " - %-14s %s, %s\n", k.Name, k.Algorithm, protection)
	}

	fmt.Fprintf(out, "\nBilinen sunucu (known_hosts) kayıtları: %d\n", len(payload.KnownHosts))
	fmt.Fprintf(out, "Bulunan ajanlar (%d):", len(payload.Agents))
	for _, a := range payload.Agents {
		fmt.Fprintf(out, " %s", a.Kind)
	}
	fmt.Fprintln(out, " — yalnız varlıkları bildirilir, token taşınmaz")
	fmt.Fprintln(out, "--------------------------------------------------------")
	fmt.Fprintln(out, "Özel anahtarlar burada gösterilmez; `portlight pair` onları")
	fmt.Fprintln(out, "yalnızca iki ekrandaki kod eşleştikten sonra, şifreli gönderir.")
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
	fmt.Fprintf(w, "Atlananlar (%d):\n", len(warnings))
	for _, warning := range warnings {
		fmt.Fprintf(w, "  ! %s\n", warning)
	}
}

// ErrKeyOptions is returned for an authorized_keys line that carries
// options such as command="..." — enroll only adds plain keys.
var ErrKeyOptions = errors.New("key has authorized_keys options; only a plain public key can be enrolled")

// EnrollKey adds a phone-generated public key to authorized_keys in sshDir
// (default ~/.ssh). The input must be exactly one plain public key: no
// options, no second line. It is re-encoded before writing, so nothing
// but the key and a fixed comment reaches the file.
func EnrollKey(publicKey, sshDir string, out io.Writer) error {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return fmt.Errorf("public key is empty")
	}
	if strings.ContainsAny(publicKey, "\r\n") {
		return fmt.Errorf("expected a single public key line")
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return fmt.Errorf("not a valid public key: %w", err)
	}
	if len(options) > 0 {
		return ErrKeyOptions
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return fmt.Errorf("expected a single public key line")
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
				fmt.Fprintf(out, "Bu anahtar zaten %s dosyasında.\n", authPath)
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
	fmt.Fprintf(out, "✓ Anahtar %s dosyasına eklendi (%s).\n", authPath, ssh.FingerprintSHA256(pub))
	return nil
}
