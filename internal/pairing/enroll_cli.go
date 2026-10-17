package pairing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tudiapps/portlight-cli/internal/enroll"
	"github.com/tudiapps/portlight-cli/internal/i18n"
	"golang.org/x/crypto/ssh"
)

// EnrollMode chooses what `portlight pair` does about a key of the phone's
// own (docs/pairing-protocol.md "Enroll uzantısı").
type EnrollMode int

const (
	// EnrollOffer sends hosts and keys as before, then keeps the session
	// open so the phone can also add a key of its own to servers.
	EnrollOffer EnrollMode = iota
	// EnrollOnly sends no private keys at all: the phone makes its own key
	// and this machine adds it to the servers the user picks.
	EnrollOnly
	// EnrollOff is protocol v1 exactly: the session ends at the envelope.
	EnrollOff
)

// EnrollEnv names the environment variable that sets the default mode:
// "only" (or "1") for EnrollOnly, "off" (or "0") for EnrollOff.
const EnrollEnv = "PORTLIGHT_ENROLL"

// EnrollModeFromEnv reads EnrollEnv; anything else is EnrollOffer.
func EnrollModeFromEnv() EnrollMode {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnrollEnv))) {
	case "only", "1", "true", "yes":
		return EnrollOnly
	case "off", "0", "false", "no":
		return EnrollOff
	}
	return EnrollOffer
}

// EnrollOfferPayload is the payload's "enroll" field.
type EnrollOfferPayload struct {
	// Key is ek, base64url without padding. It exists only inside the
	// sealed envelope.
	Key string `json:"key"`
	// Only is true when no private keys were sent (EnrollOnly).
	Only bool `json:"only,omitempty"`
}

// desktopEnroll is the desktop side of one enroll request: it shows the
// hosts, asks the user, and adds the key.
type desktopEnroll struct {
	dist  *enroll.Distributor
	in    io.Reader
	stdin *bufio.Reader
	out   io.Writer
}

func (d *desktopEnroll) handle(ctx context.Context, req enroll.Request, pub ssh.PublicKey) ([]enroll.Result, bool) {
	out := d.out
	plans, err := d.dist.Plan(req.Hosts)
	if err != nil {
		fmt.Fprintf(out, i18n.S("\n! Cannot read known_hosts (%v); nothing was written.\n", "\n! known_hosts okunamadı (%v); hiçbir şey yazılmadı.\n"), err)
		return nil, false
	}
	fmt.Fprintln(out, "\n--------------------------------------------------------")
	fmt.Fprintln(out, i18n.S(
		"The phone made its own SSH key and asks to add it to these servers:",
		"Telefon kendi SSH anahtarını üretti ve şu sunuculara eklenmesini istiyor:"))
	fmt.Fprintf(out, i18n.S("Phone key: %s (%s)\n", "Telefon anahtarı: %s (%s)\n"), ssh.FingerprintSHA256(pub), pub.Type())
	reachable := 0
	for _, p := range plans {
		if p.Target == nil {
			fmt.Fprintf(out, "  – %-16s %s\n", p.Host.Alias, reasonText(p.Reason))
			continue
		}
		reachable++
		via := ""
		if p.Target.Jump != nil {
			via = fmt.Sprintf(i18n.S(" (via %s)", " (%s üzerinden)"), p.Target.JumpName)
		}
		fmt.Fprintf(out, "  ✓ %-16s %s@%s%s\n", p.Host.Alias, p.Target.User, p.Target.Addr, via)
	}
	if reachable == 0 {
		fmt.Fprintln(out, i18n.S(
			"None of these servers is known to this computer; nothing to do.",
			"Bu sunucuların hiçbiri bu bilgisayarda tanınmıyor; yapılacak bir şey yok."))
		results := make([]enroll.Result, len(plans))
		for i, p := range plans {
			results[i] = enroll.Result{Alias: p.Host.Alias, Status: enroll.StatusFailed, Reason: p.Reason}
		}
		return results, true
	}
	fmt.Fprintf(out, i18n.S(
		"Add the phone's key to authorized_keys on %d server(s), using this computer's SSH access? Type \"y\" and press Enter [y/N]: ",
		"Telefonun anahtarı bu bilgisayarın SSH erişimiyle %d sunucuda authorized_keys'e eklensin mi? \"e\" yazıp Enter'a basın [e/H]: "),
		reachable)
	if !d.ask(EnrollDecisionTTL) {
		fmt.Fprintln(out, i18n.S("\nNot added; nothing was written to any server.", "\nEklenmedi; hiçbir sunucuya bir şey yazılmadı."))
		return nil, false
	}
	return d.dist.Run(ctx, pub, plans), true
}

// ask reads a yes/no answer, giving up (no) after timeout.
func (d *desktopEnroll) ask(timeout time.Duration) bool {
	answer := make(chan string, 1)
	go func() {
		line, _ := d.stdin.ReadString('\n')
		answer <- strings.ToLower(strings.TrimSpace(line))
	}()
	select {
	case a := <-answer:
		return a == "e" || a == "evet" || a == "y" || a == "yes"
	case <-time.After(timeout):
		fmt.Fprintln(d.out, i18n.S("\nTime is up.", "\nSüre doldu."))
		return false
	}
}

func (d *desktopEnroll) passphrase(keyName string, attempt int) ([]byte, error) {
	if attempt > 1 {
		fmt.Fprintln(d.out, i18n.S("Wrong passphrase.", "Passphrase yanlış."))
	}
	fmt.Fprintf(d.out, i18n.S(
		"Passphrase for this computer's key %s, to log in to the servers (leave empty to skip): ",
		"Sunuculara giriş için bu bilgisayardaki %s anahtarının passphrase'i (atlamak için boş bırakın): "), keyName)
	return readSecret(d.in, d.stdin, d.out)
}

func (d *desktopEnroll) progress(p enroll.Plan, r enroll.Result, detail error) {
	switch r.Status {
	case enroll.StatusAdded:
		fmt.Fprintf(d.out, i18n.S("  ✓ %s: key added\n", "  ✓ %s: anahtar eklendi\n"), r.Alias)
	case enroll.StatusPresent:
		fmt.Fprintf(d.out, i18n.S("  = %s: key was already there\n", "  = %s: anahtar zaten vardı\n"), r.Alias)
	default:
		if detail != nil {
			fmt.Fprintf(d.out, "  ✗ %s: %s (%v)\n", r.Alias, reasonText(r.Reason), detail)
		} else {
			fmt.Fprintf(d.out, "  ✗ %s: %s\n", r.Alias, reasonText(r.Reason))
		}
	}
}

func reasonText(reason string) string {
	switch reason {
	case enroll.ReasonNotKnown:
		return i18n.S("not known on this computer (not in ssh config or known_hosts) — skipped",
			"bu bilgisayarda tanınmıyor (ssh config'te ve known_hosts'ta yok) — atlandı")
	case enroll.ReasonUnknownHostKey:
		return i18n.S("server key not in known_hosts — never accepted automatically; connect once with ssh first",
			"sunucu anahtarı known_hosts'ta yok — otomatik kabul edilmez; önce bir kez ssh ile bağlanın")
	case enroll.ReasonHostKeyChanged:
		return i18n.S("server key differs from known_hosts — refused", "sunucu anahtarı known_hosts'takinden farklı — reddedildi")
	case enroll.ReasonAuthFailed:
		return i18n.S("this computer's keys / agent were refused", "bu bilgisayarın anahtarları / agent'ı kabul edilmedi")
	case enroll.ReasonUnreachable:
		return i18n.S("could not connect", "bağlanılamadı")
	case enroll.ReasonProxyJump:
		return i18n.S("ProxyJump chain or jump host not usable", "ProxyJump zinciri ya da atlama host'u kullanılamıyor")
	case enroll.ReasonWriteFailed:
		return i18n.S("could not read or write ~/.ssh/authorized_keys", "~/.ssh/authorized_keys okunamadı ya da yazılamadı")
	case enroll.ReasonTimeout:
		return i18n.S("timed out", "süre doldu")
	}
	return reason
}

// printEnrollOutcome tells the desktop user how the enroll phase ended.
func printEnrollOutcome(out io.Writer, outcome EnrollOutcome, results []enroll.Result) {
	added, present, failed := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case enroll.StatusAdded:
			added++
		case enroll.StatusPresent:
			present++
		default:
			failed++
		}
	}
	switch outcome {
	case EnrollCompleted:
		fmt.Fprintf(out, i18n.S(
			"\n✓ Phone key: added on %d, already on %d, failed on %d server(s). The phone now tests the first login. Session closed.\n",
			"\n✓ Telefon anahtarı: %d sunucuya eklendi, %d sunucuda zaten vardı, %d sunucuda olmadı. Telefon ilk girişi deniyor. Oturum kapandı.\n"),
			added, present, failed)
	case EnrollDeclined:
		fmt.Fprintln(out, i18n.S("\nPhone key not added. Session closed.", "\nTelefon anahtarı eklenmedi. Oturum kapandı."))
	case EnrollExpired:
		if len(results) > 0 {
			fmt.Fprintln(out, i18n.S(
				"\nThe key was added (see above) but the phone did not collect the results. Session closed.",
				"\nAnahtar eklendi (yukarıya bakın) ama telefon sonuçları almadı. Oturum kapandı."))
		} else {
			fmt.Fprintln(out, i18n.S("\nNo key came from the phone. Session closed.", "\nTelefondan anahtar gelmedi. Oturum kapandı."))
		}
	default:
		fmt.Fprintln(out, i18n.S("\nSession closed.", "\nOturum kapandı."))
	}
}

// Delivered is closed once the envelope reached the phone in a session
// that offers enroll; the session then waits for the phone's key.
func (s *Server) Delivered() <-chan struct{} { return s.delivered }
