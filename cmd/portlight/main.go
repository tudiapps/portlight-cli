// Command portlight pairs a desktop machine with the Portlight mobile app.
//
// It reads ~/.ssh/config, the private keys it references and known_hosts,
// seals them into an encrypted envelope addressed to the phone's ephemeral
// X25519 key, and hands the envelope over the local network via HTTP & QR code.
//
// The binary is stateless by default: it writes nothing to disk during pairing
// and exits immediately when pairing completes.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tudiapps/portlight-cli/internal/agent"
	"github.com/tudiapps/portlight-cli/internal/pairing"
)

// version is set at build time by goreleaser.
var version = "dev"

func main() {
	// Agent commands run non-interactively (the hook under Claude Code, the
	// rest over SSH from the phone) and carry their own exit codes.
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		os.Exit(agent.Main(os.Args[2:], os.Stdin, os.Stdout, os.Stderr, version))
	}

	isInteractive := len(os.Args) <= 1
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nportlight hatası:", err)
	}

	// Windows'ta çift tıklanarak açıldığında pencerenin anında kapanmasını önle
	if isInteractive {
		pauseExit()
	}

	if err != nil {
		os.Exit(1)
	}
}

func pauseExit() {
	fmt.Println("\nÇıkmak için Enter tuşuna basın...")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Println("========================================================")
		fmt.Println("           PORTLIGHT MASAÜSTÜ YARDIMCISI (CLI)          ")
		fmt.Println("========================================================")
		fmt.Println("1) Telefon ile Eşleştir (QR Kod Başlat) [Varsayılan]")
		fmt.Println("2) SSH Yapılandırmasını Önizle (Export)")
		fmt.Println("3) Telefon Açık Anahtarını Yetkilendir (Enroll)")
		fmt.Println("4) Yardım ve Kullanım Bilgisi")
		fmt.Print("\nSeçiminiz (1-4) [Enter = 1]: ")

		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(line)

		switch choice {
		case "2":
			args = []string{"export"}
		case "3":
			args = []string{"enroll"}
		case "4":
			usage()
			return nil
		default:
			args = []string{"pair"}
		}
	}

	switch args[0] {
	case "pair":
		pairCmd := flag.NewFlagSet("pair", flag.ContinueOnError)
		portFlag := pairCmd.Int("port", 4455, "port to listen on for pairing HTTP server")
		configFlag := pairCmd.String("config", "", "path to custom ssh config file")
		relayFlag := pairCmd.String("relay", os.Getenv(pairing.RelayEnv),
			"mailbox relay base URL (https://), used only if the phone cannot reach this machine; default $"+pairing.RelayEnv)
		if err := pairCmd.Parse(args[1:]); err != nil {
			return err
		}

		return pairing.RunInteractive(*configFlag, *portFlag, *relayFlag, os.Stdin, os.Stdout)

	case "export":
		exportCmd := flag.NewFlagSet("export", flag.ContinueOnError)
		jsonFlag := exportCmd.Bool("json", false, "output configuration as JSON")
		configFlag := exportCmd.String("config", "", "path to custom ssh config file")
		if err := exportCmd.Parse(args[1:]); err != nil {
			return err
		}

		return pairing.ExportConfig(*configFlag, *jsonFlag, os.Stdout, os.Stderr)

	case "enroll":
		enrollCmd := flag.NewFlagSet("enroll", flag.ContinueOnError)
		keyFlag := enrollCmd.String("key", "", "public key to append to authorized_keys")
		if err := enrollCmd.Parse(args[1:]); err != nil {
			return err
		}

		key := *keyFlag
		if key == "" && len(enrollCmd.Args()) > 0 {
			key = strings.Join(enrollCmd.Args(), " ")
		}

		if strings.TrimSpace(key) == "" {
			fmt.Print("Telefondaki genel anahtarı girin (örn: ssh-ed25519 AAA...): ")
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			key = strings.TrimSpace(line)
		}

		return pairing.EnrollKey(key, "", os.Stdout)

	case "version", "--version", "-v":
		fmt.Printf("portlight version %s\n", version)
		return nil

	case "help", "--help", "-h":
		usage()
		return nil

	default:
		return fmt.Errorf("unknown command %q (try `portlight help`)", args[0])
	}
}

func usage() {
	fmt.Print(`portlight — pair this machine with the Portlight app

Usage:
  portlight pair [--port 4455] [--config ~/.ssh/config] [--relay https://…]
      Send hosts, keys and known_hosts to your phone via encrypted QR code.
      --relay (or $PORTLIGHT_RELAY) adds a mailbox relay as a last resort
      when the phone cannot reach this machine; it only carries sealed,
      MAC'd messages and cannot read them.
  portlight export [--json] [--config ~/.ssh/config]
      Print what pairing would send (auditable, sends nothing)
  portlight enroll [<public-key>] [--key "<public-key>"]
      Authorize a phone-generated key into ~/.ssh/authorized_keys
  portlight agent install claude-code [--wait 120s]
      Let the phone approve Claude Code permission requests on this server
      (also: agent uninstall|status|pending|decide|events; see
      ` + "`portlight agent help`" + `)
  portlight version
      Print the version

Nothing is uploaded to third-party servers unless you pass --relay.
Pairing talks to the phone directly over the local network; the payload is an age (X25519 +
ChaCha20-Poly1305) envelope sent only after you confirm that the 6-digit
code matches on both screens. The session expires after 60 seconds.
`)
}
