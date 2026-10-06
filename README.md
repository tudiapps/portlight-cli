# portlight

Desktop companion for the Portlight mobile app. One command hands your SSH
hosts, keys and known hosts to your phone — over your local network,
end-to-end encrypted, after you compare a 6-digit code on both screens.

```sh
portlight pair      # show a QR code, pair with the phone
portlight export    # print what pairing would send (private keys hidden)
portlight enroll <public-key>   # authorize a phone-generated key
```

## Quick start

You need the [Portlight app](https://play.google.com/store/apps/details?id=com.tudiapps.portlight)
on your phone, and the phone and computer on the same network.

**Windows** — open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.ps1 | iex
```

**macOS** — open Terminal and run:

```sh
brew install tudiapps/tap/portlight
```

No Homebrew? Use the script instead (also for Linux):

```sh
curl -fsSL https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.sh | sh
```

Then, on the computer:

```sh
portlight pair
```

A QR code appears. In the app: **Settings → Pairing → Open camera and scan**,
scan it, check that the 6-digit code is the same on both screens, and confirm
on the computer. Your hosts and keys arrive on the phone.

If Windows asks whether `portlight` may use the network, allow it.

### Türkçe

Telefonda [Portlight](https://play.google.com/store/apps/details?id=com.tudiapps.portlight)
yüklü olsun, telefon ve bilgisayar aynı ağda olsun.

1. **Windows:** PowerShell'i aç, yukarıdaki `irm … | iex` satırını çalıştır.
   **macOS:** Terminal'i aç, `brew install tudiapps/tap/portlight` (Homebrew
   yoksa `curl … | sh` satırı).
2. Bilgisayarda `portlight pair` çalıştır; ekranda QR kod çıkar.
3. Uygulamada **Ayarlar → Eşleştirme → Kamerayı aç ve okut**, QR'ı okut, iki
   ekrandaki 6 haneli kodun aynı olduğunu kontrol et, bilgisayarda onayla.

Windows ağ izni sorarsa izin ver.

## Install

| | |
|---|---|
| macOS, Linux (Homebrew) | `brew install tudiapps/tap/portlight` |
| Windows (winget) | `winget install Tudiapps.Portlight` — in Microsoft's review, not available yet |
| Windows (Scoop) | `scoop bucket add tudiapps https://github.com/tudiapps/scoop-bucket` then `scoop install tudiapps/portlight` |
| macOS, Linux (script) | `curl -fsSL https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.sh \| sh` |
| Windows (script) | `irm https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.ps1 \| iex` |
| Go | `go install github.com/tudiapps/portlight-cli/cmd/portlight@latest` |

Or download an archive from the
[releases](https://github.com/tudiapps/portlight-cli/releases). Every
release has a `checksums.txt`, signed keylessly with
[cosign](https://docs.sigstore.dev/) by this repository's release workflow:

```sh
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/tudiapps/portlight-cli/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

The install scripts check the archive against `checksums.txt`, and the
signature too when `cosign` is installed. The macOS binary is not notarized;
the Homebrew cask clears the quarantine flag, a manual download needs
`xattr -d com.apple.quarantine portlight`.

## What gets sent

- Hosts from `~/.ssh/config` (with `Include`; `Match exec/user/…` blocks
  are skipped and reported).
- On Windows, PuTTY's saved SSH sessions too (group `putty`), with their
  `.ppk` key. A session named like a host in `~/.ssh/config` is skipped.
  PuTTY stores no passwords, so none are read.
- The private keys those hosts use, plus `~/.ssh/id_{ed25519,ecdsa,rsa}` and
  `~/.ssh/*.ppk`. Keys go as they are on disk: a passphrase-protected key
  stays protected. PuTTY keys are converted to OpenSSH first; a protected
  one is re-encrypted with the same passphrase.
- `~/.ssh/known_hosts`.
- Which AI agents are installed (Hermes, Claude Code, OpenClaw) — the kind
  only, never their files or tokens.

Desktop paths are not sent. Run `portlight export` to see exactly what
would go.

## How pairing stays private

1. The QR carries a one-time session id and a secret that never crosses the
   network. Only a device that saw the QR can claim the session.
2. Phone and desktop run a commit/reveal exchange and both show the same
   6-digit code. You confirm on the desktop that they match; nothing is sent
   before that.
3. The payload is sealed with [age](https://age-encryption.org) to a key the
   phone generated for this pairing only.
4. The session is single-use and expires after 60 seconds. `portlight`
   writes nothing to disk while pairing.

Full protocol: [docs/pairing-protocol.md](docs/pairing-protocol.md).

## Relay (optional)

If the phone cannot reach this machine (different network, client
isolation), `portlight pair --relay https://relay.example.com` (or
`PORTLIGHT_RELAY`) adds a mailbox relay as the last fallback. The same
MAC'd messages and the same age envelope go through it; the relay sees box
ids, sizes, timing and IP addresses, never the QR secret, the code or the
payload. There is no default relay. For local development:
`go run ./cmd/devrelay` prints `{"url": "http://127.0.0.1:NNNN"}`.

## Windows

If Windows Firewall asks, allow `portlight` on the network you are on —
otherwise the phone cannot reach it. On a network marked *Public*, the
firewall blocks incoming connections by default.
