#!/bin/sh
# Installs the portlight CLI from its GitHub release (macOS, Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.sh | sh
#
# Options, as environment variables:
#   PORTLIGHT_VERSION      a tag such as v0.1.0 (default: the latest release)
#   PORTLIGHT_INSTALL_DIR  where the binary goes (default: /usr/local/bin if
#                          writable, otherwise ~/.local/bin)
#
# The archive is checked against the release's checksums.txt before anything
# is installed. When cosign is on PATH, checksums.txt's signature is checked
# too.
set -eu

repo="tudiapps/portlight-cli"

say() { printf '%s\n' "$*" >&2; }
fail() { say "portlight install: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "needs $1"; }
need uname
need tar
need mktemp

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL -o "$2" "$1"; }
  latest() { curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  latest() { wget -S --spider "https://github.com/$repo/releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
else
  fail "needs curl or wget"
fi

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

tag="${PORTLIGHT_VERSION:-}"
if [ -z "$tag" ]; then
  tag="$(latest)"
  tag="${tag##*/}"
fi
case "$tag" in
  v[0-9]*) ;;
  *) fail "could not find the latest release (got '$tag')" ;;
esac
version="${tag#v}"

archive="portlight_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading portlight $tag for $os/$arch"
fetch "$base/$archive" "$tmp/$archive"
fetch "$base/checksums.txt" "$tmp/checksums.txt"

expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$expected" ] || fail "$archive is not in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{ print $1 }')"
else
  need shasum
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive"

if command -v cosign >/dev/null 2>&1; then
  fetch "$base/checksums.txt.sig" "$tmp/checksums.txt.sig"
  fetch "$base/checksums.txt.pem" "$tmp/checksums.txt.pem"
  cosign verify-blob \
    --certificate "$tmp/checksums.txt.pem" \
    --signature "$tmp/checksums.txt.sig" \
    --certificate-identity-regexp "^https://github.com/$repo/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$tmp/checksums.txt" >/dev/null 2>&1 || fail "signature check failed"
  say "Signature verified"
fi

tar -xzf "$tmp/$archive" -C "$tmp" portlight

dir="${PORTLIGHT_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/portlight" "$dir/portlight" 2>/dev/null ||
  { cp "$tmp/portlight" "$dir/portlight" && chmod 0755 "$dir/portlight"; }

say "Installed $("$dir/portlight" version) to $dir/portlight"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Add $dir to your PATH to run it as 'portlight'." ;;
esac
