#!/usr/bin/env bash
# Build the .deb in a Debian container (the reference machine is macOS) from
# the committed tree, then install it into a fresh debian:bookworm container
# and run a smoke test. Unsigned. Usage: scripts/package-deb.sh [--arch arm64|amd64]
# amd64 on an Apple Silicon host runs under emulation and is slow (30+ min).
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
if [ "${1:-}" = "--arch" ]; then
  ARCH=${2:-}
  case "$ARCH" in arm64|amd64) ;; *)
    echo "usage: scripts/package-deb.sh [--arch arm64|amd64]" >&2; exit 2 ;;
  esac
fi
mkdir -p dist
# The git revision goes into the daemon's configuration fingerprint, so a
# rebuilt engine re-mirrors every folder (crates/inumakid/src/config.rs).
# Read here: the container sees only the exported tree, not .git.
if REV=$(git rev-parse --short HEAD 2>/dev/null); then export INUMAKI_BUILD_REV="$REV"; fi
docker run --rm --platform "linux/$ARCH" -e INUMAKI_BUILD_REV \
  -v "$PWD":/src:ro -v "$PWD/dist":/out \
  -v inumaki-deb-registry:/usr/local/cargo/registry \
  -v "inumaki-deb-target-$ARCH":/build/target \
  rust:1-bookworm bash -ec '
    mkdir -p /build && cd /src && git archive HEAD | tar -x -C /build && cd /build
    export PATH=/build/target/tools/bin:$PATH
    command -v cargo-deb >/dev/null || cargo install cargo-deb --locked --root /build/target/tools
    cargo build --release --locked -p inumaki-cli -p inumakid -p inumaki-mcp -p inumaki-hook
    cargo deb -p inumaki-cli --no-build --output /out/
    ls -l /out/*.deb'
DEB=$(ls -t dist/inumaki_*_"$ARCH".deb | head -1)
echo "built $DEB"
docker run --rm --platform "linux/$ARCH" -v "$PWD/dist":/dist:ro debian:bookworm bash -ec "
    apt-get update -qq >/dev/null && apt-get install -y -qq /dist/$(basename "$DEB") >/dev/null
    inumaki --version
    echo 'IBAN AT61 1904 3002 3457 3201' | inumaki tokenize --profile offline - | grep -q '<IBAN_'
    test -f /usr/lib/systemd/user/inumakid.service
    test -f /usr/share/inumaki/default.toml
    test -f /usr/share/doc/inumaki/runbook.md
    echo 'deb install smoke ok'"
