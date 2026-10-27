#!/usr/bin/env bash
# Source tarball and rendered Homebrew formula under dist/; with --brew-test,
# install the formula from source, run its test block, and uninstall.
# Usage: scripts/package.sh [--brew-test]      (the brew step takes minutes)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)"$/\1/')
mkdir -p dist
TAR="dist/inumaki-$VERSION.tar.gz"
# The formula's cargo build exports it as INUMAKI_BUILD_REV, which goes into
# the daemon's configuration fingerprint (crates/inumakid/src/config.rs).
REV=$(git rev-parse --short HEAD)
git archive --format=tar.gz --prefix="inumaki-$VERSION/" -o "$TAR" HEAD
SHA=$(shasum -a 256 "$TAR" | cut -d' ' -f1)
# Control-char delimiter (cannot occur in a path); escape \ and & in the values
# so a checkout path with spaces, |, or & renders correctly.
D=$'\001'
esc() { printf '%s' "$1" | sed -e 's/[\\&]/\\&/g'; }
sed -e "s${D}@URL@${D}$(esc "file://$PWD/$TAR")${D}" \
    -e "s${D}@SHA256@${D}$(esc "$SHA")${D}" \
    -e "s${D}@VERSION@${D}$(esc "$VERSION")${D}" \
    -e "s${D}@BUILD_REV@${D}$(esc "$REV")${D}" \
  packaging/homebrew/inumaki.rb.in > dist/inumaki.rb
ruby -c dist/inumaki.rb >/dev/null
echo "rendered dist/inumaki.rb from $TAR (sha256 $SHA)"
if [ "${1:-}" = "--brew-test" ]; then
  brew install --formula --build-from-source dist/inumaki.rb
  brew test inumaki
  brew uninstall inumaki
  echo "brew install/test/uninstall ok"
fi
