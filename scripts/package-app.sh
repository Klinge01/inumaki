#!/usr/bin/env bash
# Build Inumaki.app with the four helper binaries inside (Tauri sidecars),
# sign it ad hoc, verify the signature, and wrap it in dist/Inumaki-<version>.dmg.
# Unsigned in the Developer-ID sense (M6 spec §7.3). macOS only.
# Usage: scripts/package-app.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 1; }
VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)"$/\1/')
TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
# The git revision goes into the daemon's configuration fingerprint, so a
# rebuilt engine re-mirrors every folder (crates/inumakid/src/config.rs).
if REV=$(git rev-parse --short HEAD 2>/dev/null); then export INUMAKI_BUILD_REV="$REV"; fi
cargo build --release --locked -p inumaki-cli -p inumakid -p inumaki-mcp -p inumaki-hook
BIN=apps/inumaki-app/src-tauri/binaries
mkdir -p "$BIN"
for b in inumakid inumaki inumaki-mcp inumaki-hook; do
  cp "target/release/$b" "$BIN/$b-$TRIPLE"
done
(cd apps/inumaki-app && npm ci && npx tauri build --config src-tauri/tauri.bundle.conf.json)
APP=$(ls -d apps/inumaki-app/src-tauri/target/release/bundle/macos/*.app | head -1)
# Re-sign the whole bundle ad hoc so the sidecars and the app share one signature.
codesign --force --deep -s - "$APP"
codesign --verify --deep --strict "$APP"
mkdir -p dist
DMG="dist/Inumaki-$VERSION.dmg"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname Inumaki -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
echo "built $DMG"
