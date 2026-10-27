#!/usr/bin/env sh
# Start the pinned GreenMail image for the mail tests (M4 spec §13).
# Ports are host-side; another GreenMail on this machine may own the
# defaults, so pass GREENMAIL_IMAP_PORT to move it. Plaintext IMAP only:
# GreenMail's IMAPS certificate is self-signed and not trusted by the
# connector (docs/mail-providers.md).
set -eu
IMAGE="greenmail/standalone:2.1.14"
NAME="${GREENMAIL_NAME:-inumaki-greenmail}"
IMAP="${GREENMAIL_IMAP_PORT:-3143}"
USER_="${GREENMAIL_USER:-agent}"
PASS="${GREENMAIL_PASSWORD:-secret}"
case "${1:-start}" in
  start)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run --rm -d --name "$NAME" \
      -e GREENMAIL_OPTS="-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=${USER_}:${PASS}@example.test -Dgreenmail.verbose" \
      -p "127.0.0.1:${IMAP}:3143" "$IMAGE" >/dev/null
    for _ in $(seq 1 60); do
      if docker logs "$NAME" 2>&1 | grep -q 'Started imap'; then
        echo "greenmail ${IMAGE} ready: imap 127.0.0.1:${IMAP} user ${USER_}"
        exit 0
      fi
      sleep 0.5
    done
    echo "greenmail did not start" >&2
    docker logs "$NAME" >&2 || true
    exit 1
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    ;;
  *)
    echo "usage: $0 [start|stop]" >&2
    exit 2
    ;;
esac
