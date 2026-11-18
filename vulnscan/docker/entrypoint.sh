#!/bin/sh
# Start as root only long enough to make the data volume writable, then drop to the
# unprivileged 'scanner' user for the actual process (defence in depth).
set -e
if [ "$(id -u)" = "0" ]; then
  chown -R scanner:scanner /data 2>/dev/null || true
  exec gosu scanner "$@"
fi
exec "$@"
