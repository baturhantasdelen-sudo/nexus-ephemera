#!/bin/sh
# Fresh package bootstrap. Rust owns private creation, schema and sealing.
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -n "${NEXUS_PREFIX:-}" ]; then
  PREFIX=$NEXUS_PREFIX
elif [ "$(id -u)" -eq 0 ]; then
  PREFIX=/etc/nexus-ephemera
else
  PREFIX=$ROOT/var/nexus-ephemera
fi
case $(uname -s) in
  MINGW*|MSYS*|CYGWIN*) LISTEN='\\.\pipe\nexus-ephemera' ;;
  *) LISTEN=$PREFIX/broker.sock ;;
esac
cargo build --locked --manifest-path "$ROOT/Cargo.toml" --release --bin nexus-daemon
"$ROOT/target/release/nexus-daemon" --listen "$LISTEN" --package "$PREFIX" --init-package
"$ROOT/target/release/nexus-daemon" --package "$PREFIX" --check
echo "installed $PREFIX"
