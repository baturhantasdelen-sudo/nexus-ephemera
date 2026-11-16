#!/bin/sh
# Install the broker daemon and seal the pilot package.
# Root uses /etc/nexus-ephemera. Everyone else uses ./var/nexus-ephemera
# or NEXUS_PREFIX. The broker secret is not written by this script.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -n "${NEXUS_PREFIX:-}" ]; then
  PREFIX=$NEXUS_PREFIX
elif [ "$(id -u)" -eq 0 ]; then
  PREFIX=/etc/nexus-ephemera
else
  PREFIX=$ROOT/var/nexus-ephemera
fi
mkdir -p "$PREFIX"
cp "$ROOT/policies/pilot_support_agent.json" "$PREFIX/pilot_support_agent.json"
case $(uname -s) in
  MINGW*|MSYS*|CYGWIN*) LISTEN='\\.\pipe\nexus-ephemera' ;;
  *) LISTEN=$PREFIX/broker.sock ;;
esac
cat > "$PREFIX/config.toml" <<EOF
listen = "$LISTEN"
timeout_ms = 5000
policy = "pilot_support_agent.json"
allow = "https://api.github.com/repos/pilot-org/support-queue/issues"
redis = ""
EOF
cat > "$PREFIX/.env" <<EOF
NEXUS_LISTEN=$LISTEN
NEXUS_POLICY=pilot_support_agent.json
NEXUS_TIMEOUT_MS=5000
NEXUS_REDIS_URL=
EOF
cargo build --manifest-path "$ROOT/Cargo.toml" --release --bin nexus-daemon
"$ROOT/target/release/nexus-daemon" --package "$PREFIX" --seal
"$ROOT/target/release/nexus-daemon" --package "$PREFIX" --check
echo "installed $PREFIX"
