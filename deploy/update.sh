#!/bin/bash
# Baut den Filter neu und startet ihn. Einmal mit sudo ausführen.
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Bitte mit sudo ausführen." >&2
  exit 1
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f /root/.cargo/env ]]; then
  # shellcheck disable=SC1091
  source /root/.cargo/env
elif [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
cd "$ROOT"
cargo build --release
install -m 755 target/release/dns-server /usr/local/bin/dns-server
systemctl restart dns-server
echo "fertig"
