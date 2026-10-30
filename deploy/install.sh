#!/bin/bash
# Richtet Unbound als lokalen Resolver und den Filter davor ein.
# Einmal mit sudo ausführen. Schreibt kein Token auf die Konsole.
# HOSTNAME steht in deploy/site.env.
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/site.env"
if [[ "$HOSTNAME" == "beispiel.domain" || "$ADMIN_HOST" == "dns.beispiel.domain" || "$ADMIN_USER" == "dein_username" ]]; then
  echo "HOSTNAME, ADMIN_HOST und ADMIN_USER in deploy/site.env auf die eigenen Werte setzen." >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Bitte mit sudo ausführen." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG=/tmp/dns-server-install.log
touch "$LOG"
chmod 644 "$LOG"
exec > >(tee -a "$LOG") 2>&1
echo "== $(date -Is) Installation startet aus $ROOT"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y unbound dnsutils build-essential cmake pkg-config libssl-dev curl ca-certificates

install -d -m 755 /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/filter.conf << 'EOF'
server:
    interface: ::1
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    prefetch: yes
    verbosity: 1
EOF

unbound-checkconf
interfaces="$(unbound-checkconf -o interface || true)"
if printf '%s\n' "$interfaces" | grep -Eq '^(0\.0\.0\.0|::)$'; then
  echo "Unbound würde auf allen Adressen lauschen: $interfaces" >&2
  exit 1
fi
systemctl enable unbound
systemctl restart unbound
dig +time=4 +tries=1 @127.0.0.1 example.com A | grep -q 'status: NOERROR'

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
cd "$ROOT"
cargo build --release

if ! id dns-server >/dev/null 2>&1; then
  useradd --system --home /var/lib/dns-server --shell /usr/sbin/nologin dns-server
fi
install -d -o dns-server -g dns-server -m 750 /var/lib/dns-server
install -d -o dns-server -g dns-server -m 750 /var/lib/dns-server/lists
if [[ -d "$ROOT/data/lists" ]]; then
  cp -a "$ROOT/data/lists/." /var/lib/dns-server/lists/
  chown -R dns-server:dns-server /var/lib/dns-server/lists
fi

install -m 755 "$ROOT/target/release/dns-server" /usr/local/bin/dns-server
install -m 644 "$ROOT/deploy/dns-server.service" /etc/systemd/system/dns-server.service

LIVE=/etc/letsencrypt/live/$HOSTNAME
if [[ ! -r "$LIVE/fullchain.pem" || ! -r "$LIVE/privkey.pem" ]]; then
  echo "Let's-Encrypt-Zertifikat für $HOSTNAME fehlt." >&2
  exit 1
fi
install -o dns-server -g dns-server -m 640 "$LIVE/fullchain.pem" /var/lib/dns-server/tls.crt
install -o dns-server -g dns-server -m 640 "$LIVE/privkey.pem" /var/lib/dns-server/tls.key

if [[ ! -f /var/lib/dns-server/server.toml ]]; then
  token="$(openssl rand -hex 32)"
  cat > /var/lib/dns-server/server.toml << EOF
hostname = "$HOSTNAME"
dns_listen = "127.0.0.1:5300"
doh_listen = "0.0.0.0:8443"
admin_listen = "127.0.0.1:8090"
clients = []
upstreams = ["127.0.0.1:53"]
block_mode = "nxdomain"
paused = false
allow = []
deny = ["data.microsoft.com", "office.com"]
rewrites = []
doh_token = "$token"
self_signed = false
cert_hostname = "$HOSTNAME"

[[blocklists]]
id = "oisd-small"
name = "OISD Small"
url = "https://small.oisd.nl/domainswild"
enabled = false

[[blocklists]]
id = "hagezi-pro"
name = "HaGeZi Pro"
url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
enabled = true

[[blocklists]]
id = "hagezi-tif"
name = "HaGeZi TIF"
url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt"
enabled = true

[[blocklists]]
id = "nrd-7"
name = "Neu registrierte Domains, 7 Tage"
url = "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt"
enabled = false
EOF
  chown dns-server:dns-server /var/lib/dns-server/server.toml
  chmod 640 /var/lib/dns-server/server.toml
fi

cat > /etc/letsencrypt/renewal-hooks/deploy/dns-server.sh << EOF
#!/bin/bash
set -euo pipefail
LIVE=/etc/letsencrypt/live/${HOSTNAME}
install -o dns-server -g dns-server -m 640 "\$LIVE/fullchain.pem" /var/lib/dns-server/tls.crt
install -o dns-server -g dns-server -m 640 "\$LIVE/privkey.pem" /var/lib/dns-server/tls.key
systemctl try-restart dns-server
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/dns-server.sh

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
  ufw allow 8443/tcp
fi

systemctl daemon-reload
systemctl enable dns-server
systemctl restart dns-server
systemctl --no-pager --full status unbound dns-server || true
echo "== $(date -Is) Installation fertig. Oberfläche: http://127.0.0.1:8090/"
