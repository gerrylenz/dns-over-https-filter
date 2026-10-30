#!/bin/bash
# Apache, Module, Ports 80 und 443 und das Zertifikat.
# Einmal mit sudo ausführen, bevor install.sh läuft.
# Die Namen müssen beim Anbieter der Domain schon auf diesen Server zeigen.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Bitte mit sudo ausführen." >&2
  exit 1
fi

# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/site.env"

if [[ "$HOSTNAME" == "beispiel.domain" || "$ADMIN_HOST" == "dns.beispiel.domain" || "$ADMIN_USER" == "dein_username" ]]; then
  echo "HOSTNAME, ADMIN_HOST und ADMIN_USER in deploy/site.env auf die eigenen Werte setzen." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apache2 apache2-utils certbot dnsutils curl ca-certificates

a2enmod ssl proxy proxy_http rewrite
a2ensite 000-default
systemctl enable --now apache2

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi

server_ip="$(curl -4 -fsS --max-time 15 https://api.ipify.org || true)"
if [[ -z "$server_ip" ]]; then
  echo "Die öffentliche IPv4-Adresse dieses Servers ist nicht ermittelbar." >&2
  exit 1
fi

names=("$HOSTNAME")
if [[ "$ADMIN_HOST" != "$HOSTNAME" ]]; then
  names+=("$ADMIN_HOST")
fi

for name in "${names[@]}"; do
  mapfile -t found < <(dig +time=4 +tries=1 +short A "$name" @1.1.1.1)
  match=0
  for ip in "${found[@]}"; do
    if [[ "$ip" == "$server_ip" ]]; then
      match=1
    fi
  done
  if [[ "$match" -ne 1 ]]; then
    echo "$name zeigt nicht auf $server_ip." >&2
    echo "Beim Anbieter der Domain den A-Eintrag setzen und warten, bis er hier sichtbar ist." >&2
    if [[ ${#found[@]} -eq 0 ]]; then
      echo "  gefunden: nichts" >&2
    else
      printf '  gefunden: %s\n' "${found[@]}" >&2
    fi
    exit 1
  fi
done

cert_args=(certbot certonly --webroot -w /var/www/html --agree-tos --non-interactive --keep-until-expiring)
if [[ -n "${CERTBOT_EMAIL:-}" ]]; then
  cert_args+=(--email "$CERTBOT_EMAIL")
else
  cert_args+=(--register-unsafely-without-email)
fi
for name in "${names[@]}"; do
  cert_args+=(-d "$name")
done
"${cert_args[@]}"

echo "fertig. Als Nächstes: deploy/install.sh"
