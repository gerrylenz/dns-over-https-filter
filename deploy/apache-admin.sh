#!/bin/bash
# Öffnet die Oberfläche über https://$ADMIN_HOST/ mit Anmeldung.
# Die Oberfläche selbst bleibt auf 127.0.0.1. Einmal mit sudo ausführen.
# HOSTNAME, ADMIN_HOST und ADMIN_USER stehen in deploy/site.env.
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

PASSFILE=/etc/apache2/dns-filter.htpasswd
if [[ ! -f "$PASSFILE" ]]; then
  password="$(openssl rand -base64 18)"
  htpasswd -B -b -c "$PASSFILE" "$ADMIN_USER" "$password"
  chown root:www-data "$PASSFILE"
  chmod 640 "$PASSFILE"
  echo "Anmeldung: Benutzer $ADMIN_USER"
  echo "Passwort: $password"
else
  echo "Anmeldung bleibt unverändert."
fi

cat > /etc/apache2/sites-available/dns-filter.conf << EOF
<VirtualHost *:80>
    ServerName ${ADMIN_HOST}
    DocumentRoot /var/www/html
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/
    RewriteRule ^ https://${ADMIN_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName ${ADMIN_HOST}
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${HOSTNAME}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${HOSTNAME}/privkey.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8090/
    ProxyPassReverse / http://127.0.0.1:8090/

    <Location />
        AuthType Basic
        AuthName "DNS-over-HTTPS Filter"
        AuthUserFile /etc/apache2/dns-filter.htpasswd
        Require valid-user
    </Location>
</VirtualHost>
EOF

a2ensite dns-filter
apache2ctl configtest
systemctl reload apache2
echo "fertig: https://${ADMIN_HOST}/"
