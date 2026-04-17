#!/usr/bin/env bash
set -e

APP_DIR="/opt/komdesk"
SERVICE_NAME="komdesk"
GIT_REPO="https://github.com/KomveraITGmbH/KomDesk.git"
NODE_MAJOR="20"
NGINX_CONF="/etc/nginx/sites-available/${SERVICE_NAME}"

# ──────────────────────────────────────────────
# Sprachauswahl / Language selection
# ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         Sprache / Language               ║"
echo "╠══════════════════════════════════════════╣"
echo "║  1) Deutsch                              ║"
echo "║  2) English                              ║"
echo "╚══════════════════════════════════════════╝"
echo ""

exec < /dev/tty
read -r -p "Auswahl / Select [1/2]: " LANG_CHOICE

if [[ "$LANG_CHOICE" == "2" ]]; then
    LANG_CODE="en"
    # ── English strings ──
    MSG_CHECK_SYS="==> Checking system..."
    MSG_DETECTED="Detected system"
    MSG_UNSUPPORTED="Unsupported Linux system."
    MSG_ONLY_DEBIAN="This script only supports Ubuntu, Debian and Raspberry Pi OS."
    MSG_HTTPS_TITLE="║         HTTPS / SSL Setup                ║"
    MSG_HTTPS_Q="Do you want to set up HTTPS with Let's Encrypt (DNS challenge)?"
    MSG_HTTPS_REQ1="  → Requirement: A domain (internal server – no public access needed)"
    MSG_HTTPS_REQ2="  → You must be able to add a DNS TXT record to your domain"
    MSG_HTTPS_REQ3="  → Required for Microsoft SSO – server stays internal"
    MSG_HTTPS_PROMPT="Set up HTTPS? [y/N]: "
    MSG_HTTPS_YES_REGEX="^[yYjJ]$"
    MSG_DOMAIN_PROMPT="Enter domain (e.g. komdesk.example.com): "
    MSG_NO_DOMAIN="No domain entered – continuing with HTTP."
    MSG_EMAIL_PROMPT="E-Mail for Let's Encrypt: "
    MSG_NO_EMAIL="No e-mail entered – continuing with HTTP."
    MSG_HTTP_FALLBACK="  → Continuing with HTTP."
    MSG_DOMAIN_LBL="  Domain"
    MSG_EMAIL_LBL="  E-Mail"
    MSG_HTTPS_LBL="  HTTPS"
    MSG_HTTPS_VAL="will be configured (DNS challenge)"
    MSG_CLEANUP="==> Cleaning up previous installation..."
    MSG_PACKAGES="==> Installing packages..."
    MSG_FIREWALL="==> Configuring firewall..."
    MSG_NODE_INSTALL="==> Installing Node.js ${NODE_MAJOR}..."
    MSG_APP_INSTALL="==> Installing application to"
    MSG_UPDATE="==> Updating existing installation..."
    MSG_CLONE="==> Cloning repository..."
    MSG_NPM="==> Running npm install..."
    MSG_NGINX="==> Configuring nginx..."
    MSG_SERVICE="==> Creating systemd service..."
    MSG_SUDOERS="==> Creating sudoers entry..."
    MSG_SUDOERS_OK="==> sudoers OK"
    MSG_SUDOERS_WARN="==> WARNING: sudoers syntax error, removing"
    MSG_CERTBOT_INSTALL="==> Installing Certbot..."
    MSG_CERTBOT_CLEAN="==> Cleaning up old certificate configuration..."
    MSG_CERTBOT_REQ="==> Requesting SSL certificate via DNS challenge..."
    MSG_DNS_HINT="  → Certbot will now show you a TXT record to add to your DNS."
    MSG_DNS_HINT2="  → Add it, wait ~60 seconds for propagation, then press Enter."
    MSG_CERT_OK="✅ Certificate obtained"
    MSG_SVC_START="==> Starting service..."
    MSG_SVC_OK="✅ Service is running"
    MSG_SVC_FAIL="❌ Service could not be started. Logs:"
    MSG_DONE_TITLE="║          ✅ Installation complete        ║"
    MSG_REACH="   App available at"
    MSG_UPDATE_CMD="Update:"
    MSG_LOGS_CMD="Logs:"
else
    LANG_CODE="de"
    # ── Deutsche strings ──
    MSG_CHECK_SYS="==> Prüfe System..."
    MSG_DETECTED="Erkanntes System"
    MSG_UNSUPPORTED="Nicht unterstütztes Linux-System."
    MSG_ONLY_DEBIAN="Dieses Script unterstützt nur Ubuntu, Debian und Raspberry Pi OS."
    MSG_HTTPS_TITLE="║         HTTPS / SSL Einrichtung          ║"
    MSG_HTTPS_Q="Möchtest du HTTPS mit Let's Encrypt (DNS-Challenge) einrichten?"
    MSG_HTTPS_REQ1="  → Voraussetzung: Eine Domain (interner Server – kein öffentlicher Zugriff nötig)"
    MSG_HTTPS_REQ2="  → Du musst einen DNS TXT-Eintrag bei deiner Domain setzen können"
    MSG_HTTPS_REQ3="  → Wird für Microsoft SSO benötigt – Server bleibt intern"
    MSG_HTTPS_PROMPT="HTTPS einrichten? [j/N]: "
    MSG_HTTPS_YES_REGEX="^[jJyY]$"
    MSG_DOMAIN_PROMPT="Domain eingeben (z.B. komdesk.example.com): "
    MSG_NO_DOMAIN="Keine Domain eingegeben – weiter mit HTTP."
    MSG_EMAIL_PROMPT="E-Mail für Let's Encrypt: "
    MSG_NO_EMAIL="Keine E-Mail eingegeben – weiter mit HTTP."
    MSG_HTTP_FALLBACK="  → Weiter mit HTTP."
    MSG_DOMAIN_LBL="  Domain"
    MSG_EMAIL_LBL="  E-Mail"
    MSG_HTTPS_LBL="  HTTPS"
    MSG_HTTPS_VAL="wird eingerichtet (DNS-Challenge)"
    MSG_CLEANUP="==> Vorherige Installation wird bereinigt..."
    MSG_PACKAGES="==> Pakete werden installiert..."
    MSG_FIREWALL="==> Firewall wird konfiguriert..."
    MSG_NODE_INSTALL="==> Node.js ${NODE_MAJOR} wird installiert..."
    MSG_APP_INSTALL="==> Installiere Anwendung nach"
    MSG_UPDATE="==> Update wird durchgeführt..."
    MSG_CLONE="==> Repo wird geklont..."
    MSG_NPM="==> npm install läuft..."
    MSG_NGINX="==> nginx wird konfiguriert..."
    MSG_SERVICE="==> systemd Service wird erstellt..."
    MSG_SUDOERS="==> sudoers Eintrag wird erstellt..."
    MSG_SUDOERS_OK="==> sudoers OK"
    MSG_SUDOERS_WARN="==> WARNUNG: sudoers Syntax-Fehler, wird entfernt"
    MSG_CERTBOT_INSTALL="==> Certbot wird installiert..."
    MSG_CERTBOT_CLEAN="==> Alte Zertifikatskonfiguration bereinigen..."
    MSG_CERTBOT_REQ="==> SSL-Zertifikat wird per DNS-Challenge beantragt..."
    MSG_DNS_HINT="  → Certbot zeigt dir gleich einen TXT-Eintrag für deine DNS."
    MSG_DNS_HINT2="  → Eintrag setzen, ~60 Sekunden warten, dann Enter drücken."
    MSG_CERT_OK="✅ Zertifikat erhalten"
    MSG_SVC_START="==> Service wird gestartet..."
    MSG_SVC_OK="✅ Service läuft"
    MSG_SVC_FAIL="❌ Service konnte nicht gestartet werden. Logs:"
    MSG_DONE_TITLE="║          ✅ Installation fertig          ║"
    MSG_REACH="   App erreichbar unter"
    MSG_UPDATE_CMD="Update:"
    MSG_LOGS_CMD="Logs:"
fi

# ──────────────────────────────────────────────
# System prüfen
# ──────────────────────────────────────────────
echo "$MSG_CHECK_SYS"

if [ ! -f /etc/os-release ]; then
    echo "$MSG_UNSUPPORTED"
    exit 1
fi

. /etc/os-release
echo "$MSG_DETECTED: $PRETTY_NAME"

case "$ID" in
    ubuntu|debian|raspbian) ;;
    *)
        echo "$MSG_ONLY_DEBIAN"
        exit 1
        ;;
esac

# ──────────────────────────────────────────────
# HTTPS-Auswahl
# ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "$MSG_HTTPS_TITLE"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "$MSG_HTTPS_Q"
echo "$MSG_HTTPS_REQ1"
echo "$MSG_HTTPS_REQ2"
echo "$MSG_HTTPS_REQ3"
echo ""

HTTPS_ENABLED=false
DOMAIN=""
LE_EMAIL=""

read -r -p "$MSG_HTTPS_PROMPT" HTTPS_CHOICE

if [[ "$HTTPS_CHOICE" =~ $MSG_HTTPS_YES_REGEX ]]; then
    echo ""
    read -r -p "$MSG_DOMAIN_PROMPT" DOMAIN
    DOMAIN="${DOMAIN// /}"

    if [ -z "$DOMAIN" ]; then
        echo "$MSG_NO_DOMAIN"
    else
        echo ""
        read -r -p "$MSG_EMAIL_PROMPT" LE_EMAIL
        LE_EMAIL="${LE_EMAIL// /}"

        if [ -z "$LE_EMAIL" ]; then
            echo "$MSG_NO_EMAIL"
            DOMAIN=""
        else
            HTTPS_ENABLED=true
            echo ""
            echo "$MSG_DOMAIN_LBL : $DOMAIN"
            echo "$MSG_EMAIL_LBL  : $LE_EMAIL"
            echo "$MSG_HTTPS_LBL  : $MSG_HTTPS_VAL"
        fi
    fi
else
    echo "$MSG_HTTP_FALLBACK"
fi

echo ""

# ──────────────────────────────────────────────
# Vorherige Installation bereinigen
# ──────────────────────────────────────────────
echo "$MSG_CLEANUP"
sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true
sudo systemctl disable ${SERVICE_NAME} 2>/dev/null || true
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
sudo systemctl stop apache2 2>/dev/null || true
sudo systemctl disable apache2 2>/dev/null || true
sudo apt-get remove --purge -y apache2 apache2-bin apache2-data apache2-utils 2>/dev/null || true
sudo rm -rf /etc/apache2 2>/dev/null || true
sudo systemctl stop nginx 2>/dev/null || true
sudo rm -f /etc/nginx/sites-enabled/*
sudo rm -f /etc/nginx/sites-available/*
sudo rm -f /etc/nginx/conf.d/*.conf 2>/dev/null || true
sudo systemctl daemon-reload
sudo apt-get autoremove -y 2>/dev/null || true

# ──────────────────────────────────────────────
# Pakete installieren
# ──────────────────────────────────────────────
echo "$MSG_PACKAGES"
sudo apt-get update -qq
sudo apt-get install -y curl ca-certificates gnupg git ufw nginx

# ──────────────────────────────────────────────
# Firewall konfigurieren
# ──────────────────────────────────────────────
echo "$MSG_FIREWALL"
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# ──────────────────────────────────────────────
# Node.js installieren
# ──────────────────────────────────────────────
NODE_OK=false
if command -v node >/dev/null 2>&1; then
    INSTALLED_MAJOR=$(node -e "process.stdout.write(process.version.split('.')[0].replace('v',''))" 2>/dev/null || echo "0")
    if [ "$INSTALLED_MAJOR" -ge "$NODE_MAJOR" ]; then
        NODE_OK=true
    fi
fi

if [ "$NODE_OK" = false ]; then
    echo "$MSG_NODE_INSTALL"
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "==> Node $(node -v) / npm $(npm -v)"

# ──────────────────────────────────────────────
# App installieren
# ──────────────────────────────────────────────
echo "$MSG_APP_INSTALL $APP_DIR..."
sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"

if [ -d "$APP_DIR/.git" ]; then
    echo "$MSG_UPDATE"
    git -C "$APP_DIR" pull
else
    echo "$MSG_CLONE"
    git clone "$GIT_REPO" "$APP_DIR"
fi

cd "$APP_DIR"
mkdir -p public

echo "$MSG_NPM"
npm install --omit=dev

# ──────────────────────────────────────────────
# Let's Encrypt via DNS-Challenge
# ──────────────────────────────────────────────
if [ "$HTTPS_ENABLED" = true ]; then
    echo ""
    echo "$MSG_CERTBOT_INSTALL"
    sudo apt-get install -y certbot

    echo "$MSG_CERTBOT_CLEAN"
    sudo certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || true

    echo ""
    echo "$MSG_CERTBOT_REQ"
    echo "$MSG_DNS_HINT"
    echo "$MSG_DNS_HINT2"
    echo ""

    sudo certbot certonly \
        --manual \
        --preferred-challenges dns \
        -d "$DOMAIN" \
        --email "$LE_EMAIL" \
        --agree-tos

    echo ""
    echo "$MSG_CERT_OK: /etc/letsencrypt/live/${DOMAIN}/"
fi

# ──────────────────────────────────────────────
# nginx konfigurieren
# ──────────────────────────────────────────────
echo "$MSG_NGINX"

if [ "$HTTPS_ENABLED" = true ]; then
    sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
}
EOF
else
    sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name _;
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
}
EOF
fi

sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/${SERVICE_NAME}
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

# ──────────────────────────────────────────────
# systemd Service
# ──────────────────────────────────────────────
echo "$MSG_SERVICE"

sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=KomDesk
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=$(which node) ${APP_DIR}/server.js
Restart=always
RestartSec=5
User=${USER}
Environment=NODE_ENV=production
Environment=DEFAULT_LANG=${LANG_CODE}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}

# ──────────────────────────────────────────────
# sudoers
# ──────────────────────────────────────────────
echo "$MSG_SUDOERS"
SYSTEMCTL_BIN=$(readlink -f "$(which systemctl)")
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_NAME}"
sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
${USER} ALL=(ALL) NOPASSWD: ${SYSTEMCTL_BIN} status ${SERVICE_NAME} --no-pager -l
${USER} ALL=(ALL) NOPASSWD: ${SYSTEMCTL_BIN} restart ${SERVICE_NAME}
${USER} ALL=(ALL) NOPASSWD: ${SYSTEMCTL_BIN} start ${SERVICE_NAME}
${USER} ALL=(ALL) NOPASSWD: ${SYSTEMCTL_BIN} stop ${SERVICE_NAME}
${USER} ALL=(ALL) NOPASSWD: ${SYSTEMCTL_BIN} reboot
EOF
sudo chmod 440 "$SUDOERS_FILE"
if sudo visudo -cf "$SUDOERS_FILE"; then
    echo "$MSG_SUDOERS_OK"
else
    echo "$MSG_SUDOERS_WARN"
    sudo rm -f "$SUDOERS_FILE"
fi

# ──────────────────────────────────────────────
# Service starten
# ──────────────────────────────────────────────
echo "$MSG_SVC_START"
sudo systemctl restart ${SERVICE_NAME}

sleep 2
if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
    echo "$MSG_SVC_OK"
else
    echo "$MSG_SVC_FAIL"
    sudo journalctl -u ${SERVICE_NAME} -n 20 --no-pager
    exit 1
fi

# ──────────────────────────────────────────────
# Fertig
# ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "$MSG_DONE_TITLE"
echo "╚══════════════════════════════════════════╝"
echo ""

if [ "$HTTPS_ENABLED" = true ]; then
    echo "$MSG_REACH: https://${DOMAIN}"
else
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo "$MSG_REACH: http://${SERVER_IP}"
fi

echo ""
echo "$MSG_UPDATE_CMD"
echo "  cd ${APP_DIR} && git pull && npm install --omit=dev && sudo systemctl restart ${SERVICE_NAME}"
echo ""
echo "$MSG_LOGS_CMD"
echo "  journalctl -u ${SERVICE_NAME} -f"
echo ""
