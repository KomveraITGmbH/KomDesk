#!/usr/bin/env bash
set -e

APP_DIR="/opt/komvera-deskview"
SERVICE_NAME="komvera-deskview"
GIT_REPO="https://github.com/JasonDarrKomvera/KomveraDeskView.git"
NODE_MAJOR="20"

# ──────────────────────────────────────────────
# System prüfen
# ──────────────────────────────────────────────
echo "==> Prüfe System..."

if [ ! -f /etc/os-release ]; then
    echo "Nicht unterstütztes Linux-System."
    exit 1
fi

. /etc/os-release
echo "Erkanntes System: $PRETTY_NAME"

case "$ID" in
    ubuntu|debian|raspbian) ;;
    *)
        echo "Dieses Script unterstützt nur Ubuntu, Debian und Raspberry Pi OS."
        exit 1
        ;;
esac

# ──────────────────────────────────────────────
# HTTPS-Auswahl
# ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         HTTPS / SSL Einrichtung          ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Möchtest du HTTPS mit Let's Encrypt einrichten?"
echo "  → Voraussetzung: Eine Domain mit A-Record auf diesen Server"
echo "  → Port 443 muss vom Router auf diesen Server weitergeleitet sein"
echo "  → Ohne HTTPS läuft die App über HTTP auf Port 80"
echo ""

HTTPS_ENABLED=false
DOMAIN=""
LE_EMAIL=""

exec < /dev/tty

read -r -p "HTTPS einrichten? [j/N]: " HTTPS_CHOICE

if [[ "$HTTPS_CHOICE" =~ ^[jJyY]$ ]]; then
    echo ""
    read -r -p "Domain eingeben (z.B. deskview.example.com): " DOMAIN
    DOMAIN="${DOMAIN// /}"

    if [ -z "$DOMAIN" ]; then
        echo "Keine Domain eingegeben – weiter mit HTTP."
    else
        echo ""
        read -r -p "E-Mail für Let's Encrypt: " LE_EMAIL
        LE_EMAIL="${LE_EMAIL// /}"

        if [ -z "$LE_EMAIL" ]; then
            echo "Keine E-Mail eingegeben – weiter mit HTTP."
            DOMAIN=""
        else
            HTTPS_ENABLED=true
            echo ""
            echo "  Domain : $DOMAIN"
            echo "  E-Mail : $LE_EMAIL"
            echo "  HTTPS  : wird eingerichtet"
        fi
    fi
else
    echo "  → Weiter mit HTTP."
fi

echo ""

# ──────────────────────────────────────────────
# Basispakete + Firewall
# ──────────────────────────────────────────────
echo "==> Basispakete werden installiert..."
sudo apt-get update -qq
sudo apt-get install -y curl ca-certificates gnupg git ufw

echo "==> Firewall wird konfiguriert..."
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# ──────────────────────────────────────────────
# Let's Encrypt – ZUERST, bevor alles andere läuft
# ──────────────────────────────────────────────
if [ "$HTTPS_ENABLED" = true ]; then
    echo ""
    echo "==> Apache + Certbot werden installiert..."
    sudo apt-get install -y apache2 certbot python3-certbot-apache

    echo "==> Apache wird gestartet..."
    sudo systemctl start apache2

    echo "==> Alte Zertifikatskonfiguration bereinigen..."
    sudo certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || true

    echo "==> SSL-Zertifikat wird beantragt (via Apache)..."
    sudo certbot certonly --apache \
        -d "$DOMAIN" \
        --email "$LE_EMAIL" \
        --agree-tos \
        --non-interactive

    echo "==> Apache wird gestoppt und deaktiviert..."
    sudo systemctl stop apache2
    sudo systemctl disable apache2

    echo ""
    echo "✅ Zertifikat erhalten: /etc/letsencrypt/live/${DOMAIN}/"
fi

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
    echo "==> Node.js ${NODE_MAJOR} wird installiert..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "==> Node $(node -v) / npm $(npm -v)"

# ──────────────────────────────────────────────
# App installieren
# ──────────────────────────────────────────────
echo "==> Installiere Anwendung nach $APP_DIR..."
sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"

if [ -d "$APP_DIR/.git" ]; then
    echo "==> Update wird durchgeführt..."
    git -C "$APP_DIR" pull
else
    echo "==> Repo wird geklont..."
    git clone "$GIT_REPO" "$APP_DIR"
fi

cd "$APP_DIR"
mkdir -p public

echo "==> npm install läuft..."
npm install --omit=dev

# ──────────────────────────────────────────────
# systemd Service
# ──────────────────────────────────────────────
echo "==> systemd Service wird erstellt..."

if [ "$HTTPS_ENABLED" = true ]; then
    EXTRA_ENV="Environment=NODE_ENV=production
Environment=HTTPS_ENABLED=true
Environment=DOMAIN=${DOMAIN}"
else
    EXTRA_ENV="Environment=NODE_ENV=production"
fi

sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Komvera DeskView
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=$(which node) ${APP_DIR}/server.js
Restart=always
RestartSec=5
User=${USER}
${EXTRA_ENV}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}

# ──────────────────────────────────────────────
# sudoers
# ──────────────────────────────────────────────
echo "==> sudoers Eintrag wird erstellt..."
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
    echo "==> sudoers OK"
else
    echo "==> WARNUNG: sudoers Syntax-Fehler, wird entfernt"
    sudo rm -f "$SUDOERS_FILE"
fi

# ──────────────────────────────────────────────
# Service starten
# ──────────────────────────────────────────────
echo "==> Service wird gestartet..."
sudo systemctl restart ${SERVICE_NAME}

sleep 2
if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
    echo "✅ Service läuft"
else
    echo "❌ Service konnte nicht gestartet werden. Logs:"
    sudo journalctl -u ${SERVICE_NAME} -n 20 --no-pager
    exit 1
fi

# ──────────────────────────────────────────────
# Fertig
# ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║          ✅ Installation fertig          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

if [ "$HTTPS_ENABLED" = true ]; then
    echo "   App erreichbar unter: https://${DOMAIN}"
else
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo "   App erreichbar unter: http://${SERVER_IP}:3000"
fi

echo ""
echo "Update:"
echo "  cd ${APP_DIR} && git pull && npm install --omit=dev && sudo systemctl restart ${SERVICE_NAME}"
echo ""
echo "Logs:"
echo "  journalctl -u ${SERVICE_NAME} -f"
echo ""
