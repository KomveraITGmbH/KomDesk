#!/usr/bin/env bash
set -e


APP_DIR="/opt/komvera-deskview"
SERVICE_NAME="komvera-deskview"
GIT_REPO="https://github.com/JasonDarrKomvera/KomveraDeskView.git"
NODE_MAJOR="20"

echo "==> Prüfe System..."

if [ ! -f /etc/os-release ]; then
    echo "Nicht unterstütztes Linux-System."
    exit 1
fi

. /etc/os-release

echo "Erkanntes System: $PRETTY_NAME"

case "$ID" in
    ubuntu|debian|raspbian)
        echo "==> Debian-basiertes System erkannt"
        ;;
    *)
        echo "Dieses Installationsscript unterstützt aktuell nur Ubuntu, Debian und Raspberry Pi OS."
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
echo "Möchtest du HTTPS mit nginx + Let's Encrypt einrichten?"
echo "  → Voraussetzung: Eine Domain die auf diesen Server zeigt"
echo "  → Ohne HTTPS läuft die App über HTTP (nur lokal/intern empfohlen)"
echo ""

HTTPS_ENABLED=false
DOMAIN=""

# Stelle sicher dass stdin vom Terminal kommt (auch bei curl | bash)
exec < /dev/tty

read -r -p "HTTPS einrichten? [j/N]: " HTTPS_CHOICE

if [[ "$HTTPS_CHOICE" =~ ^[jJyY]$ ]]; then
    echo ""
    read -r -p "Domain eingeben (z.B. deskview.example.com): " DOMAIN
    DOMAIN="${DOMAIN// /}"

    if [ -z "$DOMAIN" ]; then
        echo "Keine Domain eingegeben – weiter mit HTTP."
        HTTPS_ENABLED=false
    else
        echo ""
        read -r -p "E-Mail für Let's Encrypt (für Zertifikat-Benachrichtigungen): " LE_EMAIL
        LE_EMAIL="${LE_EMAIL// /}"
        if [ -z "$LE_EMAIL" ]; then
            echo "Keine E-Mail eingegeben – weiter mit HTTP."
            HTTPS_ENABLED=false
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
# System vorbereiten
# ──────────────────────────────────────────────
echo "==> System wird vorbereitet..."
sudo apt update
sudo apt install -y curl ca-certificates gnupg git

if ! command -v node >/dev/null 2>&1; then
    echo "==> Node.js wird installiert..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
    sudo apt install -y nodejs
fi

echo "==> Node Version:"
node -v
npm -v

# ──────────────────────────────────────────────
# App installieren
# ──────────────────────────────────────────────
echo "==> Installiere Anwendung nach $APP_DIR..."
sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"

if [ -d "$APP_DIR/.git" ]; then
    echo "==> Vorhandenes Repo gefunden, Update wird durchgeführt..."
    cd "$APP_DIR"
    git pull
else
    echo "==> Repo wird geklont..."
    git clone "$GIT_REPO" "$APP_DIR"
fi

cd "$APP_DIR"

echo "==> npm install läuft..."
npm install --omit=dev

mkdir -p public

# ──────────────────────────────────────────────
# systemd Service
# ──────────────────────────────────────────────
echo "==> systemd Service wird erstellt..."

if [ "$HTTPS_ENABLED" = true ]; then
    EXTRA_ENV="Environment=NODE_ENV=production
Environment=HTTPS_ENABLED=true"
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
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=always
RestartSec=5
User=${USER}
${EXTRA_ENV}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl restart ${SERVICE_NAME}

# ──────────────────────────────────────────────
# sudoers – Befehle ohne Passwort
# ──────────────────────────────────────────────
echo "==> sudoers Eintrag wird erstellt..."
SYSTEMCTL_BIN=$(readlink -f "$(which systemctl 2>/dev/null || echo "/usr/bin/systemctl")")
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
# Let's Encrypt (nur wenn HTTPS gewählt)
# ──────────────────────────────────────────────
if [ "$HTTPS_ENABLED" = true ]; then
    echo ""
    echo "==> Certbot wird installiert..."
    sudo apt install -y certbot

    echo "==> SSL-Zertifikat wird beantragt (Let's Encrypt)..."
    sudo certbot certonly --standalone \
        -d "$DOMAIN" \
        --email "$LE_EMAIL" \
        --agree-tos \
        --non-interactive

    echo ""
    echo "✅ Zertifikat erhalten"
    echo "   Pfad: /etc/letsencrypt/live/${DOMAIN}/"
    echo "   Zertifikat wird automatisch erneuert (certbot-Timer aktiv)."
fi

# ──────────────────────────────────────────────
# Fertig
# ──────────────────────────────────────────────
echo ""
echo "✅ Installation fertig"

if [ "$HTTPS_ENABLED" = true ]; then
    echo "   App erreichbar unter: https://${DOMAIN}"
else
    echo "   App erreichbar unter: http://<Server-IP>:3000"
fi

echo ""
echo "Update einspielen mit:"
echo "  cd ${APP_DIR} && git pull && npm install --omit=dev && sudo systemctl restart ${SERVICE_NAME}"
echo ""
echo "Status prüfen mit:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo ""
echo "Logs ansehen mit:"
echo "  journalctl -u ${SERVICE_NAME} -f"
