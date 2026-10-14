#!/usr/bin/env bash
# SIWANKURDSH panel installer (Ubuntu/Debian, run as root)
set -e
[ "$EUID" -eq 0 ] || { echo "Please run as root: sudo bash install.sh"; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/siwankurdsh
PROXY=/opt/mtprotoproxy

read -rp "Admin username [admin]: " ADMIN_USER; ADMIN_USER=${ADMIN_USER:-admin}
while true; do
  read -rsp "Admin password: " ADMIN_PASS; echo
  [[ -n "$ADMIN_PASS" && "$ADMIN_PASS" != *\"* && "$ADMIN_PASS" != *\\* && "$ADMIN_PASS" != *\'* ]] && break
  echo "Password must not be empty or contain quotes / backslash."
done
DEF_IP=$(curl -s4 --max-time 5 ifconfig.me || true)
read -rp "Server IP or domain [$DEF_IP]: " SERVER_HOST; SERVER_HOST=${SERVER_HOST:-$DEF_IP}
read -rp "Proxy port [443]: " PROXY_PORT; PROXY_PORT=${PROXY_PORT:-443}
read -rp "Panel port [8080]: " PANEL_PORT; PANEL_PORT=${PANEL_PORT:-8080}
read -rp "Fake-TLS domain [www.google.com]: " TLS_DOMAIN; TLS_DOMAIN=${TLS_DOMAIN:-www.google.com}

apt-get update -y
apt-get install -y python3 python3-venv python3-pip git curl

# --- panel
mkdir -p "$APP"
cp -r "$SRC/app.py" "$SRC/requirements.txt" "$APP/"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

cat > "$APP/.env" <<ENV
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
SERVER_HOST=$SERVER_HOST
PROXY_PORT=$PROXY_PORT
PANEL_PORT=$PANEL_PORT
TLS_DOMAIN=$TLS_DOMAIN
PROXY_DIR=$PROXY
DATA_DIR=$APP/data
ENV
chmod 600 "$APP/.env"

# --- telegram proxy (mtprotoproxy)
if [ ! -d "$PROXY/.git" ]; then git clone --depth 1 https://github.com/alexbers/mtprotoproxy "$PROXY"; fi
python3 -m venv "$PROXY/venv"
"$PROXY/venv/bin/pip" install -q cryptography uvloop

cat > /etc/systemd/system/mtprotoproxy.service <<UNIT
[Unit]
Description=Telegram MTProto proxy
After=network.target

[Service]
WorkingDirectory=$PROXY
ExecStart=$PROXY/venv/bin/python3 $PROXY/mtprotoproxy.py
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/siwankurdsh.service <<UNIT
[Unit]
Description=SIWANKURDSH panel
After=network.target

[Service]
WorkingDirectory=$APP
EnvironmentFile=$APP/.env
ExecStart=$APP/venv/bin/python3 $APP/app.py
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now siwankurdsh mtprotoproxy

if command -v ufw >/dev/null 2>&1; then
  ufw allow "$PROXY_PORT"/tcp || true
  ufw allow "$PANEL_PORT"/tcp || true
fi

echo
echo "Done. Panel: http://$SERVER_HOST:$PANEL_PORT  (user: $ADMIN_USER)"
