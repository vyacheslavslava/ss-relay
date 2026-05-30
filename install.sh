#!/usr/bin/env bash
#
# install.sh — разворачивает WebSocket-релей (входную ноду) на чистом Ubuntu.
# Ставит Node 20, PM2, nginx, certbot; пишет релей; берёт TLS; поднимает под PM2.
# Без генерации конфигов — чистый маршрутизатор WS -> Shadowsocks-бэкенд.
#
# Использование:
#   sudo env API_URL='...' API_AUTH='...' bash -s -- <домен> [email]
#
# Обязательно через env:
#   API_URL   — эндпоинт со списком серверов
#   API_AUTH  — значение заголовка Authorization
#
set -euo pipefail

# ───────────────────────── параметры ──────────────────────────────────────
DOMAIN="${1:-}"
EMAIL="${2:-}"
API_URL="${API_URL:-}"
API_AUTH="${API_AUTH:-}"

APP_DIR="/opt/relay"
NODE_MAJOR="20"
RELAY_PORT="8080"

# ───────────────────────── проверки ───────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "Запускай от root (sudo)." >&2
  exit 1
fi

if [ -z "$DOMAIN" ]; then
  echo "Укажи домен первым аргументом." >&2
  exit 1
fi

if [ -z "$API_URL" ]; then
  echo "Не задан API_URL (эндпоинт со списком серверов)." >&2
  echo "Передай через env: sudo env API_URL='https://...' API_AUTH='...' bash -s -- $DOMAIN" >&2
  exit 1
fi

if [ -z "$API_AUTH" ]; then
  echo "Не задан API_AUTH (секрет заголовка Authorization)." >&2
  echo "Передай через env: sudo env API_URL='https://...' API_AUTH='...' bash -s -- $DOMAIN" >&2
  exit 1
fi

echo "==> Домен:   $DOMAIN"
echo "==> API:     $API_URL"
echo "==> Каталог: $APP_DIR"

# Проверим DNS (предупреждение, не блок).
MYIP="$(curl -fsS https://api.ipify.org || true)"
DNSIP="$(getent hosts "$DOMAIN" | awk '{print $1}' | head -n1 || true)"
if [ -n "$MYIP" ] && [ -n "$DNSIP" ] && [ "$MYIP" != "$DNSIP" ]; then
  echo "!!  ВНИМАНИЕ: A-запись $DOMAIN ($DNSIP) != IP сервера ($MYIP)."
  echo "!!  certbot не выдаст сертификат, пока DNS не указывает сюда."
  echo "!!  За Cloudflare — DNS only (серое облако)."
fi

# ───────────────────────── освободить порты (если был Caddy) ──────────────
if command -v caddy >/dev/null 2>&1; then
  echo "==> Останавливаю Caddy"
  systemctl stop caddy 2>/dev/null || true
  systemctl disable caddy 2>/dev/null || true
  pkill -9 caddy 2>/dev/null || true
fi

# ───────────────────────── система + пакеты ───────────────────────────────
echo "==> apt update + базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl git ufw ca-certificates

echo "==> Node $NODE_MAJOR"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | sed 's/v\([0-9]*\).*/\1/')" -lt 18 ]; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
fi
node -v

echo "==> PM2"
npm install -g pm2 >/dev/null 2>&1 || npm install -g pm2

echo "==> nginx + certbot"
apt-get install -y nginx certbot python3-certbot-nginx

# ───────────────────────── фаервол ────────────────────────────────────────
echo "==> ufw 22/80/443"
ufw allow OpenSSH       >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow 80/tcp        >/dev/null 2>&1 || true
ufw allow 443/tcp       >/dev/null 2>&1 || true
ufw --force enable

# ───────────────────────── файлы релея ────────────────────────────────────
echo "==> Пишу релей в $APP_DIR"
mkdir -p "$APP_DIR"

cat > "$APP_DIR/package.json" <<'PKGEOF'
{
  "name": "relay",
  "version": "1.0.0",
  "private": true,
  "main": "relay-api.js",
  "dependencies": { "ws": "^8.18.0" }
}
PKGEOF

cat > "$APP_DIR/relay-api.js" <<'RELAYEOF'
'use strict';

// Входная нода: WebSocket -> Shadowsocks-бэкенд. Список серверов из API.
// Путь = id сервера. Тупой WS<->TCP/UDP мост, без генерации конфигов.
//   /<ID>/tcp   — WS-stream -> TCP
//   /<ID>/udp   — WS-packet -> UDP
//   прочее      — 404 (декой)

const http = require('http');
const https = require('https');
const net = require('net');
const dgram = require('dgram');
const { URL } = require('url');
const WebSocket = require('ws');

const API_URL     = process.env.API_URL  || '';
const API_AUTH    = process.env.API_AUTH || '';
const REFRESH_MS  = parseInt(process.env.REFRESH_MS || '30000', 10);
const LISTEN_PORT = process.env.PORT || 8080;
const LISTEN_HOST = process.env.HOST || '127.0.0.1';

let servers = new Map(); // id -> { host, port }

function fetchJSON(urlStr, cb) {
  let u;
  try { u = new URL(urlStr); } catch (e) { cb(e); return; }
  const mod = u.protocol === 'https:' ? https : http;
  const opts = { method: 'GET', headers: { 'Authorization': API_AUTH } };
  const req = mod.request(u, opts, function (res) {
    let body = '';
    res.on('data', function (c) { body += c; });
    res.on('end', function () {
      if (res.statusCode !== 200) {
        cb(new Error('HTTP ' + res.statusCode));
      } else {
        let json;
        try { json = JSON.parse(body); cb(null, json); }
        catch (e) { cb(e); }
      }
    });
  });
  req.on('error', function (e) { cb(e); });
  req.setTimeout(10000, function () { req.destroy(new Error('api timeout')); });
  req.end();
}

function loadServers(cb) {
  fetchJSON(API_URL, function (err, list) {
    if (err) {
      console.error('servers load failed:', err.message);
      if (cb) { cb(err); }
    } else if (!Array.isArray(list)) {
      console.error('servers: API вернул не массив');
      if (cb) { cb(new Error('bad payload')); }
    } else {
      const next = new Map();
      for (let i = 0; i < list.length; i++) {
        const s = list[i];
        if (s && s.id != null && s.host && s.port) {
          next.set(String(s.id), { host: s.host, port: s.port });
        }
      }
      servers = next;
      console.log('servers loaded:', servers.size);
      if (cb) { cb(null); }
    }
  });
}

const server = http.createServer();

server.on('request', function (req, res) {
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', function (req, socket, head) {
  const clean = req.url.replace(/^\/+/, '').split('?')[0];
  const parts = clean.split('/');
  const mode = parts.pop();
  const id = parts.join('/');
  const target = servers.get(id);

  if (!target) {
    socket.destroy();
  } else if (mode !== 'tcp' && mode !== 'udp') {
    socket.destroy();
  } else {
    wss.handleUpgrade(req, socket, head, function (ws) {
      if (mode === 'tcp') { bridgeTcp(ws, target); }
      else { bridgeUdp(ws, target); }
    });
  }
});

function bridgeTcp(ws, target) {
  const tcp = net.connect(target.port, target.host);
  let closed = false;
  ws.on('message', function (data) {
    if (tcp.writable) {
      if (tcp.write(data) === false) {
        ws._socket.pause();
        tcp.once('drain', function () { if (!closed) { ws._socket.resume(); } });
      }
    }
  });
  tcp.on('data', function (data) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data, { binary: true });
      if (ws.bufferedAmount > (1 << 20)) { tcp.pause(); }
      else if (tcp.isPaused()) { tcp.resume(); }
    }
  });
  function close() {
    if (!closed) {
      closed = true;
      try { ws.close(); } catch (e) {}
      try { tcp.destroy(); } catch (e) {}
    }
  }
  ws.on('close', close); ws.on('error', close);
  tcp.on('close', close); tcp.on('error', close);
}

function bridgeUdp(ws, target) {
  const udp = dgram.createSocket('udp4');
  let closed = false;
  ws.on('message', function (data) {
    if (!closed) {
      udp.send(data, target.port, target.host, function (err) { if (err) { close(); } });
    }
  });
  udp.on('message', function (msg) {
    if (ws.readyState === WebSocket.OPEN) { ws.send(msg, { binary: true }); }
  });
  function close() {
    if (!closed) {
      closed = true;
      try { ws.close(); } catch (e) {}
      try { udp.close(); } catch (e) {}
    }
  }
  ws.on('close', close); ws.on('error', close);
  udp.on('error', close);
}

function boot() {
  loadServers(function (err) {
    if (err) {
      console.error('initial load failed, retry in 5s');
      setTimeout(boot, 5000);
    } else {
      server.listen(LISTEN_PORT, LISTEN_HOST, function () {
        console.log('relay up on ' + LISTEN_HOST + ':' + LISTEN_PORT);
      });
      setInterval(function () { loadServers(); }, REFRESH_MS);
    }
  });
}

boot();
RELAYEOF

echo "==> npm install"
( cd "$APP_DIR" && npm install --omit=dev )

# ───────────────────────── nginx ──────────────────────────────────────────
echo "==> nginx site"
cat > /etc/nginx/sites-available/relay <<NGINXEOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${RELAY_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/relay /etc/nginx/sites-enabled/relay
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

# ───────────────────────── TLS ────────────────────────────────────────────
echo "==> certbot"
if [ -n "$EMAIL" ]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
else
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
fi
nginx -t && systemctl reload nginx

# ───────────────────────── PM2 ────────────────────────────────────────────
echo "==> PM2"
cd "$APP_DIR"
API_URL="$API_URL" API_AUTH="$API_AUTH" pm2 start relay-api.js --name relay --update-env || \
API_URL="$API_URL" API_AUTH="$API_AUTH" pm2 restart relay --update-env
pm2 save
pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true

# ───────────────────────── проверка ───────────────────────────────────────
echo
echo "==> Готово. Проверка:"
sleep 2
echo "--- pm2 ---";       pm2 list | sed -n '1,20p' || true
echo "--- API ---";       curl -fsS -H "Authorization: ${API_AUTH}" "$API_URL" | head -c 300; echo
echo "--- HTTPS (ждём 404) ---"; curl -s -o /dev/null -w "%{http_code}\n" "https://${DOMAIN}/"
echo
echo "Фронт поднят на https://${DOMAIN} . WS-пути: /<ID>/tcp и /<ID>/udp"
echo "Логи релея:  pm2 logs relay"
