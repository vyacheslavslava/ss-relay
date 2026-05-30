#!/usr/bin/env bash
# WS-relay installer (stateless, encrypted-path). Usage:
#   sudo env RELAY_KEY='<64 hex>' bash -s -- <domain> [email]
# Same RELAY_KEY must be set on the config generator.
# Safe to rerun: reinstalls / updates the relay in place (no manual cleanup).
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
RELAY_KEY="${RELAY_KEY:-}"

APP_DIR="/opt/relay"
NODE_MAJOR="20"
RELAY_PORT="8080"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi
if [ -z "$DOMAIN" ]; then
  echo "Pass domain as first argument." >&2
  exit 1
fi
if ! printf '%s' "$RELAY_KEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "Set RELAY_KEY to 64 hex chars (openssl rand -hex 32):" >&2
  echo "  sudo env RELAY_KEY='<64 hex>' bash -s -- $DOMAIN" >&2
  exit 1
fi

echo "==> domain: $DOMAIN"

MYIP="$(curl -fsS https://api.ipify.org || true)"
DNSIP="$(getent hosts "$DOMAIN" | awk '{print $1}' | head -n1 || true)"
if [ -n "$MYIP" ] && [ -n "$DNSIP" ] && [ "$MYIP" != "$DNSIP" ]; then
  echo "!!  A-record $DOMAIN ($DNSIP) != server IP ($MYIP). certbot will fail until DNS points here."
fi

echo "==> disabling Outline (if present)"
if command -v docker >/dev/null 2>&1; then
  for c in shadowbox watchtower; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
      docker update --restart=no "$c" >/dev/null 2>&1 || true
      docker stop "$c" >/dev/null 2>&1 || true
      echo "    stopped $c"
    fi
  done
else
  echo "    docker not found, skip"
fi

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw ca-certificates

echo "==> node $NODE_MAJOR"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | sed 's/v\([0-9]*\).*/\1/')" -lt 18 ]; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
fi

echo "==> pm2"
npm install -g pm2 >/dev/null 2>&1 || npm install -g pm2

echo "==> nginx + certbot"
apt-get install -y nginx certbot python3-certbot-nginx

echo "==> firewall"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow 80/tcp  >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw --force enable

echo "==> relay files"
mkdir -p "$APP_DIR"

cat > "$APP_DIR/package.json" <<'PKGEOF'
{
  "name": "relay",
  "version": "1.0.0",
  "private": true,
  "main": "relay.js",
  "dependencies": { "ws": "^8.18.0" }
}
PKGEOF

cat > "$APP_DIR/relay.js" <<'RELAYEOF'
'use strict';

const http = require('http');
const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const WebSocket = require('ws');

const KEY         = Buffer.from(process.env.RELAY_KEY || '', 'hex');
const LISTEN_PORT = process.env.PORT || 8080;
const LISTEN_HOST = process.env.HOST || '127.0.0.1';

function unb64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) { s += '='; }
  return Buffer.from(s, 'base64');
}

function open(token) {
  let raw;
  try { raw = unb64url(token); } catch (e) { return null; }
  if (raw.length < 12 + 16) { return null; }
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch (e) {
    return null;
  }
}

const server = http.createServer();

server.on('request', function (req, res) {
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', function (req, socket, head) {
  const seg = req.url.replace(/^\/+/, '').split('?')[0].split('/')[0];
  const pt = open(seg);
  if (pt === null) {
    socket.destroy();
  } else {
    const parts = pt.split('|');
    const mode = parts[0];
    const host = parts[1];
    const port = parseInt(parts[2], 10);
    const exp = parts[3] ? parseInt(parts[3], 10) : 0;
    if (mode !== 'tcp' && mode !== 'udp') {
      socket.destroy();
    } else if (!host || !port) {
      socket.destroy();
    } else if (exp && (Date.now() / 1000) > exp) {
      socket.destroy();
    } else {
      wss.handleUpgrade(req, socket, head, function (ws) {
        if (mode === 'tcp') { bridgeTcp(ws, { host: host, port: port }); }
        else { bridgeUdp(ws, { host: host, port: port }); }
      });
    }
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

if (KEY.length !== 32) {
  console.error('RELAY_KEY must be 32 bytes hex (openssl rand -hex 32)');
  process.exit(1);
}

server.listen(LISTEN_PORT, LISTEN_HOST, function () {
  console.log('relay up on ' + LISTEN_HOST + ':' + LISTEN_PORT);
});
RELAYEOF

echo "==> npm install"
( cd "$APP_DIR" && npm install --omit=dev )

echo "==> nginx"
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
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx

echo "==> certbot"
if [ -n "$EMAIL" ]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
else
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
fi
nginx -t && systemctl reload nginx

echo "==> pm2 start"
cd "$APP_DIR"
pm2 delete relay >/dev/null 2>&1 || true
RELAY_KEY="$RELAY_KEY" pm2 start relay.js --name relay --update-env
pm2 save
pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true

echo
echo "==> done. checks:"
sleep 2
pm2 list | sed -n '1,20p' || true
echo -n "HTTPS (expect 404): "; curl -s -o /dev/null -w "%{http_code}\n" "https://${DOMAIN}/"
echo "relay on https://${DOMAIN}  | logs: pm2 logs relay"
