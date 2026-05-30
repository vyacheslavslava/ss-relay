#!/usr/bin/env bash
# WS-relay installer (stateless, encrypted-path, shared wildcard cert).
#   sudo env RELAY_KEY='<64 hex>' CERT_API_URL='https://...' CERT_TOKEN='...' bash -s -- <domain>
# Cert (wildcard) is fetched from API, NOT issued via certbot.
# Safe to rerun: reinstalls / updates in place.
set -euo pipefail

DOMAIN="${1:-}"
RELAY_KEY="${RELAY_KEY:-}"
CERT_API_URL="${CERT_API_URL:-}"
CERT_TOKEN="${CERT_TOKEN:-}"

APP_DIR="/opt/relay"
NODE_MAJOR="20"
RELAY_PORT="8080"

if [ "$(id -u)" -ne 0 ]; then echo "Run as root." >&2; exit 1; fi
if [ -z "$DOMAIN" ]; then echo "Pass domain as first argument." >&2; exit 1; fi
if ! printf '%s' "$RELAY_KEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "Set RELAY_KEY to 64 hex chars." >&2; exit 1; fi
if [ -z "$CERT_API_URL" ] || [ -z "$CERT_TOKEN" ]; then
  echo "Set CERT_API_URL and CERT_TOKEN via env." >&2; exit 1; fi

# база wildcard = домен без первой метки: cdn10.yamedia.net -> yamedia.net
CERT_DOMAIN="${DOMAIN#*.}"
CERT_DIR="/etc/ssl/relay/${CERT_DOMAIN}"

echo "==> domain: $DOMAIN | cert base: $CERT_DOMAIN"

echo "==> disabling Outline (if present)"
if command -v docker >/dev/null 2>&1; then
  for c in shadowbox watchtower; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
      docker update --restart=no "$c" >/dev/null 2>&1 || true
      docker stop "$c" >/dev/null 2>&1 || true
      echo "    stopped $c"
    fi
  done
fi

echo "==> disabling certbot auto-renew (old scheme, if present)"
# мы раздаём wildcard через API; certbot renew не нужен и может перезаписать nginx-конфиг
for unit in certbot.timer certbot-renewal.timer snap.certbot.renew.timer; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
# вычистить cron-задания certbot, если были
if command -v crontab >/dev/null 2>&1; then
  ( crontab -l 2>/dev/null | grep -v certbot ) | crontab - 2>/dev/null || true
fi
rm -f /etc/cron.d/certbot 2>/dev/null || true

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw ca-certificates

echo "==> kernel/network tuning"
cat > /etc/sysctl.d/99-relay.conf <<'SYSCTLEOF'
# высокая нагрузка по соединениям (релей открывает много исходящих к бэкендам)
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = 2097152
# против bufferbloat (раздутые очереди -> высокий пинг под нагрузкой)
net.core.default_qdisc = fq_codel
SYSCTLEOF
# BBR — если модуль есть; BBR лучше работает с fq, тогда меняем qdisc на fq
QDISC="fq_codel"
modprobe tcp_bbr 2>/dev/null || true
if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
  sed -i 's/^net.core.default_qdisc.*/net.core.default_qdisc = fq/' /etc/sysctl.d/99-relay.conf
  echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-relay.conf
  QDISC="fq"
  echo "    bbr enabled (qdisc fq)"
else
  echo "    bbr not available, qdisc fq_codel"
fi
sysctl --system >/dev/null 2>&1 || true
# применить qdisc на живой интерфейс сразу (без ребута)
IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
if [ -n "$IFACE" ]; then
  tc qdisc replace dev "$IFACE" root $QDISC 2>/dev/null || true
  echo "    qdisc $QDISC on $IFACE"
fi

echo "==> node $NODE_MAJOR"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | sed 's/v\([0-9]*\).*/\1/')" -lt 18 ]; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
fi

echo "==> pm2"
npm install -g pm2 >/dev/null 2>&1 || npm install -g pm2

echo "==> nginx"
apt-get install -y nginx

echo "==> firewall"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow 80/tcp  >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw --force enable

echo "==> relay files"
mkdir -p "$APP_DIR"

cat > "$APP_DIR/package.json" <<'PKGEOF'
{ "name": "relay", "version": "1.0.0", "private": true, "main": "relay.js", "dependencies": { "ws": "^8.18.0", "bufferutil": "^4.0.8" } }
PKGEOF

cat > "$APP_DIR/relay.js" <<'RELAYEOF'
'use strict';
const http = require('http');
const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const { URL } = require('url');
const WebSocket = require('ws');

const KEY         = Buffer.from(process.env.RELAY_KEY || '', 'hex');
const LISTEN_PORT = process.env.PORT || 8080;
const LISTEN_HOST = process.env.HOST || '127.0.0.1';
// пороги backpressure (можно переопределить env при старте)
const BUF_HIGH = parseInt(process.env.WS_BUFFER_HIGH || (1024 * 1024), 10); // пауза чтения с бэкенда
const BUF_LOW  = parseInt(process.env.WS_BUFFER_LOW  || (512 * 1024), 10);  // возобновление

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
  } catch (e) { return null; }
}

const server = http.createServer();
server.on('request', function (req, res) {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/ping') {
    const code = u.searchParams.get('code');
    if (!code) {
      res.writeHead(302, { 'Location': '/' });
      res.end();
    } else {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('' + parseInt(code, 10));
    }
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
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
  tcp.setNoDelay(true);
  try { ws._socket.setNoDelay(true); } catch (e) {}
  let done = false;

  function cleanup() {
    if (done) { return; }
    done = true;
    try { tcp.destroy(); } catch (e) {}
    try { if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) { ws.terminate(); } } catch (e) {}
  }

  // клиент -> бэкенд
  let waitingDrain = false;
  ws.on('message', function (data) {
    if (!tcp.writable) { return; }
    if (tcp.write(data) === false && !waitingDrain) {
      waitingDrain = true;
      try { ws._socket.pause(); } catch (e) {}
      tcp.once('drain', function () {
        waitingDrain = false;
        if (!done) { try { ws._socket.resume(); } catch (e) {} }
      });
    }
  });

  // бэкенд -> клиент
  tcp.on('data', function (data) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data, { binary: true });
      if (ws.bufferedAmount > BUF_HIGH && !tcp.isPaused()) {
        tcp.pause();
        (function check() {
          if (done) { return; }
          if (ws.readyState === WebSocket.OPEN && ws.bufferedAmount > BUF_LOW) {
            setTimeout(check, 20);
          } else {
            try { tcp.resume(); } catch (e) {}
          }
        })();
      }
    }
  });

  // бэкенд прислал FIN (half-close): дольём буфер клиенту, затем мягко закроем ws
  tcp.on('end', function () {
    try { if (ws.readyState === WebSocket.OPEN) { ws.close(); } } catch (e) {}
  });

  // клиент закрыл ws: мягкий FIN бэкенду (даём долить ожидающие записи), затем страховка
  ws.on('close', function () {
    try { tcp.end(); } catch (e) {}
    setTimeout(cleanup, 10000);
  });

  // ошибки -> жёсткое закрытие
  ws.on('error', cleanup);
  tcp.on('error', cleanup);

  // бэкенд полностью закрылся
  tcp.on('close', function () {
    if (ws.readyState === WebSocket.OPEN && ws.bufferedAmount === 0) {
      try { ws.close(); } catch (e) {}
    }
    setTimeout(cleanup, 10000);
  });
}

function bridgeUdp(ws, target) {
  const udp = dgram.createSocket('udp4');
  let closed = false;
  ws.on('message', function (data) {
    if (!closed) { udp.send(data, target.port, target.host, function (err) { if (err) { close(); } }); }
  });
  udp.on('message', function (msg) {
    if (ws.readyState === WebSocket.OPEN) { ws.send(msg, { binary: true }); }
  });
  function close() {
    if (!closed) { closed = true; try { ws.close(); } catch (e) {} try { udp.close(); } catch (e) {} }
  }
  ws.on('close', close); ws.on('error', close);
  udp.on('error', close);
}

if (KEY.length !== 32) { console.error('RELAY_KEY must be 32 bytes hex'); process.exit(1); }
server.listen(LISTEN_PORT, LISTEN_HOST, function () {
  console.log('relay up on ' + LISTEN_HOST + ':' + LISTEN_PORT);
});
RELAYEOF

# ── cert-sync: тянет wildcard с API, при изменении reload nginx ───────────────
cat > "$APP_DIR/cert-sync.sh" <<'CSEOF'
#!/usr/bin/env bash
set -euo pipefail
CERT_API_URL="${CERT_API_URL:-}"
CERT_TOKEN="${CERT_TOKEN:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"
CERT_DIR="/etc/ssl/relay/${CERT_DOMAIN}"
if [ -z "$CERT_API_URL" ] || [ -z "$CERT_TOKEN" ] || [ -z "$CERT_DOMAIN" ]; then
  echo "cert-sync: env not set" >&2; exit 1; fi
mkdir -p "$CERT_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
if ! curl -fsS -H "Authorization: ${CERT_TOKEN}" "$CERT_API_URL" -o "$TMP/cert.json"; then
  echo "cert-sync: fetch failed" >&2; exit 1; fi
node -e '
const fs=require("fs");
const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
if(!j.fullchain||!j.privkey){console.error("cert-sync: bad payload");process.exit(1);}
fs.writeFileSync(process.argv[2],j.fullchain);
fs.writeFileSync(process.argv[3],j.privkey);
' "$TMP/cert.json" "$TMP/fullchain.pem" "$TMP/privkey.pem"
changed=1
if [ -f "$CERT_DIR/fullchain.pem" ] && cmp -s "$TMP/fullchain.pem" "$CERT_DIR/fullchain.pem"; then changed=0; fi
if [ "$changed" -eq 1 ]; then
  install -m 644 "$TMP/fullchain.pem" "$CERT_DIR/fullchain.pem"
  install -m 600 "$TMP/privkey.pem"  "$CERT_DIR/privkey.pem"
  if nginx -t 2>/dev/null; then nginx -s reload 2>/dev/null || true; echo "cert-sync: updated + reloaded";
  else echo "cert-sync: nginx test failed" >&2; exit 1; fi
else
  echo "cert-sync: unchanged"
fi
CSEOF
chmod +x "$APP_DIR/cert-sync.sh"

echo "==> npm install"
( cd "$APP_DIR" && npm install --omit=dev )

# ── первый забор серта (до старта nginx с ssl) ───────────────────────────────
echo "==> fetching cert"
CERT_API_URL="$CERT_API_URL" CERT_TOKEN="$CERT_TOKEN" CERT_DOMAIN="$CERT_DOMAIN" "$APP_DIR/cert-sync.sh"

# ── nginx с готовым wildcard (без certbot) ───────────────────────────────────
echo "==> nginx config"
cat > /etc/nginx/sites-available/relay <<NGINXEOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;

    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets on;
    tcp_nodelay on;

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

# ── тюнинг воркеров nginx (по умолчанию 768 коннектов — мало под нагрузкой) ──
# worker_processes по ядрам, поднимаем лимит соединений и file descriptors
sed -i 's/^worker_processes.*/worker_processes auto;/' /etc/nginx/nginx.conf
if grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf; then
  sed -i 's/^worker_rlimit_nofile.*/worker_rlimit_nofile 1048576;/' /etc/nginx/nginx.conf
else
  sed -i '1i worker_rlimit_nofile 1048576;' /etc/nginx/nginx.conf
fi
# worker_connections внутри events {}
sed -i 's/worker_connections[[:space:]]*[0-9]*;/worker_connections 65535;/' /etc/nginx/nginx.conf

# systemd-лимит fd для nginx (иначе worker_rlimit_nofile упрётся в него)
mkdir -p /etc/systemd/system/nginx.service.d
printf '[Service]\nLimitNOFILE=1048576\n' > /etc/systemd/system/nginx.service.d/limits.conf
systemctl daemon-reload

nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx

# ── суточный таймер обновления серта (со случайным разбросом) ────────────────
echo "==> cert-sync timer"
cat > /etc/systemd/system/relay-cert-sync.service <<SVCEOF
[Unit]
Description=relay wildcard cert sync
After=network-online.target

[Service]
Type=oneshot
Environment=CERT_API_URL=${CERT_API_URL}
Environment=CERT_TOKEN=${CERT_TOKEN}
Environment=CERT_DOMAIN=${CERT_DOMAIN}
ExecStart=${APP_DIR}/cert-sync.sh
SVCEOF

cat > /etc/systemd/system/relay-cert-sync.timer <<TMREOF
[Unit]
Description=relay cert sync daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=43200
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

systemctl daemon-reload
systemctl enable --now relay-cert-sync.timer >/dev/null 2>&1 || true

echo "==> pm2 start"
cd "$APP_DIR"
pm2 delete relay >/dev/null 2>&1 || true
RELAY_KEY="$RELAY_KEY" pm2 start relay.js --name relay --update-env
pm2 save
pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true

echo
echo "==> done."
sleep 2
pm2 list | sed -n '1,20p' || true
echo -n "HTTPS (expect 404): "; curl -sk -o /dev/null -w "%{http_code}\n" "https://${DOMAIN}/"
echo "relay on https://${DOMAIN} | cert: ${CERT_DIR} | logs: pm2 logs relay"
