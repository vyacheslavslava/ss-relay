#!/usr/bin/env bash
# Тянет wildcard-серт с API и, если изменился, обновляет nginx.
# Ставится установщиком в /opt/relay/cert-sync.sh, гоняется суточным таймером.
# env: CERT_API_URL, CERT_TOKEN, CERT_DOMAIN
set -euo pipefail

CERT_API_URL="${CERT_API_URL:-}"
CERT_TOKEN="${CERT_TOKEN:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"
CERT_DIR="/etc/ssl/relay/${CERT_DOMAIN}"

if [ -z "$CERT_API_URL" ] || [ -z "$CERT_TOKEN" ] || [ -z "$CERT_DOMAIN" ]; then
  echo "cert-sync: CERT_API_URL/CERT_TOKEN/CERT_DOMAIN not set" >&2
  exit 1
fi

mkdir -p "$CERT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# забираем JSON { fullchain, privkey }
if ! curl -fsS -H "Authorization: ${CERT_TOKEN}" "$CERT_API_URL" -o "$TMP/cert.json"; then
  echo "cert-sync: fetch failed" >&2
  exit 1
fi

# распаковываем поля без jq (node есть на ноде — релей на нём)
node -e '
const fs=require("fs");
const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
if(!j.fullchain||!j.privkey){console.error("cert-sync: bad payload");process.exit(1);}
fs.writeFileSync(process.argv[2],j.fullchain);
fs.writeFileSync(process.argv[3],j.privkey);
' "$TMP/cert.json" "$TMP/fullchain.pem" "$TMP/privkey.pem"

# сравниваем с тем, что уже стоит
changed=1
if [ -f "$CERT_DIR/fullchain.pem" ] && cmp -s "$TMP/fullchain.pem" "$CERT_DIR/fullchain.pem"; then
  changed=0
fi

if [ "$changed" -eq 1 ]; then
  install -m 644 "$TMP/fullchain.pem" "$CERT_DIR/fullchain.pem"
  install -m 600 "$TMP/privkey.pem"  "$CERT_DIR/privkey.pem"
  if nginx -t 2>/dev/null; then
    nginx -s reload
    echo "cert-sync: cert updated, nginx reloaded"
  else
    echo "cert-sync: nginx config test failed, NOT reloaded" >&2
    exit 1
  fi
else
  echo "cert-sync: cert unchanged"
fi
