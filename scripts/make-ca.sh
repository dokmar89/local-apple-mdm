#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/openssl.sh"
: "${MDM_HOSTNAME:?Set MDM_HOSTNAME to your Mac hostname}"
: "${MDM_LAN_IP:?Set MDM_LAN_IP to your Mac LAN IPv4 address}"
MDM_ORG_NAME="${MDM_ORG_NAME:-LocalMDM}"
safe_name "$MDM_HOSTNAME"
safe_name "$MDM_ORG_NAME"
[[ "$MDM_LAN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo 'Invalid IPv4 address' >&2; exit 1; }
if [[ -e ca/root-ca.key || -e ca/root-ca.crt || -e ca/server.key || -e ca/server.crt ]]; then
  [[ -f ca/root-ca.key && -f ca/root-ca.crt && -f ca/server.key && -f ca/server.crt ]] || { echo 'Partial PKI exists; restore it or move it aside explicitly. No keys overwritten.' >&2; exit 1; }
  echo 'Existing PKI retained. Checking certificates; no keys overwritten.'
else
  "$OPENSSL" req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 -keyout ca/root-ca.key -out ca/root-ca.crt \
    -subj "/C=CZ/O=$MDM_ORG_NAME/CN=$MDM_ORG_NAME MDM Root CA" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash'
  "$OPENSSL" req -new -newkey rsa:2048 -nodes -sha256 -keyout ca/server.key -out ca/server.csr -subj "/C=CZ/O=$MDM_ORG_NAME/CN=$MDM_HOSTNAME"
  cat > ca/server.ext <<EOF
basicConstraints=critical,CA:FALSE
subjectAltName=DNS:$MDM_HOSTNAME,DNS:localhost,IP:$MDM_LAN_IP,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
EOF
  "$OPENSSL" x509 -req -in ca/server.csr -CA ca/root-ca.crt -CAkey ca/root-ca.key -set_serial "0x$("$OPENSSL" rand -hex 16)" -days 397 -sha256 -extfile ca/server.ext -out ca/server.crt
fi
"$OPENSSL" verify -purpose sslserver -CAfile ca/root-ca.crt ca/server.crt
"$OPENSSL" x509 -in ca/server.crt -noout -checkhost "$MDM_HOSTNAME"
"$OPENSSL" x509 -in ca/server.crt -noout -checkip "$MDM_LAN_IP"
"$OPENSSL" x509 -in ca/server.crt -noout -text
"$OPENSSL" x509 -in ca/root-ca.crt -noout -fingerprint -sha256
