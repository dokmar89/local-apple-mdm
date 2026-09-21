#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/openssl.sh"
name="${1:?Usage: make-client-cert.sh device-name}"
safe_name "$name"
: "${P12_PASSWORD:?Set P12_PASSWORD}"
export P12_PASSWORD
if [[ -e "ca/$name.key" || -e "ca/$name.crt" || -e "ca/$name.p12" ]]; then
  [[ -f "ca/$name.key" && -f "ca/$name.crt" && -f "ca/$name.p12" ]] || { echo 'Partial identity exists; restore it or move it aside explicitly.' >&2; exit 1; }
  echo 'Existing client identity retained.'
else
  "$OPENSSL" req -new -newkey rsa:2048 -nodes -sha256 -keyout "ca/$name.key" -out "ca/$name.csr" -subj "/C=CZ/CN=$name"
  cat > "ca/$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature,keyEncipherment
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
EOF
  "$OPENSSL" x509 -req -in "ca/$name.csr" -CA ca/root-ca.crt -CAkey ca/root-ca.key -set_serial "0x$("$OPENSSL" rand -hex 16)" -days 730 -sha256 -extfile "ca/$name.ext" -out "ca/$name.crt"
  "$OPENSSL" pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
    -inkey "ca/$name.key" -in "ca/$name.crt" -certfile ca/root-ca.crt -name "$name" -passout env:P12_PASSWORD -out "ca/$name.p12"
fi
"$OPENSSL" verify -purpose sslclient -CAfile ca/root-ca.crt "ca/$name.crt"
"$OPENSSL" x509 -in "ca/$name.crt" -noout -text
"$OPENSSL" x509 -in ca/root-ca.crt -noout -fingerprint -sha256
