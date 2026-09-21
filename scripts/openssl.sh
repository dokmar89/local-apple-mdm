#!/usr/bin/env bash
# Sourced by PKI scripts; Apple's LibreSSL cannot reliably export legacy PKCS#12.
set -euo pipefail
if command -v brew >/dev/null 2>&1 && prefix="$(brew --prefix openssl@3 2>/dev/null)" && [[ -x "$prefix/bin/openssl" ]]; then
  OPENSSL="$prefix/bin/openssl"
else
  OPENSSL="${OPENSSL_BIN:-openssl}"
fi
version="$("$OPENSSL" version)"
[[ "$version" == 'OpenSSL 3.'* ]] || { echo 'OpenSSL 3 required. On macOS: brew install openssl@3' >&2; exit 1; }
export OPENSSL
cd "$(dirname "${BASH_SOURCE[0]}")/.."
umask 077
mkdir -p ca

safe_name() { [[ "$1" =~ ^[a-zA-Z0-9._-]+$ ]] || { echo 'Identifier must contain only letters, digits, dot, underscore or dash.' >&2; exit 1; }; }
