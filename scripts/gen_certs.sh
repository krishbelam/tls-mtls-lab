#!/usr/bin/env bash
# Generates a lab CA, a server cert and a client cert (strict-safe extensions).
# Output goes to ca/, server/ and client/ at the repo root. Re-running overwrites them.
set -euo pipefail
cd "$(dirname "$0")/.."

KEY_BITS="${KEY_BITS:-2048}"
DAYS="${DAYS:-365}"
SERVER_NAME="${SERVER_NAME:-localhost}"
SUBJ_BASE="/C=IN/ST=Telangana/L=Hyderabad"

mkdir -p ca server client

echo "==> CA (ca.key never leaves this machine)"
openssl genrsa -out ca/ca.key 4096
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 \
  -subj "${SUBJ_BASE}/O=Lab/CN=My Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca/ca.crt

echo "==> Server certificate"
openssl genrsa -out server/server.key "${KEY_BITS}"
openssl req -new -key server/server.key \
  -subj "${SUBJ_BASE}/O=Lab/CN=${SERVER_NAME}" -out server/server.csr
cat > server/server.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${SERVER_NAME},IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl x509 -req -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extfile server/server.ext -out server/server.crt

echo "==> Client certificate"
openssl genrsa -out client/client.key "${KEY_BITS}"
openssl req -new -key client/client.key \
  -subj "${SUBJ_BASE}/O=engineers/CN=alice" -out client/client.csr
cat > client/client.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl x509 -req -in client/client.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extfile client/client.ext -out client/client.crt

echo "==> Verify (strict, same as Python 3.13+ defaults)"
openssl verify -x509_strict -CAfile ca/ca.crt server/server.crt client/client.crt

chmod 600 ca/ca.key server/server.key client/client.key
echo "Done. Certificates written to ca/, server/ and client/."