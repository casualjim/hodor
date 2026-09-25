#!/usr/bin/env bash
# One-shot PKI for the demo: a throwaway CA plus one leaf for the api
# service (SAN DNS:api). hodor loads ca.pem (cert + PKCS#8 key), verifies
# the api leaf as its upstream TLS peer, and mints MITM leaves from the
# same key. The client trusts ca.crt only.
set -euo pipefail

dir=${1:-/certs}

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/ca.key"
openssl req -new -x509 -key "$dir/ca.key" -out "$dir/ca.crt" -days 2 \
  -subj "/CN=hodor demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/api.key"
openssl req -new -key "$dir/api.key" -out "$dir/api.csr" -subj "/CN=api"
printf "subjectAltName=DNS:api\n" > "$dir/api.ext"
openssl x509 -req -in "$dir/api.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/api.crt" -days 2 -extfile "$dir/api.ext"

# The db service presents this leaf on its TLS leg. SAN carries the static
# address because the transparent grant identifies the captured destination
# by address and the client dials the IP literal.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/pg.key"
openssl req -new -key "$dir/pg.key" -out "$dir/pg.csr" -subj "/CN=db"
printf "subjectAltName=IP:10.202.0.30,DNS:db\n" > "$dir/pg.ext"
openssl x509 -req -in "$dir/pg.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/pg.crt" -days 2 -extfile "$dir/pg.ext"

cat "$dir/ca.crt" "$dir/ca.key" > "$dir/ca.pem"
chmod 600 "$dir/ca.key" "$dir/ca.pem"
echo "certs ready in $dir"
