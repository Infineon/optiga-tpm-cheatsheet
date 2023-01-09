#!/usr/bin/env bash
set -exo pipefail

#export TPM2TSSENGINE_TCTI="mssim:host=localhost,port=2321"

touch ~/.rnd

# Generate client key
openssl genrsa -out client.key 2048

# Generate CSR
openssl req -new -key client.key -subj "/CN=TPM/O=Infineon/C=SG"  -out client.csr

# Generate CA signed client cert
rm -rf ca 2> /dev/null
mkdir ca 2> /dev/null
touch ca/index.txt
touch ca/index.txt.attr
echo 'unique_subject = no' >> ca/index.txt.attr
echo '01' > ca/serial
(yes || true) | openssl ca -config config -in client.csr -out client.crt

# Read cert
#openssl x509 -in client.crt -text -noout

