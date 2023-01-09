#!/usr/bin/env bash
set -exo pipefail

#export TPM2TSSENGINE_TCTI="mssim:host=localhost,port=2321"

touch ~/.rnd

# Generate CSR
openssl req -new -engine tpm2tss -keyform engine -key 0x81000001 -subj "/CN=TPM/O=Infineon/C=SG"  -out server.csr

# Generate CA signed client cert
rm -rf ca 2> /dev/null
mkdir ca 2> /dev/null
touch ca/index.txt
touch ca/index.txt.attr
echo '01' > ca/serial
(yes || true) | openssl ca -config config -in server.csr -out server.crt

# Read cert
#openssl x509 -in server.crt -text -noout

