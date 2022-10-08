#!/usr/bin/env bash
set -exo pipefail

#export TPM2TSSENGINE_TCTI="mssim:host=localhost,port=2321"

touch ~/.rnd

# Generate CSR
openssl req -new -engine tpm2tss -keyform engine -key 0x81000001 -subj "/CN=TPM/O=Infineon/C=SG"  -out tpm.csr

# Generate CA signed client cert
rm -rf ca 2> /dev/null
mkdir ca 2> /dev/null
touch ca/index.txt
touch ca/index.txt.attr
echo '01' > ca/serial
(yes || true) | openssl ca -config config -in tpm.csr -out tpm.crt

# Generate self-signed client cert to demonstrate an invalid client cert (not CA signed)
openssl req -x509 -sha256 -engine tpm2tss -keyform engine -key 0x81000001 -in tpm.csr -out bad-tpm.crt

# Read cert
#openssl x509 -in tpm.crt -text -noout
#openssl x509 -in bad-tpm.crt -text -noout

