#!/usr/bin/env bash
set -exo pipefail

touch ~/.rnd

# Generate CSR
openssl req -new -key software.key -subj "/CN=Software/O=Infineon/C=SG" -out software.csr

# Generate CA signed client cert
rm -rf ca 2> /dev/null
mkdir ca 2> /dev/null
touch ca/index.txt
touch ca/index.txt.attr
echo '01' > ca/serial
(yes || true) | openssl ca -config config -in software.csr -out software.crt

# Read cert
#openssl x509 -in software.crt -text -noout

