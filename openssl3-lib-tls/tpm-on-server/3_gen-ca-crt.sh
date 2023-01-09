#!/usr/bin/env bash
set -exo pipefail

touch ~/.rnd

# Generate CA
openssl req -x509 -sha256 -nodes -days 365 -subj "/CN=CA/O=Infineon/C=SG" -newkey rsa:2048 -keyout local-ca.key -out local-ca.crt

# Read cert
#openssl x509 -in local-ca.crt -text -noout


