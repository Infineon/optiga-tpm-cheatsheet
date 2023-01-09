#!/usr/bin/env bash
set -exo pipefail

#
# CAfile: A file containing trusted certificates to use during client authentication
# cert: Server certificate
# key: Server private key
#
openssl s_server -engine tpm2tss -keyform engine -Verify 1 -tls1_2 -CAfile local-ca.crt -cert server.crt -key 0x81000001 -verify_return_error -quiet -accept 8443

