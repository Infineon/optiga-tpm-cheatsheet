#!/usr/bin/env bash
set -exo pipefail

#
# CAfile: A file containing trusted certificates to use during client authentication
# cert: Server certificate
# key: Server private key
#
openssl s_server -Verify 1 -tls1_2 -CAfile local-ca.crt -cert local-ca.crt -key local-ca.key -verify_return_error -quiet -accept 8443

