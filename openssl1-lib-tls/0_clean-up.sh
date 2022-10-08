#!/usr/bin/env bash
set -exo pipefail

rm -rf *.crt ca local-ca.* *.ctx rsakey.* *.csr *.key server client-software client-tpm 2> /dev/null
