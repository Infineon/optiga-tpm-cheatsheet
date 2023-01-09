#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail

rm -rf *.crt ca local-ca.* *.ctx rsakey.* *.csr 2> /dev/null
