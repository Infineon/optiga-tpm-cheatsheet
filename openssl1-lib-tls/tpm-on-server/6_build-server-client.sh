#!/usr/bin/env bash
set -exo pipefail

gcc -Wall -o server server.c -lssl -lcrypto -DENABLE_TPM_TSS_ENGINE
gcc -Wall -o client-software client.c -lssl -lcrypto
