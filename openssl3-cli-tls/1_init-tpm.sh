#!/usr/bin/env bash
set -exo pipefail

#export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"

# perform tpm startup
tpm2_startup -c
# clear tpm
tpm2_clear -c p
# create primary key under owner hierarchy
tpm2_createprimary -G ecc -c primary.ctx
# make primary key persisted at handle 0x81000000
tpm2_evictcontrol -c primary.ctx 0x81000000
# remove all transient objects
tpm2_flushcontext -t
# create and output an rsa keypair (rsakey.pub, rsakey.priv) which is protected by the primary key
tpm2_create -G rsa3072 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda" -C 0x81000000 -u rsakey.pub -r rsakey.priv
# remove all transient objects
tpm2_flushcontext -t
# load the rsa keypair into tpm 
tpm2_load -C primary.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx
# make rsa keypair persisted at handle 0x81000001
tpm2_evictcontrol -c rsakey.ctx 0x81000001
# remove all transient objects
tpm2_flushcontext -t
