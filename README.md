[![example workflow](https://github.com/infineon/optiga-tpm-cheatsheet/workflows/CI/badge.svg?branch=master)](https://github.com/infineon/optiga-tpm-cheatsheet/actions)

# Introduction

OPTIGA™ TPM 2.0 command reference and code examples.

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Setup on Debian/Ubuntu](#setup-on-debianubuntu)**
- **[Setup on Raspberry Pi](#setup-on-raspberry-pi)**
- **[Behaviour of Microsoft TPM2.0 Simulator](#behaviour-of-microsoft-tpm20-simulator)**
- **[Examples (SAPI/ESAPI)](#examples-sapiesapi)**
    - **[Audit](#audit)**
    - **[Certify](#certify)**
    - **[Clock & Time](#clock--time)**
    - **[Clear Control](#clear-control)**
    - **[Create Keys](#create-keys)**
    - **[Dictionary Attack Protection](#dictionary-attack-protection)**
    - **[Display TPM Capabilities](#display-tpm-capabilities)**
    - **[EK Credential](#ek-credential)**
    - **[Encrypted Session](#encrypted-session)**
    - **[Encryption & Decryption](#encryption--decryption)**
    - **[Get Random](#get-random)**
    - **[Hashing](#hashing)**
    - **[Hierarchy Control](#hierarchy-control)**
    - **[Import Externally Created key](#import-externally-created-key)**
        - **[Under a Parent Key](#under-a-parent-key)**
        - **[Under Hierarchy](#under-hierarchy)**
    - **[NV Storage](#nv-storage)**
    - **[OpenSSL 1.x CLI](#openssl-1x-cli)**
        - **[PEM Encoded Key Object](#pem-encoded-key-object)**
            - **[Conversion to PEM Encoded Key Object](#conversion-to-pem-encoded-key-object)**
        - **[Persistent Key](#persistent-key-1)**
        - **[Server-client TLS Communication](#server-client-tls-communication)**
        - **[Nginx & Curl](#nginx--curl)**
            - **[PEM Encoded Key Object](#pem-encoded-key-object-1)**
            - **[Persistent Key](#persistent-key-2)**
            - **[Housekeeping](#housekeeping)**
    - **[OpenSSL 1.x Library](#openssl-1x-library)**
        - **[General Examples](#general-examples)**
        - **[Server-client TLS Communication](#server-client-tls-communication-1)**
    - **[OpenSSL 3.x CLI](#openssl-3x-cli)**
        - **[PEM Encoded Key Object](#pem-encoded-key-object-2)**
        - **[Serialized Key](#serialized-key)**
        - **[Persistent Key](#persistent-key-3)**
        - **[Server-client TLS Communication](#server-client-tls-communication-2)**
    - **[OpenSSL 3.x Library](#openssl-3x-library)**
        - **[General Examples](#general-examples-1)**
        - **[Server-client TLS Communication](#server-client-tls-communication-3)**
    - **[Password Authorization](#password-authorization)**
    - **[PCR](#pcr)**
    - **[Persistent Key](#persistent-key)**
    - **[PKCS #11](#pkcs-11)**
    - **[Quote](#quote)**
    - **[Read EK Certificate](#read-ek-certificate)**
    - **[Read Public](#read-public)**
    - **[Seal](#seal)**
    - **[Secure Key Transfer (Duplicate Key)](#secure-key-transfer-duplicate-key)**
        - **[Without Credential Protection](#without-credential-protection)**
        - **[With Credential Protection](#with-credential-protection)**
    - **[Self Test](#self-test)**
    - **[Session-based Authorization](#session-based-authorization)**
        - **[HMAC](#hmac)**
        - **[Policy](#policy)**
            - **[tpm2_policyauthorize](#tpm2_policyauthorize)**
            - **[tpm2_policyauthorizenv](#tpm2_policyauthorizenv)**
            - **[tpm2_policyauthvalue](#tpm2_policyauthvalue)**
            - **[tpm2_policycommandcode](#tpm2_policycommandcode)**
            - **[tpm2_policycountertimer](#tpm2_policycountertimer)**
            - **[tpm2_policycphash](#tpm2_policycphash)**
            - **[tpm2_policyduplicationselect](#tpm2_policyduplicationselect)**
            - **[tpm2_policylocality](#tpm2_policylocality)**
            - **[tpm2_policynamehash](#tpm2_policynamehash)**
            - **[tpm2_policynv](#tpm2_policynv)**
            - **[tpm2_policynvwritten](#tpm2_policynvwritten)**
            - **[tpm2_policyor](#tpm2_policyor)**
            - **[tpm2_policypassword](#tpm2_policypassword)**
            - **[tpm2_policypcr](#tpm2_policypcr)**
            - **[tpm2_policyrestart](#tpm2_policyrestart)**
            - **[tpm2_policysecret](#tpm2_policysecret)**
            - **[tpm2_policysigned](#tpm2_policysigned)**
            - **[tpm2_policytemplate](#tpm2_policytemplate)**
            - **[tpm2_policyticket](#tpm2_policyticket)**
    - **[Set Hierarchy Auth Value](#set-hierarchy-auth-value)**
    - **[Set Hierarchy Policy](#set-hierarchy-policy)**
    - **[Signing & Verification](#signing--verification)**
    - **[Startup](#startup)**
    - **[TPM Clear](#tpm-clear)**
    - **[Vendor](#vendor)**
- **[Examples (FAPI)](#examples-fapi)**
    - **[Provision](#provision)**
    - **[Change Auth](#change-auth)**
    - **[Create Key](#create-key)**
    - **[Delete Key](#delete-key)**
    - **[Encryption & Decryption](#encryption--decryption-1)**
    - **[Get Info](#get-info)**
    - **[Get EK Certificate](#get-ek-certificate)**
    - **[Get Random](#get-random-1)**
    - **[Get TPM Blob](#get-tpm-blob)**
    - **[Import](#import)**
    - **[List Objects](#list-objects)**
    - **[PCR](#pcr-1)**
    - **[Quote](#quote-1)**
    - **[Seal/Unseal](#sealunseal)**
    - **[Set/Get App Data](#setget-app-data)**
    - **[Set/Get Certificate](#setget-certificate)**
    - **[Set/Get Description](#setget-description)**
    - **[Signing & Verification](#signing--verification-1)**
- **[CI Self Test](#ci-self-test)**
- **[References](#references)**
- **[License](#license)**

# Prerequisites

- Platform: x86_64, aarch64
- OS: Debian (buster, bullseye), Ubuntu (18.04, 20.04, 22.04)

<!--
- For hardware TPM 2.0, tested on Raspberry Pi 4 Model B with Iridium 9670 TPM 2.0 board [[10]](#10). For detailed setup guide please visit [[8]](#8).
-->

<!-- to-do:
CI failed on aarch64 with Ubuntu:22.04 image. Unable to launch swtpm, returned error: "swtpm: seccomp_load failed with errno 125: Operation canceled". Should be docker issue, however passing "--security-opt=seccomp:unconfined" to docker run does not help...
-->

# Setup on Debian/Ubuntu

Download package information:
```all
$ sudo apt update
```

Install generic packages:
```all
$ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev autoconf doxygen libjson-c-dev libini-config-dev libcurl4-openssl-dev uuid-dev pandoc acl libglib2.0-dev xxd
```

Install platform dependent packages on Ubuntu (18.04, 20.04):
```ubuntu-18.04,ubuntu-20.04
$ sudo apt -y install python-yaml
```

Download this project for later use:
```exclude
$ git clone https://github.com/Infineon/optiga-tpm-cheatsheet ~/optiga-tpm-cheatsheet
```

Install tpm2-tss:
```all
$ git clone https://github.com/tpm2-software/tpm2-tss ~/tpm2-tss
$ cd ~/tpm2-tss
$ git checkout 3.2.0
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig

# For debugging:
# Possible levels are: NONE, ERROR, WARNING, INFO, DEBUG, TRACE
# export TSS2_LOG=all+TRACE
```

Install tpm2-tools:
```all
$ git clone https://github.com/tpm2-software/tpm2-tools ~/tpm2-tools
$ cd ~/tpm2-tools
$ git checkout 5.2
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Install tpm2-abrmd:
```all
$ git clone https://github.com/tpm2-software/tpm2-abrmd ~/tpm2-abrmd
$ cd ~/tpm2-abrmd
$ git checkout 2.4.1
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Install tpm2-tss-engine on Debian (Bullseye, Buster), Ubuntu (18.04, 20.04):
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ git clone https://github.com/tpm2-software/tpm2-tss-engine ~/tpm2-tss-engine
$ cd ~/tpm2-tss-engine
$ git checkout v1.1.0
$ ./bootstrap
$ ./configure <--- optional: "--enable-debug"
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Install tpm2-openssl (substitute for tpm2-tss-engine) on Ubuntu-22.04:
```ubuntu-22.04
$ git clone https://github.com/tpm2-software/tpm2-openssl ~/tpm2-openssl
$ cd ~/tpm2-openssl
$ git checkout 1.1.0
$ ./bootstrap
$ ./configure <--- optional: "--enable-debug"
$ make -j$(nproc) <--- "$ make check" to execute self-test. Do not run test in multithreading mode
$ sudo make install
$ sudo ldconfig
```

Install Microsoft TPM2.0 simulator on Debian (Bullseye, Buster), Ubuntu (18.04, 20.04):
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ git clone https://github.com/microsoft/ms-tpm-20-ref ~/ms-tpm-20-ref
$ cd ~/ms-tpm-20-ref/TPMCmd
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
```

Install libtpms-based TPM emulator on Ubuntu-22.04:
```ubuntu-22.04
# Install dependencies
$ sudo apt-get install -y dh-autoreconf libtasn1-6-dev net-tools libgnutls28-dev expect gawk socat libfuse-dev libseccomp-dev make libjson-glib-dev gnutls-bin

# Install libtpms-devel
$ git clone https://github.com/stefanberger/libtpms ~/libtpms
$ cd ~/libtpms
$ git checkout v0.9.5
$ ./autogen.sh --with-tpm2 --with-openssl
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig

# Install Libtpms-based TPM emulator
$ git clone https://github.com/stefanberger/swtpm ~/swtpm
$ cd ~/swtpm
$ git checkout v0.7.3
$ ./autogen.sh --with-openssl --prefix=/usr
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Test installation:
1. Start Microsoft TPM2.0 simulator on Debian (Bullseye, Buster), Ubuntu (18.04, 20.04):
    ```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
    $ cd ~
    $ tpm2-simulator &
    LIBRARY_COMPATIBILITY_CHECK is ON
    Manufacturing NV state...
    Size of OBJECT = 1204
    Size of components in TPMT_SENSITIVE = 744
        TPMI_ALG_PUBLIC                 2
        TPM2B_AUTH                      50
        TPM2B_DIGEST                    50
        TPMU_SENSITIVE_COMPOSITE        642
    MAX_CONTEXT_SIZE can be reduced to 1264 (1344)
    TPM command server listening on port 2321
    Platform server listening on port 2322
    $ sleep 5
    ```
    Start Libtpms-based TPM emulator on Ubuntu-22.04:
    ```ubuntu-22.04
    $ mkdir /tmp/emulated_tpm
    $ swtpm_setup --create-config-files root --tpmstate /tmp/emulated_tpm --create-ek-cert --create-platform-cert --tpm2 --overwrite
    $ swtpm socket --tpm2 --flags not-need-init --tpmstate dir=/tmp/emulated_tpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 &   <--- to debug, add "--log level=?"
    $ sleep 5
    ```

2. Start TPM resource manager on a session dbus instead of system dbus:<br>
    Start a session dbus which is limited to the current login session:
    ```all
    $ sudo apt install -y dbus
    $ export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
    ```
    Start TPM resource manager on Debian (Bullseye, Buster), Ubuntu (18.04, 20.04):
    ```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
    $ tpm2-abrmd --allow-root --session --tcti=mssim &
    $ sleep 5
    ```
    Start TPM resource manager on Ubuntu-22.04:
    ```ubuntu-22.04
    $ tpm2-abrmd --allow-root --session --tcti=swtpm:host=127.0.0.1,port=2321 &
    $ sleep 5
    ```

3. Set TCTI:
    ```all
    # for tpm2-tools
    $ export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"

    # for tpm2-tss-engine (Debian Bullseye, Debian Buster, Ubuntu-18.04, Ubuntu-20.04)
    $ export TPM2TSSENGINE_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"

    # for tpm2-openssl (Ubuntu-22.04)
    $ export TPM2OPENSSL_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
    ```

4. Perform TPM startup:
    ```all
    $ tpm2_startup -c
    ```

5. Get random:
    ```all
    $ tpm2_getrandom --hex 16
    ```

# Setup on Raspberry Pi

<!-- For detailed Raspberry Pi setup guide please visit [[8]](#8). -->

You may explicitly set the TCTI to device node `tpm0` or `tpmrm0`:
```exclude
$ export TPM2TOOLS_TCTI="device:/dev/tpm0"
$ export TPM2TSSENGINE_TCTI="device:/dev/tpm0"
```

Test installation:
```all
$ tpm2_getrandom --hex 16
```

# Behaviour of Microsoft TPM2.0 Simulator

The Microsoft TPM2.0 simulator [[2]](#2) stores all persistent information in a file (`NVChip`). Find the file in the directory where you launched your simulator. If you wish to start fresh, erase the file before launching the simulator.

Perform TPM startup after launching the simulator, otherwise, all subsequent commands will fail with the error code 0x100 (TPM not initialized by TPM2_Startup):
```all
$ tpm2_startup -c
```

When you are not using the TPM resource manager, keep an eye on the TPM transient and session memory:
```all
$ tpm2_getcap handles-transient
$ tpm2_getcap handles-loaded-session
```

Once it hit 3 handles, the next command may fail with the error code 0x902 (out of memory for object contexts) / 0x903 (out of memory for session contexts). To clear the transient memory:
```all
$ tpm2_flushcontext -t
$ tpm2_flushcontext -l
```

# Examples (SAPI/ESAPI)

TCG Software Stack 2.0 (TSS 2.0) Specification Structure:
- TCG TSS 2.0 System API (SAPI) Specification [[14]](#14)
- TCG TSS 2.0 Enhanced System API (ESAPI) Specification [[15]](#15)

## Audit

<ins><b>tpm2_getsessionauditdigest</b></ins>

Retrieve the session audit digest attestation data from the TPM. The attestation data includes the session audit digest and a signature over the session audit digest:

```all
$ tpm2_createprimary -C e -g sha256 -G ecc -c primary_eh.ctx
$ tpm2_create -C primary_eh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv
$ tpm2_load -C primary_eh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_startauthsession -S session.ctx --audit-session
$ tpm2_getrandom 1 --hex -S session.ctx
$ tpm2_getsessionauditdigest -c signing.key.ctx -g sha256 -m attest.out -s signature.out -S session.ctx
$ tpm2_flushcontext session.ctx

$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out
```

<!-- command not supported
<ins><b>tpm2_setcommandauditstatus</b></ins>

Add or remove TPM2 commands to the audited commands list.
-->

<!-- command not supported
<ins><b>tpm2_getcommandauditdigest</b></ins>

Retrieve the command audit attestation data from the TPM. The attestation data includes the audit digest of the commands in the setlist setup using the command `tpm2_setcommandauditstatus`. Also the attestation data includes the digest of the list of commands setup for audit. The audit digest algorith is setup in the `tpm2_setcommandauditstatus`.

tpm2_getcommandauditdigest -c signing.key.ctx -g sha256 -m attest.out -s signature.out
-->

## Certify

<ins><b>tpm2_certify</b></ins>

`tpm2_certify` proves that an object with a specific NAME is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a public area with a given Name is self consistent and associated with a valid sensitive area:
```all
# Create a policy to restrict the usage of a signing key to only command TPM2_CC_Certify
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx -L policy.ctx TPM2_CC_Certify
$ tpm2_flushcontext session.ctx

# Create keys
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv -L policy.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_startauthsession  --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Certify
$ tpm2_certify -C signing.key.ctx -c primary_sh.ctx -p session:session.ctx -g sha256 -o attest.out -s signature.out
$ tpm2_flushcontext session.ctx

$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out
```
The `attest.out` structure:
- TPM2B_ATTEST ->
    - TPMS_ATTEST ->
        - TPMI_ST_ATTEST = TPM_ST_ATTEST_CERTIFY, it determines the data type of TPMU_ATTEST
        - TPMU_ATTEST ->
            - TPMS_CERTIFY_INFO ->
                - Qualified Name of the certified object

<!-- Needs TPM2_CertifyX509 but has not implemented in tpm2-tools yet
<ins><b>tpm2_certifyX509certutil</b></ins>

`tpm2_certifyX509certutil` generates a partial certificate that is suitable as the third input parameter for TPM2_certifyX509 command, however, TPM2_CertifyX509 is not implemented in tpm2-tools yet.

The purpose of TPM2_CertifyX509 is to generate an X.509 certificate that proves an object with a specific public key and attributes is loaded in the TPM. In contrast to TPM2_Certify, which uses a TCG-defined data structure to convey attestation information (`attest.out`), TPM2_CertifyX509 encodes the attestation information in a DER-encoded X.509 certificate that is compliant with RFC5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.
-->

<ins><b>tpm2_certifycreation</b></ins>

When an object is created, the TPM creates a creation data that describes the environment in which the object was created. The TPM also produces a ticket that will allow the TPM to validate that the creation data was generated by the TPM. In other words, this allows the TPM to certify that it created the Object (TPM2_CertifyCreation()). This is most useful when fixedTPM is CLEAR in the created object. An example:

```all
$ tpm2_createprimary -C o -g sha256 -G ecc --creation-data creation.data -d creation.data.hash -t creation.ticket -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv
$ tpm2_load -C primary_sh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_certifycreation -C signing.key.ctx -c primary_sh.ctx -d creation.data.hash -t creation.ticket -g sha256 -o signature.out --attestation attest.out

$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out
```

Another example involving policy:
```all
# Create a policy to restrict the usage of a signing key to only command TPM2_CC_CertifyCreation
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx -L policy.ctx TPM2_CC_CertifyCreation
$ tpm2_flushcontext session.ctx

$ tpm2_createprimary -C o -g sha256 -G ecc --creation-data creation.data -d creation.data.hash -t creation.ticket -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv -L policy.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_CertifyCreation
$ tpm2_certifycreation -C signing.key.ctx -P session:session.ctx -c primary_sh.ctx -d creation.data.hash -t creation.ticket -g sha256 -o signature.out --attestation attest.out
$ tpm2_flushcontext session.ctx

$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out
```

<ins><b>tpm2_nvcertify</b></ins>

Provides attestation of the content of an NV index. An example:

```all
$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -s 32 -a "authread|authwrite"
$ tpm2_nvwrite 0x01000000 -i data

$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv -p key123
$ tpm2_load -C primary_sh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_nvcertify -C signing.key.ctx -P key123 -g sha256 -o signature.out --attestation attest.out --size 32 0x01000000
$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out

# or use OpenSSL to verify signature
$ tpm2_nvcertify -C signing.key.ctx -P key123 -g sha256 -f plain -o signature.out --attestation attest.out --size 32 0x01000000
$ tpm2_readpublic -c signing.key.ctx -o public.pem -f pem
$ openssl dgst -sha256 -verify public.pem -keyform pem -signature signature.out attest.out

$ tpm2_nvundefine 0x01000000 -C o
```

Another example involving policy:
```all
# Create a policy to restrict the usage of a signing key to only command TPM2_CC_NV_Certify
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx -L policy.ctx TPM2_CC_NV_Certify
$ tpm2_flushcontext session.ctx

$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -s 32 -a "authread|authwrite"
$ tpm2_nvwrite 0x01000000 -i data

$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u signing.key.pub -r signing.key.priv -L policy.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u signing.key.pub -r signing.key.priv -c signing.key.ctx

$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_NV_Certify
$ tpm2_nvcertify -C signing.key.ctx -P session:session.ctx -g sha256 -o signature.out --attestation attest.out --size 32 0x01000000
$ tpm2_verifysignature -c signing.key.ctx -g sha256 -m attest.out -s signature.out
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

# Clock & Time

<ins><b>tpm2_readclock</b></ins>

```all
$ tpm2_readclock
  time: 12286
  clock_info:
    clock: 12286
    reset_count: 0
    restart_count: 0
    safe: yes
```

The command reads the current TPMS_TIME_INFO structure that contains the current setting of Time, Clock, Safe, resetCount, and restartCount:
- Reset count: This counter shall increment on each TPM Reset. This counter shall be reset to zero by TPM2_Clear(). A TPM Reset is either an unorderly shutdown or an orderly shutdown:
    ```exclude
    $ tpm2_shutdown -c
    < cold/warm reset >
    $ tpm2_startup -c
    $ tpm2_readclock
    ```
- Restart count: This counter shall increment by one for each TPM Restart or TPM Resume. The restartCount shall be reset to zero on a TPM Reset or TPM2_Clear(). A TPM Restart is:
    ```exclude
    $ tpm2_shutdown
    < cold/warm reset >
    $ tpm2_startup -c
    $ tpm2_readclock
    ```
    A TPM Resume is:
    ```exclude
    $ tpm2_shutdown
    < cold/warm reset >
    $ tpm2_startup
    $ tpm2_readclock
    ```
- Clock: It is a time value in milliseconds that advances while the TPM is powered. The value shall be reset to zero by TPM2_Clear(). This value may be advanced by TPM2_ClockSet().

    Clock will be non-volatile but may have a volatile component that is updated every millisecond with the non-volatile component updated at a lower rate. The non-volatile component shall be updated no less frequently than every 222 milliseconds (~69.9 minutes). The update rate of the non-volatile portion of Clock shall be reported by command `tpm2_getcap properties-fixed` check property TPM_PT_CLOCK_UPDATE:
    ```all
    $ tpm2_getcap properties-fixed
      ...
      TPM2_PT_CLOCK_UPDATE:
      raw: 0x40000 --> 262144ms -> 262s --> 4.4m
      ...
    ```
- Safe: This parameter is set to YES when the value reported in Clock is guaranteed to be greater than any previous value. This parameter will be set to YES by TPM2_Clear(). An unorderly shutdown will put the parameter to NO. After an unorderly shutdown, the parameter will return to YES when ((Clock % TPM2_PT_CLOCK_UPDATE) == 0).
- Time: It is a time value in milliseconds that advances while the TPM is powered. The value is reset whenever power to the time circuit is reestablished (in other words a cold reset).

<ins><b>tpm2_setclock</b></ins>

Sets the clock on the TPM to a time (milliseconds) in the future:
```all
# print the clock
$ tpm2_readclock
  time: 5097
  clock_info:
    clock: 5097
    reset_count: 0
    restart_count: 0
    safe: yes

# get current clock in milliseconds
$ CURRENT_CLOCK=`tpm2_readclock | grep 'clock:' | sed 's/.* //'`

# set to 10 seconds in the future
$ FUTURE=$(($CURRENT_CLOCK + 10000))

# set the clock
$ tpm2_setclock $FUTURE
```

## Clear Control

Read the disableClear attribute:
```all
$ tpm2_getcap properties-variable | grep disableClear
```

Disable clear:
```all
$ tpm2_clearcontrol -C p s
$ tpm2_getcap properties-variable | grep disableClear

# tpm clear will fail
# tpm2_clear -c p
```

Enable clear:
```all
$ tpm2_clearcontrol -C p c
$ tpm2_getcap properties-variable | grep disableClear

# tpm clear will succeed
$ tpm2_clear -c p
```

## Create Keys

Create primary key in platform hierarchy:
```all
$ tpm2_createprimary -C p -g sha256 -G ecc -c primary_ph.ctx
```

Create primary key in storage hierarchy:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
```

Create ordinary keys:
```all
# RSA
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

# EC
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u eckey.pub -r eckey.priv
$ tpm2_load -C primary_sh.ctx -u eckey.pub -r eckey.priv -c eckey.ctx

# HMAC
$ tpm2_create -C primary_sh.ctx -G hmac -c hmackey.ctx

# AES
$ tpm2_create -C primary_sh.ctx -G aes256 -u aeskey.pub -r aeskey.priv
$ tpm2_load -C primary_sh.ctx -u aeskey.pub -r aeskey.priv -c aeskey.ctx
```

## Dictionary Attack Protection

For practice, try this on simulator. Use hardware TPM at your own risk.

Before we start, understand the basic:
- failedTries (TPM2_PT_LOCKOUT_COUNTER): Increment when an authorization failed or unorderly shutdown
- maxTries (TPM2_PT_MAX_AUTH_FAIL): In lockout mode when failedTries reaches this value
- recoveryTime (TPM2_PT_LOCKOUT_INTERVAL): This value indicates the rate at which failedTries is decremented in seconds
- lockoutRecovery (TPM2_PT_LOCKOUT_RECOVERY): This value indicates the retry delay in seconds after an authorization failure using lockout auth

Check the TPM lockout parameters:
```all
$ tpm2_getcap properties-variable
```

Set lockout auth:
```all
$ tpm2_changeauth -c l lockout123
```

Set lockout parameters to:
- maxTries = 5 tries
- recoveryTime = 10 seconds
- lockoutRecovery = 20 seconds
```all
$ tpm2_dictionarylockout -s -n 5 -t 10 -l 20 -p lockout123
```

To trigger a lockout:
```exclude
$ tpm2_createprimary -G ecc -c primary.ctx -p primary123
$ tpm2_create -G ecc -C primary.ctx -P badauth -u key.pub -r key.priv
WARNING:esys:src/tss2-esys/api/Esys_Create.c:398:Esys_Create_Finish() Received TPM Error
ERROR:esys:src/tss2-esys/api/Esys_Create.c:134:Esys_Create() Esys Finish ErrorCode (0x0000098e)
ERROR: Esys_Create(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented
ERROR: Unable to run tpm2_create
$ tpm2_create -G ecc -C primary.ctx -P badauth -u key.pub -r key.priv
WARNING:esys:src/tss2-esys/api/Esys_Create.c:398:Esys_Create_Finish() Received TPM Error
ERROR:esys:src/tss2-esys/api/Esys_Create.c:134:Esys_Create() Esys Finish ErrorCode (0x0000098e)
ERROR: Esys_Create(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented
ERROR: Unable to run tpm2_create
$ tpm2_create -G ecc -C primary.ctx -P badauth -u key.pub -r key.priv
WARNING:esys:src/tss2-esys/api/Esys_Create.c:398:Esys_Create_Finish() Received TPM Error
ERROR:esys:src/tss2-esys/api/Esys_Create.c:134:Esys_Create() Esys Finish ErrorCode (0x0000098e)
ERROR: Esys_Create(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented
ERROR: Unable to run tpm2_create
$ tpm2_create -G ecc -C primary.ctx -P badauth -u key.pub -r key.priv
WARNING:esys:src/tss2-esys/api/Esys_Create.c:398:Esys_Create_Finish() Received TPM Error
ERROR:esys:src/tss2-esys/api/Esys_Create.c:134:Esys_Create() Esys Finish ErrorCode (0x0000098e)
ERROR: Esys_Create(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented
ERROR: Unable to run tpm2_create
$ tpm2_create -G ecc -C primary.ctx -P badauth -u key.pub -r key.priv
WARNING:esys:src/tss2-esys/api/Esys_Create.c:398:Esys_Create_Finish() Received TPM Error
ERROR:esys:src/tss2-esys/api/Esys_Create.c:134:Esys_Create() Esys Finish ErrorCode (0x00000921)
ERROR: Esys_Create(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode
ERROR: Unable to run tpm2_create
```

To exit lockout state, wait for 10 seconds (recoveryTime), use lockout auth:
```all
$ tpm2_dictionarylockout -c -p lockout123
```

To trigger a lockout on the lockout auth:
```exclude
$ tpm2_dictionarylockout -c -p badauth
```

Wait for 20 seconds (lockoutRecovery) before you can try again.

As a last resort, use `tpm2_clear -c p` to exit all lockout state:
```all
$ tpm2_clear -c p
```

## Display TPM Capabilities

Return a list of supported capability names:
```all
$ tpm2_getcap -l
- algorithms
- commands
- pcrs
- properties-fixed
- properties-variable
- ecc-curves
- handles-transient
- handles-persistent
- handles-permanent
- handles-pcr
- handles-nv-index
- handles-loaded-session
- handles-saved-session
```

Find TPM 2.0 library specification revision [[9]](#9) by:
```all
$ tpm2_getcap properties-fixed
TPM2_PT_FAMILY_INDICATOR:
  raw: 0x322E3000
  value: "2.0"
TPM2_PT_LEVEL:
  raw: 0
TPM2_PT_REVISION:
  raw: 0x74
  value: 1.16 <----------- revision 1.16
TPM2_PT_DAY_OF_YEAR:
  raw: 0xF
TPM2_PT_YEAR:
  raw: 0x7E0
TPM2_PT_MANUFACTURER:
  raw: 0x49465800
  value: "IFX"
TPM2_PT_VENDOR_STRING_1:
  raw: 0x534C4239
  value: "SLB9"
TPM2_PT_VENDOR_STRING_2:
  raw: 0x36373000
  value: "670"
TPM2_PT_VENDOR_STRING_3:
  raw: 0x0
  value: ""
TPM2_PT_VENDOR_STRING_4:
  raw: 0x0
  value: ""
TPM2_PT_VENDOR_TPM_TYPE:
  raw: 0x0
TPM2_PT_FIRMWARE_VERSION_1:
  raw: 0x7003D
TPM2_PT_FIRMWARE_VERSION_2:
  raw: 0xAE100
TPM2_PT_INPUT_BUFFER:
  raw: 0x400
TPM2_PT_HR_TRANSIENT_MIN:
  raw: 0x3
TPM2_PT_HR_PERSISTENT_MIN:
  raw: 0x7
TPM2_PT_HR_LOADED_MIN:
  raw: 0x3
TPM2_PT_ACTIVE_SESSIONS_MAX:
  raw: 0x40
TPM2_PT_PCR_COUNT:
  raw: 0x18
TPM2_PT_PCR_SELECT_MIN:
  raw: 0x3
TPM2_PT_CONTEXT_GAP_MAX:
  raw: 0xFFFF
TPM2_PT_NV_COUNTERS_MAX:
  raw: 0x8
TPM2_PT_NV_INDEX_MAX:
  raw: 0x680
TPM2_PT_MEMORY:
  raw: 0x6
TPM2_PT_CLOCK_UPDATE:
  raw: 0x80000
TPM2_PT_CONTEXT_HASH:
  raw: 0xB
TPM2_PT_CONTEXT_SYM:
  raw: 0x6
TPM2_PT_CONTEXT_SYM_SIZE:
  raw: 0x80
TPM2_PT_ORDERLY_COUNT:
  raw: 0xFF
TPM2_PT_MAX_COMMAND_SIZE:
  raw: 0x500
TPM2_PT_MAX_RESPONSE_SIZE:
  raw: 0x500
TPM2_PT_MAX_DIGEST:
  raw: 0x20
TPM2_PT_MAX_OBJECT_CONTEXT:
  raw: 0x3B8
TPM2_PT_MAX_SESSION_CONTEXT:
  raw: 0xEB
TPM2_PT_PS_FAMILY_INDICATOR:
  raw: 0x1
TPM2_PT_PS_LEVEL:
  raw: 0x0
TPM2_PT_PS_REVISION:
  raw: 0x100
TPM2_PT_PS_DAY_OF_YEAR:
  raw: 0x0
TPM2_PT_PS_YEAR:
  raw: 0x0
TPM2_PT_SPLIT_MAX:
  raw: 0x80
TPM2_PT_TOTAL_COMMANDS:
  raw: 0x5A
TPM2_PT_LIBRARY_COMMANDS:
  raw: 0x59
TPM2_PT_VENDOR_COMMANDS:
  raw: 0x1
TPM2_PT_NV_BUFFER_MAX:
  raw: 0x300
```

Check what commands are supported:
```all
$ tpm2_getcap commands
```

## EK Credential

Create EK and AK:
```all
$ tpm2_createek -c 0x81010001 -G rsa -u ek.pub
$ tpm2_createak -C 0x81010001 -c ak.ctx -u ak.pub -n ak.name
$ tpm2_evictcontrol -C o -c ak.ctx 0x81010002
$ tpm2_getcap handles-persistent
```

Make credential:
```all
$ dd if=/dev/urandom of=data.clear bs=1 count=16
$ tpm2_makecredential -e ek.pub -s data.clear -n $(xxd -ps -c 100 ak.name) -o data.cipher
```

Activate credential:
```all
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c e
$ tpm2_activatecredential -c 0x81010002 -C 0x81010001 -i data.cipher -o data.decipher -P session:session.ctx
$ tpm2_flushcontext session.ctx
$ diff data.decipher data.clear

$ tpm2_clear -c p
```

## Encrypted Session

Using a HMAC session to enable encryption of selected parameters.

Get random:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ tpm2_startauthsession --hmac-session -c primary_sh.ctx -S session.ctx
$ tpm2_getrandom -S session.ctx --hex 16
$ tpm2_flushcontext session.ctx
```

Decryption:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

# create RSA key
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

$ echo "some secret" > secret.clear
$ tpm2_rsaencrypt -c rsakey.ctx -o secret.cipher secret.clear

$ tpm2_startauthsession --hmac-session -c primary_sh.ctx -S session.ctx
$ tpm2_rsadecrypt -p session:session.ctx -c rsakey.ctx -o secret.decipher secret.cipher
$ tpm2_flushcontext session.ctx
```

Sign:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

# create RSA key
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

$ echo "some message" > message

$ tpm2_startauthsession --hmac-session -c primary_sh.ctx -S session.ctx
$ tpm2_sign -p session:session.ctx -c rsakey.ctx -g sha256 -o signature message
$ tpm2_flushcontext session.ctx

$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m message -s signature
```

HMAC:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

# create HMAC key
$ tpm2_create -C primary_sh.ctx -G hmac -c hmackey.ctx

$ echo "some message" > message

$ tpm2_startauthsession --hmac-session -c primary_sh.ctx -S session.ctx
$ tpm2_hmac -p session:session.ctx -c hmackey.ctx --hex message
$ tpm2_flushcontext session.ctx
```

NV operations:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -C o -s 32 -a "ownerwrite|ownerread"

$ tpm2_startauthsession --hmac-session -c primary_sh.ctx -S session.ctx
$ tpm2_nvwrite 0x01000000 -P session:session.ctx -C o -i data
$ tpm2_nvread 0x01000000 -P session:session.ctx -C o -o out
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

## Encryption & Decryption

Using RSA key:
```all
# create RSA key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

$ echo "some secret" > secret.clear
$ tpm2_rsaencrypt -c rsakey.ctx -o secret.cipher secret.clear
$ tpm2_rsadecrypt -c rsakey.ctx -o secret.decipher secret.cipher
$ diff secret.decipher secret.clear

# or use OpenSSL to encrypt message

$ tpm2_readpublic -c rsakey.ctx -o public.pem -f pem
$ openssl rsautl -encrypt -inkey public.pem -in secret.clear -pubin -out secret.cipher
$ tpm2_rsadecrypt -c rsakey.ctx -o secret.decipher secret.cipher
$ diff secret.decipher secret.clear
```

Using AES key:
```all
# create AES key
$ tpm2_create -C primary_sh.ctx -G aes256 -u aeskey.pub -r aeskey.priv
$ tpm2_load -C primary_sh.ctx -u aeskey.pub -r aeskey.priv -c aeskey.ctx

$ echo "some secret" > secret.clear
$ tpm2_getrandom 16 > iv
$ tpm2_encryptdecrypt -c aeskey.ctx -t iv -o secret.cipher secret.clear
$ tpm2_encryptdecrypt -d -c aeskey.ctx -t iv -o secret.decipher secret.cipher
$ diff secret.decipher secret.clear
```

## Get Random

Get 16 bytes of random:
```all
$ tpm2_getrandom --hex 16
```

## Hashing

```all
$ echo "some message" > message
$ tpm2_hash -g sha256 --hex message
```

## Hierarchy Control

Disable/Enable storage hierarchy:
```all
$ tpm2_hierarchycontrol -C o shEnable clear
$ tpm2_hierarchycontrol -C p shEnable set
```

Disable/Enable endorsement hierarchy:
```all
$ tpm2_hierarchycontrol -C e ehEnable clear
$ tpm2_hierarchycontrol -C p ehEnable set
```

Disable platform hierarchy:
```exclude
$ tpm2_hierarchycontrol -C p phEnable clear
```

phEnable, shEnable, and ehEnable flag is not persistent. All hierarchies will be set to TRUE after a reset.

To simulate a reset (power cycling) simply terminate and relaunch the simulator, remember to run `tpm2_startup -c`.

View hierarchy information:
```all
$ tpm2_getcap properties-variable
```

## Import Externally Created key

### Under a Parent Key

RSA key:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ openssl genrsa -out rsa_private.pem 2048
$ tpm2_import -C primary_sh.ctx -G rsa -i rsa_private.pem -u rsakey_imported.pub -r rsakey_imported.priv
$ tpm2_load -C primary_sh.ctx -u rsakey_imported.pub -r rsakey_imported.priv -c rsakey_imported.ctx
```

EC key:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ openssl ecparam -name prime256v1 -genkey -noout -out ecc_private.pem
$ tpm2_import -C primary_sh.ctx -G ecc -i ecc_private.pem -u eckey_imported.pub -r eckey_imported.priv
$ tpm2_load -C primary_sh.ctx -u eckey_imported.pub -r eckey_imported.priv -c eckey_imported.ctx
```

HMAC key:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ dd if=/dev/urandom of=raw.key bs=1 count=32
$ tpm2_import -C primary_sh.ctx -G hmac -i raw.key -u hmackey_imported.pub -r hmackey_imported.priv
$ tpm2_load -C primary_sh.ctx -u hmackey_imported.pub -r hmackey_imported.priv -c hmackey_imported.ctx
```

### Under Hierarchy

Load of a public external object area allows the object to be associated with a hierarchy. If the public and sensitive portions of the object are loaded, hierarchy is required to be TPM_RH_NULL.

RSA key to null hierarchy:
```all
$ openssl genrsa -out rsa_private.pem 2048
$ tpm2_loadexternal -C n -G rsa -r rsa_private.pem -c rsakey_imported.ctx
```

EC key to null hierarchy:
```all
$ openssl ecparam -name prime256v1 -genkey -noout -out ecc_private.pem
$ tpm2_loadexternal -C n -G ecc -r ecc_private.pem -c eckey_imported.ctx
```

Just the public component of an RSA key to storage hierarchy:
```all
$ openssl genrsa -out rsa_private.pem 2048
$ openssl rsa -in rsa_private.pem -out rsa_public.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u rsa_public.pem -c rsakey_imported.ctx
```

## NV Storage

<!-- to-do: platform NV -->

NV define, write, and read:
```all
$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -C o -s 32 -a "ownerwrite|ownerread"
$ tpm2_nvwrite 0x01000000 -C o -i data
$ tpm2_nvread 0x01000000 -C o -o out
$ diff data out
```

NV read public:
```all
$ tpm2_nvreadpublic
```

Read NV indices:
```all
$ tpm2_getcap handles-nv-index
```

NV undefine:
```all
$ tpm2_nvundefine 0x01000000 -C o
```

NV with authvalue protection:
```all
$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -C o -s 32 -a "authread|authwrite" -p pswd
$ tpm2_nvwrite 0x01000000 -i data -P pswd
$ tpm2_nvread 0x01000000 -o out -P pswd
$ diff data out

$ tpm2_nvundefine 0x01000000 -C o
```

NV under platform hierarchy. In this mode, the NV index cannot be cleared by `tpm2_clear`:
```all
$ dd bs=1 count=32 </dev/urandom >data
$ tpm2_nvdefine 0x01000000 -C p -s 32 -a "ppwrite|ppread|platformcreate"
$ tpm2_nvwrite 0x01000000 -C p -i data
$ tpm2_nvread 0x01000000 -C p -o out
$ diff data out

$ tpm2_nvundefine 0x01000000 -C p
```

Define a 64-bit NV for OR operation:
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=bits|ownerwrite|ownerread"

# OR 1's into NV index
$ tpm2_nvsetbits 0x01000000 -C o -i 0x1111111111111111
$ tpm2_nvread 0x01000000 -C o | xxd -p

$ tpm2_nvundefine 0x01000000 -C o
```

Define a 64-bit NV for counting operation:
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=counter|ownerwrite|ownerread"

# increment
$ tpm2_nvincrement 0x01000000 -C o
$ tpm2_nvread 0x01000000 -C o | xxd -p

$ tpm2_nvundefine 0x01000000 -C o
```

Define a 64-bit NV for extend operation. The name algorithm decides the hash algorithm used for the extend:
```all
$ tpm2_nvdefine 0x01000000 -C o -g sha256 -a "nt=extend|ownerwrite|ownerread"

# extend
$ echo "plaintext" > plain.txt
$ tpm2_nvextend 0x01000000 -C o -i plain.txt
$ tpm2_nvread 0x01000000 -C o | xxd -c 32 -p

$ tpm2_nvundefine 0x01000000 -C o
```

Define an NV for pinfail operation:
<!-- Use `tpm2_nvread 0x01000000 -C o` to read the NV instead of `tpm2_nvread 0x01000000 -C 0x01000000 -P pass123`, because a successful authentication using index authvalue will reset the pinCount -->
<!-- If TPM_NT is TPM_NT_PIN_FAIL, TPMA_NV_NO_DA must be SET. This removes ambiguity over which Dictionary Attack defense protects a TPM_NV_PIN_FAIL's authValue. -->
<!-- TPMA_NV_AUTHWRITE must set to CLEAR. For reasoning purpose: imagine if TPMA_NV_AUTHWRITE was SET for a pinpass/pinfail, a user knowing the authorization value could decrease pinCount or increase pinLimit, defeating the purpose of a pinfail/pinfail. -->
<!-- pinCount is incremented after an authorization attempt using authValue succeeds -->
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=pinfail|ownerwrite|ownerread|authread|no_da" -p pass123

# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x05' > data
$ tpm2_nvwrite 0x01000000 -C o -i data
$ tpm2_nvread 0x01000000 -C o | xxd -p

# trigger localized dictionary attack protection
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123 <---- expected to fail
  tpm2_nvread 0x01000000 -C o | xxd -p            <---- notice pinCount increases by 1
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123
  tpm2_nvread 0x01000000 -C 0x01000000 -P fail123 <---- authorization via authValue is now locked out

# exit authValue lockout
$ tpm2_nvwrite 0x01000000 -C o -i data

$ tpm2_nvundefine 0x01000000 -C o
```

A more meaningful pinfail example:
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=pinfail|ownerwrite|ownerread|authread|no_da" -p pass123

# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x05' > data
$ tpm2_nvwrite 0x01000000 -C o -i data
$ tpm2_nvread 0x01000000 -C o | xxd -p

# create a policy to use nv auth for authorization
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysecret -S session.ctx -L secret.policy -c 0x01000000 pass123
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L secret.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x01000000 pass123
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# trigger localized dictionary attack protection
$ tpm2_startauthsession --policy-session -S session.ctx
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123 <---- expected to fail
# tpm2_nvread 0x01000000 -C o | xxd -p                   <---- notice pinCount increases by 1
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123 <---- notice pinCount == pinLimit
# tpm2_policysecret -S session.ctx -c 0x01000000 fail123 <---- authorization using authValue will fail
$ tpm2_flushcontext session.ctx

# re-enable NV authValue
$ tpm2_nvwrite 0x01000000 -C o -i data

$ tpm2_nvundefine 0x01000000 -C o
```

Define an NV for pinpass operation:
<!-- Use `tpm2_nvread 0x01000000 -C o` to read the NV instead of `tpm2_nvread 0x01000000 -C 0x01000000 -P pass123`, because a successful authentication using index authvalue will increase the pinCount -->
<!-- TPMA_NV_AUTHWRITE must set to CLEAR. For reasoning purpose: imagine if TPMA_NV_AUTHWRITE was SET for a pinpass/pinfail, a user knowing the authorization value could decrease pinCount or increase pinLimit, defeating the purpose of a pinfail/pinfail. -->
<!-- pinCount is incremented after an authorization attempt using authValue fails -->
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=pinpass|ownerwrite|ownerread|authread" -p pass123

# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x05' > data
$ tpm2_nvwrite 0x01000000 -C o -i data
$ tpm2_nvread 0x01000000 -C o | xxd -p

# restricting the number of uses with pinpass
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p  <---- notice pinCount increases by 1
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p
$ tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p  <---- notice pinCount == pinLimit
# tpm2_nvread 0x01000000 -C 0x01000000 -P pass123 | xxd -p  <---- authorization using authValue will fail

# re-enable NV authValue
$ tpm2_nvwrite 0x01000000 -C o -i data

$ tpm2_nvundefine 0x01000000 -C o
```

A more meaningful pinpass example:
```all
$ tpm2_nvdefine 0x01000000 -C o -a "nt=pinpass|ownerwrite|ownerread|authread" -p pass123

# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x05' > data
$ tpm2_nvwrite 0x01000000 -C o -i data
$ tpm2_nvread 0x01000000 -C o | xxd -p

# create a policy to use nv auth for authorization
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysecret -S session.ctx -L secret.policy -c 0x01000000 pass123
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L secret.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x01000000 pass123
$ tpm2_nvread 0x01000000 -C o | xxd -p                   <---- notice pinCount increases by 1 (now 2)
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# restricting the number of uses of an object with pinpass
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x01000000 pass123
$ tpm2_nvread 0x01000000 -C o | xxd -p                   <---- notice pinCount increases by 1
$ tpm2_policysecret -S session.ctx -c 0x01000000 pass123
$ tpm2_policysecret -S session.ctx -c 0x01000000 pass123
$ tpm2_nvread 0x01000000 -C o | xxd -p                   <---- notice pinCount == pinLimit
# tpm2_policysecret -S session.ctx -c 0x01000000 pass123 <---- authorization using authValue will fail
$ tpm2_flushcontext session.ctx

# re-enable NV authValue
$ tpm2_nvwrite 0x01000000 -C o -i data

$ tpm2_nvundefine 0x01000000 -C o
```

## OpenSSL 1.x CLI

This section is for Debian (Bullseye, Buster), Ubuntu (18.04, 20.04).

Verify TPM engine (tpm2-tss-engine) installation:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl engine -t -c tpm2tss
(tpm2tss) TPM2-TSS engine for OpenSSL
 [RSA, RAND]
     [ available ]
```

Generate random value:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl rand -engine tpm2tss -hex 10
```

### PEM Encoded Key Object

Create parent key:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_evictcontrol -C o -c primary_sh.ctx 0x81000001
```

Create RSA key using tpm2-tss-engine tool, the output is a PEM encoded TPM key object:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2tss-genkey -P 0x81000001 -a rsa -s 2048 rsakey.pem

# or

$ tpm2tss-genkey -a rsa -s 2048 rsakey.pem
```

Create EC key using tpm2-tss-engine tool:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2tss-genkey -P 0x81000001 -a ecdsa eckey.pem

# or

$ tpm2tss-genkey -a ecdsa eckey.pem
```

Read public component:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl rsa -engine tpm2tss -inform engine -in rsakey.pem -pubout -outform pem -out rsakey.pub.pem
$ openssl ec -engine tpm2tss -inform engine -in eckey.pem -pubout -outform pem -out eckey.pub.pem
```

RSA encryption & decryption:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ echo "some secret" > secret.clear
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -in secret.clear -encrypt -out secret.cipher
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey rsakey.pem -decrypt -in secret.cipher -out secret.decipher
$ diff secret.clear secret.decipher
```

RSA signing & verification:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey rsakey.pem -sign -in data -out data.sig
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -verify -in data -sigfile data.sig
```

EC signing & verification:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey eckey.pem -sign -in data -out data.sig
$ openssl pkeyutl -pubin -inkey eckey.pub.pem -verify -in data -sigfile data.sig
```

Create self-signed certificate:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key rsakey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.crt.pem
$ openssl x509 -in rsakey.crt.pem -text -noout
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key eckey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.crt.pem
$ openssl x509 -in eckey.crt.pem -text -noout
```

Create certificate signing request (CSR):
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl req -new -engine tpm2tss -keyform engine -key rsakey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.csr.pem
$ openssl req -in rsakey.csr.pem -text -noout
$ openssl req -new -engine tpm2tss -keyform engine -key eckey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.csr.pem
$ openssl req -in eckey.csr.pem -text -noout
```

Clean up:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_clear -c p
```

#### Conversion to PEM Encoded Key Object

In the event that TPM key is not created using `tpm2tss-genkey`, use the following tool to make the conversion.

Build the tool and set LD_LIBRARY_PATH:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
# Create a symbolic link to discard the platform dependent path
$ ln -fs /usr/lib/*-linux-gnu /usr/lib/any-linux-gnu
$ export LD_LIBRARY_PATH=/usr/lib/any-linux-gnu/engines-1.1

$ gcc -Wall -o convert ~/optiga-tpm-cheatsheet/openssl-lib-convert-to-pem-key/convert.c -L$LD_LIBRARY_PATH -lcrypto -ltss2-mu -ltpm2tss
```

RSA key:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_evictcontrol -C o -c primary_sh.ctx 0x81000001
$ tpm2_create -C 0x81000001 -g sha256 -G rsa -u rsakey.pub -r rsakey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda"

$ ./convert 0x81000001 rsakey.pub rsakey.priv rsakey.pem

# quick verification
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey rsakey.pem -sign -in data -out data.sig
$ openssl rsa -engine tpm2tss -inform engine -in rsakey.pem -pubout -outform pem -out rsakey.pub.pem
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -verify -in data -sigfile data.sig

$ tpm2_clear -c p
```

EC key:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_evictcontrol -C o -c primary_sh.ctx 0x81000001
$ tpm2_create -C 0x81000001 -g sha256 -G ecc -u eckey.pub -r eckey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"

$ ./convert 0x81000001 eckey.pub eckey.priv eckey.pem

# quick verification
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey eckey.pem -sign -in data -out data.sig
$ openssl ec -engine tpm2tss -inform engine -in eckey.pem -pubout -outform pem -out eckey.pub.pem
$ openssl pkeyutl -pubin -inkey eckey.pub.pem -verify -in data -sigfile data.sig

$ tpm2_clear -c p
```

### Persistent Key

Generate persistent RSA and EC keys using tpm2-tools:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx
$ tpm2_evictcontrol -C o -c rsakey.ctx 0x81000002

$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u eckey.pub -r eckey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"
$ tpm2_load -C primary_sh.ctx -u eckey.pub -r eckey.priv -c eckey.ctx
$ tpm2_evictcontrol -C o -c eckey.ctx 0x81000003
```

Read public component:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl rsa -engine tpm2tss -inform engine -in 0x81000002 -pubout -outform pem -out rsakey.pub.pem
$ openssl ec -engine tpm2tss -inform engine -in 0x81000003 -pubout -outform pem -out eckey.pub.pem
```

RSA encryption & decryption:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ echo "some secret" > secret.clear
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -in secret.clear -encrypt -out secret.cipher
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey 0x81000002 -decrypt -in secret.cipher -out secret.decipher
$ diff secret.clear secret.decipher
```

RSA signing & verification:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey 0x81000002 -sign -in data -out data.sig
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -verify -in data -sigfile data.sig
```

EC signing & verification:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey 0x81000003 -sign -in data -out data.sig
$ openssl pkeyutl -pubin -inkey eckey.pub.pem -verify -in data -sigfile data.sig
```

Create self-signed certificate:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key 0x81000002 -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.crt.pem
$ openssl x509 -in rsakey.crt.pem -text -noout
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key 0x81000003 -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.crt.pem
$ openssl x509 -in eckey.crt.pem -text -noout
```

Create certificate signing request (CSR):
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ openssl req -new -engine tpm2tss -keyform engine -key 0x81000002 -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.csr.pem
$ openssl req -in rsakey.csr.pem -text -noout
$ openssl req -new -engine tpm2tss -keyform engine -key 0x81000003 -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.csr.pem
$ openssl req -in eckey.csr.pem -text -noout
```

Clean up:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_clear -c p
```

### Server-client TLS Communication

```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ cd ~/optiga-tpm-cheatsheet/openssl1-cli-tls
$ chmod a+x *.sh
$ ./0_clean-up.sh
$ ./1_init-tpm.sh
$ ./2_gen-ca-crt.sh
$ ./3_gen-client-crt.sh

# start server
$ ./4_start-server.sh &
$ sleep 5

# start client
$ ./5_start-good-client.sh

# house keeping
$ ./0_clean-up.sh
$ pkill openssl
$ tpm2_clear -c p
```

### Nginx & Curl

<!--
nginx -V
cat /var/log/nginx/error.log
-->

Install Nginx and Curl on your host:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo apt install -y nginx curl
```

Add `ssl_engine tpm2tss;` to `/etc/nginx/nginx.conf`, check reference [nginx/nginx.conf](nginx/nginx.conf)
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo cp ~/optiga-tpm-cheatsheet/nginx/nginx.conf /etc/nginx/nginx.conf
```

#### PEM Encoded Key Object

Create key & self-signed certificate:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ cd /tmp
$ tpm2tss-genkey -a rsa -s 2048 rsakey.pem
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key rsakey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.crt.pem
```

Edit `/etc/nginx/sites-enabled/default` to enable SSL, check reference [nginx/default-pem](nginx/default-pem)
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo cp ~/optiga-tpm-cheatsheet/nginx/default-pem /etc/nginx/sites-enabled/default
```

Terminate TPM resource manager so Nginx can directly access TPM via tcti `mssim:host=127.0.0.1,port=2321`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ pkill tpm2-abrmd
$ sleep 5
```

Overwrite the `openssl.cnf`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ mv /usr/lib/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf.bkup
$ cp ~/optiga-tpm-cheatsheet/nginx/openssl.cnf /usr/lib/ssl/openssl.cnf

# Create a symbolic link to discard the platform dependent path
$ ln -fs /usr/lib/*-linux-gnu /usr/lib/any-linux-gnu
```

Restart Nginx:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo service nginx restart
```

Using Curl to test the connection:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ curl --insecure --engine tpm2tss --key-type ENG --key rsakey.pem --cert rsakey.crt.pem https://127.0.0.1
```

Start TPM resource manager:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2-abrmd --allow-root --session --tcti=mssim &
$ sleep 5
```

Restore `openssl.cnf`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ mv /usr/lib/ssl/openssl.cnf.bkup /usr/lib/ssl/openssl.cnf
```

#### Persistent Key

Create key & self-signed certificate:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx
$ tpm2_evictcontrol -C o -c rsakey.ctx 0x81000002
$ openssl req -new -x509 -engine tpm2tss -keyform engine -key 0x81000002 -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.crt.pem
```

Edit `/etc/nginx/sites-enabled/default` to enable SSL, check reference [nginx/default-persistent](nginx/default-persistent)
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo cp ~/optiga-tpm-cheatsheet/nginx/default-persistent /etc/nginx/sites-enabled/default
```

Terminate TPM resource manager so Nginx can directly access TPM via tcti `mssim:host=127.0.0.1,port=2321`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ pkill tpm2-abrmd
$ sleep 5
```

Overwrite the `openssl.cnf`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ mv /usr/lib/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf.bkup
$ cp ~/optiga-tpm-cheatsheet/nginx/openssl.cnf /usr/lib/ssl/openssl.cnf
```

Restart Nginx:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo service nginx restart
```

Using Curl to test the connection:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ curl --insecure --engine tpm2tss --key-type ENG --key 0x81000002 --cert rsakey.crt.pem https://127.0.0.1
```

Start TPM resource manager:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2-abrmd --allow-root --session --tcti=mssim &
$ sleep 5
```

Restore `openssl.cnf`:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ mv /usr/lib/ssl/openssl.cnf.bkup /usr/lib/ssl/openssl.cnf
```

#### Housekeeping

Reset TPM:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ tpm2_clear -c p
```

Stop Nginx:
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ sudo service nginx stop
```

## OpenSSL 1.x Library

This section is for Debian (Bullseye, Buster), Ubuntu (18.04, 20.04).

### General Examples

- Get random
- RSA/EC key creation
- RSA encryption/decryption/sign/verification
- EC sign/verification

Debian (Bullseye, Buster), Ubuntu (18.04, 20.04):
```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ ln -fs /usr/lib/*-linux-gnu /usr/lib/any-linux-gnu
$ export LD_LIBRARY_PATH=/usr/lib/any-linux-gnu/engines-1.1

$ gcc -Wall -o examples ~/optiga-tpm-cheatsheet/openssl1-lib-general-examples/examples.c -L$LD_LIBRARY_PATH -lssl -lcrypto -ltpm2tss
$ ./examples
```

Raspberry Pi:
```exclude
$ export LD_LIBRARY_PATH=/usr/lib/arm-linux-gnueabihf/engines-1.1
$ gcc -Wall -o examples ~/optiga-tpm-cheatsheet/openssl-lib-general-examples/examples.c -lssl -lcrypto -L$LD_LIBRARY_PATH -ltpm2tss -DENABLE_OPTIGA_TPM
$ ./examples
```

### Server-client TLS Communication

```debian-bullseye,debian-buster,ubuntu-18.04,ubuntu-20.04
$ cd ~/optiga-tpm-cheatsheet/openssl1-lib-tls
$ chmod a+x *.sh
$ ./0_clean-up.sh
$ ./1_init-tpm-key.sh
$ ./2_init-software-key.sh
$ ./3_gen-ca-crt.sh
$ ./4_gen-tpm-client-crt.sh
$ ./5_gen-software-client-crt.sh
$ ./6_build-server-client.sh

# start server
$ ./7_start-server.sh &
$ sleep 5

# start client
$ ./8_start-software-client.sh
$ ./9_start-tpm-client.sh

# house keeping
$ ./0_clean-up.sh
$ pkill server
$ tpm2_clear -c p
```

## OpenSSL 3.x CLI

This section is for Ubuntu-22.04.

Verify TPM provider:
```ubuntu-22.04
$ openssl list -providers -provider tpm2 -verbose
```

Generate random value:
```ubuntu-22.04
$ openssl rand -provider tpm2 -hex 10
```

### PEM Encoded Key Object

Create parent key:
```ubuntu-22.04
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_evictcontrol -C o -c primary_sh.ctx 0x81000001
```

Create RSA and EC keys:
```ubuntu-22.04
$ openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:2048 -pkeyopt parent:0x81000001 -out rsakey.pem
$ openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -pkeyopt parent:0x81000001 -out eckey.pem
```

Read public component:
```ubuntu-22.04
$ openssl pkey -provider tpm2 -provider base -in rsakey.pem -pubout -out rsakey.pub.pem
$ openssl rsa -pubin -text -in rsakey.pub.pem

$ openssl pkey -provider tpm2 -provider base -in eckey.pem -pubout -out eckey.pub.pem
$ openssl ec -pubin -text -in eckey.pub.pem
```

RSA encryption & decryption:
```ubuntu-22.04
$ echo "some secret" > secret.clear
$ openssl pkeyutl -pubin -inkey rsakey.pub.pem -in secret.clear -encrypt -out secret.cipher
$ openssl pkeyutl -provider tpm2 -provider base -inkey rsakey.pem -decrypt -in secret.cipher -out secret.decipher
$ diff secret.clear secret.decipher
```

RSA signing & verification (padding schemes: pkcs1, pss):
```ubuntu-22.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -provider tpm2 -provider base -pkeyopt pad-mode:pss -digest sha256 -inkey rsakey.pem -sign -rawin -in data -out data.sig
$ openssl pkeyutl -pkeyopt pad-mode:pss -digest sha256 -pubin -inkey rsakey.pub.pem -verify -rawin -in data -sigfile data.sig
```

EC signing & verification:
```ubuntu-22.04
$ dd bs=1 count=32 </dev/urandom > data
$ openssl pkeyutl -provider tpm2 -provider base -digest sha256 -inkey eckey.pem -sign -rawin -in data -out data.sig
$ openssl pkeyutl -digest sha256 -pubin -inkey eckey.pub.pem -verify -rawin -in data -sigfile data.sig
```

Create self-signed certificate:
```ubuntu-22.04
$ openssl req -new -x509 -provider tpm2 -provider base -key rsakey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.crt.pem
$ openssl x509 -in rsakey.crt.pem -text -noout
$ openssl req -new -x509 -provider tpm2 -provider base -key eckey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.crt.pem
$ openssl x509 -in eckey.crt.pem -text -noout
```

Create certificate signing request (CSR):
```ubuntu-22.04
$ openssl req -new -provider tpm2 -provider base -key rsakey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out rsakey.csr.pem
$ openssl req -in rsakey.csr.pem -text -noout
$ openssl req -new -provider tpm2 -provider base -key eckey.pem -subj "/CN=TPM/O=Infineon/C=SG" -out eckey.csr.pem
$ openssl req -in eckey.csr.pem -text -noout
```

Clean up:
```ubuntu-22.04
$ tpm2_clear -c p
```

### Serialized Key

```ubuntu-22.04
# Create keys
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

# Output the serialized object
$ tpm2_evictcontrol -c rsakey.ctx -o rsakey.serialized 0x81000000

# Read the public component
$ openssl pkey -provider tpm2 -in object:rsakey.serialized -pubout -out rsakey.pub.pem
$ openssl rsa -pubin -text -in rsakey.pub.pem

# Housekeeping
$ tpm2_clear -c p
```

### Persistent Key

```ubuntu-22.04
# Create keys
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

# Make a key persistent
$ tpm2_evictcontrol -c rsakey.ctx 0x81000000

# Read the public component
$ openssl pkey -provider tpm2 -in handle:0x81000000 -pubout -out rsakey.pub.pem
$ openssl rsa -pubin -text -in rsakey.pub.pem

# Housekeeping
$ tpm2_clear -c p
```

### Server-client TLS Communication

```ubuntu-22.04
$ cd ~/optiga-tpm-cheatsheet/openssl3-cli-tls
$ chmod a+x *.sh
$ ./0_clean-up.sh
$ ./1_init-tpm.sh
$ ./2_gen-ca-crt.sh
$ ./3_gen-client-crt.sh

# start server
$ ./4_start-server.sh &
$ sleep 5

# start client
$ ./5_start-good-client.sh

# house keeping
$ ./0_clean-up.sh
$ pkill openssl
$ tpm2_clear -c p
```

## OpenSSL 3.x Library

This section is for Ubuntu-22.04.

### General Examples

- Get random
- RSA/EC key creation
- RSA encryption/decryption/sign/verification
- EC sign/verification

```ubuntu-22.04
$ gcc -Wall -o examples ~/optiga-tpm-cheatsheet/openssl3-lib-general-examples/examples.c -lssl -lcrypto
$ ./examples
```

### Server-client TLS Communication

```ubuntu-22.04
$ cd ~/optiga-tpm-cheatsheet/openssl3-lib-tls
$ chmod a+x *.sh
$ ./0_clean-up.sh
$ ./1_init-tpm-key.sh
$ ./2_init-software-key.sh
$ ./3_gen-ca-crt.sh
$ ./4_gen-tpm-client-crt.sh
$ ./5_gen-software-client-crt.sh
$ ./6_build-server-client.sh

# start server
$ ./7_start-server.sh &
$ sleep 5

# start client
$ ./8_start-software-client.sh
$ ./9_start-tpm-client.sh

# house keeping
$ ./0_clean-up.sh
$ pkill server
$ tpm2_clear -c p
```

## Password Authorization

A plaintext password value may be used to authorize an action when use of an authValue is allowed. Unfortunately, this cannot be demonstrated here. tpm2-tools treats all password authorization as HMAC session-based authorization:
<!-- https://github.com/remuswu1019/tpm2-tools/commit/a82f766e9bc42df9cfbdb12712de071e4e539c9f -->
<!-- https://github.com/tpm2-software/tpm2-tools/pull/2719 -->

```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

# create a key safeguarded by the a password
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign" -p pass123
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# provide the password to access the key for signing use
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p pass123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
```

## PCR

<!--
Linux kernel operates only on locality 0 (Static OS), there is no function to change locality, so you are able to access non-resettable PCRs (0-15) and of course the free to use PCRs (PCR 16 and PCR 23)

Statement below is taken from TCG spec PC Client

Free to use PCRs (PCR 16 and PCR 23)

Non-resettable PCRs (0-15):
Used by Static RTM (Root of Trust for Measurement) or Static OS

Locality Resettable PCRs (17-22):
Is also known as "Resettable PCRs" in the doc, with the exception of PCR 16 and PCR 23, are a set of PCRs for use by the Dynamic RTM (Root of Trust for Measurement) and its chain of trust. Access to these PCR is controlled by the various locality indicators. *since Linux kernel uses only locality 0, there is no way to reset PCRs 17-22.

Locality Uses:
Usage of Locality 0 PCRs is determined by the TCG PC Client Specific Implementation Specification. Usage of Locality 1-3 PCRs is reserved for uses which are outside the purview of this specification. The idea behind locality is that certain combinations of Software and hardware are allowed more privileges than other combinations. For instance, the highest level of locality might be cycles that only hardware could create.
While higher localities may exist, Locality 4 is the highest locality level defined. These cycles are generated by hardware in support of the D-RTM. Cycles which require Locality 4 would include things such as the HASH_START/_DATA/_END interface commands. As an example, assume a platform, including Software, has an operating system based on the Static RTM or Static OS, based on either using no PCRs or the set of non-resettable PCRs (0-15), and trusted Software, the dynamically launched operating system, or Dynamic OS, which uses the resettable PCRs (17-22). In this case, there is a need to differentiate cycles originating from the two operating systems. Localities 1-3 are used by the Dynamic OS for its transactions. The Dynamic OS has created certain values in the resettable PCRs. Only the Dynamic OS should be able to issue commands based on those PCRs. The Static OS uses Locality 0. The non-resettable PCRs (i.e., PCR[0-15]) are not part of the Dynamic OS’s domain, so Locality 0 transactions can freely use those PCRs, but must be prevented from resetting or extending PCRs used by the Dynamic OS (see Section 4.6.1 PCR Attributes for the PCR’s which are resettable by the Dynamic OS).
-->

PCR bank allocation. In other words, enable/disable PCR banks. Cold/Warm reset the TPM after executing the following command to see the effects:
<!-- TPM2_PCR_Allocate() takes effect at _TPM_Init(), not TPM2_Startup(). -->
```all
# enable only sha256 bank
$ tpm2_pcrallocate sha1:none+sha256:all+sha384:none
```

Read PCRs:
```all
$ tpm2_pcrread
```

Compute and show the hash value of a file without extending to PCR:
```all
$ echo "plaintext" > plain.txt
$ tpm2_pcrevent plain.txt
```

Extend a file to PCR:
```all
$ echo "plaintext" > plain.txt
$ tpm2_pcrevent 16 plain.txt
```

Extend a hash value to PCR:
```all
$ tpm2_pcrextend 16:sha256=beefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafe
```

Reset PCR index:
```all
$ tpm2_pcrreset 16
```

## Persistent Key

Make storage key persistent:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_evictcontrol -C o -c primary_sh.ctx 0x81000001
```

Make platform key persistent:
```all
$ tpm2_createprimary -C p -g sha256 -G ecc -c primary_ph.ctx
$ tpm2_evictcontrol -C p -c primary_ph.ctx 0x81800001
```

List persistent handles:
```all
$ tpm2_getcap handles-persistent
```

Access the persistent and non-persistent key:
```all
$ tpm2_readpublic -c 0x81000001
$ tpm2_readpublic -c primary_sh.ctx
```

Evict persistent handle:
```all
$ tpm2_evictcontrol -C o -c 0x81000001
$ tpm2_evictcontrol -C p -c 0x81800001
```

## PKCS #11

Please refer to [[7]](#7).

## Quote

A simple example:
```all
# create key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx -f pem -o rsakey.pem

# generate quote
$ PCR="sha256:0,1"
$ QUALIFICATION=`tpm2_getrandom 8 --hex`
$ tpm2_quote -g sha256 -c rsakey.ctx -q $QUALIFICATION -l $PCR -m quote.bin -s signature.bin -o pcrs.bin

# validate the quote
$ tpm2_checkquote -g sha256 -u rsakey.pem -q $QUALIFICATION -m quote.bin -s signature.bin -f pcrs.bin
```

Example using an event log:
<!--
eventlog syntax check TCG spec: PC Client Platform Firmware Profile, 10 Event Logging
and checkout https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_CEL_v1_r0p35_11july2021.pdf
-->
```all
# cold/warm reset the TPM to clear pcr index 0
# power cycle the TPM or press the reset button on the TPM board before executing the following command
$ tpm2_startup -c

# create key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx -f pem -o rsakey.pem

# make a copy of the sample event log
$ cp ~/tpm2-tools/test/integration/fixtures/event.bin ./event.bin

# read the event log
$ tpm2_eventlog event.bin

# extend the log EventNum 1 digest to the pcr
$ tpm2_pcrextend 0:sha256=660375b3c94d47f04e30912dd931b28532d313271d1ae1bdead0a1b8f1276ed1

# generate quote
$ PCR="sha256:0"
$ QUALIFICATION=`tpm2_getrandom 8 --hex`
$ tpm2_quote -g sha256 -c rsakey.ctx -q $QUALIFICATION -l $PCR -m quote.bin -s signature.bin -o pcrs.bin

# validate the quote
$ tpm2_checkquote -g sha256 -u rsakey.pem -q $QUALIFICATION -m quote.bin -s signature.bin -f pcrs.bin -e event.bin
```

Visit [[13]](#13) to find a remote attestation implementation using TPM quote.

## Read EK Certificate

This section only work on hardware TPM.

The issuing certificate authority (CA) and certificate revocation list (CRL) information of an EK certificate can be found in the EK certificate "X509v3 extensions" field.

Read RSA & ECC endorsement key certificates from NV:
```exclude
# RSA
$ tpm2_nvread 0x1c00002 -o rsa_ek.crt.der
$ openssl x509 -inform der -in rsa_ek.crt.der -text

# ECC
$ tpm2_nvread 0x1c0000a -o ecc_ek.crt.der
$ openssl x509 -inform der -in ecc_ek.crt.der -text
```

Read RSA & ECC endorsement key certificates using tpm2-tools:
```exclude
$ tpm2_getekcertificate -o rsa_ek.crt.der -o ecc_ek.crt.der
```

## Read Public

Print the public component of a key:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx
```

Output the name and the public key in PEM format:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx -n rsakey.name -f pem -o rsakey.pub.pem
```

Print the public component of an NV index:
```all
$ tpm2_nvdefine 0x01000000 -C o -s 32 -a "ownerwrite|ownerread"
$ tpm2_nvreadpublic 0x01000000
$ tpm2_nvundefine 0x01000000 -C o
```

Output the name of an NV index:
```all
$ tpm2_nvdefine 0x01000000 -C o -s 32 -a "ownerwrite|ownerread"
$ tpm2_nvreadpublic 0x01000000 | grep 'name' | sed 's/.* //' | xxd -p -r > nv_0x01000000.name
$ tpm2_nvundefine 0x01000000 -C o
```

## Seal

Seal data to a TPM:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx

$ echo "some message" > message

# seal
$ tpm2_create -C primary_sh.ctx -i message -u message.seal.pub -r message.seal.priv
$ tpm2_load -C primary_sh.ctx -u message.seal.pub -r message.seal.priv -c message.seal.ctx

# unseal
$ tpm2_unseal -c message.seal.ctx -o message.unseal
$ diff message message.unseal
```

<!-- to-do: TPM2_CreatePrimary can be used for sealing too, check if it is possible with tpm2-tools  -->

## Secure Key Transfer (Duplicate Key)

Examples showing here are in the following settings:
- Both sender and recipient resided on a same TPM. Alternatively, it is possible to have recipient on another TPM.
- Sender is a TPM. Alternatively, it is possible to have a non-TPM sender, check [[6]](#6) for detailed implementation guide.

### Without Credential Protection

\[Both\] Create duplication policy:
```all
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx -L policy.ctx TPM2_CC_Duplicate
$ tpm2_flushcontext session.ctx
```

\[Recipient\] Create a recipient's parent key:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -r recipient_parent.prv -u recipient_parent.pub -a "restricted|sensitivedataorigin|decrypt|userwithauth"
```

\[Sender\] Create an RSA key under the primary object:
```all
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -r rsakey.prv -u rsakey.pub -L policy.ctx -a "sensitivedataorigin|userwithauth|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -r rsakey.prv -u rsakey.pub -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx -o rsakey.pub
```

\[Sender\] Create duplication blob:
```all
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
$ tpm2_loadexternal -C o -u recipient_parent.pub -c recipient_parent.ctx
$ tpm2_duplicate -C recipient_parent.ctx -c rsakey.ctx -G null -p session:session.ctx -r dup.priv -s dup.seed
$ tpm2_flushcontext session.ctx
```

\[Recipient\] Import the blob (RSA key):
```all
$ tpm2_load -C primary_sh.ctx -u recipient_parent.pub -r recipient_parent.prv -c recipient_parent.ctx
$ tpm2_import -C recipient_parent.ctx -u rsakey.pub -r rsakey_imported.prv -i dup.priv -s dup.seed
$ tpm2_load -C recipient_parent.ctx -u rsakey.pub -r rsakey_imported.prv -c rsakey_imported.ctx
```

### With Credential Protection

\[Both\] Create duplication policy:
```all
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx -L policy.ctx TPM2_CC_Duplicate
$ tpm2_flushcontext session.ctx
```

\[Recipient\] Create EK:
```all
$ tpm2_createek -c 0x81010001 -G rsa -u ek.pub
```

\[Recipient\] Read recipient public component:
```all
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_readpublic -c primary_sh.ctx -o recipient_parent.pub -n recipient_parent.name
```

\[Sender\] Create a sender's parent key:
```all
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -r sender_parent.prv -u sender_parent.pub -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"
$ tpm2_load -C primary_sh.ctx -u sender_parent.pub -r sender_parent.prv -c sender_parent.ctx
```

\[Sender\] Create an RSA key under the parent key:
```all
$ tpm2_create -C sender_parent.ctx -g sha256 -G rsa -r rsakey.prv -u rsakey.pub -L policy.ctx -a "sensitivedataorigin|userwithauth|decrypt|sign"
$ tpm2_load -C sender_parent.ctx -r rsakey.prv -u rsakey.pub -c rsakey.ctx
$ tpm2_readpublic -c rsakey.ctx -o rsakey.pub
```

\[Sender\] Create an inner wrap key and protect it with EK credential. Usually, recipient should also provide EK certificate for verification purpose:
```all
$ dd if=/dev/urandom of=innerwrapkey.clear bs=1 count=16
$ tpm2_makecredential -e ek.pub -s innerwrapkey.clear -n $(xxd -ps -c 100 recipient_parent.name) -o innerwrapkey.cipher
```

\[Sender\] Create duplication blob:
```all
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
$ tpm2_loadexternal -C o -u recipient_parent.pub -c recipient_parent.ctx
$ tpm2_duplicate -C recipient_parent.ctx -c rsakey.ctx -G aes -i innerwrapkey.clear -p session:session.ctx -r dup.priv -s dup.seed
$ tpm2_flushcontext session.ctx
```

\[Recipient\] Recover the inner wrap key with EK credential:
```all
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c e
$ tpm2_activatecredential -c primary_sh.ctx -C 0x81010001 -i innerwrapkey.cipher -o innerwrapkey.decipher -P session:session.ctx
$ tpm2_flushcontext session.ctx
```

\[Recipient\] Import the blob (RSA key):
```all
$ tpm2_import -C primary_sh.ctx -u rsakey.pub -r rsakey_imported.prv -k innerwrapkey.decipher -i dup.priv -s dup.seed
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey_imported.prv -c rsakey_imported.ctx
```

Clean up:
```all
$ tpm2_clear -c p
```

## Self Test

Self test command causes the TPM to perform a test of its capabilities. `tpm2_selftest -f` (full test) TPM will test all functions. `tpm2_selftest` (simple test) TPM will test functions that require testing.

Incremental self test causes the TPM to perform a test of the selected algorithms. If the command contains an algorithm that has already been tested, it will not be tested again. `tpm2_incrementalselftest` will return a list of algorithms left to be tested. Provide a list of algorithms to the command to start a test, e.g., `tpm2_incrementalselftest rsa ecc` will test the RSA & ECC algorithms and return a list of algorithms left to be tested.

`tpm2_gettestresult` returns manufacturer-specific information regarding the results of a self-test and an indication of the test status.

Once a TPM has received TPM2_SelfTest() and before completion of all tests, the TPM will return TPM_RC_TESTING for any command that uses a function that requires a test.

## Session-based Authorization

### HMAC

<!-- When the session is an HMAC session, the HMAC sessionKey is derived from the authValue -->

Commands below should have the same effect as password authorization due to tpm2-tools implementation. It treats all password authorization as HMAC session-based authorization:
```all
# create a key safeguarded by the a password
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign" -p pass123
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# provide the password to access the key for signing use
$ tpm2_startauthsession --hmac-session -S session.ctx
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx+pass123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx
```

### Policy

Also known as enhanced authorization.

Enhanced authorization is a TPM capability that allows entity-creators or administrators to require specific tests or actions to be performed before an action can be completed. The specific policy is encapsulated in a value called an authPolicy that is associated with an entity. When an HMAC session is used for authorization, the authValue of the entity is used to determine if the authorization is valid. When a policy session is used for authorization, the authPolicy of the entity is used.

#### tpm2_policyauthorize

Allows for mutable policies by tethering to a signing authority. In this approach, authority can add new policy but unable to revoke old policy:
<!-- This is an immediate assertion. This assertion evaluation checks to see if the current policyDigest is authorized by a signing key. So the order of tpm2_policyauthorize matters. Only authority signed policies should appear before tpm2_policyauthorize assertion, other policies should appear after tpm2_policyauthorize. -->

```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create an authorize policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthorize -S session.ctx -L authorize.policy -n authority_key.name
$ tpm2_flushcontext session.ctx

# create a policy to restrict a key to signing use only
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign -L sign.policy
$ tpm2_flushcontext session.ctx

# authority sign the policy
$ openssl dgst -sha256 -sign authority_sk.pem -out sign_policy.signature sign.policy

# create a key safeguarded by the authorize policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L authorize.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign
$ tpm2_verifysignature -c authority_key.ctx -g sha256 -m sign.policy -s sign_policy.signature -t sign_policy.ticket -f rsassa
$ tpm2_policyauthorize -S session.ctx -i sign.policy -n authority_key.name -t sign_policy.ticket
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# create a new policy to restrict a key to decryption use only
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_RSA_Decrypt -L decrypt.policy
$ tpm2_flushcontext session.ctx

# authority sign the new policy
$ openssl dgst -sha256 -sign authority_sk.pem -out decrypt_policy.signature decrypt.policy

# encrypt some data
$ echo "some secret" > secret.clear
$ tpm2_rsaencrypt -c rsakey.ctx -o secret.cipher secret.clear

# satisfy the new policy to access the key for decryption use
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_RSA_Decrypt
$ tpm2_verifysignature -c authority_key.ctx -g sha256 -m decrypt.policy -s decrypt_policy.signature -t decrypt_policy.ticket -f rsassa
$ tpm2_policyauthorize -S session.ctx -i decrypt.policy -n authority_key.name -t decrypt_policy.ticket
$ tpm2_rsadecrypt -c rsakey.ctx -o secret.decipher secret.cipher -p session:session.ctx
$ diff secret.decipher secret.clear
$ tpm2_flushcontext session.ctx
```

#### tpm2_policyauthorizenv

Allows for mutable policies by referencing to a policy from an NV index. In other words, an object policy is stored in NV and it can be replaced any time, hence mutable policy:
<!-- This is an immediate assertion. This assertion evaluation checks to see if the current policyDigest is equivalent to the computed policy stored in NV. So the order of tpm2_policyauthorizenv matters. Only policies that associated with the policy value stored in NV should appear before tpm2_policyauthorizenv assertion, other policies should appear after tpm2_policyauthorizenv. -->

```all
# create NV to store policy
$ tpm2_nvdefine -C o -p pass123 -a "authread|authwrite" -s 34 0x1000000

# create a policy to restrict a key to signing use only
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign -L sign.policy
$ tpm2_flushcontext session.ctx

# store the policy in NV
$ echo "000b" | xxd -p -r | cat - sign.policy > policy.bin
$ tpm2_nvwrite -P pass123 0x1000000 -i policy.bin

# create the authorize NV policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthorizenv -S session.ctx -C 0x1000000 -P pass123 -L authorizenv.policy 0x1000000
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the authorize NV policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L authorizenv.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy both policy to access the key for signing use
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign
$ tpm2_policyauthorizenv -S session.ctx -C 0x1000000 -P pass123 0x1000000
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# create a new policy to restrict a key to decryption use only
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_RSA_Decrypt -L decrypt.policy
$ tpm2_flushcontext session.ctx

# replace the policy in NV
$ echo "000b" | xxd -p -r | cat - decrypt.policy > policy.bin
$ tpm2_nvwrite -P pass123 0x1000000 -i policy.bin

# encrypt some data
$ echo "some secret" > secret.clear
$ tpm2_rsaencrypt -c rsakey.ctx -o secret.cipher secret.clear

# satisfy the new policy to access the key for decryption use
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policycommandcode -S session.ctx TPM2_CC_RSA_Decrypt
$ tpm2_policyauthorizenv -S session.ctx -C 0x1000000 -P pass123 0x1000000
$ tpm2_rsadecrypt -c rsakey.ctx -o secret.decipher secret.cipher -p session:session.ctx
$ diff secret.decipher secret.clear
$ tpm2_flushcontext session.ctx
```

#### tpm2_policyauthvalue

Enables binding a policy to the authorization value of the authorized TPM object. Enables a policy that requires the object's authentication passphrase be provided. This is equivalent to authenticating using the object passphrase in HMAC, only this enforces it as a policy:

```all
# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthvalue -S session.ctx -L authvalue.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L authvalue.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign" -p pass123
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyauthvalue -S session.ctx
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx+pass123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx
```

#### tpm2_policycommandcode

Check policy command code `man tpm2_policycommandcode` for list of supported commands.

Restrict a key for signing use only:
```all
# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign -L sign.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L sign.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Sign
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx
```

#### tpm2_policycountertimer

Enables policy authorization by evaluating the comparison operation on the TPMS_CLOCK_INFO: reset count, restart count, time, clock, and clock safe flag.

One example is to restrict the usage of a key to only the first 2 minutes of TPM Clock:
```all
# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycountertimer -S session.ctx -L time.policy --ult clock=120000
$ tpm2_flushcontext session.ctx

# reset TPM clock
$ tpm2_clear -c p

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L time.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycountertimer -S session.ctx --ult clock=120000
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# set the clock to future time
$ tpm2_setclock 120000

# attempt to access the key for signing use
# tpm2_startauthsession --policy-session -S session.ctx
# tpm2_policycountertimer -S session.ctx --ult clock=120000
# tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx <---- expected to fail
# tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
# tpm2_flushcontext session.ctx
```

#### tpm2_policycphash

Couples a policy with command parameters of the command. Used in conjunction with tpm2_policyauthorize/tpm2_policyauthorizenv.

<!--
The policy needs tpm2_policyauthorize/tpm2_policyauthorizenv otherwise it turns into a chicken and egg problem. We know from the beginning, a policy has to be created first then it is set to an object. Finally, the policy protected object can be used to perform certain actions (e.g., sign, decrypt, ...). However, to create tpm2_policycphash you will need to generate cpHash and the cpHash recipe requires an object name. And that is exactly the chicken and egg problem, you cant create tpm2_policycphash without creating an object first; on the other hand, you cant create an object without creating a policy first. To break the deadlock, create an object with tpm2_policyauthorize/tpm2_policyauthorizenv. Now tpm2_policycphash can be associated with the object at a later stage.
-->
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create an authorize policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthorize -S session.ctx -L authorize.policy -n authority_key.name
$ tpm2_flushcontext session.ctx

# define a special purpose NV
# The authValue of this NV will be used to authorize pinCount reset
$ tpm2_nvdefine 0x01000001 -C o -a "authread|authwrite" -p pass123

# define an NV pinpass safeguarded by the authorize policy
$ tpm2_nvdefine 0x01000000 -C o -a "nt=pinpass|policywrite|authread|ownerwrite" -L authorize.policy

# initialize the NV
# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x05' > data
$ tpm2_nvwrite 0x01000000 -C o -i data

# obtain cphash (the command will calculate cphash without performing NV write)
# set the TPMS_NV_PIN_COUNTER_PARAMETERS structure (pinCount=0|pinLimit=5)
$ tpm2_nvwrite 0x01000000 -C 0x01000000 -i data --cphash cp.hash

# create cphash policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycphash -S session.ctx -L cphash.policy --cphash cp.hash             <----- restrict tpm2_nvwrite command parameters and handles
$ tpm2_policysecret -S session.ctx -L cphash+secret.policy -c 0x01000001 pass123 <----- use authvalue of another entity to authorize reset of pinCount
$ tpm2_flushcontext session.ctx

# authority sign the policy
$ openssl dgst -sha256 -sign authority_sk.pem -out cphash+secret_policy.signature cphash+secret.policy

# utilize NV authvalue to increase pinCount
$ tpm2_nvread 0x01000000 -C 0x01000000 | xxd -p    <----- notice pinCount increases by 1
$ tpm2_nvread 0x01000000 -C 0x01000000 | xxd -p
$ tpm2_nvread 0x01000000 -C 0x01000000 | xxd -p

# satisfy the policy and perform nvwrite to reset the pinCount
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policycphash -S session.ctx --cphash cp.hash
$ tpm2_policysecret -S session.ctx -c 0x01000001 pass123
$ tpm2_verifysignature -c authority_key.ctx -g sha256 -m cphash+secret.policy -s cphash+secret_policy.signature -t cphash+secret_policy.ticket -f rsassa
$ tpm2_policyauthorize -S session.ctx -i cphash+secret.policy -n authority_key.name -t cphash+secret_policy.ticket
$ tpm2_nvwrite 0x01000000 -C 0x01000000 -i data -P session:session.ctx
$ tpm2_flushcontext session.ctx

# utilize NV authvalue to increase pinCount
$ tpm2_nvread 0x01000000 -C 0x01000000 | xxd -p    <----- notice pinCount back to 1

$ tpm2_nvundefine 0x01000000 -C o
$ tpm2_nvundefine 0x01000001 -C o
```

#### tpm2_policyduplicationselect

Restricts duplication to a specific new parent.

<!--
If duplication is allowed, authorization must always be provided by a policy session and the authPolicy equation of the object must contain a command that sets the policy command code to TPM_CC_Duplicate. tpm2_policyduplicationselect/tpm2_policycommandcode(TPM_CC_Duplicate) both will set policy command code to TPM_CC_Duplicate. There is no need to have both policies involve in a single operation.
-->

Not used in conjunction with tpm2_policyauthorize/tpm2_policyauthorizenv. Policy specifies only the new parent but not the duplication object:
```all
# create a source (old) parent and destination (new) parent
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh_scr.ctx
$ tpm2_createprimary -C n -g sha256 -G ecc -c primary_sh_dest.ctx

# create a duplication policy
$ tpm2_readpublic -c primary_sh_dest.ctx -n primary_sh_dest.name
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyduplicationselect -S session.ctx -N primary_sh_dest.name -L duplicate.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_create -C primary_sh_scr.ctx -g sha256 -G ecc -u eckey.pub -r eckey.priv -L duplicate.policy -a "sensitivedataorigin|userwithauth|sign"
$ tpm2_load -C primary_sh_scr.ctx -u eckey.pub -r eckey.priv -n eckey.name -c eckey.ctx

# satisfy the policy and duplicate the key
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyduplicationselect -S session.ctx -N primary_sh_dest.name -n eckey.name
$ tpm2_duplicate -C primary_sh_dest.ctx -c eckey.ctx -G null -p session:session.ctx -r eckey_dup.priv -s eckey_dup.seed
$ tpm2_flushcontext session.ctx

# import the key to the destination parent
$ tpm2_import -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -i eckey_dup.priv -s eckey_dup.seed
$ tpm2_load -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -c eckey_imported.ctx
```

Used in conjunction with tpm2_policyauthorize/tpm2_policyauthorizenv. Policy specifies the new parent and duplication object. This is to prevent other objects with PolicyAuthorize (with same authority) from being allowed to perform duplication:
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create an authorize policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthorize -S session.ctx -L authorize.policy -n authority_key.name
$ tpm2_flushcontext session.ctx

# create a source (old) parent and destination (new) parent
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh_scr.ctx
$ tpm2_createprimary -C n -g sha256 -G ecc -c primary_sh_dest.ctx

# create a key safeguarded by the authorize policy
$ tpm2_create -C primary_sh_scr.ctx -G ecc -u eckey.pub -r eckey.priv -L authorize.policy -a "sensitivedataorigin|userwithauth|sign"
$ tpm2_load -C primary_sh_scr.ctx -u eckey.pub -r eckey.priv -n eckey.name -c eckey.ctx

# create a duplication policy
$ tpm2_readpublic -c primary_sh_dest.ctx -n primary_sh_dest.name
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyduplicationselect -S session.ctx -N primary_sh_dest.name -n eckey.name -L duplicate.policy
$ tpm2_flushcontext session.ctx

# authority sign the duplication policy
$ openssl dgst -sha256 -sign authority_sk.pem -out duplicate_policy.signature duplicate.policy

# satisfy the policy and duplicate the key
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyduplicationselect -S session.ctx -N primary_sh_dest.name -n eckey.name
$ tpm2_verifysignature -c authority_key.ctx -g sha256 -m duplicate.policy -s duplicate_policy.signature -t duplicate_policy.ticket -f rsassa
$ tpm2_policyauthorize -S session.ctx -i duplicate.policy -n authority_key.name -t duplicate_policy.ticket
$ tpm2_duplicate -C primary_sh_dest.ctx -c eckey.ctx -G null -p session:session.ctx -r eckey_dup.priv -s eckey_dup.seed
$ tpm2_flushcontext session.ctx

# import the key to the destination parent
$ tpm2_import -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -i eckey_dup.priv -s eckey_dup.seed
$ tpm2_load -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -c eckey_imported.ctx
```

#### tpm2_policylocality

<!--
Linux kernel operates only on locality 0 (Static OS), there is no function to change locality, so you are able to access non-resettable PCRs (0-15) and of course the free to use PCRs (PCR 16 and PCR 23)

Statement below is taken from TCG spec PC Client

Locality Uses:
Usage of Locality 0 PCRs is determined by the TCG PC Client Specific Implementation Specification. Usage of Locality 1-3 PCRs is reserved for uses which are outside the purview of this specification. The idea behind locality is that certain combinations of Software and hardware are allowed more privileges than other combinations. For instance, the highest level of locality might be cycles that only hardware could create.
While higher localities may exist, Locality 4 is the highest locality level defined. These cycles are generated by hardware in support of the D-RTM. Cycles which require Locality 4 would include things such as the HASH_START/_DATA/_END interface commands. As an example, assume a platform, including Software, has an operating system based on the Static RTM or Static OS, based on either using no PCRs or the set of non-resettable PCRs (0-15), and trusted Software, the dynamically launched operating system, or Dynamic OS, which uses the resettable PCRs (17-22). In this case, there is a need to differentiate cycles originating from the two operating systems. Localities 1-3 are used by the Dynamic OS for its transactions. The Dynamic OS has created certain values in the resettable PCRs. Only the Dynamic OS should be able to issue commands based on those PCRs. The Static OS uses Locality 0. The non-resettable PCRs (i.e., PCR[0-15]) are not part of the Dynamic OS’s domain, so Locality 0 transactions can freely use those PCRs, but must be prevented from resetting or extending PCRs used by the Dynamic OS (see Section 4.6.1 PCR Attributes for the PCR’s which are resettable by the Dynamic OS).
-->

Restrict TPM object authorization to specific localities. Changing locality of TPM varies on different platforms. Linux driver doesn't expose a mechanism for user space applications to set locality for the moment ([[11]](#11)). The default locality used in Linux for user space applications is zero.

<!-- to-do: check if this is fixed in latest version -->
**Warning:** Apply the fix ([[12]](#12)) to pass the example using tpm2-tools version 5.2.

```all
# create a locality policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policylocality -S session.ctx -L locality.policy zero
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the locality policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L locality.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy policy to access the key for signing use
# tpm2_startauthsession -S session.ctx --policy-session
# tpm2_policylocality -S session.ctx zero
# tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
# tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
# tpm2_flushcontext session.ctx
```

#### tpm2_policynamehash

Couples a policy with names of specific objects. Names of all object handles in a TPM command is checked against the one specified in the policy. Used in conjunction with tpm2_policyauthorize/tpm2_policyauthorizenv.

This command allows a policy to be bound to a specific set of TPM entities without being bound to the parameters of the command. This is most useful for commands such as TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a policy.

Example, to authorize key duplication:
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create an authorize + commandcode policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthorize -S session.ctx -n authority_key.name
$ tpm2_policycommandcode -S session.ctx -L authorize+cc.policy TPM2_CC_Duplicate
$ tpm2_flushcontext session.ctx

# create a source (old) parent and destination (new) parent
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh_scr.ctx
$ tpm2_createprimary -C n -g sha256 -G ecc -c primary_sh_dest.ctx

# create a key safeguarded by the authorize policy
$ tpm2_create -C primary_sh_scr.ctx -G ecc -u eckey.pub -r eckey.priv -L authorize+cc.policy -a "sensitivedataorigin|userwithauth|sign"
$ tpm2_load -C primary_sh_scr.ctx -u eckey.pub -r eckey.priv -n eckey.name -c eckey.ctx

# create a namehash policy
$ tpm2_readpublic -c primary_sh_dest.ctx -n primary_sh_dest.name
$ cat eckey.name primary_sh_dest.name | openssl dgst -sha256 -binary > name.hash
$ tpm2_startauthsession -S session.ctx
$ tpm2_policynamehash -S session.ctx -n name.hash -L namehash.policy
$ tpm2_flushcontext session.ctx

# authority sign the namehash policy
$ openssl dgst -sha256 -sign authority_sk.pem -out namehash_policy.signature namehash.policy

# satisfy the policy and duplicate the key
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policynamehash -S session.ctx -n name.hash
$ tpm2_verifysignature -c authority_key.ctx -g sha256 -m namehash.policy -s namehash_policy.signature -t namehash_policy.ticket -f rsassa
$ tpm2_policyauthorize -S session.ctx -i namehash.policy -n authority_key.name -t namehash_policy.ticket
$ tpm2_policycommandcode -S session.ctx TPM2_CC_Duplicate
$ tpm2_duplicate -C primary_sh_dest.ctx -c eckey.ctx -G null -p session:session.ctx -r eckey_dup.priv -s eckey_dup.seed
$ tpm2_flushcontext session.ctx

# import the key to the destination parent
$ tpm2_import -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -i eckey_dup.priv -s eckey_dup.seed
$ tpm2_load -C primary_sh_dest.ctx -u eckey.pub -r eckey_imported.priv -c eckey_imported.ctx
```

<!-- to-do: need better examples, how is it different from tpm2_policyduplicationselect? -->

<!--
TPM_CC_PCR_SetAuthPolicy not supported so skip this.

Example, pcrevent:
```all
```
-->

#### tpm2_policynv

Evaluates policy authorization by comparing a specified value against the contents in the specified NV Index. The comparison operator can be specified as follows:
- "eq" if operandA = operandB
- "neq" if operandA != operandB
- "sgt" if signed operandA > signed operandB
- "ugt" if unsigned operandA > unsigned operandB
- "slt" if signed operandA < signed operandB
- "ult" if unsigned operandA < unsigned operandB
- "sge" if signed operandA >= signed operandB
- "uge" if unsigned operandA >= unsigned operandB
- "sle" if signed operandA <= unsigned operandB
- "ule" if unsigned operandA <= unsigned operandB
- "bs" if all bits set in operandA are set in operandB
- "bc" if all bits set in operandA are clear in operandB

<!-- It is an immediate assertion. The name of NV index is taken into the policy calculation, so the NV has to be initialized before trial policy session. -->

Example using "eq":
```all
# define a special purpose NV
# The value of this NV will be used for authorization
$ tpm2_nvdefine 0x01000000 -C o -a "authread|authwrite" -s 1 -p pass123

# initialize the NV before creating the policy
$ echo -n -e '\x00' > init.bin
$ tpm2_nvwrite 0x01000000 -C 0x01000000 -P pass123 -i init.bin

# create policynv. The policy checks if the NV value is equivalent to expected.bin
$ echo -n -e '\x55' > expected.bin
$ tpm2_startauthsession -S session.ctx
$ tpm2_policynv -S session.ctx 0x01000000 eq -i expected.bin -P pass123 -L nv.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L nv.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

# write the expected data into NV
$ echo -n -e '\x55' > data.bin
$ tpm2_nvwrite 0x01000000 -C 0x01000000 -P pass123 -i data.bin

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policynv -S session.ctx 0x01000000 eq -i expected.bin -P pass123
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

#### tpm2_policynvwritten

Restrict TPM object authorization to the written state (TPMA_NV_WRITTEN attribute) of an NV index.

Example, create a one time programmable NV:
```all
# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policycommandcode -S session.ctx TPM2_CC_NV_Write
$ tpm2_policynvwritten -S session.ctx -L cc+nvwritten.policy c
$ tpm2_flushcontext session.ctx

# define an NV safeguarded by the policy
$ tpm2_nvdefine -C o 0x01000000 -s 1 -a "authread|policywrite" -L cc+nvwritten.policy

# satisfy the policy and write the NV
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policycommandcode -S session.ctx TPM2_CC_NV_Write
$ tpm2_policynvwritten -S session.ctx c
$ echo 0xAA | xxd -r -p | tpm2_nvwrite 0x01000000 -i - -P session:session.ctx
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

#### tpm2_policyor

Logically OR's two policies together.

```all
# define a special purpose NV
# The authValue of this NV will be used on another entity
$ tpm2_nvdefine 0x01000000 -C o -a "authread|authwrite" -s 1 -p admin123

# create a secret policy to use authValue of another entity
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x01000000 -L secret.policy admin123
$ tpm2_flushcontext session.ctx

# create an authvalue policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyauthvalue -S session.ctx -L authvalue.policy
$ tpm2_flushcontext session.ctx

# compound the two policies in an OR fashion
$ tpm2_startauthsession -S session.ctx
$ tpm2_policyor -S session.ctx -L secret+or+authvalue.policy sha256:secret.policy,authvalue.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -p user123 -L secret+or+authvalue.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

# satisfy just the secret policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysecret -S session.ctx -c 0x01000000 admin123
$ tpm2_policyor -S session.ctx sha256:secret.policy,authvalue.policy
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# satisfy just the authvalue policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyauthvalue -S session.ctx
$ tpm2_policyor -S session.ctx sha256:secret.policy,authvalue.policy
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx+user123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

#### tpm2_policypassword

Enables binding a policy to the authorization value of the authorized TPM object. Enables a policy that requires the object's authentication passphrase be provided. This is equivalent to authenticating using the object passphrase in plaintext, only this enforces it as a policy.

```all
# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policypassword -S session.ctx -L authvalue.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L authvalue.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign" -p pass123
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policypassword -S session.ctx
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx+pass123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx
```

#### tpm2_policypcr

Create a policy that includes specific PCR values.

```all
# check if sha256 bank of pcr is enabled
# if it is not, enable it using tpm2_pcrallocate
$ tpm2_pcrread

# create the pcr policy
$ tpm2_pcrread "sha256:0,1,2,3,16" -o pcr.bin
$ tpm2_startauthsession -S session.ctx
$ tpm2_policypcr -S session.ctx -l "sha256:0,1,2,3,16" -f pcr.bin -L pcr.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L pcr.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policypcr -S session.ctx -l "sha256:0,1,2,3,16" -f pcr.bin
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx+pass123
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# change the value of pcr
$ tpm2_pcrextend 16:sha256=beefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafe

# attempt to satisfy the policy, expected to fail
# tpm2_startauthsession -S session.ctx --policy-session
# tpm2_policypcr -S session.ctx -l "sha256:0,1,2,3,16" -f pcr.bin
# tpm2_flushcontext session.ctx

$ tpm2_pcrreset 16
```

#### tpm2_policyrestart

This is not a policy. This command is used to reset the policy data without changing the nonce (nonceTPM/nonceCaller) or the start time of a session.

<!-- TCG spec part4: 8.9.6.8 SessionResetPolicyData() -->

You may restart the existing session:
```all
$ tpm2_startauthsession --policy-session -S session.ctx
# tpm2_policy...
# tpm2_...
$ tpm2_policyrestart -S session.ctx
# tpm2_policy...
# tpm2_...
$ tpm2_policyrestart -S session.ctx
# tpm2_policy...
# tpm2_...
$ tpm2_flushcontext session.ctx
```

#### tpm2_policysecret

Couples the authorization of an object to that of an existing object.

<!--
contain a special feature where you can set/get policy expiration time.
-->
A simple example:
```all
# define a special purpose NV
# The authValue of this NV will be used on another entity
$ tpm2_nvdefine 0x01000000 -C o -a "authread|authwrite" -s 1 -p admin123

# create a secret policy to use authValue of another entity
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x01000000 -L secret.policy admin123
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L secret.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysecret -S session.ctx -c 0x01000000 admin123
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

#### tpm2_policysigned

Enables policy authorization by verifying signature of optional TPM2 parameters. The authorizing entity will sign a digest of the authorization qualifiers:
- nonceTPM: the nonceTPM parameter from the TPM2_StartAuthSession() response. If the authorization is not limited to this session, the size of this value is zero.
- expiration: time limit on authorization set by authorizing object. This 32-bit value is set to zero if the expiration time is not being set.
- cpHashA: digest of the command parameters for the command being approved using the hash algorithm of the policy session. Set to an Empty Digest if the authorization is not limited to a specific command.
- policyRef: an opaque value determined by the authorizing entity. Set to the Empty Buffer if no value is present.

Example with all qualifiers set to zero/empty buffer, a not so useful example:
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# manually construct the authorization qualifiers
# just zeros if there are no restrictions
$ echo "00 00 00 00" | xxd -r -p > qualifiers.bin

# use tool to construct the authorization qualifiers
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx --raw-data qualifiers.out.bin
$ tpm2_flushcontext session.ctx
$ diff qualifiers.bin qualifiers.out.bin

# authority sign the digest of the authorization qualifiers
$ openssl dgst -sha256 -sign authority_sk.pem -out qualifiers.signature qualifiers.bin

# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx -L signed.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L signed.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx
```

Example with only expiration set. The expiration is based on TPM time:
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# get current time in milliseconds
$ CURRENT_TIME=`tpm2_readclock | grep 'time' | sed 's/.* //'`

# set expiration after 60 seconds
$ EXPIRE=$(($CURRENT_TIME/1000 + 60))

# use tool to construct the authorization qualifiers
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx -t $EXPIRE --raw-data qualifiers.bin
$ tpm2_flushcontext session.ctx

# authority sign the digest of the authorization qualifiers
$ openssl dgst -sha256 -sign authority_sk.pem -out qualifiers.signature qualifiers.bin

# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx -L signed.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L signed.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# after 60 seconds, authorization will fail with error TPM_RC_EXPIRED
# tpm2_startauthsession -S session.ctx --policy-session
# tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE
# tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
# tpm2_flushcontext session.ctx
```

Example with both nonceTPM and expiration set. The expiration is measured from the time that nonceTPM is generated:
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx -L signed.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L signed.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

# start an auth session and keep it alive
$ tpm2_startauthsession -S session.ctx --policy-session

# set expiration after 60 seconds
$ EXPIRE=60

# use tool to construct the authorization qualifiers (nonceTPM + expiration)
$ tpm2_policysigned -S session.ctx -g sha256 -f rsassa -c authority_key.ctx -t $EXPIRE -x --raw-data qualifiers.bin

# authority sign the digest of the authorization qualifiers
$ openssl dgst -sha256 -sign authority_sk.pem -out qualifiers.signature qualifiers.bin

$ echo "plaintext" > plain.txt

# satisfy the policy and use the key for signing
# after 60 seconds from the time session is created (tpm2_startauthsession), authorization will fail with error TPM_RC_EXPIRED
$ tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE -x
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature

# restart the session, clear policy hash
$ tpm2_policyrestart -S session.ctx

# error TPM_RC_SIGNATURE (0x5DB) is expected due to nonceTPM change. Each time the session is used for authorization, nonceTPM will change
# and tpm2_policyrestart does not reset nonce
# tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE -x

# set expiration after 120 seconds
$ EXPIRE=120

# use tool to construct the authorization qualifiers (nonceTPM + expiration)
$ tpm2_policysigned -S session.ctx -g sha256 -f rsassa -c authority_key.ctx -t $EXPIRE -x --raw-data qualifiers.bin

# authority sign the digest of the authorization qualifiers
$ openssl dgst -sha256 -sign authority_sk.pem -out qualifiers.signature qualifiers.bin

# restart the session, clear policy hash
$ tpm2_policyrestart -S session.ctx

# satisfy the policy and use the key for signing
# after 120 seconds from the time session is created (tpm2_startauthsession), authorization will fail with error TPM_RC_EXPIRED
$ tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE -x
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature

$ tpm2_flushcontext session.ctx
```

<!-- to-do: need examples for other qualifiers... -->

#### tpm2_policytemplate

Couples a policy with public template of an object.

```all
# get the primary key template hash
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx --template-data primary_sh.template
$ openssl dgst -sha256 -binary -out primary_sh.template.hash primary_sh.template

# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policytemplate -S session.ctx --template-hash primary_sh.template.hash -L template.policy
$ tpm2_flushcontext session.ctx

# set storage hierarchy policy
$ tpm2_setprimarypolicy -C o -g sha256 -L template.policy

# set storage hierarchy authValue
$ tpm2_changeauth -c o ownerpswd

# satisfy the policy and create primary key
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policytemplate -S session.ctx --template-hash primary_sh.template.hash
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx -P session:session.ctx
$ tpm2_flushcontext session.ctx

$ tpm2_clear -c p
```

#### tpm2_policyticket

This command is similar to tpm2_policysigned except that it takes a ticket instead of a signed authorization. The ticket represents a validated authorization that had an expiration time associated with it. The ticket is generated by tpm2_policysigned or tpm2_policysecret.
<!-- Both TPM2_PolicySigned() and TPM2_PolicySecret() can produce tickets that enable authorizations to be used over a period of time and in different policy sessions. -->
<!-- a ticket cannot be shared by both TPM2_PolicySigned and TPM2_PolicySecret, because ticket contains the value TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET -->
<!-- TPM2_PolicySigned uses an authority generated signature for verification, TPM2_PolicySecret uses an authority's authValue for verification -->

Example using tpm2_policysigned's ticket with only expiration set. The expiration is based on TPM time:
<!-- to-do: what is the advantage of using tpm2_policyticket instead of tpm2_policysigned here??-->
```all
# create a signing authority
$ openssl genrsa -out authority_sk.pem 2048
$ openssl rsa -in authority_sk.pem -out authority_pk.pem -pubout
$ tpm2_loadexternal -C o -G rsa -u authority_pk.pem -c authority_key.ctx -n authority_key.name

# create the policy
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -c authority_key.ctx -L signed.policy
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L signed.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

# get current time in milliseconds
$ CURRENT_TIME=`tpm2_readclock | grep 'time' | sed 's/.* //'`

# set expiration after 60 seconds
# make the value negative, this is mandatory for ticket creation
$ EXPIRE=-$(($CURRENT_TIME/1000 + 60))

# use tool to construct the authorization qualifiers
$ tpm2_startauthsession -S session.ctx
$ tpm2_policysigned -S session.ctx -g sha256 -f rsassa -c authority_key.ctx -t $EXPIRE --raw-data qualifiers.bin
$ tpm2_flushcontext session.ctx

# authority sign the digest of the authorization qualifiers
$ openssl dgst -sha256 -sign authority_sk.pem -out qualifiers.signature qualifiers.bin

# get a ticket from the TPM
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysigned -S session.ctx -g sha256 -s qualifiers.signature -f rsassa -c authority_key.ctx -t $EXPIRE --ticket ticket.bin --timeout timeout.bin
$ tpm2_flushcontext session.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy using the ticket and use the key for signing
# after 60 seconds, authorization will fail with error TPM_RC_EXPIRED
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyticket -S session.ctx -n authority_key.name --ticket ticket.bin --timeout timeout.bin
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_flushcontext session.ctx
```

Example using tpm2_policysecret's ticket with only expiration set. The expiration is based on TPM time:
<!-- the advantage of using ticket for authorization here is, no need to reveal the NV authValue to user. You can have a designated authority to issue time-bound ticket to users. -->
```all
# define a special purpose NV
# The authValue of this NV will be used on another entity
$ tpm2_nvdefine 0x01000000 -C o -a "authread|authwrite" -s 1 -p admin123
$ tpm2_nvreadpublic 0x01000000 | grep 'name' | sed 's/.* //' | xxd -p -r > authority.name

# get current time in milliseconds
$ CURRENT_TIME=`tpm2_readclock | grep 'time' | sed 's/.* //'`

# set expiration after 60 seconds
$ EXPIRE=-$(($CURRENT_TIME/1000 + 60))

# create a secret policy to use authValue of another entity
# meanwhile, create a ticket
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysecret -S session.ctx -c 0x01000000 -t $EXPIRE --ticket ticket.bin --timeout timeout.bin -L secret.policy admin123
$ tpm2_flushcontext session.ctx

# create a key safeguarded by the policy
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx --template-data primary_sh.template
$ tpm2_create -C primary_sh.ctx -G rsa -u rsakey.pub -r rsakey.priv -L secret.policy -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -n rsakey.name -c rsakey.ctx

$ echo "plaintext" > plain.txt

# satisfy the policy using the ticket and use the key for signing
# after 60 seconds, authorization will fail with error TPM_RC_EXPIRED
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policyticket -S session.ctx -n authority.name --ticket ticket.bin --timeout timeout.bin
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

# satisfy the policy using the NV authValue and use the key for signing
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policysecret -S session.ctx -c 0x01000000 admin123
$ tpm2_sign -c rsakey.ctx -o signature plain.txt -p session:session.ctx
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m plain.txt -s signature
$ tpm2_flushcontext session.ctx

$ tpm2_nvundefine 0x01000000 -C o
```

## Set Hierarchy Auth Value

Set storage hierarchy auth:
```all
$ tpm2_changeauth -c o ownerpswd
```

Set endorsement hierarchy auth:
```all
$ tpm2_changeauth -c e endorsementpswd
```

Set platform hierarchy auth:
```exclude
$ tpm2_changeauth -c p platformpswd
```

Set lockout auth:
```all
$ tpm2_changeauth -c l lockoutpswd
```

Platform authvalue is not persistent, after a TPM reset, it will be set to empty auth.

Check auth set information:
```all
$ tpm2_getcap properties-variable
```

Storage, endorsement, and lockout auth can be cleared by:
```all
$ tpm2_clear -c p
```

Platform auth can be cleared by cold/warm reset.

## Set Hierarchy Policy

Sets the authorization policy for the lockout, the platform hierarchy, the storage hierarchy, and the endorsement hierarchy using the command `tpm2_setprimarypolicy`.

## Signing & Verification

Using RSA key:
```all
# create RSA key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G rsa -u rsakey.pub -r rsakey.priv
$ tpm2_load -C primary_sh.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx

$ echo "some message" > message
$ tpm2_sign -c rsakey.ctx -g sha256 -o signature message
$ tpm2_verifysignature -c rsakey.ctx -g sha256 -m message -s signature

# or use OpenSSL to verify signature

$ echo "some message" > message
$ tpm2_sign -c rsakey.ctx -g sha256 -f plain -o signature message
$ tpm2_readpublic -c rsakey.ctx -o public.pem -f pem
$ openssl dgst -sha256 -verify public.pem -keyform pem -signature signature message
```

Using ECC key:
```all
# create ECC key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -g sha256 -G ecc -u eckey.pub -r eckey.priv
$ tpm2_load -C primary_sh.ctx -u eckey.pub -r eckey.priv -c eckey.ctx

$ echo "some message" > message
$ tpm2_sign -c eckey.ctx -g sha256 -o signature message
$ tpm2_verifysignature -c eckey.ctx -g sha256 -m message -s signature

# or use OpenSSL to verify signature

$ echo "some message" > message
$ tpm2_sign -c eckey.ctx -g sha256 -f plain -o signature message
$ tpm2_readpublic -c eckey.ctx -o public.pem -f pem
$ openssl dgst -sha256 -verify public.pem -keyform pem -signature signature message
```

Keyed-hash (HMAC):
```all
# create HMAC key
$ tpm2_createprimary -C o -g sha256 -G ecc -c primary_sh.ctx
$ tpm2_create -C primary_sh.ctx -G hmac -c hmackey.ctx

$ echo "some message" > message
$ tpm2_hmac -c hmackey.ctx --hex message
```

## Startup

Type of startup and shutdown operations:

- `tpm2_startup -c` to perform Startup(TPM_SU_CLEAR)
- `tpm2_startup` to perform Startup(TPM_SU_STATE), this requires a preceding Shutdown(TPM_SU_STATE)
- `tpm2_shutdown -c` to perform Shutdown(TPM_SU_CLEAR)
- `tpm2_shutdown` to perform Shutdown(TPM_SU_STATE)

3 methods of preparing a TPM for operation:

1. TPM Reset: Startup(TPM_SU_CLEAR) that follows a Shutdown(TPM_SU_CLEAR), or Startup(TPM_SU_CLEAR) for which there was no preceding Shutdown() (a disorderly shutdown). A TPM reset is roughly analogous to a **reboot** of a platform.
    ```exclude
    $ tpm2_shutdown -c
    < cold/warm reset >
    $ tpm2_startup -c
    ```
2. TPM Restart: Startup(TPM_SU_CLEAR) that follows a Shutdown(TPM_SU_STATE). This indicates a system that is restoring the OS from non-volatile storage, sometimes called **"hibernation"**. For a TPM restart, the TPM restores values saved by the preceding Shutdown(TPM_SU_STATE) except that all the PCR are set to their default initial state.
    ```exclude
    $ tpm2_shutdown
    < cold/warm reset >
    $ tpm2_startup -c
    ```
3. TPM Resume: Startup(TPM_SU_STATE) that follows a Shutdown(TPM_SU_STATE). This indicates a system that is restarting the OS from RAM memory, sometimes called **"sleep"**. TPM Resume restores all of the state that was saved by Shutdown(STATE), including those PCR that are designated as being preserved by Startup(STATE). PCR not designated as being preserved, are reset to their default initial state.
    ```exclude
    $ tpm2_shutdown
    < cold/warm reset >
    $ tpm2_startup
    ```

*Remarks:*
- *Cold reset means power on reset*
- *Warm reset means using the TPM RST signal (reset pin) to trigger a reset without losing power*

## TPM Clear

Perform TPM clear using platform or lockout hierarchy:
```all
$ tpm2_clear -c p
$ tpm2_clear -c l
```

TPM clear highlights:
- Flush any transient or persistent objects associated with the storage or endorsement hierarchies
- Release any NV index locations that do not have their `platformcreate` attribute SET
- Set shEnable, ehEnable, phEnable to TRUE
- Set ownerAuth, endorsementAuth, and lockoutAuth to an empty auth
- Set ownerPolicy, endorsementPolicy, and lockoutPolicy to an empty policy
- Change the storage primary seed (SPS) to a new value from the TPM's random number generator

To change the platform primary seed (PPS) to a new value from the TPM's random number generator:
```exclude
$ tpm2_changepps
```

To change the endorsement primary seed (EPS) to a new value from the TPM's random number generator. **This action will change the EK thus the EK certificate will also become unusable.**:
```exclude
$ tpm2_changeeps
```

## Vendor

This section only applicable to SPI-based TPM firmware version 16.00 and above, and I2C-based TPM firmware version 26.00 and above.

Use command TPM_CC_GetCapability to read vendor specific capabilities (below contains default responses from TPM):
```exclude
# TPM_PT_VENDOR_VAR_ENCRYPTDECRYPT2
$ echo 8001000000160000017a00000100c000000500000001 | xxd -r -p | tpm2_send | xxd -p
80010000001900000000000000010000000001000400010000
                                      ^TPM2B_DATA.size = 4
                                                 .buffer[0:1] = Indicates whether configuration is enabled (0x0001) / disabled (0x0000)
                                                        [2:3] = Indicates whether feature is permanently locked (0x0001)

# TPM_PT_VENDOR_VAR_CHANGEEPS
$ echo 8001000000160000017a00000100c000000600000001 | xxd -r -p | tpm2_send | xxd -p
80010000001900000000000000010000000001000400010000

# TPM_PT_VENDOR_VAR_TPMID_NV
$ echo 8001000000160000017a00000100c000000700000001 | xxd -r -p | tpm2_send | xxd -p
80010000001900000000000000010000000001000400010000
```

Install eltt2 [[17]](#17):
```all
$ git clone https://github.com/Infineon/eltt2 ~/eltt2
$ cd ~/eltt2
$ git checkout 3d55476179da9bd61c2df1ba1ef010afe27e7776
$ gcc eltt2.c -o eltt2
```

Set vendor capabilities with `eltt2` instead of `tpm2_send` because we are not using standard commands to set these capabilities. **Be warned, know what you are doing, there is no return after setting it to permanently locked state. Examples here only set the enable/disable flag.**
```exclude
$ cd ~/eltt2

# disable TPM_PT_VENDOR_VAR_ENCRYPTDECRYPT2
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000500000000
# enable TPM_PT_VENDOR_VAR_ENCRYPTDECRYPT2
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000500010000
# read TPM_PT_VENDOR_VAR_ENCRYPTDECRYPT2
$ ./eltt2 -b 8001000000160000017a00000100c000000500000001

# disable TPM_PT_VENDOR_VAR_CHANGEEPS
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000600000000
# enable TPM_PT_VENDOR_VAR_CHANGEEPS
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000600010000
# read TPM_PT_VENDOR_VAR_CHANGEEPS
$ ./eltt2 -b 8001000000160000017a00000100c000000600000001

# disable TPM_PT_VENDOR_VAR_TPMID_NV
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000700000000
# enable TPM_PT_VENDOR_VAR_TPMID_NV
$ ./eltt2 -b 800200000023200004004000000c00000009400000090000010000c000000700010000
# read TPM_PT_VENDOR_VAR_TPMID_NV
$ ./eltt2 -b 8001000000160000017a00000100c000000700000001
```

# Examples (FAPI)

TCG Software Stack 2.0 (TSS 2.0) Specification Structure:
- TCG TSS 2.0 Feature API (FAPI) Specification [[16]](#16)

## Provision

One-time provision:

1. Recommended change in `/usr/local/etc/tpm2-tss/fapi-config.json`:
    - Move all directories to user space, hence avoid access permission issues and `double free or corruption` regression
    - Profile can be `P_RSA2048SHA256` or `P_ECCP256SHA256`. You may use `P_ECCP256SHA256` for better performance. You may also update the `tcti` parameter to switch between hardware or simulated TPM. If you are using TPM simulator, is possible to set ek_cert_less:
    ```all
    {
        "profile_name": "P_RSA2048SHA256",
        "profile_dir": "/usr/local/etc/tpm2-tss/fapi-profiles/",
        "user_dir": "/tmp/tpm2-tss/user/keystore/",
        "system_dir": "/tmp/tpm2-tss/system/keystore/",
        "tcti": "tabrmd:bus_type=session",
        "ek_cert_less": "yes",
        "system_pcrs" : [],
        "log_dir" : "/tmp/tpm2-tss/eventlog/"
    }
    ```
    Let's automate the change:
    ```all,timeless
    $ rm /usr/local/etc/tpm2-tss/fapi-config.json
    $ cat > /usr/local/etc/tpm2-tss/fapi-config.json << EOF
    $ {
    $     "profile_name": "P_RSA2048SHA256",
    $     "profile_dir": "/usr/local/etc/tpm2-tss/fapi-profiles/",
    $     "user_dir": "/tmp/tpm2-tss/user/keystore/",
    $     "system_dir": "/tmp/tpm2-tss/system/keystore/",
    $     "tcti": "tabrmd:bus_type=session",
    $     "ek_cert_less": "yes",
    $     "system_pcrs" : [],
    $     "log_dir" : "/tmp/tpm2-tss/eventlog/"
    $ }
    $ EOF
    $ cat /usr/local/etc/tpm2-tss/fapi-config.json
    ```
2. Reset the FAPI database:
    ```all
    $ sudo rm -rf /home/pi/.local/share/tpm2-tss
    ```
3. Clear TPM:
    ```all
    $ tpm2_clear -c p
    ```
4. Provision TPM and initialize the metadata.<br>
   Storage Root Key (SRK) will be created based on the profile `profile_dir/profile_name` and made persistent at handle `0x81000001` (specified in the profile) with no authorization value. TPM metadata is stored in the directory `system_dir`.
    ```all
    $ tss2_provision
    ```

## Change Auth

```all
# create a key with authvalue
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a "pass123"

# change the authvalue
#$ yes "pass123" | tss2_changeauth -p /P_RSA2048SHA256/HS/SRK/LeafKey -a "321ssap"

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
```
<!--
A callback is registered using Fapi_SetAuthCB to allow the TSS to get authorization values from the application layer.
-->

## Create Key

```all
# create a key without authvalue
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey1 -t "decrypt,sign" -a ""

# create a key with authvalue
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey2 -t "decrypt,sign" -a "pass123"

# create a persistent key
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey3 -t "decrypt,sign,0x81000002" -a ""

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey1
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey2
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey3
```

Location of keys in metadata store:
```all
# user key: /home/pi/.local/share/tpm2-tss/user/keystore/P_RSA2048SHA256/HS/SRK/
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey1 -t "decrypt,sign" -a ""

# system key: /home/pi/.local/share/tpm2-tss/system/keystore/P_RSA2048SHA256/HS/SRK/
# system: Stores the data blobs and metadata for a created key or seal in the system-wide directory instead of user’s personal directory.
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey2 -t "system,decrypt,sign" -a ""

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey1
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey2
```

## Delete Key

```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
```

## Encryption & Decryption

For profile `P_RSA2048SHA256`:
```all
# create key
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# get the PEM encoded public key
$ tss2_getrandom -n 32 -f -o dummy
$ tss2_sign -p /P_RSA2048SHA256/HS/SRK/LeafKey -s "RSA_SSA" -d dummy -f -o dummy.sig -k key.pub.pem -c key.crt
$ openssl rsa -inform PEM -noout -text -in key.pub.pem -pubin

$ echo "some secret" > secret.clear

# use TPM for encryption
$ tss2_encrypt -p /P_RSA2048SHA256/HS/SRK/LeafKey -i secret.clear -o secret1.cipher

# use OpenSSL for encryption
$ openssl rsautl -encrypt -inkey key.pub.pem -in secret.clear -pubin -out secret2.cipher

# decryption
$ tss2_decrypt -p /P_RSA2048SHA256/HS/SRK/LeafKey -i secret1.cipher -o secret1.decipher
$ diff secret1.decipher secret.clear
$ tss2_decrypt -p /P_RSA2048SHA256/HS/SRK/LeafKey -i secret1.cipher -o secret2.decipher
$ diff secret2.decipher secret.clear

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm secret.clear secret1.* secret2.* dummy dummy.* key.*
```

## Get Info

Get TPM capabilities:
```all
$ tss2_getinfo -o -

# or

$ tss2_getinfo -o info.txt
```

## Get EK Certificate

```exclude
$ tss2_getcertificate -p /P_RSA2048SHA256/HE/EK -o ek.crt
$ openssl x509 -inform pem -in ek.crt -text
```

## Get Random

```all
$ tss2_getrandom -n 32 --hex -o -
$ tss2_getrandom -n 32 -f -o random.bin
$ rm random.bin
```

## Get TPM Blob

```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# get TPM2B_PUBLIC, TPM2B_PRIVATE, and policy
$ tss2_gettpmblobs -p /P_RSA2048SHA256/HS/SRK/LeafKey -f -u key.pub -r key.priv --policy key.policy

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm key.*
```

## Import

Use imported public key for signature verification:
```all
# create RSA key
$ openssl genrsa -out rsa.priv.pem 2048
$ openssl rsa -in rsa.priv.pem -pubout > rsa.pub.pem

# create a message
$ echo "some message" > message
$ openssl dgst -sha256 -binary -out message.digest message

# use OpenSSL for signing
$ openssl dgst -sha256 -sign rsa.priv.pem -out message.sig message

# import the public key
$ tss2_import -p /ext/RsaPubKey -i rsa.pub.pem

# use TPM for verification
$ tss2_verifysignature -p /ext/RsaPubKey -d message.digest -i message.sig

# clean up
$ tss2_delete -p /ext/RsaPubKey
$ rm rsa.* message message.*
```

<!--
to-do: check if following is possible

Use imported public key for encryption:
```exclude
# create RSA key
$ openssl genrsa -out rsa.priv.pem 2048
$ openssl rsa -in rsa.priv.pem -pubout > rsa.pub.pem

# create a message
$ echo "some secret" > secret.clear

# import the public key
$ tss2_import -p /ext/RsaPubKey -i rsa.pub.pem

# use TPM for encryption
$ tss2_encrypt -p /ext/RsaPubKey -i secret.clear -o secret.cipher
    ERROR:fapi:src/tss2-fapi/fapi_util.c:263:init_explicit_key_path() Hierarchy cannot be determined.
    ERROR:fapi:src/tss2-fapi/fapi_util.c:510:get_explicit_key_path() init_explicit_key_path ErrorCode (0x0006001d)
    ERROR:fapi:src/tss2-fapi/fapi_util.c:1555:ifapi_load_keys_async() Compute explicit path. ErrorCode (0x0006001d)
    ERROR:fapi:src/tss2-fapi/api/Fapi_Encrypt.c:290:Fapi_Encrypt_Finish() Load keys. ErrorCode (0x0006001d)
    ERROR:fapi:src/tss2-fapi/api/Fapi_Encrypt.c:126:Fapi_Encrypt() ErrorCode (0x0006001d) Data_Encrypt
    Fapi_Encrypt(0x6001D) - fapi:The provided path is bad

# clean up
$ tss2_delete -p /ext/RsaPubKey
$ rm rsa.* secret.*
```
-->

Import policy:
```all
# get a sample policy
$ cp ~/tpm2-tss/test/data/fapi/policy/pol_signed.json .

# import the policy
$ tss2_import -p /policy/pol_signed -i pol_signed.json

# clean up
$ tss2_delete -p /policy/pol_signed
```

## List Objects

Enumerates and show all objects in the FAPI metadata store:

```all
$ tss2_list
```

Immediately after `tss2_provision` you should see:
- `/P_RSA2048SHA256/HS`: Storage hierarchy
    - `/P_RSA2048SHA256/HS/SRK`: Storage root key (primary key)
- `/P_RSA2048SHA256/LOCKOUT`: Lockout hierarchy
- `/P_RSA2048SHA256/HE`: Endorsement hierarchy
    - `/P_RSA2048SHA256/HE/EK`: Endorsement key
- `/P_RSA2048SHA256/HN`: Null hierarchy

## PCR

<!--
The data file binary in hex is "736f6d6520646174610a". You will find it in the `pcr.log`.
-->
```all
# extend some data to PCR. The data will be hashed using the respective PCR’s hash algorithm
$ echo "some data" > data
$ tss2_pcrextend -x 23 -i data

# read
$ tss2_pcrread -x 23 -f -o pcr.bin -l pcr.log
$ xxd pcr.bin
$ cat pcr.log

# clean up
$ rm data pcr.*
```

## Policy

<!--
Find the list of policy in `TCG TSS 2.0 JSON Data Types and Policy Language Specification` (https://trustedcomputinggroup.org/resource/tcg-tss-json/)

Examples:
- Find the JSON encoded policy at https://github.com/tpm2-software/tpm2-tss/tree/master/test/data/fapi/policy
- Search for the policy usage in https://github.com/tpm2-software/tpm2-tss/tree/master/test/integration

to-do: policy examples
-->

## Quote

<!--
If you see error "The digest computed from event list does not match the attest.", most likely is because eventlog and PCR 23 digest is out of sync, reset PCR 23 and re-provision fapi

Is possible to select multiple pcrs: -x "0,16,23"
-->
```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# extend some data to PCR
$ echo "some data" > data
$ tss2_pcrextend -x 23 -i data

# generate quote
$ tss2_getrandom -n 16 -f -o quote.qualifying
$ tss2_quote -p /P_RSA2048SHA256/HS/SRK/LeafKey -x "23" -Q quote.qualifying -f -o quote.sig -l quote.log -c key.crt -q quote.info

# verify quote
$ tss2_verifyquote -k /P_RSA2048SHA256/HS/SRK/LeafKey -Q quote.qualifying -q quote.info -i quote.sig -l quote.log

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm quote.* key.* data
```

## Seal/Unseal

```all
$ echo "some secret" > secret.clear

# seal the secret
$ tss2_createseal -p /P_RSA2048SHA256/HS/SRK/LeafKey -a "" -i secret.clear

# unseal the secret
$ tss2_unseal -p /P_RSA2048SHA256/HS/SRK/LeafKey -f -o secret.unseal
$ diff secret.unseal secret.clear

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm secret.*
```

## Set/Get App Data

```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# associate an arbitrary data blob with a given object
# the data will be stored in plain in `/home/pi/.local/share/tpm2-tss/user/keystore/P_RSA2048SHA256/HS/SRK/LeafKey/object.json`
$ tss2_getrandom -n 32 -f -o data-in.bin
$ tss2_setappdata -p /P_RSA2048SHA256/HS/SRK/LeafKey -i data-in.bin

# get the data
$ tss2_getappdata -p /P_RSA2048SHA256/HS/SRK/LeafKey -f -o data-out.bin
$ diff data-in.bin data-out.bin

# remove the data
$ tss2_setappdata -p /P_RSA2048SHA256/HS/SRK/LeafKey

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm data-in.bin data-out.bin
```

## Set/Get Certificate

```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# create a dummy certificate (follow the CSR flow to obtain a valid certificate)
$ openssl req -x509 -sha256 -nodes -days 365 -subj "/CN=Dummy/O=Infineon/C=SG" -newkey rsa:2048 -keyout dummy.key -out dummy-in.crt
$ openssl x509 -inform pem -in dummy-in.crt -text

# associate a certificate (PEM encoding) with a given object
# the certificate will be stored in plain in `/home/pi/.local/share/tpm2-tss/user/keystore/P_RSA2048SHA256/HS/SRK/LeafKey/object.json`
$ tss2_setcertificate -p /P_RSA2048SHA256/HS/SRK/LeafKey --x509certData dummy-in.crt

# get the certificate
$ tss2_getcertificate -p /P_RSA2048SHA256/HS/SRK/LeafKey -o dummy-out.crt
$ diff dummy-in.crt dummy-out.crt

# remove the certificate
$ tss2_setcertificate -p /P_RSA2048SHA256/HS/SRK/LeafKey

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm dummy.key dummy-in.crt dummy-out.crt
```

## Set/Get Description

```all
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# assign a human readable description to an object in the metadata store
# the description will be stored in plain in `/home/pi/.local/share/tpm2-tss/user/keystore/P_RSA2048SHA256/HS/SRK/LeafKey/object.json`
$ tss2_setdescription -p /P_RSA2048SHA256/HS/SRK/LeafKey -i "This is a leaf key"

# get the description
$ tss2_getdescription -p /P_RSA2048SHA256/HS/SRK/LeafKey -o -

# remove the description
$ tss2_setdescription -p /P_RSA2048SHA256/HS/SRK/LeafKey

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
```

## Signing & Verification

For profile `P_RSA2048SHA256`:
```all
# create signing key
$ tss2_createkey -p /P_RSA2048SHA256/HS/SRK/LeafKey -a ""

# generate digest
$ echo "some message" > message
$ openssl dgst -sha256 -binary -out message.digest message

# sign and receive the signature, public component of the signing key (PEM encoded), and the associated certificate (if there is one)
$ tss2_sign -p /P_RSA2048SHA256/HS/SRK/LeafKey -s "RSA_SSA" -d message.digest -f -o message.sig -k key.pub -c key.crt
# openssl x509 -inform pem -in key.crt -text
$ openssl rsa -inform PEM -noout -text -in key.pub -pubin

# verify the signature using TPM
$ tss2_verifysignature -p /P_RSA2048SHA256/HS/SRK/LeafKey -d message.digest -i message.sig

# verify the signature using OpenSSL
$ openssl dgst -sha256 -verify key.pub -keyform pem -signature message.sig message

# clean up
$ tss2_delete -p /P_RSA2048SHA256/HS/SRK/LeafKey
$ rm message message.* key.*
```

For profile `P_ECCP256SHA256`:
```exclude
# create signing key
$ tss2_createkey -p /P_ECCP256SHA256/HS/SRK/LeafKey -a ""

# generate digest
$ echo "some message" > message
$ openssl dgst -sha256 -binary -out message.digest message

# sign and receive the signature, public component of the signing key (PEM encoded), and the associated certificate (if there is one)
$ tss2_sign -p /P_ECCP256SHA256/HS/SRK/LeafKey -d message.digest -f -o message.sig -k key.pub -c key.crt
# openssl x509 -inform pem -in key.crt -text
$ openssl ec -inform PEM -noout -text -in key.pub -pubin

# verify the signature using TPM
$ tss2_verifysignature -p /P_ECCP256SHA256/HS/SRK/LeafKey -d message.digest -i message.sig

# verify the signature using OpenSSL
$ openssl dgst -sha256 -verify key.pub -keyform pem -signature message.sig message

# clean up
$ tss2_delete -p /P_ECCP256SHA256/HS/SRK/LeafKey
$ rm message message.* key.*
```

# CI Self Test

Manually trigger the CI workflow using the following command:

```exclude
$ git clone https://github.com/infineon/optiga-tpm-cheatsheet ~/optiga-tpm-cheatsheet
$ cd ~/optiga-tpm-cheatsheet

# Linux
$ export DOCKER_IMAGE=debian-bullseye
$ docker run  --cpus=$(nproc) \
              --memory=7g \
              -it \
              --env WORKSPACE_DIR=/workspace \
              --env DOCKER_IMAGE=$DOCKER_IMAGE \
              --env-file .ci/docker.env \
              -v "$(pwd):/root/optiga-tpm-cheatsheet" \
              `echo ${DOCKER_IMAGE} | sed 's/-/:/'` \
              /bin/bash -c "/root/optiga-tpm-cheatsheet/.ci/docker.sh"
```
<!--
# Windows
$ set DOCKER_IMAGE=debian-bullseye
$ docker run  --cpus=%NUMBER_OF_PROCESSORS% ^
              --memory=7g ^
              -it ^
              --env WORKSPACE_DIR=/workspace ^
              --env DOCKER_IMAGE=%DOCKER_IMAGE% ^
              --env-file .ci/docker.env ^
              -v "%cd%:/root/optiga-tpm-cheatsheet" ^
              %DOCKER_IMAGE% ^
              /bin/bash -c "/root/optiga-tpm-cheatsheet/.ci/docker.sh"
-->

# References

<a id="1">[1] https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/</a><br>
<a id="2">[2] https://github.com/microsoft/ms-tpm-20-ref</a><br>
<a id="3">[3] https://github.com/tpm2-software/tpm2-tss</a><br>
<a id="4">[4] https://github.com/tpm2-software/tpm2-tools</a><br>
<a id="5">[5] https://github.com/tpm2-software/tpm2-tss-engine</a><br>
<a id="6">[6] https://github.com/Infineon/ek-based-onboarding-optiga-tpm</a><br>
<a id="7">[7] https://github.com/Infineon/pkcs11-optiga-tpm</a><br>
<!--<a id="8">[8] https://github.com/wxleong/tpm2-rpi4</a><br>-->
<a id="9">[9] https://trustedcomputinggroup.org/resource/tpm-library-specification/</a><br>
<a id="10">[10] https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/</a><br>
<a id="11">[11] https://github.com/tpm2-software/tpm2-tss/blob/master/src/tss2-tcti/tcti-device.c#L371</a><br>
<a id="12">[12] https://github.com/tpm2-software/tpm2-tools/commit/7b6600d3214dd45531bdb53d5f2510404c31fd6b#diff-b7ca48acb8f12449d165509c68d04600fac53b56bfc4c43462908815b9602def</a><br>
<a id="13">[13] https://github.com/Infineon/remote-attestation-optiga-tpm</a><br>
<a id="14">[14] https://trustedcomputinggroup.org/resource/tcg-tss-2-0-system-level-api-sapi-specification/</a><br>
<a id="15">[15] https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/</a><br>
<a id="16">[16] https://trustedcomputinggroup.org/resource/tss-fapi/</a><br>
<a id="17">[17] https://github.com/Infineon/eltt2</a><br>

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# To-dos

Look for `to-do` in the raw format.

<!--
to-do:
- fapi NV
- fapi event log
- fapi import of key (/ext/key123) and policy (/policy/policy123)
  https://trustedcomputinggroup.org/resource/tcg-tss-json/
-->
