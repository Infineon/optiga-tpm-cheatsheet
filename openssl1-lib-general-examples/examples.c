/**
 * MIT License
 *
 * Copyright (c) 2021 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <tpm2-tss-engine.h>
#include <tss2/tss2_tctildr.h>

#define PRINT(...) printf(__VA_ARGS__); \
                    printf("\n");

//#define TPM_ENGINE_PATH "/usr/lib/x86_64-linux-gnu/engines-1.1/libtpm2tss.so"
#define RSA_KEY_PATH "/tmp/rsa-key"
#define EC_KEY_PATH "/tmp/ec-key"

void init_openssl()
{ 
    OpenSSL_add_all_algorithms();    
    SSL_load_error_strings();  
    SSL_library_init();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

int
gen_random()
{
    unsigned char buf[4];

    int rc = RAND_bytes(buf, sizeof(buf));

    if(rc != 1) {
        PRINT("RAND_bytes failed");
        return -1;
    }

    PRINT("Obtained random: %02x%02x%02x%02x", buf[0], buf[1], buf[2], buf[3]);

    return 0;
}

int
rsa_genkey()
{
    RSA *rsa = NULL;
    int ret = -1;

    PRINT("Generating RSA key using TPM");

    BIGNUM *e = BN_new();
    if (!e) {
        PRINT("out of memory");
        goto err1;
    }
    BN_set_word(e, /* exponent */ 65537);

    rsa = RSA_new();
    if (!rsa) {
        PRINT("out of memory");
        goto err2;
    }
    if (!tpm2tss_rsa_genkey(rsa, /* key size */ 2048, e, /* password */ NULL, /* parent keyhandle or TPM2_RH_OWNER or 0 */ 0)) { 
        PRINT("tpm2tss_rsa_genkey failed");
        goto err3;
    }

    PRINT("RSA Key generated");

    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        PRINT("out of memory");
        goto err3;
    }

    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    if (!tpm2tss_tpm2data_write(tpm2Data, RSA_KEY_PATH)) {
        PRINT("Error writing file");
        goto err4;
    }

    PRINT("RSA Key written to %s", RSA_KEY_PATH);

    ret = 0;

err4:
    free(tpm2Data);
err3:
    RSA_free(rsa);
err2:
    BN_free(e);
err1:
    return ret;
}

int
ec_genkey()
{
    EC_KEY *eckey = NULL;
    int ret = -1;

    PRINT("Generating EC key using TPM");

    eckey = EC_KEY_new();
    if (!eckey) {
        PRINT("out of memory");
        goto err1;
    }
    
    //TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384
    if (!tpm2tss_ecc_genkey(eckey, TPM2_ECC_NIST_P256, /* password */ NULL, /* parent keyhandle or TPM2_RH_OWNER or 0 */ 0)) { 
        PRINT("tpm2tss_rsa_genkey failed");
        goto err2;
    }

    PRINT("EC Key generated");

    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        PRINT("out of memory");
        goto err2;
    }

    memcpy(tpm2Data, tpm2tss_ecc_getappdata(eckey), sizeof(*tpm2Data));

    if (!tpm2tss_tpm2data_write(tpm2Data, EC_KEY_PATH)) {
        PRINT("Error writing file");
        goto err3;
    }

    PRINT("EC Key written to %s", EC_KEY_PATH);

    ret = 0;

err3:
    free(tpm2Data);
err2:
    EC_KEY_free(eckey);
err1:
    return ret;
}

int
ec_evp_pkey_sign_verify(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        PRINT("EC EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Signing */

    PRINT("EC signing");
    
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_sign(ctx, NULL, &sigLen, sha256, sha256Len) <= 0) {
        PRINT("EC sign init error");
        goto err2;
    }
    
    sig = OPENSSL_malloc(sigLen);
    
    if (!sig) {
        PRINT("EC malloc error");
        goto err2;
    }

    PRINT("EC generating signature");

    if (EVP_PKEY_sign(ctx, sig, &sigLen, sha256, sha256Len) <= 0) {
        PRINT("EC signing error");
        goto err3;
    }
    
    /* Verification */

    PRINT("EC verify signature");

    if (EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        PRINT("EC verification init error");
        goto err2;
    }

    /* ret == 1 indicates success, 0 verify failure and < 0 for some
     * other error.
     */
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) <= 0) {
        PRINT("EC signature verification error");
        goto err3;
    }

    PRINT("EC signature verification ok");

    // corrupt the hash
    sha256[3] = 1;
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) == 0) {
        PRINT("EC signature verification expected to fail, ok");
    } else {
        PRINT("EC signature verification error");
        goto err3;
    }
    
    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
rsa_evp_pkey_sign_verify(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        PRINT("RSA EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Signing */

    PRINT("RSA signing");
    
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_sign(ctx, NULL, &sigLen, sha256, sha256Len) <= 0) {
        PRINT("RSA sign init error");
        goto err2;
    }
    
    sig = OPENSSL_malloc(sigLen);
    
    if (!sig) {
        PRINT("RSA malloc error");
        goto err2;
    }

    PRINT("RSA generating signature");

    if (EVP_PKEY_sign(ctx, sig, &sigLen, sha256, sha256Len) <= 0) {
        PRINT("RSA signing error");
        goto err3;
    }
    
    /* Verification */

    PRINT("RSA verify signature");

    if (EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        PRINT("RSA verification init error");
        goto err2;
    }

    /* ret == 1 indicates success, 0 verify failure and < 0 for some
     * other error.
     */
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) <= 0) {
        PRINT("RSA signature verification error");
        goto err3;
    }

    PRINT("RSA signature verification ok");

    // corrupt the hash
    sha256[3] = 1;
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) == 0) {
        PRINT("RSA signature verification expected to fail, ok");
    } else {
        PRINT("RSA signature verification error");
        goto err3;
    }
    
    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
ec_sign_verify(EVP_PKEY *pKey)
{
    EC_KEY *eckey = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    unsigned int sigLen = 0;
    int ret = -1;

    eckey = EVP_PKEY_get1_EC_KEY(pKey);
    if (eckey == NULL) {
        PRINT("EC EVP_PKEY_get1_EC_KEY error");
        goto err1;
    }

    /* Signing */
   
    sig = OPENSSL_malloc(ECDSA_size(eckey));
    if (!sig) {
        PRINT("EC malloc error");
        goto err2;
    }

    PRINT("EC Generating signature");

    if (!ECDSA_sign(0, sha256, sizeof(sha256), sig, &sigLen, eckey)) {
        PRINT("EC signing error");
        goto err3;
    }

    /* optionally use ECDSA_do_sign(...) -> https://www.openssl.org/docs/man1.1.0/man3/ECDSA_sign.html */


    /* Verification */

    PRINT("EC verify signature");

    if (ECDSA_verify(0, sha256, sizeof(sha256), sig, sigLen, eckey) != 1) {
        PRINT("EC signature verification error");
        goto err3;
    }
    
    PRINT("EC signature verification ok");
    
    sha256[2] = 1;
    if (ECDSA_verify(0, sha256, sizeof(sha256), sig, sigLen, eckey) == 0) {
        PRINT("EC signature verification expected to fail, ok");
    } else {
        PRINT("EC signature verification error");
        goto err3;
    }
    
    /* optionally use ECDSA_do_verify(...) -> https://www.openssl.org/docs/man1.1.0/man3/ECDSA_sign.html */

    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EC_KEY_free(eckey);
err1:
    return ret;
}

int
rsa_sign_verify(EVP_PKEY *pKey)
{
    RSA *rsa = NULL;
    unsigned char message[] = {1,2,3};
    unsigned char *sig = NULL;
    unsigned int sigLen = 0;
    int ret = -1;

    rsa = EVP_PKEY_get1_RSA(pKey);
    if (rsa == NULL) {
        PRINT("RSA EVP_PKEY_get1_RSA error");
        goto err1;
    }

    /* Signing */
   
    sig = OPENSSL_malloc(RSA_size(rsa));
    if (!sig) {
        PRINT("RSA malloc error");
        goto err2;
    }

    PRINT("RSA generating signature");

    if (!RSA_sign(RSA_PKCS1_PADDING, message, sizeof(message), sig, &sigLen, rsa)) {
        PRINT("RSA signing error");
        goto err3;
    }

    /* Verification */

    PRINT("RSA verify signature");

    if (!RSA_verify(RSA_PKCS1_PADDING, message, sizeof(message), sig, sigLen, rsa)) {
        PRINT("RSA signature verification error");
        goto err3;
    }
    
    PRINT("RSA signature verification ok");
    
    message[2] = 1;
    if (!RSA_verify(RSA_PKCS1_PADDING, message, sizeof(message), sig, sigLen, rsa)) {
        PRINT("RSA signature verification expected to fail, ok");
    } else {
        PRINT("RSA signature verification error");
        goto err3;
    }

    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    RSA_free(rsa);
err1:
    return ret;
}

int
rsa_evp_pkey_encrypt_decrypt(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char clear[] = {1,2,3};
    unsigned char *ciphered = NULL, *deciphered = NULL;
    size_t cipheredLen = 0, decipheredLen = 0, clearLen = 3;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        PRINT("EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Encryption (RSA_PKCS1_PADDING) */

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, NULL, &cipheredLen, clear, clearLen) <= 0) {
        PRINT("Encryption init error");
        goto err2;
    }

    ciphered = OPENSSL_malloc(cipheredLen);
    if (!ciphered) {
        PRINT("malloc error");
        goto err2;
    }

    PRINT("Generating encryption blob");

    if (EVP_PKEY_encrypt(ctx, ciphered, &cipheredLen, clear, clearLen) <= 0) {
        PRINT("Encryption error");
        goto err3;
    }

    /* Decryption (support only RSA_PKCS1_PADDING, https://github.com/tpm2-software/tpm2-tss-engine/pull/89) */

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_decrypt(ctx, NULL, &decipheredLen, ciphered, cipheredLen) <= 0) {
        PRINT("Decryption init error");
        goto err2;
    }

    deciphered = OPENSSL_malloc(decipheredLen);
    if (!deciphered) {
        PRINT("malloc error");
        goto err2;
    }
    
    memset(deciphered, 0, decipheredLen);

    PRINT("Decrypting encrypted blob");

    if (EVP_PKEY_decrypt(ctx, deciphered, &decipheredLen, ciphered, cipheredLen) <= 0) {
        PRINT("Decryption error");
        goto err3;
    }

    if((decipheredLen != clearLen) || (strncmp((const char *)clear, (const char *)deciphered, decipheredLen) != 0))
    {
        PRINT("Decryption error, value not the same");
        goto err3;
    }

    PRINT("Decryption verification ok");
    
    ret = 0;
    
err3:
    OPENSSL_free(ciphered);
    OPENSSL_free(deciphered);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
rsa_encrypt_decrypt(EVP_PKEY *pKey)
{
    RSA *rsa = NULL;
    unsigned char clear[] = {1,2,3};
    unsigned char *ciphered = NULL, *deciphered = NULL;
    int cipheredLen = 0, decipheredLen = 0, clearLen = 3;
    int ret = -1;

    rsa = EVP_PKEY_get1_RSA(pKey);
    if (rsa == NULL) {
        PRINT("EVP_PKEY_get1_RSA error");
        goto err1;
    }

    /* Encrypt (RSA_PKCS1_OAEP_PADDING) */
   
    ciphered = OPENSSL_malloc(RSA_size(rsa));
    if (!ciphered) {
        PRINT("malloc error");
        goto err2;
    }

    PRINT("Generating encryption blob");

    cipheredLen = RSA_public_encrypt (clearLen, clear, ciphered, rsa, RSA_PKCS1_OAEP_PADDING);
    if (cipheredLen == -1) {
        PRINT("Encryption error");
        goto err3;
    }

    /* Decrypt (RSA_PKCS1_OAEP_PADDING) */

    deciphered = OPENSSL_malloc(RSA_size(rsa));
    if (!deciphered) {
        PRINT("malloc error");
        goto err2;
    }

    PRINT("Decrypting encrypted blob");

    decipheredLen = RSA_private_decrypt(cipheredLen, ciphered, deciphered, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decipheredLen == -1) {
        PRINT("Decryption error");
        goto err3;
    }
    
    if((decipheredLen != clearLen) || (strncmp((const char *)clear, (const char *)deciphered, decipheredLen) != 0))
    {
        PRINT("Decryption error, value not the same");
        goto err3;
    }
    
    PRINT("Decryption verification ok");

    ret = 0;
    
err3:
    OPENSSL_free(ciphered);
    OPENSSL_free(deciphered);
err2:
    RSA_free(rsa);
err1:
    return ret;
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    ENGINE  *pEngine = NULL;
    EVP_PKEY *pRsaKey = NULL;
    EVP_PKEY *pEcKey = NULL;
  
    PRINT("Starting...");
  
    init_openssl();

#ifdef TPM_ENGINE_PATH
    ENGINE_load_dynamic();
    pEngine = ENGINE_by_id("dynamic");
    if (!pEngine)
    {
        PRINT("Unable to load dynamic engine.");
        goto err1;
    }

    if (!ENGINE_ctrl_cmd_string(pEngine, "SO_PATH", TPM_ENGINE_PATH, 0)
        || !ENGINE_ctrl_cmd_string(pEngine, "ID", "tpm2tss", 0)
        || !ENGINE_ctrl_cmd_string(pEngine, "LOAD", NULL, 0)) {
        PRINT("Unable to load TPM OpenSSL engine ENGINE_ctrl_cmd_string.");
        goto err2;
    }
#else
    /* Load TPM OpenSSL engine. */
    ENGINE_load_builtin_engines();
    pEngine = ENGINE_by_id("tpm2tss");
    if (!pEngine)
    {
        PRINT("Unable to load tpm2tss engine.");
        goto err1;
    }
#endif

    if (!ENGINE_init(pEngine))
    {
        PRINT("Unable to init TPM2 Engine.");
        goto err2;
    }

    if (!ENGINE_set_default(pEngine, ENGINE_METHOD_ALL))
    {
        PRINT("Unable to set TPM2 Engine.");
        goto err2;
    }

#ifdef ENABLE_OPTIGA_TPM
    if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "device:/dev/tpmrm0", NULL))
    {
        PRINT("Unable to switch to TPM device mode (/dev/tpmrm0).");
#else
    if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "tabrmd:bus_type=session", NULL))
    {
        PRINT("Unable to switch to TPM simulator mode.");
#endif
        goto err2;
    }

    /* Generate true random */
    if (gen_random())
        goto err2;

    /* Generate TPM RSA key using tpm2-tss-engine library */
    if (rsa_genkey())
        goto err2;

    /* Generate TPM EC key using tpm2-tss-engine library */
    if (ec_genkey())
        goto err2;
    
    /* Load RSA Key */
    //pRsaKey = ENGINE_load_private_key(pEngine, "0x81000002", NULL, NULL);
    pRsaKey = ENGINE_load_private_key(pEngine, RSA_KEY_PATH, NULL, NULL);
    if (pRsaKey == NULL) {
        PRINT("RSA Key loading error");
        goto err2;
    }
    PRINT("Loaded RSA key");
    
    /* Load EC Key */
    pEcKey = ENGINE_load_private_key(pEngine, EC_KEY_PATH, NULL, NULL);
    if (pEcKey == NULL) {
        PRINT("EC Key loading error");
        goto err2;
    }
    PRINT("Loaded EC key");
    
    /* EC signing & verification */
    if (ec_evp_pkey_sign_verify(pEcKey))
        goto err3;
    if (ec_sign_verify(pEcKey))
        goto err3;
    
    /* RSA signing & verification */
    if (rsa_evp_pkey_sign_verify(pRsaKey))
        goto err3;
    if (rsa_sign_verify(pRsaKey))
        goto err3;

    /* RSA encryption & decryption */
    if (rsa_evp_pkey_encrypt_decrypt(pRsaKey))
        goto err3;
    if (rsa_encrypt_decrypt(pRsaKey))
        goto err3;

    PRINT("Exiting...");

err3:
    EVP_PKEY_free(pRsaKey);
    EVP_PKEY_free(pEcKey);
err2:
    ENGINE_free(pEngine);
err1:
    cleanup_openssl();

}

