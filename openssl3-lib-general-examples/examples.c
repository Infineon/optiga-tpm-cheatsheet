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
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

#define PRINT(...) printf(__VA_ARGS__); \
                    printf("\n");

#define RSA_KEY_PATH "/tmp/rsa-key"
#define EC_KEY_PATH "/tmp/ec-key"

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
gen_rsaKey()
{
    int ret = 1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned int bits = 3072;
    BIO *out = NULL;

    /**
     * For more options please refer to the tpm2 provider:
     * https://github.com/tpm2-software/tpm2-openssl/blob/1.1.0/src/tpm2-provider-keymgmt-rsa.c#L224
     */
    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_end();

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=tpm2")) == NULL ||
        EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_generate(ctx, &pkey) <= 0) {
        PRINT("Failed to generate RSA key");
        return ret;
    }

    // Print the public component (modulus)
    EVP_PKEY_print_public_fp(stdout, pkey, 0, NULL);

    // Store the key object on disk
    if ((out = BIO_new_file(RSA_KEY_PATH, "w")) == NULL) {
        PRINT("Failed to create a new file");
        goto err1;
    }
    if (!PEM_write_bio_PrivateKey(out, pkey, 0, NULL, 0, 0, NULL)) {
        PRINT("Failed to write RSA key to disk");
        goto err2;
    }

    ret = 0;
    PRINT("Generated RSA key and saved to disk");

err2:
    BIO_free_all(out);
err1:
    EVP_PKEY_free(pkey);
    return ret;
}

int
gen_ecKey()
{
    int ret = 1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    BIO *out = NULL;
    char *group = "P-256";

    /**
     * For more options please refer to the tpm2 provider:
     * https://github.com/tpm2-software/tpm2-openssl/blob/1.1.0/src/tpm2-provider-keymgmt-ec.c#L183
     */
    params[0] = OSSL_PARAM_construct_utf8_string("group", group, sizeof(group));
    params[1] = OSSL_PARAM_construct_end();

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=tpm2")) == NULL ||
        EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_generate(ctx, &pkey) <= 0) {
        PRINT("Failed to generate EC key");
        return ret;
    }

    // Print the public component
    EVP_PKEY_print_public_fp(stdout, pkey, 0, NULL);

    // Store the key object on disk
    if ((out = BIO_new_file(EC_KEY_PATH, "w")) == NULL) {
        PRINT("Failed to create a new file");
        goto err1;
    }
    if (!PEM_write_bio_PrivateKey(out, pkey, 0, NULL, 0, 0, NULL)) {
        PRINT("Failed to write EC key to disk");
        goto err2;
    }

    ret = 0;
    PRINT("Generated EC key and saved to disk");

err2:
    BIO_free_all(out);
err1:
    EVP_PKEY_free(pkey);
    return ret;
}

EVP_PKEY *
load_rsa_key()
{
    EVP_PKEY *pKey = NULL;
    BIO *bio = NULL;

    if ((bio = BIO_new_file(RSA_KEY_PATH, "r")) == NULL) {
        PRINT("Failed to open RSA_KEY_PATH");
        goto err1;
    }

    if ((pKey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL)) == NULL) {
        PRINT("Failed to read RSA key");
        goto err2;
    }

    PRINT("Loaded RSA key from disk");

err2:
    BIO_free_all(bio);
err1:
    return pKey;
}

EVP_PKEY *
load_ec_key()
{
    EVP_PKEY *pKey = NULL;
    BIO *bio = NULL;

    if ((bio = BIO_new_file(EC_KEY_PATH, "r")) == NULL) {
        PRINT("Failed to open RSA_KEY_PATH");
        goto err1;
    }

    if ((pKey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL)) == NULL) {
        PRINT("Failed to read EC key");
        goto err2;
    }

    PRINT("Loaded EC key from disk");

err2:
    BIO_free_all(bio);
err1:
    return pKey;
}

int
ec_evp_pkey_sign_verify(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctx2 = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    //ctx = EVP_PKEY_CTX_new(pKey, NULL);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=tpm2");
    if (!ctx) {
        PRINT("EC sign EVP_PKEY_CTX_new_from_pkey error");
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

    if ((ctx2 = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=default")) == NULL) {
        PRINT("EC verify signature EVP_PKEY_CTX_new_from_pkey error");
        goto err3;
    }

    if (EVP_PKEY_verify_init(ctx2) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx2, EVP_sha256()) <= 0) {
        PRINT("EC verification init error");
        goto err4;
    }

    if (EVP_PKEY_verify(ctx2, sig, sigLen, sha256, sha256Len) <= 0) {
        PRINT("EC signature verification error");
        goto err4;
    }

    PRINT("EC signature verification ok");

    // corrupt the hash
    sha256[3] = ~sha256[3];
    if (EVP_PKEY_verify(ctx2, sig, sigLen, sha256, sha256Len) == 0) {
        PRINT("EC signature verification expected to fail, ok");
    } else {
        PRINT("EC signature verification error");
        goto err4;
    }

    ret = 0;

err4:
    EVP_PKEY_CTX_free(ctx2);
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
    EVP_PKEY_CTX *ctx2 = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=tpm2");
    if (!ctx) {
        PRINT("RSA sign EVP_PKEY_CTX_new_from_pkey error");
        goto err1;
    }

    /* Signing */

    PRINT("RSA signing");
    if (EVP_PKEY_sign_init(ctx) <= 0 ) {
        PRINT("RSA sign init error");
        goto err2;
    }
    if ( EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <=0) {
        PRINT("set md error");
        goto err2;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        PRINT("EVP_PKEY_CTX_set_rsa_padding error");
        goto err2;
    }

    if (EVP_PKEY_sign(ctx, NULL, &sigLen, sha256, sha256Len) <= 0) {
        PRINT("get siglen error");
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

    if ((ctx2 = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=default")) == NULL) {
        PRINT("RSA verify signature EVP_PKEY_CTX_new_from_pkey error");
        goto err3;
    }

    if (EVP_PKEY_verify_init(ctx2) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx2, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx2, EVP_sha256()) <= 0) {
        PRINT("RSA verification init error");
        goto err4;
    }

    if (EVP_PKEY_verify(ctx2, sig, sigLen, sha256, sha256Len) <= 0) {
        PRINT("RSA signature verification error");
        goto err4;
    }

    PRINT("RSA signature verification ok");

    // corrupt the hash
    sha256[3] = ~sha256[3];
    if (EVP_PKEY_verify(ctx2, sig, sigLen, sha256, sha256Len) == 0) {
        PRINT("RSA signature verification expected to fail, ok");
    } else {
        PRINT("RSA signature verification error");
        goto err4;
    }

    ret = 0;

err4:
    EVP_PKEY_CTX_free(ctx2);
err3:
    OPENSSL_free(sig);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
rsa_evp_pkey_encrypt_decrypt(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctx2 = NULL;
    unsigned char clear[] = {1,2,3};
    unsigned char *ciphered = NULL, *deciphered = NULL;
    size_t cipheredLen = 0, decipheredLen = 0, clearLen = 3;
    int ret = -1;


    /* Encryption (RSA_PKCS1_PADDING == TPM2_ALG_RSAES) */

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=default")) == NULL) {
        PRINT("RSA encrypt EVP_PKEY_CTX_new_from_pkey error");
        goto err1;
    }

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

    /* Decryption (RSA_PKCS1_PADDING == TPM2_ALG_RSAES) */

    ctx2 = EVP_PKEY_CTX_new_from_pkey(NULL, pKey, "provider=tpm2");
    if (!ctx2) {
        PRINT("RSA decrypt EVP_PKEY_CTX_new_from_pkey error");
        goto err3;
    }

    if (EVP_PKEY_decrypt_init(ctx2) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx2, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_decrypt(ctx2, NULL, &decipheredLen, ciphered, cipheredLen) <= 0) {
        PRINT("Decryption init error");
        goto err4;
    }

    deciphered = OPENSSL_malloc(decipheredLen);
    if (!deciphered) {
        PRINT("malloc error");
        goto err4;
    }

    memset(deciphered, 0, decipheredLen);

    PRINT("Decrypting encrypted blob");

    if (EVP_PKEY_decrypt(ctx2, deciphered, &decipheredLen, ciphered, cipheredLen) <= 0) {
        PRINT("Decryption error");
        goto err5;
    }

    if((decipheredLen != clearLen) || (strncmp((const char *)clear, (const char *)deciphered, decipheredLen) != 0))
    {
        PRINT("Decryption error, value not the same");
        goto err5;
    }

    PRINT("Decryption verification ok");

    ret = 0;

err5:
    OPENSSL_free(deciphered);
err4:
    EVP_PKEY_CTX_free(ctx2);
err3:
    OPENSSL_free(ciphered);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    int ret = 1;
    OSSL_PROVIDER *prov_default = NULL;
    OSSL_PROVIDER *prov_tpm2 = NULL;
    EVP_PKEY *pRsaKey = NULL;
    EVP_PKEY *pEcKey = NULL;

    PRINT("Starting...");

    /*
     * Known issue:
     *
     * Cant set tcti programmatically
     * Open topic: https://github.com/openssl/openssl/issues/17182
     * Tentatively, set parameters feature will be implemented in OpenSSL 3.1
     *
     * Here we relies on ENV TPM2OPENSSL_TCTI
     */

    /* Load default provider */
    if ((prov_default = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        goto err0;

    /* Self-test */
    if (!OSSL_PROVIDER_self_test(prov_default))
        goto err1;

    /* Load TPM2 provider */
    if ((prov_tpm2 = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        goto err1;

    /* Self-test */
    if (!OSSL_PROVIDER_self_test(prov_tpm2))
        goto err2;

    /* Generate true random */
    if (gen_random())
        goto err2;

    /* Generate RSA key */
    if (gen_rsaKey())
        goto err2;

    /* Generate EC key */
    if (gen_ecKey())
        goto err2;

    /* Load RSA key */
    if ((pRsaKey = load_rsa_key()) == NULL)
        goto err2;

    /* Load EC key */
    if ((pEcKey = load_ec_key()) == NULL)
        goto err3;

    /* RSA signing & verification */
    if (rsa_evp_pkey_sign_verify(pRsaKey))
        goto err4;

    /* EC signing & verification */
    if (ec_evp_pkey_sign_verify(pEcKey))
        goto err4;

    /* RSA encryption & decryption */
    if (rsa_evp_pkey_encrypt_decrypt(pRsaKey))
        goto err4;

    PRINT("Completed without err...");

    ret = 0;

err4:
    EVP_PKEY_free(pEcKey);
err3:
    EVP_PKEY_free(pRsaKey);
err2:
    OSSL_PROVIDER_unload(prov_tpm2);
err1:
    OSSL_PROVIDER_unload(prov_default);
err0:

    return ret;
}
