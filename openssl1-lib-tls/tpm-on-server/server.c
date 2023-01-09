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
/*
 * References:
 * https://wiki.openssl.org/index.php/Simple_TLS_Server
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef ENABLE_TPM_TSS_ENGINE
#include <openssl/engine.h>
#endif

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;
    const int enable = 1;

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    //addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("Unable to set SO_REUSEADDR");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

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

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    //method = TLSv1_2_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *pSslContext, const char *serverCert, const char *serverKey,
                       const char *caCert)
{
    int32_t sslStatus = -1;

    SSL_CTX_set_ecdh_auto(pSslContext, 1);

    /* Set the server cert */
    if (SSL_CTX_use_certificate_chain_file(pSslContext, serverCert) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

#ifdef ENABLE_TPM_TSS_ENGINE
    /* Set TPM-based key */
    {
        const char  *pEngineName = "tpm2tss";
        ENGINE  *pEngine = NULL;
        UI_METHOD *pUiMethod = NULL;
        EVP_PKEY *pKey = NULL;

        /* Load TPM OpenSSL engine. */
        ENGINE_load_builtin_engines();
        pEngine = ENGINE_by_id(pEngineName);

        if (!pEngine)
        {
            perror("Unable to load TPM OpenSSL engine.");
            exit(EXIT_FAILURE);
        }

        if (!ENGINE_init(pEngine))
        {
            perror("Unable to init TPM2 Engine.");
            exit(EXIT_FAILURE);
        }

        if (!ENGINE_set_default(pEngine, ENGINE_METHOD_ALL))
        {
            perror("Unable to set TPM2 Engine.");
            exit(EXIT_FAILURE);
        }

#ifdef ENABLE_OPTIGA_TPM
        if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "device:/dev/tpmrm0", NULL))
        {
            perror("Unable to switch to TPM device mode (/dev/tpmrm0).");
#else
        if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "tabrmd:bus_type=session", NULL))
        {
            perror("Unable to switch to TPM simulator mode.");
#endif
            exit(EXIT_FAILURE);
        }

        pUiMethod = UI_OpenSSL();
        if (!pUiMethod)
        {
            perror("Unable to get OpenSSL UI method.");
            exit(EXIT_FAILURE);
        }

        pKey = ENGINE_load_private_key(pEngine, "0x81000001", pUiMethod, NULL);

        sslStatus = SSL_CTX_use_PrivateKey(pSslContext, pKey);
        if (sslStatus <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
#else
    (void)sslStatus;
    /* Set software-based key */
    if (SSL_CTX_use_PrivateKey_file(pSslContext, serverKey, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
#endif

    //SSL_CTX_set_verify(pSslContext, SSL_VERIFY_NONE, NULL); // not to verify client
    SSL_CTX_set_verify(pSslContext, SSL_VERIFY_PEER, NULL); // to verify client certificate

    /* Set CA certificate for client verification */
    {
        FILE * rootCaFile = NULL;
        X509 *rootCa = NULL;

        if ((rootCaFile = fopen(caCert, "r")) == NULL) {
            perror("Unable to find CA certificate");
            exit(EXIT_FAILURE);
        }

        if ((rootCa = PEM_read_X509(rootCaFile, NULL, NULL, NULL)) == NULL) {
            perror("Unable to decode CA certificate");
            exit(EXIT_FAILURE);
        }

        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(pSslContext), rootCa) <= 0) {
            perror("Unable to load CA certificate");
            exit(EXIT_FAILURE);
        }

        if (rootCaFile != NULL)
            fclose(rootCaFile);
    }
}

void showCert(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Client certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();
#ifdef ENABLE_TPM_TSS_ENGINE
    configure_context(ctx, "tpm.crt", "0x81000001", "local-ca.crt");
#else
    configure_context(ctx, "local-ca.crt", "local-ca.key", "local-ca.crt");
#endif

    sock = create_socket(8443);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "\nHello from server.\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            int bytes = 0;
            char buf[256];

            showCert(ssl);

            SSL_write(ssl, reply, strlen(reply));
            bytes = SSL_read(ssl, buf, sizeof(buf)); // receive message from client 
            if (bytes) {
                buf[bytes] = '\0';
                printf("\nReceived: \"%s\"\n", buf);
            }

        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

