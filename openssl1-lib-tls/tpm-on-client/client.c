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
 * https://aticleworld.com/ssl-server-client-using-openssl-in-c/
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef ENABLE_TPM_TSS_ENGINE
#include <openssl/engine.h>
#endif

int connect_socket(const char *hostname, int port)
{
    int s;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror("Unable to find server");
        exit(EXIT_FAILURE);
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect to server");
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

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *pSslContext, const char *clientCert, const char *clientKey, 
                       const char *caCert)
{
    int32_t sslStatus = -1;

    SSL_CTX_set_ecdh_auto(pSslContext, 1);

    /* Set the client cert */
    if (SSL_CTX_use_certificate_chain_file(pSslContext, clientCert) <= 0) {
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
    if (SSL_CTX_use_PrivateKey_file(pSslContext, clientKey, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
#endif

    //SSL_CTX_set_verify(pSslContext, SSL_VERIFY_NONE, NULL); // not to verify server 
    SSL_CTX_set_verify(pSslContext, SSL_VERIFY_PEER, NULL); // to verify server certificate

    /* Set CA certificate for server verification */
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
        printf("Server certificate:\n");
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
    SSL *ssl;

    init_openssl();
    ctx = create_context();
#ifdef ENABLE_TPM_TSS_ENGINE
    configure_context(ctx, "tpm.crt", "0x81000001", "local-ca.crt");
#else
    configure_context(ctx, "software.crt", "software.key", "local-ca.crt");
#endif

    sock = connect_socket("localhost", 8443);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char msg[] = "\nHello from client...\n";
        int bytes = 0;
        char buf[256];

        showCert(ssl);

        SSL_write(ssl, msg, strlen(msg)); // send message to server
        bytes = SSL_read(ssl, buf, sizeof(buf) - 1); // receive message from server 
        if (bytes) {
            buf[bytes] = '\0';
            printf("\nReceived: \"%s\"\n", buf);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

