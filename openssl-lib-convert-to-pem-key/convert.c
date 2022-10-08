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

#include <stdio.h>
#include <stdbool.h> 
#include <errno.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tpm2-tss-engine.h>
#include <openssl/crypto.h>

#define PRINT(...)  printf(__VA_ARGS__); \
                    printf("\n");

#define LOG_ERR(...)    PRINT(__VA_ARGS__);
#define xstr(s) str(s)
#define str(s) #s

#define LOAD_TYPE(type, name) \
    bool files_load_##name(const char *path, type *name) { \
    \
        UINT8 buffer[sizeof(*name)]; \
        UINT16 size = sizeof(buffer); \
        bool res = files_load_bytes_from_path(path, buffer, &size); \
        if (!res) { \
            return false; \
        } \
        \
        size_t offset = 0; \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name); \
        if (rc != TSS2_RC_SUCCESS) { \
            LOG_ERR("Error deserializing "str(name)" structure: 0x%x", rc); \
            LOG_ERR("The input file needs to be a valid "xstr(type)" data structure"); \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

static size_t readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    do {
        bread += fread(&data[bread], 1, size-bread, f);
    } while (bread < size && !feof(f) && errno == EINTR);

    return bread;
}

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            LOG_ERR("Error getting current file offset for file \"%s\" error: "
                    "%s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            LOG_ERR("Error seeking to end of file \"%s\" error: %s", path,
                    strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            LOG_ERR("ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            LOG_ERR(
                    "Could not restore initial stream position for file \"%s\" "
                    "failed: %s", path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long) size;
    return true;
}

bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path) {

    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on *size */
    if (file_size > *size) {
        if (path) {
            LOG_ERR(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u", path, file_size, *size);
        }
        return false;
    }

    /* The reported file size is not always correct, e.g. for sysfs files
       generated on the fly by the kernel when they are read, which appear as
       having size 0. Read as many bytes as we can until EOF is reached or the
       provided buffer is full. As a small sanity check, fail if the number of
       bytes read is smaller than the reported file size. */
    *size = readx(f, buf, *size);
    if (*size < file_size) {
        if (path) {
            LOG_ERR("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    return true;
}

bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {

    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\" error %s", path, strerror(errno));
        return false;
    }

    bool result = file_read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

LOAD_TYPE(TPM2B_PUBLIC, public)
LOAD_TYPE(TPM2B_PRIVATE, private)

int main(int argc, char **argv)
{
    char *keyPubPath = NULL;
    char *keyPrivPath = NULL;
    char *outPath = NULL;
    bool res = false;
    TPM2B_PUBLIC pub = {0};
    TPM2B_PRIVATE priv = {0};
    TPM2_DATA *tpm2Data = NULL;
    TPM2_HANDLE parentHandle = 0;

    PRINT("Starting...");

    if (argc != 5) {
        PRINT("invalid inputs. Usage: convert 0x81000001 key.pub key.priv key.pem");
        goto err1;
    }
    
    parentHandle = strtoul(argv[1], NULL, 16);
    keyPubPath = argv[2];
    keyPrivPath = argv[3];
    outPath = argv[4];
    PRINT("parent handle: %04x", parentHandle);
    PRINT("path to key.pub: %s", keyPubPath);
    PRINT("path to key.priv: %s", keyPrivPath);
    PRINT("path to key.pem: %s", outPath);

    res = files_load_public(keyPubPath, &pub);
    if (!res) {
        PRINT("files_load_public failed");
        goto err1;
    }

    res = files_load_private(keyPrivPath, &priv);
    if (!res) {
        PRINT("files_load_private failed");
        goto err1;
    }
    
    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        PRINT("OPENSSL_malloc failed");
        goto err1;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    tpm2Data->emptyAuth = 1;
    /*
     * To support auth value:
     *
     * tpm2Data->userauth.size = strlen(password);
     * memcpy(&tpm2Data->userauth.buffer[0], password,
     *         tpm2Data->userauth.size);
     */
    tpm2Data->parent = parentHandle;
    tpm2Data->pub = pub;
    tpm2Data->priv = priv;
    
    if (!tpm2tss_tpm2data_write(tpm2Data, outPath)) {
        PRINT("tpm2tss_tpm2data_write failed");
        free(tpm2Data);
        return 1;
    }

    OPENSSL_free(tpm2Data);
err1:
    PRINT("Exiting...");
    return 0;
}


