/*
 * This file is part of the Phicomm-k3 distribution (https://github.com/CptTZ/phicomm-k3-fun).
 * Copyright (c) 2019 CptTonyZ.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "bcmcrypto/prf.h"

#define B1_CFG_SIZE (0x10600u)
#define KEY_SIZE (0x50u)
#define VALID_BASE64 (28)

void Base64Encode(const unsigned char *buffer, size_t length, char **b64text)
{ //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return;
}

void print_help()
{
    puts("Useage: ./phi_chksum [path to decrypted config]");
    puts("  Example: ./phi_chksum /mnt/e/config_b1_decrypted.dat");
}

int main(int ac, char *av[])
{
    if (ac != 2)
    {
        print_help();
        return -1;
    }
    size_t cfg_size = B1_CFG_SIZE;
    unsigned char *file_content = malloc(cfg_size);
    void *key = malloc(KEY_SIZE);
    unsigned char *digest = malloc(KEY_SIZE);

    FILE *fp = fopen(av[1], "rb");
    if (!fp)
    {
        puts("Open fail!");
        goto Fin;
    }
    if (fread(file_content, cfg_size, 1, fp) != 1)
    {
        puts("Read fail!");
        goto Fin;
    }
    fclose(fp);

    memset(file_content + 1024, 0, 0x200u);
    snprintf((char *)file_content + 1024, 0x200u, "%s\n", "NVRAMTemporaryChecksumFiller");
    memset(key, 0, KEY_SIZE);
    memset(digest, 0, KEY_SIZE);

    hmac_sha1(file_content, cfg_size, key, 32, digest);

    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x ", digest[i]);
    }

    char *b64Out;
    Base64Encode(digest, VALID_BASE64, &b64Out);
    printf("\nOutput: %s\n\n", b64Out);
    free(b64Out);

Fin:
    free(digest);
    free(file_content);
    free(key);
    return 0;
}
