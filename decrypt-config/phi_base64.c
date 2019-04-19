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

#include "phi.h"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 *OpenSSL base64 ref: https://gist.github.com/barrysteyn/7308212
 */

void Base64Encode(const BYTE *buffer, size_t length, char **b64text)
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
}

size_t calcDecodeLength(const char *b64input)
{ //Calculates the length of a decoded string
    size_t len = strlen(b64input),
           padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;

    return (len * 3) / 4 - padding;
}

void Base64Decode(const char *b64message, BYTE **buffer, size_t *length)
{ //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (BYTE *)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    if (*length != decodeLen)
    {
        puts("Base64 decode probably went horribly wrong");
    }
    BIO_free_all(bio);
}

void print_b64(BYTE *digest, size_t b64_len)
{
    char *b64Out;
    Base64Encode(digest, b64_len, &b64Out);
    printf("Output: %s\n", b64Out);
    free(b64Out);
}

void print_hex(BYTE *data, size_t len)
{
    printf("HEX:\n  ");
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n  ");
    }
    putchar('\n');
}

int phi_b64dec(BYTE *in, char *b64)
{
    int res = 0;

    return res;
}

#ifdef BASE64_DEBUG

int main(int argc, char const *argv[])
{
    const char *a = "BwmP0Gn1XFpXNCJ8+MoU5ghk5cfyCavV5R9fTA==";
    puts(a);

    BYTE *alt_dec;
    size_t alt_dec_len;
    Base64Decode(a, &alt_dec, &alt_dec_len);
    printf("Decode length (alternative): %lu\n", alt_dec_len);
    print_hex(alt_dec, alt_dec_len);

    free(alt_dec);
    return 0;
}

#endif
