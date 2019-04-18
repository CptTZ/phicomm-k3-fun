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

void print_b64(unsigned char *digest, size_t b64_len)
{
    char *b64Out;
    Base64Encode(digest, b64_len, &b64Out);
    printf("Output: %s\n", b64Out);
    free(b64Out);
}

#ifdef BASE64_DEBUG

int chksum_decode(unsigned char *chksum_input, unsigned char *decoded_chksum)
{
    int res_len = 0, indicator = 0;
    if (!chksum_input)
        return 0;

    unsigned char *chksum_now_addr = chksum_input;
    unsigned char chksum_char = chksum_input[0];

    unsigned char v6, v8, v9;

    unsigned char v7;
    do
    {
        v7 = b64_table[4 * chksum_char + 84];
        if (v7 != -1)
        {
            switch (indicator)
            {
            case 0:
                v6 = v7;
                indicator = 1;
                break;
            case 1:
                if (res_len <= 511)
                    v6 = (v7 >> 4) & 3 | 4 * v6;
                indicator = 2;
                if (res_len <= 511)
                    *(decoded_chksum + res_len++) = v6;
                v6 = v7;
                break;
            case 2:
                if (res_len <= 511)
                    v6 = (v7 >> 2) & 0xF | 16 * v6;
                indicator = 3;
                if (res_len <= 511)
                    *(decoded_chksum + res_len++) = v6;
                v6 = v7;
                break;
            case 3:
                if (res_len <= 511)
                {
                    v8 = v7 | (v6 << 6);
                    indicator = 0;
                    v6 = v7;
                    *(decoded_chksum + res_len++) = v8;
                }
                else
                {
                    v6 = v7;
                    indicator = 0;
                }
                break;
            default:
                v6 = v7;
                break;
            }
        }
        v9 = (chksum_now_addr++)[1];
        chksum_char = v9;
    } while (v9);

    // Must be 28
    return res_len;
}

const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(int argc, char const *argv[])
{
    const char *a = "BwmP0Gn1XFpXNCJ8+MoU5ghk5cfyCavindicatorR9fTA==";
    unsigned char *b = (unsigned char *)calloc(1, 0x50);

    puts(a);
    int len = chksum_decode(a, b);

    printf("Decode length: %d\n", len);
    for (int i = 0; i < 0x50; i++)
    {
        printf("%02x ", b[i]);
        if ((i + 1) % 16 == 0)
            putchar('\n');
    }

    free(b);
    return 0;
}

#endif
