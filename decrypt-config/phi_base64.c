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

static const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int chksum_decode(unsigned char *chksum_str, unsigned char *decoded_chksum)
{
    int res_len = 0;
    unsigned char v5, v6, v8, v9 = 0;
    unsigned char v7;
    if (!chksum_str)
        return 0;
    unsigned char chksum_str_ptr = *chksum_str;
    unsigned char *chksum_str_addr = chksum_str;
    v5 = 0;
    v6 = 0;
    do
    {
        v7 = b64_table[4 * chksum_str_ptr + 84];
        if (v7 != -1)
        {
            switch (v5)
            {
            case 0:
                v6 = v7;
                v5 = 1;
                break;
            case 1:
                if (res_len <= 511)
                    v6 = (v7 >> 4) & 3 | 4 * v6;
                v5 = 2;
                if (res_len <= 511)
                    *(decoded_chksum + res_len++) = v6;
                v6 = v7;
                break;
            case 2:
                if (res_len <= 511)
                    v6 = (v7 >> 2) & 0xF | 16 * v6;
                v5 = 3;
                if (res_len <= 511)
                    *(decoded_chksum + res_len++) = v6;
                v6 = v7;
                break;
            case 3:
                if (res_len <= 511)
                {
                    v8 = v7 | (v6 << 6);
                    v5 = 0;
                    v6 = v7;
                    *(decoded_chksum + res_len++) = v8;
                }
                else
                {
                    v6 = v7;
                    v5 = 0;
                }
                break;
            default:
                v6 = v7;
                break;
            }
        }
        v9 = (chksum_str_addr++);
        printf("%02x ",v9);
        chksum_str_ptr = v9;
    } while (v9);

    return res_len;
}

int main(int argc, char const *argv[])
{
    unsigned char* a="BwmP0Gn1XFpXNCJ8+MoU5ghk5cfyCavV5R9fTA==";
    unsigned char* b=calloc(1,0x50);
    chksum_decode(a,b);
    puts(a);
    for(int i=0;i<0x50;i++) {
        printf("%02x ", b[i]);
    }
    return 0;
}
