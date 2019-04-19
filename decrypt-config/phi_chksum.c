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
#include "bcmcrypto/prf.h"

#define KEY_SIZE (0x50u)
#define VALID_BASE64 (28)

int proc(char *path, size_t cfg_size)
{
    unsigned char *phi_key = gen_phi_key();
    unsigned char *file_content = phi_config_decode(path, phi_key, cfg_size);

    if (file_content == NULL)
    {
        free(phi_key);
        return -1;
    }

    unsigned char *buf = (unsigned char *)malloc(KEY_SIZE);
    unsigned char *digest = (unsigned char *)malloc(KEY_SIZE);

    memset(file_content + 1024, 0, 0x200u);
    snprintf((char *)file_content + 1024, 0x200u, "%s\n", "NVRAMTemporaryChecksumFiller");

    memset(buf, 0, KEY_SIZE);
    memset(digest, 0, KEY_SIZE);

    hmac_sha1(file_content, cfg_size, buf, 32, digest);

    print_hex(digest, KEY_SIZE);
    print_b64(digest, VALID_BASE64);

    free(phi_key);
    free(digest);
    free(file_content);
    free(buf);
    return 0;
}

void print_help()
{
    puts("Useage: ./phi_chksum [path to original config] [a1 b1]");
    puts("  Example: ./phi_chksum /mnt/e/config.dat b1");
}

int main(int ac, char *av[])
{
    if (ac != 3)
    {
        print_help();
        return -1;
    }
    size_t cfg_size;
    if (strncmp(av[2], "a1", 2) == 0)
    {
        cfg_size = A1A2_CFG_SIZE;
    }
    else if (strncmp(av[2], "b1", 2) == 0)
    {
        cfg_size = B1_CFG_SIZE;
    }
    else
    {
        print_help();
        return -1;
    }

    return proc(av[1], cfg_size);
}
