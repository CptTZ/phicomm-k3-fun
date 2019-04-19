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
#define CHKSUM_LEN_VAL (0x14u)

char *get_chksum_infile(BYTE *data)
{
    size_t len = strlen("Checksum=");
    BYTE *data_init = data + 1024 + len;
    size_t chksum_len = strlen((char *)data_init);
    char *res = (char *)calloc(1, chksum_len);
    memcpy(res, data_init, chksum_len - 1); // Ignore last LF
    return res;
}

int proc(char *path, size_t cfg_size)
{
    printf("File path: %s (%lu)\n", path, cfg_size);
    BYTE *phi_key = gen_phi_key();
    BYTE *file_content = phi_config_decode(path, phi_key, cfg_size);

    if (file_content == NULL)
    {
        free(phi_key);
        return -1;
    }

    char *checksum_in_file = get_chksum_infile(file_content);
    printf("In-file checksum: %s\n", checksum_in_file);
    BYTE *chksum_file_dec;
    size_t dec_len = 0;
    Base64Decode(checksum_in_file, &chksum_file_dec, &dec_len);

    if (dec_len != 28)
    {
        puts("In file checksum length not 28!");
    }

    BYTE *hmac_key = (BYTE *)malloc(KEY_SIZE);
    BYTE *digest = (BYTE *)malloc(KEY_SIZE);
    memset(hmac_key, 0, KEY_SIZE);

    memset((void *)(file_content + 1024), 0, 0x200u);
    snprintf((char *)file_content + 1024, 0x200u, "%s\n", "NVRAMTemporaryChecksumFiller");
    memset(digest, 0, KEY_SIZE);

    hmac_sha1(file_content, cfg_size, hmac_key, 32, digest);

    if (memcmp(digest, chksum_file_dec, CHKSUM_LEN_VAL))
    {
        puts("Checksum mismatch!");
    }
    print_hex(digest, CHKSUM_LEN_VAL);
    print_b64(digest, CHKSUM_LEN_VAL);

    free(phi_key);
    free(digest);
    free(file_content);
    free(hmac_key);
    free(checksum_in_file);
    free(chksum_file_dec);
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
