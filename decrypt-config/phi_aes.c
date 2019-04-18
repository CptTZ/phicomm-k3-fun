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

#include <openssl/aes.h>

#define _PK_SIZE (17)

// This key is some what fixed, just remember to free it...
unsigned char *gen_phi_key()
{
    unsigned char *s = (unsigned char *)calloc(1, _PK_SIZE);
    int c = 0;
    int i = 0;
    do
    {
        if (!(i & 3))
            c = 4 * i + 15 - 25 * (((signed int)((unsigned long long)(1374389535LL * (4 * i + 15)) >> 32) >> 3) - ((4 * i + 15) >> 31)) + 'A';
        else
            c = 4 * i + 15 - 25 * (((signed int)((unsigned long long)(1374389535LL * (4 * i + 15)) >> 32) >> 3) - ((4 * i + 15) >> 31)) + 'a';
        s[i++] = c;
    } while (i != 16);
    return s;
}

unsigned char *phi_config_decode(const char *file_path, unsigned char *user_key, size_t config_size)
{
    AES_KEY aes;
    if (AES_set_decrypt_key(user_key, 128, &aes) < 0)
    {
        puts("Error: Key");
        return NULL;
    }

    // Open file
    FILE *fp = fopen(file_path, "rb");
    if (!fp)
    {
        puts("Error: Open");
        return NULL;
    }
    // Read file
    unsigned char *file_content = (unsigned char *)malloc(config_size);
    if (fread(file_content, config_size, 1, fp) != 1)
    {
        puts("Error: Read");
        free(file_content);
        return NULL;
    }
    fclose(fp);

    unsigned char *decoded_msg = (unsigned char *)malloc(config_size);
    // Decrypt
    size_t file_counter = 0;
    puts("Decrypting config file...");
    do
    {
        unsigned char *ori = (file_content) + file_counter;
        unsigned char *final = (decoded_msg) + file_counter;
        file_counter += 16;
        AES_ecb_encrypt(ori, final, &aes, AES_DECRYPT);
    } while (file_counter != config_size);

    free(file_content);
    return decoded_msg;
}

#ifdef AES_DEBUG

void print_help()
{
    puts("Useage: ./phi_aes [path to config.dat] [a1,b1]");
    puts("  Example: ./phi_aes /mnt/e/config.dat a1");
}

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        print_help();
        return -1;
    }

    size_t config_size;
    if (strncmp(argv[2], "a1", 2) == 0)
    {
        config_size = A1A2_CFG_SIZE;
    }
    else if (strncmp(argv[2], "b1", 2) == 0)
    {
        config_size = B1_CFG_SIZE;
    }
    else
    {
        print_help();
        return -1;
    }

    unsigned char *user_key = gen_phi_key();
    printf("User key: %s\n", user_key);
    printf("Backup size: %lu\n", config_size);

    unsigned char *decoded_msg_memory = phi_config_decode(argv[1], user_key, config_size);

    // Write out
    char buf[30];
    sprintf(buf, "config_%s_decrypted.dat", argv[2]);
    FILE *fp1 = fopen(buf, "w");
    if (!fp1)
    {
        puts("Error: Open Output");
        goto FINALIZE;
    }
    fwrite(decoded_msg_memory, config_size, 1, fp1);
    fclose(fp1);

FINALIZE:
    puts("Cleanning...");
    free(decoded_msg_memory);
    free(user_key);
    return 0;
}

#endif
