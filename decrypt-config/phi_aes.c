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
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#define A1A2_SIZE (0x10400u)
#define B1_SIZE (0x10600u)

void genkey(unsigned char *s)
{
    int c = 0;
    int i = 0;
    do
    {
        c = 4 * i + 15 - 25 * (((signed int)((unsigned long long)(1374389535LL * (4 * i + 15)) >> 32) >> 3) - ((4 * i + 15) >> 31)) + 'a';
        if (!(i & 3))
            c = 4 * i + 15 - 25 * (((signed int)((unsigned long long)(1374389535LL * (4 * i + 15)) >> 32) >> 3) - ((4 * i + 15) >> 31)) + 'A';
        s[i] = c;
        ++i;
    } while (i != 16);
    s[16] = 0;
}

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
        config_size = A1A2_SIZE;
    }
    else if (strncmp(argv[2], "b1", 2) == 0)
    {
        config_size = B1_SIZE;
    }
    else
    {
        print_help();
        return -1;
    }

    unsigned char *user_key = malloc(17);
    genkey(user_key);
    printf("User key: %s\n", user_key);
    printf("Backup size: %d\n", config_size);

    void *file_content = malloc(config_size);
    void *decoded_msg_memory = malloc(config_size);
    AES_KEY aes;
    if (AES_set_decrypt_key(user_key, 128, &aes) < 0)
    {
        puts("Error: Key");
        goto FINALIZE;
    }

    // Open file
    FILE *fp = fopen(argv[1], "rb");
    if (!fp)
    {
        puts("Error: Open");
        goto FINALIZE;
    }
    if (fread(file_content, config_size, 1, fp) != 1)
    {
        puts("Error: Read");
        goto FINALIZE;
    }
    fclose(fp);

    // Decrypt
    size_t file_counter = 0;
    puts("Decrypting...");
    do
    {
        char *ori = (char *)(file_content) + file_counter;
        char *final = (char *)(decoded_msg_memory) + file_counter;
        file_counter += 16;
        AES_ecb_encrypt(ori, final, &aes, AES_DECRYPT);
    } while (file_counter != config_size);

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
    free(file_content);
    free(decoded_msg_memory);
    free(user_key);
    return 0;
}
