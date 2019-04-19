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

#ifndef _PHI_H
#define _PHI_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define A1A2_CFG_SIZE (0x10400u)
#define B1_CFG_SIZE (0x10600u)

// phi_aes.c
unsigned char *gen_phi_key();
unsigned char *phi_config_decode(const char *file_path, unsigned char *user_key, size_t config_size);

// phi_base64.c
void print_hex(unsigned char *data, size_t len);
void print_b64(unsigned char *digest, size_t b64_len);
void Base64Decode(const char *b64message, unsigned char **buffer, size_t *length);
void Base64Encode(const unsigned char *buffer, size_t length, char **b64text);

#endif
