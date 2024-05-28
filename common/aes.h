// SPDX-License-Identifier: Apache-2.0

#ifndef AES_H
#define AES_H

#include <stdint.h>

void AES_ECB_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output);

#endif
