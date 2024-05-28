// SPDX-License-Identifier: Apache-2.0
#ifndef __TEST_EXTRAS_H__
#define __TEST_EXTRAS_H__

#include <stdint.h>
#include <mlca2_int.h>
#include "random_default.h"

#if (TARGET_PLATFORM == TARGET_ARM || TARGET_PLATFORM == TARGET_ARM64 || TARGET_PLATFORM == TARGET_S390X)
#define print_unit printf("nsec\n");
#else
#define print_unit printf("cycles\n");
#endif

// Access system counter for benchmarking
int64_t cpucycles(void);
void print_hex(const char* title, const unsigned char* seq, size_t seqLen, int newline);

#endif
