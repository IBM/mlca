// SPDX-License-Identifier: Apache-2.0
#include <mlca2.h>
#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include <inttypes.h>
#include <stdlib.h>
#include <keccak.h>
#include <assert.h>

const uint8_t tv_sha3_512_in[] = {
    0xd4, 0x35, 0x22, 0x21, 0x02, 0x36, 0xc6, 0x7e, 0x49, 0x81, 0xbf, 0x3f, 0x44, 0x1b, 0x94, 0x1c, 0xd5, 0x2c, 0x57, 0x32, 0xb9, 0x4a, 0xd7, 0x61, 0x60, 0xfa, 0x16, 0xf3, 0xfc, 0x74, 0xfe, 0x7e, 0xd9, 0xa7, 0x4f, 0x0b, 0xec, 0x7d, 0xdc, 0x77, 0xae, 0x60, 0xf7, 0x1a, 0x2b, 0xfd, 0x2a, 0xa7, 0x55, 0x48, 0x28, 0x53, 0x9f, 0xc0, 0x02, 0x3a, 0xc7, 0xf4, 0x9e, 0xfe, 0xf3, 0x46, 0x66, 0xb1, 0x00, 0xef, 0x3d, 0xf5, 0x17, 0x43, 0xb7, 0x61, 0x81, 0x36, 0x89, 0x27, 0xbc, 0x20, 0x3e, 0xf4, 0xce, 0xbd, 0x2c, 0x18, 0xd9, 0x78, 0xa7, 0xe7, 0xf0, 0xe9, 0x74, 0x5f, 0x29, 0x9c, 0x80, 0x0b, 0xf3, 0x14, 0xd2, 0x26, 0xaa, 0x0f, 0xbf, 0x04, 0x69, 0x0c, 0x5d, 0xae, 0x20, 0x0b, 0x3a, 0xcd, 0xe6, 0x94, 0x4d, 0xc9, 0x90, 0xfa, 0x2c, 0x31, 0x82, 0xe1, 0x80, 0x5e, 0xc5, 0xfe, 0xb6, 0x53, 0x5a, 0x1e, 0xf8, 0xe8, 0xce, 0x6a, 0x5c, 0x28, 0x0f, 0xe9, 0x5b, 0xf7, 0x7e, 0x46, 0x84, 0xf8, 0x45, 0xd4, 0x71, 0xad, 0xeb, 0xcf, 0xfb, 0xe0, 0x26, 0xe5, 0xaa, 0x42, 0xf0, 0xf4, 0x6f, 0x53, 0xdc, 0x16, 0x96, 0x81, 0xab, 0xdb, 0xf6, 0x94, 0x1a, 0xd5, 0x6b, 0x49, 0xff, 0x5a, 0x86, 0x3d, 0x94, 0x85, 0x82, 0x0d, 0x13, 0x7e, 0x7a, 0xbc, 0x83, 0xfb, 0xda, 0x55, 0xd1, 0x07, 0x14, 0xd1, 0x22, 0x03, 0x94, 0x3a, 0x68, 0xea, 0xf5, 0x11, 0x33, 0xd9, 0x75, 0xee, 0xcb, 0xce, 0xa6, 0x66, 0x7b, 0xaf, 0x67, 0x31, 0x2f, 0x8f, 0x13, 0x8c, 0x42, 0x2e, 0xf8, 0xdd, 0x91, 0xbe, 0x0b, 0x96, 0xd4, 0xed, 0xd9, 0x5b, 0x2e, 0x1f, 0xc1, 0x67, 0x02, 0xfb, 0x61, 0x2c, 0x09, 0x2a, 0x4e, 0x39, 0xa1, 0x5b, 0x08, 0x61, 0x68, 0x8b, 0x2d, 0x1a, 0x0a, 0x83, 0xec, 0x23, 0x57, 0xa2, 0xbd, 0x6a, 0x99, 0xdc, 0x4f, 0x2c, 0x24, 0x03, 0xc2, 0x5e, 0x2e, 0x45, 0x17, 0x4c, 0xe1, 0xf7, 0xe5, 0x80, 0xaf, 0x91, 0x4d, 0xe5, 0xe6, 0xf9, 0x2f, 0x2c, 0x84, 0x04, 0x9e, 0x6f, 0x4c, 0x3a, 0x92, 0x14, 0x19, 0xd9, 0xdd, 0xf5, 0x73, 0x1d, 0x61, 0xbd, 0x60, 0xbf, 0x7f, 0x95, 0x7c, 0xbb, 0xd3, 0x01, 0x4c, 0x57, 0x1e, 0x04, 0xd0, 0x61, 0x83, 0x8b, 0x57, 0xb8, 0xf7, 0x09, 0x97, 0x0e, 0xf3, 0x5e, 0xfd, 0xeb, 0x6b, 0xfd, 0x42, 0xf5, 0x04, 0x4e, 0x3f, 0x70, 0x82, 0x51, 0x02, 0x01, 0x7f, 0x85, 0x21, 0xb7, 0x63, 0x08, 0x4e, 0x4b, 0x90, 0xff, 0x2c, 0xa7, 0xdd, 0x38, 0x62, 0xa6, 0x46, 0x0e, 0xed, 0x1b, 0xe2, 0x8d, 0xba, 0x14, 0x15, 0xd7, 0x74, 0x60, 0x06, 0xc6, 0x9b, 0x4e, 0x53, 0xd3, 0xd6, 0xb8, 0x04, 0x37, 0x8a, 0x40, 0xbe, 0x50, 0xab, 0xda, 0x39, 0x45, 0xd2, 0x8b, 0xf4, 0xed, 0x90, 0x70, 0x28, 0xed, 0x03, 0x01, 0xfa, 0x21, 0xa6, 0x97, 0xf4, 0x3e, 0x6d, 0x2c, 0xb6, 0xb5, 0x12, 0x62, 0xe9, 0xda, 0xa9, 0xc7, 0x75, 0x45, 0x7b, 0x58, 0xf4, 0x78, 0x11, 0x44, 0x66, 0xc3, 0x8f, 0xf2, 0x26, 0x65, 0x44, 0x44, 0x1d, 0xf4, 0x7e, 0x1e, 0x35, 0xff, 0xa3, 0x22, 0x10, 0xf1, 0x7d, 0xbe, 0xfb, 0x38, 0xd6, 0x69, 0x1d, 0xa7, 0x45, 0x29, 0xf4, 0x19, 0x47, 0x59, 0x03, 0x58, 0x91, 0xa9, 0xc4, 0x3d, 0xa5, 0x66, 0xe4, 0x18, 0xa4, 0xfc, 0xaf, 0x51, 0x63, 0xb9, 0xca, 0x50, 0xc0, 0xd3, 0x20, 0x9b, 0x37, 0xad, 0x1e, 0x3e, 0xb0, 0x56, 0x23, 0x70, 0x9b, 0x52, 0x32, 0x73, 0x3f, 0x9e, 0xeb, 0xbc, 0x4f, 0xee, 0xb9, 0x54, 0xbf, 0x39, 0x4c, 0x7e, 0xd5, 0x77, 0x4a, 0x9a, 0x83, 0xaa, 0x41, 0x49, 0xf4, 0x1b, 0xe1, 0xd2, 0x65, 0xe6, 0x68, 0xc5, 0x36, 0xb8, 0x5d, 0xde, 0x41, 0xd8, 0x81, 0x2b, 0x6a, 0x64, 0x03, 0x71, 0x77, 0xde, 0xf3, 0xcd, 0x23, 0xe7, 0xf9, 0x97, 0x6d, 0x49, 0x47, 0x8b, 0x36, 0x3b, 0xcc, 0x2b, 0x0b, 0xe1, 0xaa, 0x5f, 0x40, 0x13, 0xeb, 0x5f, 0x3e, 0x5f, 0x6f, 0xd2, 0x1d, 0x51, 0x29, 0x38, 0x76, 0xf1, 0x8c, 0x85, 0x72, 0x8e, 0x3f, 0x0e, 0x27, 0xba, 0x18, 0xa9, 0x25, 0x96, 0x48, 0x10, 0x4b, 0x50, 0xd3, 0x87, 0xe0, 0xe9, 0x44, 0xbf, 0xdf, 0x3c, 0x9e, 0xf9, 0x91, 0x3c, 0x95, 0x6e, 0x61, 0x7d, 0xfe, 0xef, 0xed, 0xf6, 0x85, 0xc9, 0x59, 0x05, 0x9e, 0xeb, 0xe8, 0xb3, 0xbe, 0x4b, 0xcd, 0x3a, 0xca, 0x85, 0x3e, 0xc4, 0xd0, 0xc5, 0xcb, 0x76, 0xf5, 0xe8, 0xee, 0xad, 0xae, 0xde, 0xe3, 0x87, 0x33, 0x53, 0xb9, 0xa6, 0x31, 0x8e, 0xaa, 0x30, 0xbf, 0x99, 0xa8, 0x1a, 0x94, 0xa2, 0x38, 0xa7, 0x77, 0xa1, 0x83, 0x2b, 0xf6, 0x3b, 0xaa, 0x15, 0x5b, 0xe6, 0x5b, 0x2c, 0xdc, 0x4f, 0xa2, 0x19, 0x12, 0xf9, 0x01, 0x26, 0xad, 0x26, 0xc2, 0x45, 0x65, 0xfa, 0x8c, 0x54, 0x34, 0xde, 0x35, 0x9f, 0xc2, 0x23, 0xd7, 0xa7, 0x21, 0xe7, 0x26, 0x22, 0xba, 0x3d, 0x00, 0x42, 0x87, 0x88, 0x46, 0x3a, 0x83, 0x28, 0xeb, 0xff, 0x5f, 0x59, 0x4a, 0x4b, 0x77, 0x57, 0xbd, 0xe8, 0x04, 0xc7, 0x6b, 0x2b, 0x93, 0x52, 0x61, 0xbf, 0xb6, 0x93, 0xe5, 0xa3, 0xf9, 0x33, 0x06, 0x76, 0x17, 0x52, 0x78, 0xf3, 0x6e, 0x29, 0x9f, 0xb8, 0xb1, 0xee, 0xea, 0x4b, 0xdd, 0xf8, 0x62, 0x5e, 0x6e, 0x24, 0x83, 0x52, 0xd2, 0x77, 0x4a, 0xfb, 0x1e, 0x05, 0x8f, 0xa3, 0x00, 0x11, 0x95, 0x51, 0xf4, 0x75, 0xe0, 0x4b, 0xbb, 0x45, 0x46, 0xd9, 0x0a, 0xaf, 0x49, 0x4c, 0x7f, 0x25, 0xa4, 0x3f, 0xd8, 0xbf, 0x24, 0x1d, 0x67, 0xda, 0xb9, 0xe3, 0xc1, 0x06, 0xcd, 0x27, 0xb7, 0x1f, 0xd4, 0x5a, 0x87, 0xb9, 0x25, 0x4a, 0x53, 0xc1, 0x08, 0xea, 0xd1, 0x62, 0x10, 0x56, 0x45, 0x26, 0xab, 0x12, 0xac, 0x5e, 0xf7, 0x92, 0x3a, 0xc3, 0xd7, 0x00, 0x07, 0x5d, 0x47, 0x39, 0x06, 0xa4, 0xec, 0x19, 0x36, 0xe6, 0xef, 0xf8, 0x1c, 0xe8, 0x0c, 0x74, 0x70, 0xd0, 0xe6, 0x71, 0x17, 0x42, 0x9e, 0x5f, 0x51, 0xca, 0xa3, 0xbc, 0x34, 0x7a, 0xcc, 0xd9, 0x59, 0xd4, 0xa4, 0xe0, 0xd5, 0xea, 0x05, 0x16, 0x6a, 0xc3, 0xe8, 0x5e, 0xff, 0x01, 0x7b, 0xff, 0x4e, 0xc1, 0x74, 0xa6, 0xdd, 0xc3, 0xa5, 0xaf, 0x2f, 0xcb, 0xd1, 0xa0, 0x3b, 0x46, 0xbf, 0xf6, 0x1d, 0x31, 0x8c, 0x25, 0x0c, 0x37, 0x45, 0xda, 0x8c, 0x19, 0xb6, 0x83, 0xe4, 0x53, 0x7c, 0x11, 0xd3, 0xfd, 0x62, 0xfc, 0x7f, 0xef, 0xea, 0x88, 0xae, 0x28, 0x29, 0x48, 0x38, 0x71, 0xd8, 0xe0, 0xbd, 0x3d, 0xa9, 0x0e, 0x93, 0xd4, 0xd7, 0xec, 0x02, 0xb0, 0x01, 0x6f, 0xb4, 0x27, 0x38, 0x34, 0x67, 0x4b, 0x57, 0x7c, 0xe5, 0x0f, 0x92, 0x75, 0x36, 0xab, 0x52, 0xbb, 0x14, 0x41, 0x41, 0x1e, 0x9f, 0xc0, 0xa0, 0xa6, 0x52, 0x09, 0xe1, 0xd4, 0x36, 0x50, 0x72, 0x2b, 0x55, 0xc5, 0xd7, 0xef, 0x72, 0x74, 0xfb, 0x2d, 0xf7, 0x6a, 0xc8, 0xfb, 0x2f, 0x1a, 0xf5, 0x01, 0xb5, 0xff, 0x1f, 0x38, 0x2d, 0x82, 0x1c, 0xf2, 0x31, 0x1d, 0x8c, 0x1b, 0x8e, 0xc1, 0xb0, 0xbe, 0xb1, 0x75, 0x80, 0xca, 0x5c, 0x41, 0xf7, 0x17, 0x9e, 0x4a, 0xb2, 0xa4, 0x01, 0x3e, 0xb9, 0x23, 0x05, 0xf2, 0x9d, 0xb7, 0xcd, 0x4a, 0xc3, 0xfc, 0x19, 0x5a, 0xff, 0x48, 0x74, 0xca, 0x64, 0x30, 0xaf, 0x7f, 0x5b, 0x4e, 0x8d, 0x77, 0xf3, 0x42, 0xc0, 0xf5, 0x78, 0xf7, 0x14, 0xdf, 0x47, 0x28, 0xeb, 0x64, 0xe0
};
const uint8_t tv_sha3_512_out[64] = {
    0x3e, 0x2f, 0xd5, 0x1b, 0x40, 0x24, 0x08, 0x07, 0x3d, 0xe5, 0xe6, 0x65, 0xb8, 0x1c, 0xd8, 0x20, 0x52, 0xa1, 0x18, 0x05, 0x34, 0x51, 0x32, 0xa8, 0x0f, 0x76, 0x9f, 0x95, 0x74, 0x77, 0x90, 0x81, 0xde, 0x86, 0x04, 0xf9, 0xa4, 0x06, 0x99, 0xdb, 0x34, 0x73, 0xfb, 0xa4, 0x80, 0x7e, 0xb1, 0x28, 0x7d, 0xc2, 0xeb, 0x3e, 0x59, 0x76, 0x3f, 0x21, 0xd8, 0x17, 0x37, 0xb0, 0xac, 0x69, 0x15, 0xf4
};

const uint8_t tv_sha3_256_in[] = {
    0xb1, 0xca, 0xa3, 0x96, 0x77, 0x1a, 0x09, 0xa1, 0xdb, 0x9b, 0xc2, 0x05, 0x43, 0xe9, 0x88, 0xe3, 0x59, 0xd4, 0x7c, 0x2a, 0x61, 0x64, 0x17, 0xbb, 0xca, 0x1b, 0x62, 0xcb, 0x02, 0x79, 0x6a, 0x88, 0x8f, 0xc6, 0xee, 0xff, 0x5c, 0x0b, 0x5c, 0x3d, 0x50, 0x62, 0xfc, 0xb4, 0x25, 0x6f, 0x6a, 0xe1, 0x78, 0x2f, 0x49, 0x2c, 0x1c, 0xf0, 0x36, 0x10, 0xb4, 0xa1, 0xfb, 0x7b, 0x81, 0x4c, 0x05, 0x78, 0x78, 0xe1, 0x19, 0x0b, 0x98, 0x35, 0x42, 0x5c, 0x7a, 0x4a, 0x0e, 0x18, 0x2a, 0xd1, 0xf9, 0x15, 0x35, 0xed, 0x2a, 0x35, 0x03, 0x3a, 0x5d, 0x8c, 0x67, 0x0e, 0x21, 0xc5, 0x75, 0xff, 0x43, 0xc1, 0x94, 0xa5, 0x8a, 0x82, 0xd4, 0xa1, 0xa4, 0x48, 0x81, 0xdd, 0x61, 0xf9, 0xf8, 0x16, 0x1f, 0xc6, 0xb9, 0x98, 0x86, 0x0c, 0xbe, 0x49, 0x75, 0x78, 0x0b, 0xe9, 0x3b, 0x6f, 0x87, 0x98, 0x0b, 0xad, 0x0a, 0x99, 0xaa, 0x2c, 0xb7, 0x55, 0x6b, 0x47, 0x8c, 0xa3, 0x5d, 0x1f, 0x37, 0x46, 0xc3, 0x3e, 0x2b, 0xb7, 0xc4, 0x7a, 0xf4, 0x26, 0x64, 0x1c, 0xc7, 0xbb, 0xb3, 0x42, 0x5e, 0x21, 0x44, 0x82, 0x03, 0x45, 0xe1, 0xd0, 0xea, 0x5b, 0x7d, 0xa2, 0xc3, 0x23, 0x6a, 0x52, 0x90, 0x6a, 0xcd, 0xc3, 0xb4, 0xd3, 0x4e, 0x47, 0x4d, 0xd7, 0x14, 0xc0, 0xc4, 0x0b, 0xf0, 0x06, 0xa3, 0xa1, 0xd8, 0x89, 0xa6, 0x32, 0x98, 0x38, 0x14, 0xbb, 0xc4, 0xa1, 0x4f, 0xe5, 0xf1, 0x59, 0xaa, 0x89, 0x24, 0x9e, 0x7c, 0x73, 0x8b, 0x3b, 0x73, 0x66, 0x6b, 0xac, 0x2a, 0x61, 0x5a, 0x83, 0xfd, 0x21, 0xae, 0x0a, 0x1c, 0xe7, 0x35, 0x2a, 0xde, 0x7b, 0x27, 0x8b, 0x58, 0x71, 0x58, 0xfd, 0x2f, 0xab, 0xb2, 0x17, 0xaa, 0x1f, 0xe3, 0x1d, 0x0b, 0xda, 0x53, 0x27, 0x20, 0x45, 0x59, 0x80, 0x15, 0xa8, 0xae, 0x4d, 0x8c, 0xec, 0x22, 0x6f, 0xef, 0xa5, 0x8d, 0xaa, 0x05, 0x50, 0x09, 0x06, 0xc4, 0xd8, 0x5e, 0x75, 0x67
};
const uint8_t tv_sha3_256_out[32] = {
    0xcb, 0x56, 0x48, 0xa1, 0xd6, 0x1c, 0x6c, 0x5b, 0xda, 0xcd, 0x96, 0xf8, 0x1c, 0x95, 0x91, 0xde, 0xbc, 0x39, 0x50, 0xdc, 0xf6, 0x58, 0x14, 0x5b, 0x8d, 0x99, 0x65, 0x70, 0xba, 0x88, 0x1a, 0x05
};

static int test_sha3_512() {

    int rc = 0;
    uint8_t out[64];

    Keccak_state state;

    sha3_512(out, tv_sha3_512_in, sizeof(tv_sha3_512_in));
    rc = memcmp(tv_sha3_512_out, out, 64);
    print_hex("SHA3_512 vec", out, 64, 1);
    if (rc) goto err;

    for (int i = 1; i <= sizeof(tv_sha3_512_in); ++i) {
        int updates = sizeof(tv_sha3_512_in) / i;
        int remChunk = sizeof(tv_sha3_512_in) % i;
        assert(updates*i + remChunk == sizeof(tv_sha3_512_in));
        sha3_512_init(&state);
        int j;
        for (j = 0; j < updates; ++j) {
            sha3_512_update(&state, tv_sha3_512_in + j*i, i);
        }
        if (remChunk)
            sha3_512_update(&state, tv_sha3_512_in + j*i, remChunk);
        sha3_512_final(out, &state);

        rc = memcmp(tv_sha3_512_out, out, 64);
        if (rc) {
            printf("Failed: i = %d\n", i);
            print_hex("SHA3_512 vec", out, 64, 1);
            goto err;
        }
    }

    sha3_512_init(&state);
    sha3_512_update(&state, tv_sha3_512_in, 10);
    sha3_512_update(&state, tv_sha3_512_in + 10, sizeof(tv_sha3_512_in) - 10);
    sha3_512_final(out, &state);

    rc = memcmp(tv_sha3_512_out, out, 64);
    print_hex("SHA3_512 vec", out, 64, 1);
    if (rc) goto err;

    err:
    return rc;
}

static int test_sha3_256() {

    int rc = 0;
    uint8_t out[32];

    
    sha3_256(out, tv_sha3_256_in, sizeof(tv_sha3_256_in));
    rc = memcmp(tv_sha3_256_out, out, 32);

    print_hex("SHA3_256 vec", out, 32, 1);
    return rc;
}

static int test_keccak(const char* digname) {

    if (!strcmp(digname, "SHA3-512")) 
        return test_sha3_512();
    else if(!strcmp(digname, "SHA3-256"))
        return test_sha3_256();

    return 1;
}


int main(int argc, char *argv[]) {

    int rc = 0;

    printf("Argc: %d, argv[1] = %s\n", argc, argv[1]);
    rc = test_keccak(argv[1]);

    if (rc == 0) {
        printf("Success\n");
    }
    return rc;
}