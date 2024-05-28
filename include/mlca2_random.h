// SPDX-License-Identifier: Apache-2.0
/**
 * @file mlca2_random.h
 * 
 * MLCA random number generator API.
 * 
 */

#ifndef MLCA_RANDOM_H
#define MLCA_RANDOM_H

#include <stddef.h>

typedef struct mlca_random_t mlca_random_t;

/**
 * Structure to hold RNG implementation.
 */
struct mlca_random_t {

    const char* name;

    void (*randombytes_init) (const mlca_random_t *ctx,
            unsigned char *entropy_input,
            unsigned char *personalization_string,
            int security_strength);
    size_t (*randombytes) (const mlca_random_t *ctx,
            unsigned char* r,
            size_t rbytes);

    const void* aux;
};

/**
 * Initialize the RNG
 * 
 * @param random RNG context to be initialized.
 * @param entropy_input Entropy input.
 * @param personalization_string Personalization string.
 * @param security_strength Security strength.
 */
static inline void mlca_randombytes_init(const mlca_random_t *random, unsigned char *entropy_input,
                                         unsigned char *personalization_string,
                                         int security_strength) {
    random->randombytes_init(random, entropy_input, personalization_string, security_strength);
}

/**
 * Generate random bytes.
 * 
 * @param random RNG context.
 * @param r Array to be filled with random bytes.
 * @param rbytes Number of random bytes. Max number of bytes per call may be limited to 256 bytes.
 * @return Number of random bytes generated.
 */
static inline size_t mlca_randombytes(const mlca_random_t *random, unsigned char* r, size_t rbytes) {
    return random->randombytes(random, r, rbytes);
}

#endif // MLCA_RANDOM_H
