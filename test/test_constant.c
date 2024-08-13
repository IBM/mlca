// SPDX-License-Identifier: Apache-2.0
#include <memory.h>
#include "random_default.h"
#include <stdio.h>
#include <mlca2.h>
#include <stdlib.h>

#if defined(MLCA_NO_VALGRIND)
#include <stdio.h>
#define MLCA_MAKE_MEM_UNDEFINED(x, y) printf("VALGRIND constant-time tests not supported\n")
#define MLCA_MAKE_MEM_DEFINED(x, y) printf("VALGRIND constant-time tests not supported\n")
#else
#include <valgrind/memcheck.h>
#define MLCA_MAKE_MEM_UNDEFINED(x, y) VALGRIND_MAKE_MEM_UNDEFINED(x, y)
#define MLCA_MAKE_MEM_DEFINED(x, y) VALGRIND_MAKE_MEM_DEFINED(x, y)
#endif

static void randombytes_const_init(const mlca_random_t *ctx,
                                    unsigned char *entropy_input,
                                    unsigned char *personalization_string,
                                    int security_strength) {
    const mlca_random_t *rng = ctx->aux;
    mlca_randombytes_init(rng, entropy_input, personalization_string, security_strength);
}

static size_t randombytes_const (const mlca_random_t *ctx,
                              unsigned char* r,
                              size_t rbytes) {
    const mlca_random_t *rng = ctx->aux;
    int res = mlca_randombytes(rng, r, rbytes);
    MLCA_MAKE_MEM_UNDEFINED(r, rbytes);
    return res;
}

const mlca_random_t random_default_const = {
        .name = "random_default_const",
        .randombytes_init = randombytes_const_init,
        .randombytes = randombytes_const,
        .aux = &RANDOM_DEFAULT
};

int test_kem_constant(mlca_ctx_t * ctx) {

    int rc = 0;

    size_t pkLen = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen = mlca_kem_crypto_secretkeybytes(ctx);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(ctx);
    size_t ssLen = mlca_kem_crypto_bytes(ctx);

    unsigned char* pk3    = mlca_calloc(pkLen, 1);
    unsigned char* sk3    = mlca_calloc(skLen, 1);
    unsigned char* ct     = mlca_calloc(ctLen, 1);
    unsigned char* ss     = mlca_calloc(ssLen, 1);
    unsigned char* ss_rec = mlca_calloc(ssLen, 1);

    rc = mlca_set_rng(ctx, &random_default_const);
    if (rc) goto end;

    rc = mlca_kem_keygen(ctx, pk3, sk3);
    if (rc) goto end;

    MLCA_MAKE_MEM_DEFINED(pk3, pkLen);

    rc = mlca_kem_enc(ctx, ct, ss, pk3);
    if (rc) goto end;

    rc = mlca_kem_dec(ctx, ss_rec, ct, sk3);
    if ( rc ) goto end;

    MLCA_MAKE_MEM_DEFINED(sk3, skLen);
    MLCA_MAKE_MEM_DEFINED(ct, ctLen);
    MLCA_MAKE_MEM_DEFINED(ss, ssLen);
    MLCA_MAKE_MEM_DEFINED(ss_rec, ssLen);

    int eq = !memcmp(ss, ss_rec, mlca_kem_crypto_bytes(ctx));

    if (!eq) rc = 1;

    end:
    free(pk3);
    free(sk3);
    free(ct);
    free(ss);
    free(ss_rec);
    return rc;
}

static int test_sig_constant_int(mlca_ctx_t * ctx, int neg) {

    int rc = 0;

    size_t pkLen  = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen  = mlca_sig_crypto_secretkeybytes(ctx);
    size_t sigLen = mlca_sig_crypto_bytes(ctx);
    size_t mLen   = 32;

    unsigned char* pk  = mlca_calloc(pkLen, 1);
    unsigned char* sk  = mlca_calloc(skLen, 1);
    unsigned char* sig = mlca_calloc(sigLen, 1);
    unsigned char* m   = mlca_calloc(mLen, 1);

    rc = mlca_set_rng(ctx, &random_default_const);
    if (rc) goto end;

    rc = mlca_sig_keygen(ctx, pk, sk);
    if (rc) goto end;

    rc = mlca_sig_sign(ctx, sig, &sigLen, m, mLen, sk);
    if (rc) goto end;

    if (neg)
        m[0] = ~m[0];

    int sigok = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);

    MLCA_MAKE_MEM_DEFINED(&sigok, sizeof sigok);

    if (!sigok && !neg) {
        rc = 1;
        goto end;
    } else if (sigok && neg) {
        rc = 1;
        goto end;
    }

    MLCA_MAKE_MEM_DEFINED(pk, pkLen);
    MLCA_MAKE_MEM_DEFINED(sk, skLen);
    MLCA_MAKE_MEM_DEFINED(sig, sigLen);
    MLCA_MAKE_MEM_DEFINED(m, mLen);

    end:
    free(pk);
    free(sk);
    free(sig);
    free(m);
    return rc;
}

int test_sig_constant(mlca_ctx_t * ctx) {

    int rc = 0;

    rc = test_sig_constant_int(ctx, 0);
    if (rc) goto end;

    rc = test_sig_constant_int(ctx, 1);
    if (rc) goto end;

    end:
    return rc;
}