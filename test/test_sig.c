// SPDX-License-Identifier: Apache-2.0
#include <mlca2.h>
#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include <inttypes.h>
#include <stdlib.h>
#include <pqalgs.h>
#include <crystals-oids.h>


int test_sig(const mlca_ctx_t * ctx) {

    int rc = 0;

    size_t pkLen  = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen  = mlca_sig_crypto_secretkeybytes(ctx);
    size_t sigLen = mlca_sig_crypto_bytes(ctx);
    size_t mLen   = 32;

    unsigned char* pk  = mlca_calloc(pkLen, 1);
    unsigned char* sk  = mlca_calloc(skLen, 1);
    unsigned char* sig = mlca_calloc(sigLen, 1);
    unsigned char* m   = mlca_calloc(mLen, 1);

    rc = mlca_sig_keygen(ctx, pk, sk);
    if (rc) goto end;

    printf("Sig keypair:\n");
    print_hex("pk", pk, pkLen, 1);
    print_hex("sk", sk, skLen, 1);

    rc = mlca_sig_sign(ctx, sig, &sigLen, m, mLen, sk);
    if (rc) goto end;

    printf("Sig sign:\n");
    print_hex("m", m, 32, 1);
    print_hex("sig", sig, sigLen, 1);

    int sigok = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);
    if (!sigok) {
        rc = 1;
        goto end;
    }

    m[0] = ~m[0];

    sigok = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);
    if (sigok) {
        rc = 1;
        goto end;
    }

    end:
    mlca_free(pk);
    mlca_secure_free(sk, skLen);
    mlca_free(sig);
    mlca_free(m);
    return rc;
}

int test_sig_encodings_minimal(mlca_ctx_t * ctx) {

    int rc = 0;

    size_t pkEncodedLen = 0;
    size_t skEncodedLen = 0;

    size_t pkLen = 0, pkRawLen = 0;
    size_t skLen = 0, skRawLen = 0;
    unsigned char *pk = 0;
    unsigned char *sk = 0;
    unsigned char *pkRaw = 0;
    unsigned char *skRaw = 0;
    int encodingIdx;

    const char* algname = mlca_algorithm_name(ctx);

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkRawLen = mlca_sig_crypto_publickeybytes(ctx);
    skRawLen = mlca_sig_crypto_secretkeybytes(ctx);

    pkRaw = mlca_calloc(pkRawLen, 1);
    if (!pkRaw) goto end;
    
    skRaw = mlca_calloc(skRawLen, 1);
    if (!skRaw) goto end;

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkLen = mlca_sig_crypto_publickeybytes(ctx);
    skLen = mlca_sig_crypto_secretkeybytes(ctx);

    pk = mlca_calloc(pkLen, 1);
    if (!pk) goto end;

    sk = mlca_calloc(skLen, 1);
    if (!sk) goto end;


    rc = mlca_sig_keygen(ctx, pk, sk);
    if (rc) goto end;

    do {
        size_t pkEncLen = 8000;
        int pkEncLenEffective;
        size_t skEncLen = 8000;
        int skEncLenEffective;

        unsigned char* pkEnc = NULL;
        unsigned char* skEnc = NULL;
        unsigned char* pkEncDec = NULL;
        unsigned char* skEncDec = NULL;
        
        pkEnc = mlca_calloc(pkEncLen, 1);
        if (!pkEnc) goto looperr;

        skEnc = mlca_calloc(skEncLen, 1);
        if (!skEnc) goto looperr;

        pkEncLenEffective = mlca_key2wire(
            pkEnc, pkEncLen, pk, pkLen, 0, NULL, 0, NULL, 0);
        if (pkEncLenEffective <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        skEncLenEffective = mlca_key2wire(
            skEnc, skEncLen, sk, skLen, 0, pk, pkLen, NULL, 0);
        if (skEncLenEffective <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        pkEncDec = mlca_calloc(pkRawLen, 1);
        if (!pkEncDec) goto looperr;

        skEncDec = mlca_calloc(skRawLen, 1);
        if (!skEncDec) goto looperr;

        rc = mlca_wire2key(pkEncDec, pkLen, NULL, pkEnc, pkEncLenEffective, NULL, 0);
        if (rc <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        rc = mlca_wire2key(skEncDec, skLen, NULL, skEnc, skEncLenEffective, NULL, 0);
        if (rc <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        int eq = !memcmp(pk, pkEncDec, pkLen);
        if (!eq) {
            rc = 1;
            goto end;
        }

        eq = !memcmp(sk, skEncDec, skLen);
        if (!eq) {
            rc = 1;
            goto end;
        }

        memset(pkEncDec, 0, pkRawLen);

        rc = mlca_wire2key(pkEncDec, pkRawLen, NULL, skEnc, skEncLenEffective, (const unsigned char *) CR_OID_SPECIAL_PRV2PUB, CR_OID_SPECIAL_PRV2PUB_BYTES);
        if (rc <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        eq = !memcmp(pk, pkEncDec, pkLen);
        if (!eq) {
            rc = 1;
            goto end;
        }

        looperr:
        mlca_secure_free(pkEnc, pkEncLen);
        mlca_secure_free(skEnc, skEncLen);
        mlca_secure_free(pkEncDec, pkRawLen);
        mlca_secure_free(skEncDec, skRawLen);
        pkEnc = skEnc = pkEncDec = skEncDec = NULL;

    } while (0);

    end:
    mlca_free(pk);
    mlca_free(pkRaw);
    mlca_secure_free(sk, skLen);
    mlca_secure_free(skRaw, skRawLen);
    return rc;
}

int test_sig_encodings(mlca_ctx_t * ctx) {

    int rc = 0;

    size_t pkEncodedLen = 0;
    size_t skEncodedLen = 0;

    size_t pkLen = 0, pkRawLen = 0;
    size_t skLen = 0, skRawLen = 0;
    unsigned char *pk = 0;
    unsigned char *sk = 0;
    unsigned char *pkRaw = 0;
    unsigned char *skRaw = 0;
    int encodingIdx;

    const char* algname = mlca_algorithm_name(ctx);

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkRawLen = mlca_sig_crypto_publickeybytes(ctx);
    skRawLen = mlca_sig_crypto_secretkeybytes(ctx);

    pkRaw = mlca_calloc(pkRawLen, 1);
    if (!pkRaw) goto end;
    
    skRaw = mlca_calloc(skRawLen, 1);
    if (!skRaw) goto end;

    for (encodingIdx = 0; ; ++encodingIdx) {

        int rc2 = mlca_set_encoding_by_idx(ctx, encodingIdx);
        if (rc2 != MLCA_OK)
            break;

        pkLen = mlca_sig_crypto_publickeybytes(ctx);
        skLen = mlca_sig_crypto_secretkeybytes(ctx);

        pk = mlca_calloc(pkLen, 1);
        sk = mlca_calloc(skLen, 1);

        rc = mlca_sig_keygen(ctx, pk, sk);
        if (rc) goto end;

        printf("Sig keypair - encoding idx %d:\n", encodingIdx);
        print_hex("pk", pk, pkLen, 1);
        print_hex("sk", sk, skLen, 1);

        mlca_free(pk);
        mlca_secure_free(sk, skLen);
        pk = NULL;
        sk = NULL;
    }

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkLen = mlca_sig_crypto_publickeybytes(ctx);
    skLen = mlca_sig_crypto_secretkeybytes(ctx);

    pk = mlca_calloc(pkLen, 1);
    if (!pk) goto end;

    sk = mlca_calloc(skLen, 1);
    if (!sk) goto end;

    rc = mlca_sig_keygen(ctx, pk, sk);
    if (rc) goto end;


    for (encodingIdx = 1; ; ++encodingIdx) {

        int rc2 = mlca_set_encoding_by_idx(ctx, encodingIdx);
        if (rc2 != MLCA_OK)
            break;

        size_t pkEncLen = mlca_sig_crypto_publickeybytes(ctx);
        size_t skEncLen = mlca_sig_crypto_secretkeybytes(ctx);

        unsigned char* pkEnc = NULL;
        unsigned char* skEnc = NULL;
        unsigned char* pkEncDec = NULL;
        unsigned char* skEncDec = NULL;
        
        pkEnc = mlca_calloc(pkEncLen, 1);
        if (!pkEnc) goto looperr;

        skEnc = mlca_calloc(skEncLen, 1);
        if (!skEnc) goto looperr;

        rc = mlca_sig_keypair_encode(ctx, pk, &pkEnc, sk, &skEnc);
        if (rc) goto end;


        char strpk[80]; char strsk[80];
        int wbpk = sprintf(strpk, "%s-encoding-%d.pk.bin", algname, encodingIdx);
        int wbsk = sprintf(strsk, "%s-encoding-%d.sk.bin", algname, encodingIdx);

        FILE *write_ptr_pk;
        FILE *write_ptr_sk;

        write_ptr_pk = fopen(strpk,"wb");  // w for write, b for binary
        write_ptr_sk = fopen(strsk,"wb");  // w for write, b for binary

        fwrite(pkEnc,pkEncLen,1,write_ptr_pk); // write 10 bytes from our buffer
        fclose(write_ptr_pk);
        fwrite(skEnc,skEncLen,1,write_ptr_sk); // write 10 bytes from our buffer
        fclose(write_ptr_sk);

        pkEncDec = mlca_calloc(pkRawLen, 1);
        if (!pkEncDec) goto looperr;

        skEncDec = mlca_calloc(skRawLen, 1);
        if (!skEncDec) goto looperr;

        rc = mlca_sig_keypair_decode(ctx, pkEnc, &pkEncDec, skEnc, &skEncDec);
        if (rc) goto end;

        int eq = !memcmp(pk, pkEncDec, pkLen);
        if (!eq) {
            rc = 1;
            goto end;
        }

        eq = !memcmp(sk, skEncDec, skLen);
        if (!eq) {
            rc = 1;
            goto end;
        }

        looperr:
        mlca_secure_free(pkEnc, pkEncLen);
        mlca_secure_free(skEnc, skEncLen);
        mlca_secure_free(pkEncDec, pkRawLen);
        mlca_secure_free(skEncDec, skRawLen);
        pkEnc = skEnc = pkEncDec = skEncDec = NULL;
    }

    end:
    mlca_free(pk);
    mlca_free(pkRaw);
    mlca_secure_free(sk, skLen);
    mlca_secure_free(skRaw, skRawLen);
    return rc;
}

int test_sig_speed(const char* name, const mlca_ctx_t * ctx, int runs) {

    int rc = 0;
    unsigned int i;

    int64_t cycles, cycles1, cycles2;

    size_t pkLen  = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen  = mlca_kem_crypto_secretkeybytes(ctx);
    size_t sigLen = mlca_kem_crypto_bytes(ctx);
    size_t mLen = 32;

    unsigned char* pk  = calloc(pkLen, 1);
    unsigned char* sk  = calloc(skLen, 1);
    unsigned char* sig = calloc(sigLen, 1);
    unsigned char* m   = calloc(mLen, 1);

    printf("Performance of %s - OPT_LEVEL: %u (avg. of %d runs):\n", name, mlca_opt_level(ctx), runs);

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        cycles1 = cpucycles();
        mlca_sig_keygen(ctx, pk, sk);
        cycles2 = cpucycles();

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Key generation runs in ....................................... %10" PRId64 " ", (cycles / runs));
    print_unit

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        ((uint32_t*)m)[0]++;
        cycles1 = cpucycles();
        rc = mlca_sig_sign(ctx, sig, &sigLen, m, mLen, sk);
        cycles2 = cpucycles();
        if ( rc ) goto end;

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Sign runs in ................................................. %10" PRId64 " ", (cycles / runs));
    print_unit

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        cycles1 = cpucycles();
        rc = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);
        cycles2 = cpucycles();
        if (rc) {
            rc = 0;
        } else {
            rc = 1;
            goto end;
        }

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Verify runs in ............................................... %10" PRId64 " ", (cycles / runs));
    print_unit

    end:
    mlca_free(pk);
    mlca_secure_free(sk, skLen);
    mlca_free(sig);
    mlca_free(m);
    return rc;
}