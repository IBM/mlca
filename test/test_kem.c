// SPDX-License-Identifier: Apache-2.0
#include <memory.h>
#include <mlca2.h>
#include <stdio.h>
#include "test_extras.h"
#include <inttypes.h>
#include <stdlib.h>
#include <pqalgs.h>


int test_kem(mlca_ctx_t * ctx) {

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

    rc = mlca_kem_keygen(ctx, pk3, sk3);
    if (rc) goto end;

    printf("KEM keypair:\n");
    print_hex("pk", pk3, pkLen, 1);
    print_hex("sk", sk3, skLen, 1);

    rc = mlca_kem_enc(ctx, ct, ss, pk3);
    if (rc) goto end;

    printf("KEM enc:\n");
    print_hex("ct", ct, ctLen, 1);
    print_hex("ss", ss, ssLen, 1);

    rc = mlca_kem_dec(ctx, ss_rec, ct, sk3);
    if ( rc ) goto end;

    printf("KEM dec:\n");
    print_hex("ss_decaps", ss_rec, ssLen, 1);

    int eq = !memcmp(ss, ss_rec, mlca_kem_crypto_bytes(ctx));

    if (!eq) rc = 1;

    end:
    mlca_free(pk3);
    mlca_secure_free(sk3, skLen);
    mlca_free(ct);
    mlca_secure_free(ss, ssLen);
    mlca_secure_free(ss_rec, ssLen);
    return rc;
}

int test_kem_encodings_minimal(mlca_ctx_t * ctx) {

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
    const char* algoid = mlca_algorithm_oid(ctx);

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkRawLen = mlca_kem_crypto_publickeybytes(ctx);
    skRawLen = mlca_kem_crypto_secretkeybytes(ctx);

    pkRaw = mlca_calloc(pkRawLen, 1);
    if (!pkRaw) goto end;
    
    skRaw = mlca_calloc(skRawLen, 1);
    if (!skRaw) goto end;

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkLen = mlca_kem_crypto_publickeybytes(ctx);
    skLen = mlca_kem_crypto_secretkeybytes(ctx);

    pk = mlca_calloc(pkLen, 1);
    if (!pk) goto end;

    sk = mlca_calloc(skLen, 1);
    if (!sk) goto end;

    rc = mlca_kem_keygen(ctx, pk, sk);
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
            pkEnc, pkEncLen, pk, pkLen, 0, NULL, 0, (const unsigned char *) algoid, strlen(algoid));
        if (pkEncLenEffective <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        skEncLenEffective = mlca_key2wire(
            skEnc, skEncLen, sk, skLen, 0, pk, pkLen, (const unsigned char *) algoid, strlen(algoid));
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
        
        rc = mlca_wire2key(pkEncDec, pkLen, NULL, pkEnc, pkEncLenEffective, (const unsigned char *) algoid, strlen(algoid));
        if (rc <= 0) {
            rc = -1;
            goto looperr;
        } else {
            rc = 0;
        }

        rc = mlca_wire2key(skEncDec, skLen, NULL, skEnc, skEncLenEffective, (const unsigned char *) algoid, strlen(algoid));
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

int test_kem_encodings(mlca_ctx_t * ctx) {

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

    pkRawLen = mlca_kem_crypto_publickeybytes(ctx);
    skRawLen = mlca_kem_crypto_secretkeybytes(ctx);

    pkRaw = mlca_calloc(pkRawLen, 1);
    if (!pkRaw) goto end;
    
    skRaw = mlca_calloc(skRawLen, 1);
    if (!skRaw) goto end;

    for (encodingIdx = 0; ; ++encodingIdx) {

        int rc2 = mlca_set_encoding_by_idx(ctx, encodingIdx);
        if (rc2 != MLCA_OK)
            break;

        pkLen = mlca_kem_crypto_publickeybytes(ctx);
        skLen = mlca_kem_crypto_secretkeybytes(ctx);

        pk = mlca_calloc(pkLen, 1);
        if (!pk) goto end;

        sk = mlca_calloc(skLen, 1);
        if (!sk) goto end;

        rc = mlca_kem_keygen(ctx, pk, sk);
        if (rc) goto end;

        printf("KEM keypair - encoding idx %d:\n", encodingIdx);
        print_hex("pk", pk, pkLen, 1);
        print_hex("sk", sk, skLen, 1);

        mlca_free(pk);
        mlca_secure_free(sk, skLen);
        pk = NULL;
        sk = NULL;
    }

    rc = mlca_set_encoding_by_idx(ctx, 0);
    if (rc) goto end;

    pkLen = mlca_kem_crypto_publickeybytes(ctx);
    skLen = mlca_kem_crypto_secretkeybytes(ctx);

    pk = mlca_calloc(pkLen, 1);
    if (!pk) goto end;

    sk = mlca_calloc(skLen, 1);
    if (!sk) goto end;

    rc = mlca_kem_keygen(ctx, pk, sk);
    if (rc) goto end;


    for (encodingIdx = 1; ; ++encodingIdx) {

        int rc2 = mlca_set_encoding_by_idx(ctx, encodingIdx);
        if (rc2 != MLCA_OK)
            break;

        size_t pkEncLen = mlca_kem_crypto_publickeybytes(ctx);
        size_t skEncLen = mlca_kem_crypto_secretkeybytes(ctx);

        unsigned char* pkEnc = NULL;
        unsigned char* skEnc = NULL;
        unsigned char* pkEncDec = NULL;
        unsigned char* skEncDec = NULL;
        
        pkEnc = mlca_calloc(pkEncLen, 1);
        if (!pkEnc) goto looperr;

        skEnc = mlca_calloc(skEncLen, 1);
        if (!skEnc) goto looperr;

        printf("KEM keypair - encoding idx %d:\n", encodingIdx);

        print_hex("raw pk", pk, pkLen, 1);
        print_hex("raw sk", sk, skLen, 1);

        rc = mlca_kem_keypair_encode(ctx, pk, &pkEnc, sk, &skEnc);
        if (rc) goto end;

        print_hex("enc pk", pkEnc, pkEncLen, 1);
        print_hex("enc sk", skEnc, skEncLen, 1);

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

        rc = mlca_kem_keypair_decode(ctx, pkEnc, &pkEncDec, skEnc, &skEncDec);
        if (rc) goto end;

        print_hex("dec pk", pkEncDec, pkLen, 1);
        print_hex("dec sk", skEncDec, skLen, 1);

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

int test_kem_speed(const char* name, const mlca_ctx_t * params, int runs) {

    int rc = 0;
    unsigned int i;

    int64_t cycles, cycles1, cycles2;

    size_t pkLen = mlca_kem_crypto_publickeybytes(params);
    size_t skLen = mlca_kem_crypto_secretkeybytes(params);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(params);
    size_t ssLen = mlca_kem_crypto_bytes(params);

    unsigned char* pk3    = calloc(pkLen, 1);
    unsigned char* sk3    = calloc(skLen, 1);
    unsigned char* ct     = calloc(ctLen, 1);
    unsigned char* ss     = calloc(ssLen, 1);
    unsigned char* ss_rec = calloc(ssLen, 1);

    printf("Performance of %s - OPT_LEVEL: %u (avg. of %d runs):\n", name, mlca_opt_level(params), runs);

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        cycles1 = cpucycles();
        mlca_kem_keygen(params, pk3, sk3);
        cycles2 = cpucycles();

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Key generation runs in ....................................... %10" PRId64 " ", (cycles / runs));
    print_unit

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        cycles1 = cpucycles();
        rc = mlca_kem_enc(params, ct, ss, pk3);
        cycles2 = cpucycles();
        if ( rc ) goto end;

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Encapsulation runs in ........................................ %10" PRId64 " ", (cycles / runs));
    print_unit

    cycles = 0;
    for (i = 0; i < runs; ++i) {
        cycles1 = cpucycles();
        rc = mlca_kem_dec(params, ss_rec, ct, sk3);
        cycles2 = cpucycles();
        if ( rc ) goto end;

        cycles = cycles + (cycles2 - cycles1);
    }
    printf("  Decapsulation runs in ........................................ %10" PRId64 " ", (cycles / runs));
    print_unit

    end:
    free(pk3);
    free(sk3);
    free(ct);
    free(ss);
    free(ss_rec);
    return rc;
}
