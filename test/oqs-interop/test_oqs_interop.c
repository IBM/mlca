// SPDX-License-Identifier: Apache-2.0
#include <memory.h>
#include <mlca2.h>
#include <stdio.h>
#include "../test_extras.h"
#include <inttypes.h>

#include <oqs/oqs.h>

const struct {
    char* mlca_name;
    char* oqs_name;
} name_map[] = {
    { "Dilithium54_R2", "DILITHIUM_3" },
    { "Dilithium65_R2", "DILITHIUM_4" },
    { "Kyber768_R2", "Kyber768" },
    { "Kyber1024_R2", "Kyber1024" },
};

int test_oqs_interop_kem(mlca_ctx_t * ctx) {
    int rc = 0;

    const char* alg_name = mlca_algorithm_name(ctx);

    for (int i = 0; i < sizeof(name_map) / sizeof(name_map[0]); ++i) {
        if (!strcmp(name_map[i].mlca_name, alg_name))
            alg_name = name_map[i].oqs_name;
    }

    OQS_KEM* oqskem = OQS_KEM_new(alg_name);
    if (!oqskem) {
        rc = 1;
        goto end;
    }

    size_t oqs_pkLen = oqskem->length_public_key;
    size_t oqs_skLen = oqskem->length_secret_key;
    size_t oqs_ctLen = oqskem->length_ciphertext;
    size_t oqs_ssLen = oqskem->length_shared_secret;

    size_t pkLen = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen = mlca_kem_crypto_secretkeybytes(ctx);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(ctx);
    size_t ssLen = mlca_kem_crypto_bytes(ctx);

    if (oqs_pkLen != pkLen || oqs_skLen != skLen || oqs_ctLen != ctLen || oqs_ssLen != ssLen) {
        rc = 1;
        goto err;
    }

    unsigned char* pk     = mlca_calloc(pkLen, 1);
    unsigned char* sk     = mlca_calloc(skLen, 1);
    unsigned char* ct     = mlca_calloc(ctLen, 1);
    unsigned char* ss     = mlca_calloc(ssLen, 1);
    unsigned char* ss_rec = mlca_calloc(ssLen, 1);

    rc = mlca_kem_keygen(ctx, pk, sk);
    if (rc != MLCA_OK) goto err;

    printf("KEM keypair:\n");
    print_hex("pk", pk, pkLen, 1);
    print_hex("sk", sk, skLen, 1);

    rc = OQS_KEM_encaps(oqskem, ct, ss, pk);
    if (rc != OQS_SUCCESS) goto err;

    printf("KEM enc:\n");
    print_hex("ct", ct, ctLen, 1);
    print_hex("ss", ss, ssLen, 1);

    rc = mlca_kem_dec(ctx, ss_rec, ct, sk);
    if (rc != MLCA_OK) goto err;

    printf("KEM dec:\n");
    print_hex("ss_decaps", ss_rec, ssLen, 1);

    int eq = !memcmp(ss, ss_rec, ssLen);
    if (!eq) rc = 1;

    rc = OQS_KEM_keypair(oqskem, pk, sk);
    if (rc != OQS_SUCCESS) goto err;

    printf("KEM keypair:\n");
    print_hex("pk", pk, pkLen, 1);
    print_hex("sk", sk, skLen, 1);

    rc = mlca_kem_enc(ctx, ct, ss, pk);
    if (rc != MLCA_OK) goto err;

    printf("KEM enc:\n");
    print_hex("ct", ct, ctLen, 1);
    print_hex("ss", ss, ssLen, 1);

    rc = OQS_KEM_decaps(oqskem, ss_rec, ct, sk);
    if (rc != OQS_SUCCESS) goto err;

    printf("KEM dec:\n");
    print_hex("ss_decaps", ss_rec, ssLen, 1);

    eq = !memcmp(ss, ss_rec, ssLen);
    if (!eq) rc = 1;

    err:
    OQS_KEM_free(oqskem);
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(ss_rec);
    end:
    return rc;
}

int test_oqs_interop_sig(mlca_ctx_t * ctx) {
    int rc = 0;

    const char* alg_name = mlca_algorithm_name(ctx);

    for (int i = 0; i < sizeof(name_map) / sizeof(name_map[0]); ++i) {
        if (!strcmp(name_map[i].mlca_name, alg_name))
            alg_name = name_map[i].oqs_name;
    }

    OQS_SIG* oqssig = OQS_SIG_new(alg_name);
    if (!oqssig) {
        rc = 1;
        goto end;
    }

    size_t oqs_pkLen = oqssig->length_public_key;
    size_t oqs_skLen = oqssig->length_secret_key;
    size_t oqs_sigLen = oqssig->length_signature;
    size_t mLen   = 32;

    size_t pkLen = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen = mlca_sig_crypto_secretkeybytes(ctx);
    size_t sigLen = mlca_sig_crypto_bytes(ctx);

    if (oqs_pkLen != pkLen || oqs_skLen != skLen || oqs_sigLen != sigLen) {
        rc = 1;
        goto err;
    }

    unsigned char* pk     = mlca_calloc(pkLen, 1);
    unsigned char* sk     = mlca_calloc(skLen, 1);
    unsigned char* sig    = mlca_calloc(sigLen, 1);
    unsigned char* m      = mlca_calloc(mLen, 1);

    rc = mlca_sig_keygen(ctx, pk, sk);
    if (rc != MLCA_OK) goto err;

    printf("Sig keypair:\n");
    print_hex("pk", pk, pkLen, 1);
    print_hex("sk", sk, skLen, 1);

    rc = OQS_SIG_sign(oqssig, sig, &sigLen, m, mLen, sk);
    if (rc != OQS_SUCCESS) goto err;

    printf("Sig sign:\n");
    print_hex("m", m, 32, 1);
    print_hex("sig", sig, sigLen, 1);

    int sigok = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);
    if (!sigok) {
        rc = 1;
        goto err;
    }

    m[0] = ~m[0];

    sigok = mlca_sig_verify(ctx, m, mLen, sig, sigLen, pk);
    if (sigok) {
        rc = 1;
        goto err;
    }

    sigLen = mlca_sig_crypto_bytes(ctx);

    rc = OQS_SIG_keypair(oqssig, pk, sk);
    if (rc != OQS_SUCCESS) goto err;

    printf("Sig keypair:\n");
    print_hex("pk", pk, pkLen, 1);
    print_hex("sk", sk, skLen, 1);

    rc = mlca_sig_sign(ctx, sig, &sigLen, m, mLen, sk);
    if (rc != MLCA_OK) goto err;

    printf("Sig sign:\n");
    print_hex("m", m, 32, 1);
    print_hex("sig", sig, sigLen, 1);

    sigok = OQS_SIG_verify(oqssig, m, mLen, sig, sigLen, pk);
    if (sigok != OQS_SUCCESS) {
        rc = 1;
        goto err;
    }

    m[0] = ~m[0];

    sigok = OQS_SIG_verify(oqssig, m, mLen, sig, sigLen, pk);
    if (sigok != OQS_ERROR) {
        rc = 1;
        goto err;
    }

    err:
    OQS_SIG_free(oqssig);
    mlca_free(pk);
    mlca_secure_free(sk, skLen);
    mlca_free(sig);
    mlca_free(m);
    end:
    return rc;
}

static int test_param(mlca_ctx_t* params, int argc, char *argv[]) {

    int rc = 0;

    const char *arg_oqs_interop = "oqs_interop";

    if (!strcmp(argv[2], arg_oqs_interop)) {
        if (mlca_alg_type(params) == KEM)
            rc = test_oqs_interop_kem(params);
        else if (mlca_alg_type(params) == SIGNATURE)
            rc = test_oqs_interop_sig(params);
        else
            rc = 1;
        if (rc) goto end;
    } else {
        printf("Argument not supported\n");
        rc = 1;
    }

    end:
    return rc;
}

int main(int argc, char *argv[]) {

  int rc = 0;

  if (argc < 3) {
    printf("Two arguments needed\n");
    rc = 1;
    goto end;
  }

  mlca_ctx_t ctx = { 0 };

  rc = mlca_init(&ctx, 1, 0);
  if (rc) goto end;

  rc = mlca_set_rng(&ctx, NULL);
  if (rc) goto end;

  /**
   * Test Automatic selection
   */
  rc = mlca_set_alg(&ctx, argv[1], OPT_LEVEL_AUTO);
  if (rc) {
      printf("%s not found\n", argv[1]);
      goto end;
  } else {
      rc = test_param(&ctx, argc, argv);
      if (rc) goto end;
  }

end:
  return rc;
}
