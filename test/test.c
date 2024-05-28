// SPDX-License-Identifier: Apache-2.0
#include <memory.h>
#include <mlca2.h>
#include <random_ctrdrbg.h>
#include <stdio.h>
#include <stdlib.h>
#include "test_extras.h"
#include <pqalgs.h>

extern int test_kem(const mlca_ctx_t * ctx);
extern int test_kem_encodings(const mlca_ctx_t * ctx);
extern int test_kem_encodings_minimal(const mlca_ctx_t * ctx);
extern int test_kem_speed(const char* name, const mlca_ctx_t * params, int runs);
extern int test_kem_constant(mlca_ctx_t * ctx);

extern int test_sig(const mlca_ctx_t * ctx);
extern int test_sig_encodings(mlca_ctx_t * ctx);
extern int test_sig_encodings_minimal(mlca_ctx_t * ctx);
extern int test_sig_speed(const char* name, const mlca_ctx_t * ctx, int runs);
extern int test_sig_constant(mlca_ctx_t * ctx);

extern int test_nist_kat(const mlca_ctx_t * params);
extern int test_nist_kat_sign(const mlca_ctx_t * params);
extern int test_chain_kat_gen(const mlca_ctx_t * params, int numkat, int fullkat);
extern int test_chain_kat_sign_gen(const mlca_ctx_t * params, int numkat, int fullkat);
extern int test_chain_kat(const mlca_ctx_t * params, int fullkat);
extern int test_chain_kat_sign(const mlca_ctx_t * params, int fullkat);

static void
randombytes_init_failing(const mlca_random_t *ctx, unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength)
{}

static size_t randombytes_failing (const mlca_random_t *ctx,
                              unsigned char* r,
                              size_t rbytes) {
    return 0;
}

const mlca_random_t random_failing = {
        .name = "random_failing",
        .randombytes_init = randombytes_init_failing,
        .randombytes = randombytes_failing
};

static int test_param_testrng(mlca_ctx_t* params, int argc, char *argv[]) {
    int rc = 0;
    const char *arg_self           = "self";
    const char *arg_self_encodings = "self_encodings";
    const char *arg_self_encodings_minimal = "self_encodings_minimal";

    if (!strcmp(argv[2], arg_self)) {
        if (mlca_alg_type(params) == KEM)
            rc = test_kem(params);
        else if (mlca_alg_type(params) == SIGNATURE)
            rc = test_sig(params);
        else
            rc = 1;
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_self_encodings)) {
        if (mlca_alg_type(params) == KEM)
            rc = test_kem_encodings(params);
        else if (mlca_alg_type(params) == SIGNATURE)
            rc = test_sig_encodings(params);
        else
            rc = 1;
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_self_encodings_minimal)) {
        if (mlca_alg_type(params) == KEM)
            rc = test_kem_encodings_minimal(params);
        else if (mlca_alg_type(params) == SIGNATURE)
            rc = test_sig_encodings_minimal(params);
        else
            rc = 1;
        if (rc) goto end;
    }
    end:
    return rc;
}

static int test_param(mlca_ctx_t* params, int argc, char *argv[]) {
    int rc = 0;
    const char *arg_speed                  = "speed";
    const char *arg_nist_kat               = "kat_nist";
    const char *arg_chain_kat              = "kat_chain";
    const char *arg_chain_kat_gen          = "kat_chain_gen";
    const char *arg_self                   = "self";
    const char *arg_self_encodings         = "self_encodings";
    const char *arg_self_encodings_minimal = "self_encodings_minimal";
    const char *arg_self_const             = "self_const";

    if (!strcmp(argv[2], arg_self) || !strcmp(argv[2], arg_self_encodings) || !strcmp(argv[2], arg_self_encodings_minimal)) {
        mlca_set_rng(params, &random_failing);
        rc = test_param_testrng(params, argc, argv);
        if (!rc) goto end;
        mlca_set_rng(params, NULL);
        rc = test_param_testrng(params, argc, argv);
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_nist_kat)) {
        rc = mlca_set_rng(params, &random_nist);
        if (rc) goto end;
        if (mlca_alg_type(params) == KEM)
            rc = test_nist_kat(params);
        else if (mlca_alg_type(params) == SIGNATURE)
            rc = test_nist_kat_sign(params);
        else
            rc = 1;
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_chain_kat_gen)) {
        rc = mlca_set_rng(params, &random_nist);
        if (rc) goto end;
        if (mlca_alg_type(params) == KEM) {
            rc = test_chain_kat_gen(params, 100, 1);
            if (rc) goto end;
            rc = test_chain_kat_gen(params, 100, 0);
            if (rc) goto end;
        } else if (mlca_alg_type(params) == SIGNATURE) {
            rc = test_chain_kat_sign_gen(params, 100, 1);
            if (rc) goto end;
            rc = test_chain_kat_sign_gen(params, 100, 0);
            if (rc) goto end;
        } else
            rc = 1;
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_chain_kat)) {
        rc = mlca_set_rng(params, &random_nist);
        if (rc) goto end;
        if (mlca_alg_type(params) == KEM) {
            rc = test_chain_kat(params, 1);
            if (rc) goto end;
            rc = test_chain_kat(params, 0);
            if (rc) goto end;
        } else if (mlca_alg_type(params) == SIGNATURE) {
            rc = test_chain_kat_sign(params, 1);
            if (rc) goto end;
            rc = test_chain_kat_sign(params, 0);
            if (rc) goto end;
        } else
            rc = 1;
        if (rc) goto end;
    } else if (!strcmp(argv[2], arg_speed)) {

        if (argc != 4) {
            printf("Need to pass the number of runs\n");
        } else {
            int runs = atoi(argv[3]);
            if (mlca_alg_type(params) == KEM)
                rc = test_kem_speed(mlca_algorithm_name(params), params, runs);
            else if (mlca_alg_type(params) == SIGNATURE)
                rc = test_sig_speed(mlca_algorithm_name(params), params, runs);
            else
                rc = 1;
            if (rc) goto end;
        }
    } else if (!strcmp(argv[2], arg_self_const)) {
        if (mlca_alg_type(params) == KEM) {
            rc = test_kem_constant(params);
        } else if (mlca_alg_type(params) == SIGNATURE) {
            rc = test_sig_constant(params);
        } else
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

  mlca_ctx_t ctx;

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
  }
  const char* alg_oid = mlca_algorithm_oid(&ctx);
  if (!alg_oid) {
    rc = MLCA_EKEYTYPE;
    goto end;
  }
  rc = mlca_set_alg(&ctx, alg_oid, OPT_LEVEL_AUTO);
  if (rc) {
      printf("%s not found\n", argv[1]);
      goto end;
  }
  rc = test_param(&ctx, argc, argv);
  if (rc) goto end;

  rc = mlca_ctx_free(&ctx);
  if (rc) goto end;

  rc = mlca_init(&ctx, 1, 0);
  if (rc) goto end;
  rc = mlca_set_rng(&ctx, NULL);
  if (rc) goto end;

  /**
   * Test Generic implementation
   */
  rc = mlca_set_alg(&ctx, argv[1], OPT_LEVEL_GENERIC);
  if (rc) {
      printf("%s GENERIC not available.\n", argv[1]);
      rc = 0;
  } else {
      rc = test_param(&ctx, argc, argv);
      if (rc) goto end;
  }

  rc = mlca_ctx_free(&ctx);
  if (rc) goto end;

  rc = mlca_init(&ctx, 1, 0);
  if (rc) goto end;
  rc = mlca_set_rng(&ctx, NULL);
  if (rc) goto end;

  /**
   * Test Assembly implementation
   */
  rc = mlca_set_alg(&ctx, argv[1], OPT_LEVEL_ASSEMBLY);
  if (rc) {
      printf("%s ASSEMBLY not available.\n", argv[1]);
      rc = 0;
  } else {
      rc = test_param(&ctx, argc, argv);
      if (rc) goto end;
  }

  rc = mlca_ctx_free(&ctx);
  if (rc) goto end;

end:
  return rc;
}