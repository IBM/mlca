// SPDX-License-Identifier: Apache-2.0

#include <pqalgs.h>
#include <mlca2_int.h>
#include <string.h>
#include <mlca2_encoding.h>

static MLCA_RC mlca_kyber_r2_keypair(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	size_t pkbytes = ctx->alg[0]->encodings->encoding->crypto_publickeybytes;
	return mlca_generate(sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, pk, &pkbytes,  (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
}

static MLCA_RC mlca_kyber_r2_kem_enc(const mlca_ctx_t *ctx, unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
	size_t sbytes = ctx->alg[0]->encodings->encoding->crypto_secretkeybytes;
	int rc = mlca_kem1(ct, ctx->alg[0]->encodings->encoding->crypto_ciphertextbytes, ss, &sbytes, pk, ctx->alg[0]->encodings->encoding->crypto_publickeybytes, (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		return MLCA_OK;
	} else {
		return rc;
	}
}

static MLCA_RC mlca_kyber_r2_kem_dec(const mlca_ctx_t *ctx, unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
	int rc = mlca_kem2(ss, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, ct, ctx->alg[0]->encodings->encoding->crypto_ciphertextbytes, sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		return MLCA_OK;
	} else {
		return rc;
	}
}

static MLCA_RC mlca_kyber_r3_keypair(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	return mlca_kyber_r2_keypair(ctx, pk, sk);
}

static MLCA_RC mlca_kyber_r3_kem_enc(const mlca_ctx_t *ctx, unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
	return mlca_kyber_r2_kem_enc(ctx, ct, ss, pk);
}

static MLCA_RC mlca_kyber_r3_kem_dec(const mlca_ctx_t *ctx, unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
	return mlca_kyber_r2_kem_dec(ctx, ss, ct, sk);
}

static int check_compatibility_generic(const mlca_cpu_features_t *ft) {
	return 1;
}

#define KYBER768_LEN 1
#define KYBER1024_LEN 1

static const mlca_alg_impl_t Kyber768[1] = {
	{
		.opt_level = OPT_LEVEL_GENERIC,
		.alg_ctx = 0,
		.check_compatibility = check_compatibility_generic,
	}
};

static const mlca_alg_impl_t Kyber1024[1] = {
	{
		.opt_level = OPT_LEVEL_GENERIC,
		.alg_ctx = 0,
		.check_compatibility = check_compatibility_generic,
	}
};

static const mlca_kem_api_t kyberibm_kem_api = {
	.keypair = mlca_kyber_r2_keypair,
	.kem_enc = mlca_kyber_r2_kem_enc,
	.kem_dec = mlca_kyber_r2_kem_dec
};

static const mlca_kem_api_t r3_kyber_kem_api = {
	.keypair = mlca_kyber_r3_keypair,
	.kem_enc = mlca_kyber_r3_kem_enc,
	.kem_dec = mlca_kyber_r3_kem_dec
};

const mlca_alg_t kyber_mlca_ctx[4] = {
	{
		.algorithm_name = MLCA_ALGORITHM_KEM_KYBER_768,
		.algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_768_R2_OID,
		.type = KEM,
		.alg_version = "Kyber Round 2",
		.claimed_nist_level = 3,
		.ind_cca = 1,
		.encodings = &Kyber768_encoding,
		.alg_ctx_len = KYBER768_LEN,
		.alg_ctx_all = Kyber768,
		.api = &kyberibm_kem_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_KEM_KYBER_1024,
		.algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_1024_R2_OID,
		.type = KEM,
		.alg_version = "Kyber Round 2",
		.claimed_nist_level = 5,
		.ind_cca = 1,
		.encodings = &Kyber1024_encoding,
		.alg_ctx_len = KYBER1024_LEN,
		.alg_ctx_all = Kyber1024,
		.api = &kyberibm_kem_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_KEM_KYBER_768_R3,
		.algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_768_R3_OID,
		.type = KEM,
		.alg_version = "Kyber Round 3",
		.claimed_nist_level = 3,
		.ind_cca = 1,
		.encodings = &Kyber768_encoding,
		.alg_ctx_len = KYBER768_LEN,
		.alg_ctx_all = Kyber768,
		.api = &r3_kyber_kem_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_KEM_KYBER_1024_R3,
		.algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_1024_R3_OID,
		.type = KEM,
		.alg_version = "Kyber Round 3",
		.claimed_nist_level = 5,
		.ind_cca = 1,
		.encodings = &Kyber1024_encoding,
		.alg_ctx_len = KYBER1024_LEN,
		.alg_ctx_all = Kyber1024,
		.api = &r3_kyber_kem_api,
	}
};
