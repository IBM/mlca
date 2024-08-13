// SPDX-License-Identifier: Apache-2.0

#include <pqalgs.h>
#include <mlca2_int.h>
#include <string.h>
#include <mlca2_encoding.h>

typedef struct {
	int (*generate) (unsigned char *prv,   size_t prvbytes,
	                 unsigned char *pub,   size_t *pubbytes,
	                 void *rng,
	                 const unsigned char *algid, size_t ibyte);
	int (*sign) (unsigned char *sig,   size_t sbytes,
	             const unsigned char *msg,   size_t mbytes,
	             const unsigned char *prv,   size_t pbytes,
				 void *rng,
	             const unsigned char *algid, size_t ibytes);
	int (*verify) (const unsigned char *sig,   size_t sbytes,
	               const unsigned char *msg,   size_t mbytes,
	               const unsigned char *pub,   size_t pbytes,
	               const unsigned char *algid, size_t ibytes);
} crystals_alg_ctx;

typedef struct {
	int (*generate) (unsigned char *prv,   size_t prvbytes,
	                 unsigned char *pub,   size_t *pubbytes,
	                 void *rng,
	                 const unsigned char *algid, size_t ibyte);
	int (*sign) (unsigned char *sig,   size_t sbytes,
	             const unsigned char *msg,   size_t mbytes,
	             const unsigned char *prv,   size_t pbytes,
				 void *rng,
	             const unsigned char *algid, size_t ibytes);
	int (*sign_internal) (unsigned char *sig,   size_t sbytes,
	             const unsigned char *msg,   size_t mbytes,
	             const unsigned char *prv,   size_t pbytes,
				 void *rng,
	             const unsigned char *algid, size_t ibytes);
	int (*verify) (const unsigned char *sig,   size_t sbytes,
	               const unsigned char *msg,   size_t mbytes,
	               const unsigned char *pub,   size_t pbytes,
	               const unsigned char *algid, size_t ibytes);
	int (*verify_internal) (const unsigned char *sig,   size_t sbytes,
	               const unsigned char *msg,   size_t mbytes,
	               const unsigned char *pub,   size_t pbytes,
	               const unsigned char *algid, size_t ibytes);
} mldsa_alg_ctx;

static int check_compatibility_generic(const mlca_cpu_features_t *ft) {
	return 1;
}

const crystals_alg_ctx crystals_alg_ctx_generic = {
	.generate = mlca_generate,
	.sign = mlca_sign,
	.verify = mlca_verify
};

const mldsa_alg_ctx mldsa_alg_ctx_generic = {
	.generate = mlca_generate,
	.sign = mlca_sign,
	.verify = mlca_verify,
	.sign_internal = mlca_sign_internal,
	.verify_internal = mlca_verify_internal
};

static MLCA_RC dilithium_keypair(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	size_t pkbytes = ctx->alg[0]->encodings->encoding->crypto_publickeybytes;
	const crystals_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	int rc = alg_ctx->generate(sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, pk, &pkbytes,  (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		return MLCA_OK;
	} else {
		return rc;
	}
}

static MLCA_RC dilithium_sign(const mlca_ctx_t *ctx, unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk) {
	const crystals_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	int rc = alg_ctx->sign(sig, *siglen, m, mlen, sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, NULL, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		*siglen = rc;
		return MLCA_OK;
	} else {
		return MLCA_GEN;
	}
}

static int dilithium_verify (const mlca_ctx_t *ctx, const unsigned char *m, size_t mlen, const unsigned char *sig, size_t siglen, const unsigned char *pk) {
	const crystals_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	return alg_ctx->verify(sig, siglen, m, mlen, pk, ctx->alg[0]->encodings->encoding->crypto_publickeybytes, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
}

static MLCA_RC mldsa_keypair(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	size_t pkbytes = ctx->alg[0]->encodings->encoding->crypto_publickeybytes;
	const crystals_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	int rc = alg_ctx->generate(sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, pk, &pkbytes,  (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		return MLCA_OK;
	} else {
		return rc;
	}
}

static MLCA_RC mldsa_sign(const mlca_ctx_t *ctx, unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk) {
	const crystals_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	int rc = alg_ctx->sign(sig, *siglen, m, mlen, sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		*siglen = rc;
		return MLCA_OK;
	} else {
		return MLCA_GEN;
	}
}

static int mldsa_verify(const mlca_ctx_t *ctx, const unsigned char *m, size_t mlen, const unsigned char *sig, size_t siglen, const unsigned char *pk) {
	const mldsa_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	return alg_ctx->verify(sig, siglen, m, mlen, pk, ctx->alg[0]->encodings->encoding->crypto_publickeybytes, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
}

static MLCA_RC mldsa_sign_internal(const mlca_ctx_t *ctx, unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk) {
	const mldsa_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	int rc = alg_ctx->sign_internal(sig, *siglen, m, mlen, sk, ctx->alg[0]->encodings->encoding->crypto_secretkeybytes, (void *)ctx->rng, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
	if (rc > 0) {
		*siglen = rc;
		return MLCA_OK;
	} else {
		return MLCA_GEN;
	}
}

static int mldsa_verify_internal(const mlca_ctx_t *ctx, const unsigned char *m, size_t mlen, const unsigned char *sig, size_t siglen, const unsigned char *pk) {
	const mldsa_alg_ctx *alg_ctx = ctx->alg_impl[0]->alg_ctx;
	return alg_ctx->verify_internal(sig, siglen, m, mlen, pk, ctx->alg[0]->encodings->encoding->crypto_publickeybytes, (const unsigned char *)ctx->alg[0]->algorithm_oid, strlen(ctx->alg[0]->algorithm_oid));
}


#define MLDSA_44_len 1
#define MLDSA_65_len 1
#define MLDSA_87_len 1

#define Dilithium_R3_4x4_len 1
#define Dilithium_R3_6x5_len 1
#define Dilithium_R3_8x7_len 1

#define Dilithium_R2_5x4_len 1
#define Dilithium_R2_6x5_len 1
#define Dilithium_R2_8x7_len 1

static const mlca_alg_impl_t Dilithium[1] = {
	{
		.opt_level = OPT_LEVEL_GENERIC,
		.alg_ctx = &crystals_alg_ctx_generic,
		.check_compatibility = check_compatibility_generic,
	}
};

static const mlca_alg_impl_t MLDSA[1] = {
	{
		.opt_level = OPT_LEVEL_GENERIC,
		.alg_ctx = &mldsa_alg_ctx_generic,
		.check_compatibility = check_compatibility_generic,
	}
};

static const mlca_sig_api_t dilithium_sig_api = {
	.keypair    = dilithium_keypair,
	.sig_sign   = dilithium_sign,
	.sig_verify = dilithium_verify
};

static const mlca_sig_api_t mldsa_sig_api = {
	.keypair             = mldsa_keypair,
	.sig_sign            = mldsa_sign,
	.sig_verify          = mldsa_verify,
	.sig_sign_internal   = mldsa_sign_internal,
	.sig_verify_internal = mldsa_verify_internal
};

const mlca_alg_t dilithium_mlca_ctx[9] = {
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_MLDSA_44,
		.algorithm_oid = MLCA_ALGORITHM_SIG_MLDSA_44_OID,
		.type = SIGNATURE,
		.alg_version = "ML-DSA (FIPS 204)",
		.claimed_nist_level = 2,
		.encodings = &Mldsa_44_encodings,
		.alg_ctx_len = MLDSA_44_len,
		.alg_ctx_all = MLDSA,
		.api.sig_api = &mldsa_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_MLDSA_65,
		.algorithm_oid = MLCA_ALGORITHM_SIG_MLDSA_65_OID,
		.type = SIGNATURE,
		.alg_version = "ML-DSA (FIPS 204)",
		.claimed_nist_level = 3,
		.encodings = &Mldsa_65_encodings,
		.alg_ctx_len = MLDSA_65_len,
		.alg_ctx_all = MLDSA,
		.api.sig_api = &mldsa_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_MLDSA_87,
		.algorithm_oid = MLCA_ALGORITHM_SIG_MLDSA_87_OID,
		.type = SIGNATURE,
		.alg_version = "ML-DSA (FIPS 204)",
		.claimed_nist_level = 5,
		.encodings = &Mldsa_87_encodings,
		.alg_ctx_len = MLDSA_87_len,
		.alg_ctx_all = MLDSA,
		.api.sig_api = &mldsa_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_2,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 3",
		.claimed_nist_level = 2,
		.encodings = &Dilithium_R3_4x4_encodings,
		.alg_ctx_len = Dilithium_R3_4x4_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_3,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 3",
		.claimed_nist_level = 3,
		.encodings = &Dilithium_R3_6x5_encodings,
		.alg_ctx_len = Dilithium_R3_6x5_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_5,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 3",
		.claimed_nist_level = 5,
		.encodings = &Dilithium_R3_8x7_encodings,
		.alg_ctx_len = Dilithium_R3_8x7_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	},

	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_54_R2,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_5x4_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 2",
		.claimed_nist_level = 2,
		.encodings = &Dilithium_R2_5x4_encodings,
		.alg_ctx_len = Dilithium_R2_5x4_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_65_R2,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_6x5_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 2",
		.claimed_nist_level = 3,
		.encodings = &Dilithium_R2_6x5_encodings,
		.alg_ctx_len = Dilithium_R2_6x5_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	},
	{
		.algorithm_name = MLCA_ALGORITHM_SIG_DILITHIUM_87_R2,
		.algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID,
		.type = SIGNATURE,
		.alg_version = "Dilithium Round 2",
		.claimed_nist_level = 5,
		.encodings = &Dilithium_R2_8x7_encodings,
		.alg_ctx_len = Dilithium_R2_8x7_len,
		.alg_ctx_all = Dilithium,
		.api.sig_api = &dilithium_sig_api,
	}
};
