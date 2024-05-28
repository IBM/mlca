// SPDX-License-Identifier: Apache-2.0
#include <mlca2.h>
#include <mlca2_int.h>
#include <string.h>
#include <stdlib.h>
#include "random_default.h"
#include "mlca_cpuid.h"

static mlca_cpu_features_t cpu_features = { 0 };

static const struct {
	const mlca_alg_t *ctx;
	int ctx_len;
} mlca_all_algs[] = {
	{
		.ctx = kyber_mlca_ctx,
		.ctx_len = sizeof(kyber_mlca_ctx) / sizeof(mlca_alg_t)
	},
	{
		.ctx = dilithium_mlca_ctx,
		.ctx_len = sizeof(dilithium_mlca_ctx) / sizeof(mlca_alg_t)
	}
};

MLCA_RC mlca_init(mlca_ctx_t *ctx, int num_algs, int protocol) {
	if (!ctx) {
		return MLCA_EPARAM;
	}
	memset(ctx, 0, sizeof(mlca_ctx_t));
	set_cpu_features(&cpu_features);
	int ret = MLCA_OK;
	ctx->num_algs = num_algs;
	ctx->protocol = protocol;
	ctx->alg = mlca_calloc(num_algs, sizeof(mlca_alg_impl_t *));
	if (!ctx->alg) {
		ret = MLCA_EMEM;
		goto err;
	}
	ctx->alg_impl = mlca_calloc(num_algs, sizeof(mlca_alg_t *));
	if (!ctx->alg_impl) {
		ret = MLCA_EMEM;
		goto err;
	}
	ret = mlca_set_rng(ctx, NULL);;
	if (ret) {
		goto err;
	}
	ctx->alg_enc_idx = 0; // The default encoding is "Raw"
err:
	return ret;
}

MLCA_RC mlca_set_alg(mlca_ctx_t *ctx, const char *algorithm_or_oid, int opt_level) {
	int ret = MLCA_OK;
	if (!ctx) {
		return MLCA_EPARAM;
	}
	ctx->alg[0] = 0;
	ctx->alg_impl[0] = 0;
	if (!ctx->rng) {
		ret = MLCA_ERNG;
		goto err;
	}
	int len = sizeof(mlca_all_algs) / sizeof(mlca_all_algs[0]);
	const mlca_alg_t *alg = 0;
	const mlca_alg_impl_t *alg_impl = 0;
	for (int i = 0; i < len; ++i) {
		for (int j = 0; j < mlca_all_algs[i].ctx_len; ++j) {
			if (!strcmp(algorithm_or_oid, mlca_all_algs[i].ctx[j].algorithm_name) || !strcmp(algorithm_or_oid, mlca_all_algs[i].ctx[j].algorithm_oid)) {
				alg = &mlca_all_algs[i].ctx[j];
				break;
			}
		}
	}
	if (alg) {
		int j;
		for (j = 0; j < alg->alg_ctx_len; ++j) {
			if (((opt_level >= 0 && opt_level == alg->alg_ctx_all[j].opt_level) && alg->alg_ctx_all[j].check_compatibility(&cpu_features)) ||
			        (opt_level < 0 && alg->alg_ctx_all[j].check_compatibility(&cpu_features)) ) {
				alg_impl = &alg->alg_ctx_all[j];
				break;
			}
		}

		if (!alg_impl) {
			ret = MLCA_ENSUPPORT;
			goto err;
		}

		ctx->alg_impl[0] = alg_impl;
		ctx->alg[0] = alg;
	} else {
		ret = MLCA_ENSUPPORT;
	}

err:
	return ret;
}

MLCA_RC mlca_set_rng(mlca_ctx_t *ctx, const mlca_random_t *rng) {
	if (!ctx) {
		return MLCA_EPARAM;
	}
	if (rng) {
		ctx->rng = rng;
	} else {
		ctx->rng = &RANDOM_DEFAULT;
	}
	return MLCA_OK;
}

MLCA_RC mlca_set_encoding_by_idx(mlca_ctx_t *ctx, int encoding) {
	if (encoding >= 0 && encoding < ctx->alg[0]->encodings->encodings_len) {
		ctx->alg_enc_idx = encoding;
		return MLCA_OK;
	} else {
		return MLCA_ENSUPPORT;
	}
}

MLCA_RC mlca_set_encoding_by_name_oid(mlca_ctx_t *ctx, const char *oid_or_name) {
	int idx = MLCA_ENSUPPORT;
	for (int i = 0; i < ctx->alg[0]->encodings->encodings_len; ++i) {
		for (int j = 0; j < ctx->alg[0]->encodings->encodings_len; ++j) {
			const mlca_encoding_impl_t *e = &ctx->alg[0]->encodings->encoding[j];
			if (!strcmp(oid_or_name, e->encoding_name)) {
				idx = j;
				break;
			}
		}
	}
	if (idx >= 0) {
		ctx->alg_enc_idx = idx;
		idx = MLCA_OK;
	}
	return idx;
}

MLCA_RC mlca_ctx_reset(mlca_ctx_t *ctx) {
	if (!ctx) {
		return MLCA_EPARAM;
	}
	for (int i = 0; i < ctx->num_algs; ++i) {
		ctx->alg[i] = 0;
		ctx->alg_impl[i] = 0;
	}
	ctx->rng = 0;
	ctx->num_algs = 0;
	ctx->protocol = 0;
	ctx->state = 0;
	return MLCA_OK;
}

MLCA_RC mlca_ctx_free(mlca_ctx_t *ctx) {
	if (!ctx) {
		return MLCA_EPARAM;
	}
	mlca_free(ctx->alg);
	mlca_free(ctx->alg_impl);
	for (int i = 0; i < 5; ++i) {
		if (ctx->data.prov[i]) {
			continue;
		}
		if (ctx->data.len[i] > 0 && ctx->data.sec[i]) {
			mlca_secure_free(ctx->data.mem[i], ctx->data.len[i]);
		} else if (ctx->data.len[i] > 0) {
			mlca_free(ctx->data.mem[i]);
		}
	}
	memset(ctx, 0, sizeof(mlca_ctx_t));
	return MLCA_OK;
}

MLCA_RC mlca_kem_keygen(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	int ret = MLCA_OK;
	if (!ctx) {
		return MLCA_EPARAM;
	}
	if (ctx->alg_enc_idx == 0) {
		return ctx->alg[0]->api.kem_api->keypair(ctx, pk, sk);
	} else {
		size_t pkrawlen = ctx->alg[0]->encodings->encoding[0].crypto_publickeybytes;
		size_t skrawlen = ctx->alg[0]->encodings->encoding[0].crypto_secretkeybytes;

		unsigned char *pkraw = mlca_malloc(pkrawlen);
		unsigned char *skraw = mlca_malloc(skrawlen);

		ret = ctx->alg[0]->api.kem_api->keypair(ctx, pkraw, skraw);
		if (ret) {
			goto end;
		}

		ret = mlca_kem_keypair_encode(ctx, pkraw, &pk, skraw, &sk);
		if (ret) {
			goto end;
		}

		mlca_free(pkraw);
		mlca_secure_free(skraw, skrawlen);
	}
end:
	return ret;
}

MLCA_RC mlca_kem_enc(const mlca_ctx_t *ctx, unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
	return ctx->alg[0]->api.kem_api->kem_enc(ctx, ct, ss, pk);
}

MLCA_RC mlca_kem_dec(const mlca_ctx_t *ctx, unsigned char *ss, const unsigned char *ct,
                     const unsigned char *sk) {
	return ctx->alg[0]->api.kem_api->kem_dec(ctx, ss, ct, sk);
}

MLCA_RC mlca_sig_keygen(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char *sk) {
	int ret = MLCA_OK;
	if (ctx->alg_enc_idx == 0) {
		return ctx->alg[0]->api.sig_api->keypair(ctx, pk, sk);
	} else {
		size_t pkrawlen = ctx->alg[0]->encodings->encoding[0].crypto_publickeybytes;
		size_t skrawlen = ctx->alg[0]->encodings->encoding[0].crypto_secretkeybytes;

		unsigned char *pkraw = mlca_malloc(pkrawlen);
		unsigned char *skraw = mlca_malloc(skrawlen);

		ret = ctx->alg[0]->api.sig_api->keypair(ctx, pkraw, skraw);
		if (ret) {
			goto end;
		}

		ret = mlca_sig_keypair_encode(ctx, pkraw, &pk, skraw, &sk);
		if (ret) {
			goto end;
		}

		mlca_free(pkraw);
		mlca_secure_free(skraw, skrawlen);
	}
end:
	return ret;
}

MLCA_RC mlca_sig_sign(const mlca_ctx_t *ctx, unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk) {
	return ctx->alg[0]->api.sig_api->sig_sign(ctx, sig, siglen, m, mlen, sk);
}

MLCA_RC mlca_sig_verify(const mlca_ctx_t *ctx, const unsigned char *m, size_t mlen, const unsigned char *sig, size_t siglen, const unsigned char *pk) {
	return ctx->alg[0]->api.sig_api->sig_verify(ctx, m, mlen, sig, siglen, pk);
}

MLCA_RC mlca_kem_keypair_encode(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char **pkenc, unsigned char *sk, unsigned char **skenc) {
	const mlca_encoding_impl_t *e_out = &ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx];
	const mlca_encoding_impl_t *e_in = &ctx->alg[0]->encodings->encoding[0];
	return e_out->encode(e_out, e_in, pk, pkenc, sk, skenc);
}

MLCA_RC mlca_kem_keypair_decode(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char **pkdec, unsigned char *sk, unsigned char **skdec) {
	const mlca_encoding_impl_t *e_out = &ctx->alg[0]->encodings->encoding[0];
	const mlca_encoding_impl_t *e_in = &ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx];
	return e_in->decode(e_out, e_in, pk, pkdec, sk, skdec);
}

MLCA_RC mlca_sig_keypair_encode(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char **pkenc, unsigned char *sk, unsigned char **skenc) {
	const mlca_encoding_impl_t *e_out = &ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx];
	const mlca_encoding_impl_t *e_in = &ctx->alg[0]->encodings->encoding[0];
	return e_out->encode(e_out, e_in, pk, pkenc, sk, skenc);
}

MLCA_RC mlca_sig_keypair_decode(const mlca_ctx_t *ctx, unsigned char *pk, unsigned char **pkdec, unsigned char *sk, unsigned char **skdec) {
	const mlca_encoding_impl_t *e_out = &ctx->alg[0]->encodings->encoding[0];
	const mlca_encoding_impl_t *e_in = &ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx];
	return e_in->decode(e_out, e_in, pk, pkdec, sk, skdec);
}

void *mlca_malloc(size_t size) {
	return malloc(size);
}

void *mlca_calloc(size_t count, size_t size) {
	void *ret = mlca_malloc(count * size);
	memset(ret, 0, count * size);
	return ret;
}
void mlca_secure_free(void *mem, size_t size) {
	if (mem) {
		typedef void *(*memset_t)(void *, int, size_t);
		static volatile memset_t memset_func = memset;
		memset_func(mem, 0, size);
		free(mem);
	}
}
void mlca_secure_clear(void *mem, size_t size) {
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t memset_func = memset;
	memset_func(mem, 0, size);
}
void mlca_free(void *mem) {
	free(mem);
}

size_t mlca_kem_crypto_publickeybytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_publickeybytes;
}

size_t mlca_kem_crypto_secretkeybytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_secretkeybytes;
}

size_t mlca_kem_crypto_ciphertextbytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_ciphertextbytes;
}

size_t mlca_kem_crypto_bytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_bytes;
}

size_t mlca_sig_crypto_publickeybytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_publickeybytes;
}

size_t mlca_sig_crypto_secretkeybytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_secretkeybytes;
}

size_t mlca_sig_crypto_bytes(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->encodings->encoding[ctx->alg_enc_idx].crypto_bytes;
}

int mlca_claimed_nist_level(const mlca_ctx_t *ctx) {
	return (int) ctx->alg[0]->claimed_nist_level;
}

mlca_algorithm_type_t mlca_alg_type(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->type;
}

const char *mlca_algorithm_name(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->algorithm_name;
}

const char *mlca_algorithm_oid(const mlca_ctx_t *ctx) {
	return ctx->alg[0]->algorithm_oid;
}

int mlca_opt_level(const mlca_ctx_t *ctx) {
	return ctx->alg_impl[0]->opt_level;
}
