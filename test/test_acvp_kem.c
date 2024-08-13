// SPDX-License-Identifier: MIT

// This tests the test vectors published by NIST ACVP

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <mlca2.h>
#include <stdint.h>

struct {
	const uint8_t *pos;
} prng_state = {
	.pos = 0
};

static void fprintBstr(FILE *fp, const char *S, const uint8_t *A, size_t L) {
	size_t i;
	fprintf(fp, "%s", S);
	for (i = 0; i < L; i++) {
		fprintf(fp, "%02X", A[i]);
	}
	if (L == 0) {
		fprintf(fp, "00");
	}
	fprintf(fp, "\n");
}

static uint8_t hexCharToDecimal(char c) {
	if (c >= '0' && c <= '9') {
		return (uint8_t) (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (uint8_t) (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (uint8_t) (c - 'A' + 10);
	} else {
		fprintf(stderr, "Invalid hex character: %c\n", c);
		return 0;
	}
}

static void hexStringToByteArray(const char *hexString, uint8_t *byteArray) {
	size_t len = strlen(hexString);

	if (len % 2 != 0) {
		fprintf(stderr, "Hex string must have an even number of characters\n");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0, j = 0; i < len; i += 2, j++) {
		byteArray[j] = (uint8_t) ((hexCharToDecimal(hexString[i]) << 4) | hexCharToDecimal(hexString[i + 1]));
	}
}

static void MLKEM_randombytes_init(const mlca_random_t *ctx, unsigned char *entropy_input, unsigned char *personalization_string, int securityStrength) {
    (void) ctx;
	(void) personalization_string;
    (void) securityStrength;
	prng_state.pos = entropy_input;
}

static size_t MLKEM_randombytes(const mlca_random_t *ctx, unsigned char *random_array, size_t bytes_to_read) {
	memcpy(random_array, prng_state.pos, bytes_to_read);
	prng_state.pos += bytes_to_read;
    return bytes_to_read;
}

static int kem_kg_vector(mlca_ctx_t *ctx,
                         uint8_t *prng_output_stream,
                         const uint8_t *kg_pk, const uint8_t *kg_sk) {

	uint8_t *entropy_input;
	FILE *fh = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	int rc, ret = -1;

    size_t pkLen = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen = mlca_kem_crypto_secretkeybytes(ctx);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

    mlca_random_t rng;
    rng.randombytes = MLKEM_randombytes;
    rng.randombytes_init = MLKEM_randombytes_init;
	entropy_input = (uint8_t *) prng_output_stream;

    MLKEM_randombytes_init(&rng, entropy_input, NULL, 0);

    rc = mlca_set_rng(ctx, &rng);
    if (rc) goto err;

	fh = stdout;

	public_key = malloc(pkLen);
	secret_key = malloc(skLen);

	if ((public_key == NULL) || (secret_key == NULL)) {
		fprintf(stderr, "[vectors_kem] %s ERROR: malloc failed!\n", algName);
		goto err;
	}

	if ((prng_output_stream == NULL) || (kg_pk == NULL) || (kg_sk == NULL)) {
		fprintf(stderr, "[vectors_kem] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

    rc = mlca_kem_keygen(ctx, public_key, secret_key);
	if (rc) {
		fprintf(stderr, "[vectors_kem] %s ERROR: mlca_kem_keygen failed!\n", algName);
		goto err;
	}
	fprintBstr(fh, "ek: ", public_key, pkLen);
	fprintBstr(fh, "dk: ", secret_key, skLen);

	if (!memcmp(public_key, kg_pk, pkLen) && !memcmp(secret_key, kg_sk, skLen)) {
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[vectors_kem] %s ERROR: public key or private key doesn't match!\n", algName);
	}
	goto cleanup;

err:
	ret = EXIT_FAILURE;
	goto cleanup;

algo_not_enabled:
	ret = EXIT_SUCCESS;

cleanup:
    free(secret_key);
	free(public_key);
	return ret;
}


static int kem_vector_encdec_aft(mlca_ctx_t *ctx,
                                 uint8_t *prng_output_stream,
                                 const uint8_t *encdec_pk,
                                 const uint8_t *encdec_k, const uint8_t *encdec_c) {

	uint8_t *entropy_input;
	FILE *fh = NULL;
	uint8_t *ss_encaps = NULL;
	uint8_t *ct_encaps = NULL;
	int rc, ret = -1;

    size_t pkLen = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen = mlca_kem_crypto_secretkeybytes(ctx);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(ctx);
    size_t ssLen = mlca_kem_crypto_bytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

    mlca_random_t rng;
    rng.randombytes = MLKEM_randombytes;
    rng.randombytes_init = MLKEM_randombytes_init;
	entropy_input = (uint8_t *) prng_output_stream;

    MLKEM_randombytes_init(&rng, entropy_input, NULL, 0);

    rc = mlca_set_rng(ctx, &rng);
    if (rc) goto err;


	fh = stdout;

	ss_encaps = malloc(ssLen);
	ct_encaps = malloc(ctLen);
	if ((ss_encaps == NULL) || (ct_encaps == NULL)) {
		fprintf(stderr, "[vectors_kem] %s ERROR: malloc failed!\n", algName);
		goto err;
	}

	if ((prng_output_stream == NULL) || (encdec_pk == NULL) || (encdec_k == NULL) || (encdec_c == NULL)) {
		fprintf(stderr, "[vectors_kem] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

    rc = mlca_kem_enc(ctx, ct_encaps, ss_encaps, encdec_pk);
	if (rc) {
		fprintf(stderr, "[vectors_kem] %s ERROR: mlca_kem_enc failed!\n", algName);
		goto err;
	}

	fprintBstr(fh, "c: ", ct_encaps, ctLen);
	fprintBstr(fh, "k: ", ss_encaps, ssLen);

	if (!memcmp(ct_encaps, encdec_c, ctLen) && !memcmp(ss_encaps, encdec_k, ssLen)) {
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[vectors_kem] %s ERROR (AFT): ciphertext or shared secret doesn't match!\n", algName);
	}

	goto cleanup;

err:
	ret = EXIT_FAILURE;
	goto cleanup;

algo_not_enabled:
	ret = EXIT_SUCCESS;

cleanup:
	free(ss_encaps);
	free(ct_encaps);
	return ret;
}

static int kem_vector_encdec_val(mlca_ctx_t *ctx,
                                 const uint8_t *encdec_sk, const uint8_t *encdec_c,
                                 const uint8_t *encdec_k) {
	FILE *fh = NULL;
	uint8_t *ss_decaps = NULL;
	int rc, ret = EXIT_FAILURE;

    size_t pkLen = mlca_kem_crypto_publickeybytes(ctx);
    size_t skLen = mlca_kem_crypto_secretkeybytes(ctx);
    size_t ctLen = mlca_kem_crypto_ciphertextbytes(ctx);
    size_t ssLen = mlca_kem_crypto_bytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

	fh = stdout;

	ss_decaps = malloc(ssLen);

	if (ss_decaps == NULL) {
		fprintf(stderr, "[test_acvp_kem] %s ERROR: malloc failed!\n", algName);
		goto err;
	}

	if ((encdec_sk == NULL) || (encdec_k == NULL) || (encdec_c == NULL)) {
		fprintf(stderr, "[test_acvp_kem] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

    rc = mlca_kem_dec(ctx, ss_decaps, encdec_c, encdec_sk);
	if (rc) {
		fprintf(stderr, "[test_acvp_kem] %s ERROR: mlca_kem_dec failed!\n", algName);
		goto err;
	}

	fprintBstr(fh, "k: ", ss_decaps, ssLen);

	if (!memcmp(ss_decaps, encdec_k, ssLen)) {
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[test_acvp_kem] %s ERROR (AFT): ciphertext or shared secret doesn't match!\n", algName);
	}

	goto cleanup;

err:
	ret = EXIT_FAILURE;
	goto cleanup;

algo_not_enabled:
	ret = EXIT_SUCCESS;

cleanup:
	free(ss_decaps);
	return ret;
}

int main(int argc, char **argv) {
	int rc = EXIT_SUCCESS;
    mlca_ctx_t ctx = {};

	if (argc == 222) {
		fprintf(stderr, "Usage: test_acvp_kem algname testname [testargs]\n");
		fprintf(stderr, "\n");
		printf("\n");
		return EXIT_FAILURE;
	}
    
    size_t pkLen;
    size_t skLen;
    size_t ctLen;
    size_t ssLen;

	char *alg_name = argv[1];
	char *test_name = argv[2];
	char *prng_output_stream;
	char *kg_pk;
	char *kg_sk;
	char *encdec_aft_pk;
	char *encdec_aft_k;
	char *encdec_aft_c;

	char *encdec_val_sk;
	char *encdec_val_k;
	char *encdec_val_c;

	uint8_t *prng_output_stream_bytes = NULL;
	uint8_t *kg_pk_bytes = NULL;
	uint8_t *kg_sk_bytes = NULL;

	uint8_t *encdec_aft_pk_bytes = NULL;
	uint8_t *encdec_aft_k_bytes = NULL;
	uint8_t *encdec_aft_c_bytes = NULL;

	uint8_t *encdec_val_sk_bytes = NULL;
	uint8_t *encdec_val_k_bytes = NULL;
	uint8_t *encdec_val_c_bytes = NULL;


    rc = mlca_init(&ctx, 1, 0);
    if (rc) goto err;

    rc = mlca_set_alg(&ctx, alg_name, OPT_LEVEL_AUTO);
    if (rc) goto err;

    pkLen = mlca_kem_crypto_publickeybytes(&ctx);
    skLen = mlca_kem_crypto_secretkeybytes(&ctx);
    ctLen = mlca_kem_crypto_ciphertextbytes(&ctx);
    ssLen = mlca_kem_crypto_bytes(&ctx);

	if (!strcmp(test_name, "keyGen")) {
		prng_output_stream = argv[3]; // d || z
        kg_pk = argv[4];
        kg_sk = argv[5];

		if (strlen(prng_output_stream) % 2 != 0 ||
		        strlen(kg_pk) != 2 * pkLen ||
		        strlen(kg_sk) != 2 * skLen) {
			rc = EXIT_FAILURE;
			goto err;
		}

		prng_output_stream_bytes = malloc(strlen(prng_output_stream) / 2);
		kg_pk_bytes = malloc(pkLen);
		kg_sk_bytes = malloc(skLen);

		if ((prng_output_stream_bytes == NULL) || (kg_pk_bytes == NULL) || (kg_sk_bytes == NULL)) {
			fprintf(stderr, "[test_acvp_kem] ERROR: malloc failed!\n");
			rc = EXIT_FAILURE;
			goto err;
		}

		hexStringToByteArray(prng_output_stream, prng_output_stream_bytes);
		hexStringToByteArray(kg_pk, kg_pk_bytes);
		hexStringToByteArray(kg_sk, kg_sk_bytes);


		rc = kem_kg_vector(&ctx, prng_output_stream_bytes, kg_pk_bytes, kg_sk_bytes);
	} else if (!strcmp(test_name, "encDecAFT")) {
		prng_output_stream = argv[3]; // m
		encdec_aft_pk = argv[4];
		encdec_aft_k = argv[5];
		encdec_aft_c = argv[6];

		if (strlen(prng_output_stream) % 2 != 0 ||
		        strlen(encdec_aft_c) != 2 * ctLen ||
		        strlen(encdec_aft_k) != 2 * ssLen ||
		        strlen(encdec_aft_pk) != 2 * pkLen) {
			rc = EXIT_FAILURE;
			goto err;
		}

		prng_output_stream_bytes = malloc(strlen(prng_output_stream) / 2);
		encdec_aft_pk_bytes = malloc(pkLen);
		encdec_aft_k_bytes = malloc(ssLen);
		encdec_aft_c_bytes = malloc(ctLen);

		if ((prng_output_stream_bytes == NULL) || (encdec_aft_pk_bytes == NULL) || (encdec_aft_k_bytes == NULL) || (encdec_aft_c_bytes == NULL)) {
			fprintf(stderr, "[test_acvp_kem] ERROR: malloc failed!\n");
			rc = EXIT_FAILURE;
			goto err;
		}

		hexStringToByteArray(prng_output_stream, prng_output_stream_bytes);
		hexStringToByteArray(encdec_aft_pk, encdec_aft_pk_bytes);
		hexStringToByteArray(encdec_aft_k, encdec_aft_k_bytes);
		hexStringToByteArray(encdec_aft_c, encdec_aft_c_bytes);

		rc = kem_vector_encdec_aft(&ctx, prng_output_stream_bytes, encdec_aft_pk_bytes, encdec_aft_k_bytes, encdec_aft_c_bytes);
	} else if (!strcmp(test_name, "encDecVAL")) {
		encdec_val_sk = argv[3];
		encdec_val_k = argv[4];
		encdec_val_c = argv[5];

		if (strlen(encdec_val_c) != 2 * ctLen ||
		        strlen(encdec_val_k) != 2 * ssLen ||
		        strlen(encdec_val_sk) != 2 * skLen) {
			rc = EXIT_FAILURE;
			goto err;
		}

		encdec_val_sk_bytes = malloc(skLen);
		encdec_val_k_bytes = malloc(ssLen);
		encdec_val_c_bytes = malloc(ctLen);

		if ((encdec_val_sk_bytes == NULL) || (encdec_val_k_bytes == NULL) || (encdec_val_c_bytes == NULL)) {
			fprintf(stderr, "[test_acvp_kem] ERROR: malloc failed!\n");
			rc = EXIT_FAILURE;
			goto err;
		}

		hexStringToByteArray(encdec_val_sk, encdec_val_sk_bytes);
		hexStringToByteArray(encdec_val_k, encdec_val_k_bytes);
		hexStringToByteArray(encdec_val_c, encdec_val_c_bytes);

		rc = kem_vector_encdec_val(&ctx, encdec_val_sk_bytes, encdec_val_c_bytes, encdec_val_k_bytes);


	} else {
        rc = EXIT_FAILURE;
		printf("[test_acvp_kem] %s only keyGen supported!\n", alg_name);
	}

err:
	free(prng_output_stream_bytes);
	free(kg_pk_bytes);
	free(kg_sk_bytes);
	free(encdec_aft_c_bytes);
	free(encdec_aft_k_bytes);
	free(encdec_aft_pk_bytes);
	free(encdec_val_c_bytes);
	free(encdec_val_k_bytes);
	free(encdec_val_sk_bytes);

	if (rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}
