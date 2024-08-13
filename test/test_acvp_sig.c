// SPDX-License-Identifier: Apache-2.0

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

static void MLDSA_randombytes_init(const mlca_random_t *ctx, unsigned char *entropy_input, unsigned char *personalization_string, int securityStrength) {
    (void) ctx;
	(void) personalization_string;
    (void) securityStrength;
	prng_state.pos = entropy_input;
}

static size_t MLDSA_randombytes(const mlca_random_t *ctx, unsigned char *random_array, size_t bytes_to_read) {
	memcpy(random_array, prng_state.pos, bytes_to_read);
	prng_state.pos += bytes_to_read;
    return bytes_to_read;
}

static int sig_kg_vector(mlca_ctx_t * ctx,
                         uint8_t *prng_output_stream,
                         const uint8_t *kg_pk, const uint8_t *kg_sk) {

	uint8_t *entropy_input;
	FILE *fh = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	int rc, ret = -1;

    size_t pkLen = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen = mlca_sig_crypto_secretkeybytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

    mlca_random_t rng;
    rng.randombytes = MLDSA_randombytes;
    rng.randombytes_init = MLDSA_randombytes_init;
	entropy_input = (uint8_t *) prng_output_stream;

    MLDSA_randombytes_init(&rng, entropy_input, NULL, 0);

    rc = mlca_set_rng(ctx, &rng);
    if (rc) goto err;

	fh = stdout;

	public_key = malloc(pkLen);
	secret_key = malloc(skLen);

	if ((public_key == NULL) || (secret_key == NULL)) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: malloc failed!\n", algName);
		goto err;
	}

	if ((prng_output_stream == NULL) || (kg_pk == NULL) || (kg_sk == NULL)) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

    rc = mlca_sig_keygen(ctx, public_key, secret_key);
	if (rc) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: mlca_sig_keygen failed!\n", algName);
		goto err;
	}
	fprintBstr(fh, "pk: ", public_key, pkLen);
	fprintBstr(fh, "sk: ", secret_key, skLen);

	if (!memcmp(public_key, kg_pk, pkLen) && !memcmp(secret_key, kg_sk, skLen)) {
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[test_acvp_sig] %s ERROR: public key or private key doesn't match!\n", algName);
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

static int sig_ver_vector(mlca_ctx_t * ctx,
						  const uint8_t *sigVer_pk_bytes, 
						  const uint8_t *sigVer_msg_bytes, 
						  size_t msgLen, 
						  const uint8_t *sigVer_sig_bytes, int testPassed) {

	uint8_t *entropy_input;
	FILE *fh = NULL;
	int rc, ret = -1;

    size_t pkLen = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen = mlca_sig_crypto_secretkeybytes(ctx);
	size_t sigLen = mlca_sig_crypto_bytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

	fh = stdout;

	if ((sigVer_pk_bytes == NULL) || (sigVer_msg_bytes == NULL) || (sigVer_sig_bytes == NULL)) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

	rc = mlca_sig_verify_internal(ctx, sigVer_msg_bytes, msgLen, sigVer_sig_bytes, sigLen, sigVer_pk_bytes);
	if (rc != testPassed) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: mlca_sig_verify_internal failed!\n", algName);
		goto err;
	} else {
		ret = 0;
	}


	fprintBstr(fh, "testPassed: ", (const uint8_t *)&testPassed, 1);

	goto cleanup;

err:
	ret = EXIT_FAILURE;
	goto cleanup;

algo_not_enabled:
	ret = EXIT_SUCCESS;

cleanup:
	return ret;
	
}

static int sig_gen_vector(mlca_ctx_t * ctx,
                          uint8_t *prng_output_stream,
                          const uint8_t *sigGen_sk, const uint8_t *sigGen_msg, size_t sigGen_msgLen, const uint8_t *sigGen_sig, int randomized) {

	uint8_t *entropy_input;
	FILE *fh = NULL;
	uint8_t *signature = NULL;
	int rc, ret = -1;

    size_t pkLen = mlca_sig_crypto_publickeybytes(ctx);
    size_t skLen = mlca_sig_crypto_secretkeybytes(ctx);
	size_t sigLen = mlca_sig_crypto_bytes(ctx);
    const char *algName = mlca_algorithm_name(ctx);

    mlca_random_t rng;

    rng.randombytes = MLDSA_randombytes;
    rng.randombytes_init = MLDSA_randombytes_init;

	if (randomized) {
		entropy_input = (uint8_t *) prng_output_stream;
    	MLDSA_randombytes_init(&rng, entropy_input, NULL, 0);
	} else {
		entropy_input = malloc(32);
		memset(entropy_input, 0, 32);
		MLDSA_randombytes_init(&rng, entropy_input, NULL, 0);
	}

    rc = mlca_set_rng(ctx, &rng);
    if (rc) goto err;

	fh = stdout;

	signature = malloc(sigLen);

	if (signature == NULL) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: malloc failed!\n", algName);
		goto err;
	}

	if ((randomized && prng_output_stream == NULL) || (sigGen_sk == NULL) || (sigGen_msg == NULL) || (sigGen_sig == NULL)) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: inputs NULL!\n", algName);
		goto err;
	}

    rc = mlca_sig_sign_internal(ctx, signature, &sigLen, sigGen_msg, sigGen_msgLen, sigGen_sk);
	if (rc) {
		fprintf(stderr, "[test_acvp_sig] %s ERROR: mlca_sig_sign_internal failed!\n", algName);
		goto err;
	}
	fprintBstr(fh, "signature: ", signature, pkLen);

	if (!memcmp(signature, sigGen_sig, sigLen)) {
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[test_acvp_sig] %s ERROR: public key or private key doesn't match!\n", algName);
	}
	goto cleanup;

err:
	ret = EXIT_FAILURE;
	goto cleanup;

algo_not_enabled:
	ret = EXIT_SUCCESS;

cleanup:
	if (!randomized)
		free(entropy_input);
    free(signature);
	return ret;
}

int main(int argc, char **argv) {
	int rc = EXIT_SUCCESS;
    mlca_ctx_t ctx = {};

	if (argc == 222) {
		fprintf(stderr, "Usage: test_acvp_sig algname testname [testargs]\n");
		fprintf(stderr, "\n");
		printf("\n");
		return EXIT_FAILURE;
	}

	size_t pkLen;
    size_t skLen;
    size_t sigLen;
	size_t msgLen;

	char *alg_name = argv[1];
	char *test_name = argv[2];
	char *prng_output_stream;
	char *kg_pk;
	char *kg_sk;

	char *sigGen_sk;
	char *sigGen_msg;
	char *sigGen_sig;

	char *sigVer_pk;
	char *sigVer_msg;
	char *sigVer_sig;

	uint8_t *prng_output_stream_bytes = NULL;
	uint8_t *kg_pk_bytes = NULL;
	uint8_t *kg_sk_bytes = NULL;

	uint8_t *sigGen_sk_bytes = NULL;
	uint8_t *sigGen_msg_bytes = NULL;
	uint8_t *sigGen_sig_bytes = NULL;


	uint8_t *sigVer_pk_bytes = NULL;
	uint8_t *sigVer_msg_bytes = NULL;
	uint8_t *sigVer_sig_bytes = NULL;

	rc = mlca_init(&ctx, 1, 0);
    if (rc) goto err;

    rc = mlca_set_alg(&ctx, alg_name, OPT_LEVEL_AUTO);
    if (rc) goto err;

	pkLen = mlca_sig_crypto_publickeybytes(&ctx);
    skLen = mlca_sig_crypto_secretkeybytes(&ctx);
	sigLen = mlca_sig_crypto_bytes(&ctx);

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
			fprintf(stderr, "[vectors_sig] ERROR: malloc failed!\n");
			rc = EXIT_FAILURE;
			goto err;
		}

		hexStringToByteArray(prng_output_stream, prng_output_stream_bytes);
		hexStringToByteArray(kg_pk, kg_pk_bytes);
		hexStringToByteArray(kg_sk, kg_sk_bytes);


		rc = sig_kg_vector(&ctx, prng_output_stream_bytes, kg_pk_bytes, kg_sk_bytes);

	} else if (!strcmp(test_name, "sigGen_det") || !strcmp(test_name, "sigGen_rnd")) {
        sigGen_sk = argv[3];
		sigGen_msg = argv[4];
		sigGen_sig = argv[5];

		int randomized = !strcmp(test_name, "sigGen_rnd");
		if (randomized) {
			prng_output_stream = argv[6];
			if (strlen(prng_output_stream) % 2 != 0) {
				rc = EXIT_FAILURE;
				goto err;
			}
			prng_output_stream_bytes = malloc(strlen(prng_output_stream) / 2);
			if (prng_output_stream_bytes == NULL) {
				fprintf(stderr, "[vectors_sig] ERROR: malloc failed!\n");
				rc = EXIT_FAILURE;
				goto err;
			}
		}

		if ( strlen(sigGen_msg) % 2 != 0 ||
		     strlen(sigGen_sig) != 2 * sigLen) {
			rc = EXIT_FAILURE;
			goto err;
		}

		msgLen = strlen(sigGen_msg) / 2;
		
		sigGen_sk_bytes = malloc(skLen);
		sigGen_msg_bytes = malloc(msgLen);
		sigGen_sig_bytes = malloc(sigLen);

		if ((sigGen_msg_bytes == NULL) || (sigGen_sig_bytes == NULL)) {
			fprintf(stderr, "[vectors_sig] ERROR: malloc failed!\n");
			rc = EXIT_FAILURE;
			goto err;
		}

		if (randomized)
			hexStringToByteArray(prng_output_stream, prng_output_stream_bytes);
		
		hexStringToByteArray(sigGen_sk, sigGen_sk_bytes);
		hexStringToByteArray(sigGen_msg, sigGen_msg_bytes);
		hexStringToByteArray(sigGen_sig, sigGen_sig_bytes);

		rc = sig_gen_vector(&ctx, prng_output_stream_bytes, sigGen_sk_bytes, sigGen_msg_bytes, msgLen, sigGen_sig_bytes, randomized);

	} else if (!strcmp(test_name, "sigVer")) {
		sigVer_pk = argv[3];
		sigVer_msg = argv[4];
		sigVer_sig = argv[5];

		int sigVerPassed = atoi(argv[6]);

		if ( strlen(sigVer_msg) % 2 != 0 ||
		     strlen(sigVer_sig) != 2 * sigLen ||
			 strlen(sigVer_pk) != 2 * pkLen ||
			 (sigVerPassed != 0 && sigVerPassed != 1)) {
			rc = EXIT_FAILURE;
			goto err;
		}

		msgLen = strlen(sigVer_msg) / 2;
		
		sigVer_pk_bytes = malloc(pkLen);
		sigVer_msg_bytes = malloc(msgLen);
		sigVer_sig_bytes = malloc(sigLen);

		hexStringToByteArray(sigVer_pk, sigVer_pk_bytes);
		hexStringToByteArray(sigVer_msg, sigVer_msg_bytes);
		hexStringToByteArray(sigVer_sig, sigVer_sig_bytes);

		rc = sig_ver_vector(&ctx, sigVer_pk_bytes, sigVer_msg_bytes, msgLen, sigVer_sig_bytes, sigVerPassed);

	} else {
		rc = EXIT_FAILURE;
		printf("[vectors_sig] %s only keyGen/sigGen/sigVer supported!\n", alg_name);
	}

err:
	free(prng_output_stream_bytes);
	free(kg_pk_bytes);
	free(kg_sk_bytes);

	if (rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}
