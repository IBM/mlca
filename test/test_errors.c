// SPDX-License-Identifier: Apache-2.0
#include <mlca2.h>
#include <mlca2_encoding.h>
#include <pqalgs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static size_t rng_limit = SIZE_MAX;
static size_t rng_calls;

static size_t test_randombytes(const mlca_random_t* ctx, unsigned char* out, size_t bytes) {
    size_t written = bytes < rng_limit ? bytes : rng_limit;
    ++rng_calls;
    memset(out, 0x42, written);
    return written;
}

static const mlca_random_t test_rng = {
    .randombytes = test_randombytes
};

static int init_context(mlca_ctx_t* ctx, const char* algorithm) {
    rng_limit = SIZE_MAX;
    rng_calls = 0;
    CHECK(mlca_init(ctx, 1, 0) == MLCA_OK);
    CHECK(mlca_set_alg(ctx, algorithm, OPT_LEVEL_AUTO) == MLCA_OK);
    CHECK(mlca_set_rng(ctx, &test_rng) == MLCA_OK);
    return 0;
}

static int filled_with(const unsigned char* buf, size_t bytes, unsigned char value) {
    for (size_t i = 0; i < bytes; ++i) {
        if (buf[i] != value)
            return 0;
    }
    return 1;
}

static int test_signing(const char* algorithm, int rng_errors) {
    mlca_ctx_t ctx;
    const unsigned char message[] = {1, 2, 3};
    CHECK(init_context(&ctx, algorithm) == 0);
    size_t pkbytes = mlca_sig_crypto_publickeybytes(&ctx);
    size_t skbytes = mlca_sig_crypto_secretkeybytes(&ctx);
    size_t sigbytes = mlca_sig_crypto_bytes(&ctx);
    unsigned char* pk = malloc(pkbytes);
    unsigned char* sk = malloc(skbytes);
    unsigned char* sig = malloc(sigbytes);
    CHECK(pk && sk && sig);
    CHECK(mlca_sig_keygen(&ctx, pk, sk) == MLCA_OK);

    int mldsa = !strncmp(algorithm, "ML-DSA", 6);
    for (int internal = 0; internal <= mldsa; ++internal) {
        size_t lengths[] = {0, 1, sigbytes - 1};
        size_t fills[] = {0, 1, 31};
        for (size_t i = 0; i < 3; ++i) {
            size_t length = rng_errors ? sigbytes : lengths[i];
            size_t original = length;
            rng_limit = rng_errors ? fills[i] : SIZE_MAX;
            rng_calls = 0;
            memset(sig, 0xa5, sigbytes);
            int rc = internal ? mlca_sig_sign_internal(&ctx, sig, &length, message, sizeof(message), sk)
                              : mlca_sig_sign(&ctx, sig, &length, message, sizeof(message), sk);
            if (rc != (rng_errors ? MLCA_ERNG : MLCA_ETOOSMALL))
                fprintf(stderr, "%s internal=%d capacity=%zu returned %d\n", algorithm, internal, original, rc);
            CHECK(rc == (rng_errors ? MLCA_ERNG : MLCA_ETOOSMALL));
            CHECK(length == original);
            CHECK(filled_with(sig, sigbytes, 0xa5));
            CHECK(rng_calls == (rng_errors ? 1 : 0));
        }
        rng_limit = SIZE_MAX;
        size_t length = sigbytes;
        int rc = internal ? mlca_sig_sign_internal(&ctx, sig, &length, message, sizeof(message), sk)
                          : mlca_sig_sign(&ctx, sig, &length, message, sizeof(message), sk);
        CHECK(rc == MLCA_OK && length == sigbytes);
        rc = internal ? mlca_sig_verify_internal(&ctx, message, sizeof(message), sig, length, pk)
                      : mlca_sig_verify(&ctx, message, sizeof(message), sig, length, pk);
        CHECK(rc == 1);
    }
    const unsigned char* oid = (const unsigned char*)mlca_algorithm_oid(&ctx);
    size_t oidbytes = strlen((const char*)oid);
    memset(sig, 0xa5, sigbytes);
    CHECK(mlca_sign(sig, sigbytes, message, sizeof(message), sk, skbytes - 1,
                    (void*)&test_rng, oid, oidbytes) == MLCA_EKEYSIZE);
    CHECK(filled_with(sig, sigbytes, 0xa5));
    if (mldsa) {
        CHECK(mlca_sign_internal(sig, sigbytes, message, sizeof(message), sk, skbytes - 1,
                                 (void*)&test_rng, oid, oidbytes) == MLCA_EKEYSIZE);
        CHECK(filled_with(sig, sigbytes, 0xa5));
    }
    free(pk);
    free(sk);
    free(sig);
    mlca_ctx_free(&ctx);
    return 0;
}

static int test_decapsulation(const char* algorithm) {
    mlca_ctx_t ctx;
    CHECK(init_context(&ctx, algorithm) == 0);
    size_t pkbytes = mlca_kem_crypto_publickeybytes(&ctx);
    size_t skbytes = mlca_kem_crypto_secretkeybytes(&ctx);
    size_t ctbytes = mlca_kem_crypto_ciphertextbytes(&ctx);
    unsigned char* pk = malloc(pkbytes);
    unsigned char* sk = malloc(skbytes);
    unsigned char* ct = malloc(ctbytes + 1);
    unsigned char shared[32], decoded[32], short_ct[1];
    CHECK(pk && sk && ct);
    CHECK(mlca_kem_keygen(&ctx, pk, sk) == MLCA_OK);
    CHECK(mlca_kem_enc(&ctx, ct, shared, pk) == MLCA_OK);
    short_ct[0] = ct[0];
    const unsigned char* oid = (const unsigned char*)mlca_algorithm_oid(&ctx);
    size_t oidbytes = strlen((const char*)oid);
    size_t lengths[] = {0, 1, ctbytes - 1, ctbytes + 1};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        memset(decoded, 0xa5, sizeof(decoded));
        CHECK(mlca_kem2(decoded, sizeof(decoded), i < 2 ? short_ct : ct, lengths[i],
                        sk, skbytes, oid, oidbytes) == MLCA_EPARAM);
        CHECK(filled_with(decoded, sizeof(decoded), 0xa5));
    }
    CHECK(mlca_kem2(decoded, sizeof(decoded), NULL, ctbytes, sk, skbytes, oid, oidbytes) == MLCA_EPARAM);
    CHECK(mlca_kem2(decoded, sizeof(decoded), ct, ctbytes, sk, skbytes, oid, oidbytes) == sizeof(decoded));
    CHECK(!memcmp(shared, decoded, sizeof(shared)));
    free(pk);
    free(sk);
    free(ct);
    mlca_ctx_free(&ctx);
    return 0;
}

static int test_keygen_rng(const char* algorithm) {
    mlca_ctx_t ctx;
    CHECK(init_context(&ctx, algorithm) == 0);
    size_t pkbytes = mlca_kem_crypto_publickeybytes(&ctx);
    size_t skbytes = mlca_kem_crypto_secretkeybytes(&ctx);
    unsigned char* pk = malloc(pkbytes);
    unsigned char* sk = malloc(skbytes);
    CHECK(pk && sk);
    for (size_t i = 0; i < 64; ++i) {
        rng_limit = i;
        memset(pk, 0xa5, pkbytes);
        memset(sk, 0xa5, skbytes);
        CHECK(mlca_kem_keygen(&ctx, pk, sk) == MLCA_ERNG);
        CHECK(filled_with(pk, pkbytes, 0xa5));
        CHECK(filled_with(sk, skbytes, 0xa5));
    }
    rng_limit = 64;
    CHECK(mlca_kem_keygen(&ctx, pk, sk) == MLCA_OK);
    free(pk);
    free(sk);
    mlca_ctx_free(&ctx);
    return 0;
}

static int mark_encoding(const unsigned char* key, unsigned char* framing, size_t bytes,
                         int depth, int private_key) {
    size_t offset = 0;
    while (offset < bytes) {
        CHECK(bytes - offset >= 2);
        size_t header = 2;
        size_t length = key[offset + 1];
        if (length == 0x82) {
            CHECK(bytes - offset >= 4);
            header = 4;
            length = ((size_t)key[offset + 2] << 8) | key[offset + 3];
        } else {
            CHECK(length < 0x80);
        }
        CHECK(length <= bytes - offset - header);
        memset(framing + offset, 1, header);
        unsigned char tag = key[offset];
        if (tag == CRS__ASN1_SEQUENCE || (!private_key && depth == 1 && tag == CRS__ASN1_BITSTRING) ||
            (private_key && depth == 1 && tag == CRS__ASN1_OCTETSTRING)) {
            CHECK(mark_encoding(key + offset + header, framing + offset + header,
                                length, depth + 1, private_key) == 0);
        } else if (tag == CRS__ASN1_INT || tag == CRS__ASN1_OID || tag == CRS__ASN1_NULL) {
            memset(framing + offset + header, 1, length);
        }
        offset += header + length;
    }
    return 0;
}

static int test_encoding(const char* algorithm, int encoding, int kem) {
    mlca_ctx_t ctx;
    CHECK(init_context(&ctx, algorithm) == 0);
    size_t pkbytes = kem ? mlca_kem_crypto_publickeybytes(&ctx) : mlca_sig_crypto_publickeybytes(&ctx);
    size_t skbytes = kem ? mlca_kem_crypto_secretkeybytes(&ctx) : mlca_sig_crypto_secretkeybytes(&ctx);
    unsigned char* pk = malloc(pkbytes);
    unsigned char* sk = malloc(skbytes);
    unsigned char* pkdec = malloc(pkbytes);
    unsigned char* skdec = malloc(skbytes);
    CHECK(pk && sk && pkdec && skdec);
    CHECK((kem ? mlca_kem_keygen(&ctx, pk, sk) : mlca_sig_keygen(&ctx, pk, sk)) == MLCA_OK);
    unsigned char* raw = NULL;
    CHECK((kem ? mlca_kem_keypair_encode(&ctx, pk, &raw, NULL, NULL)
               : mlca_sig_keypair_encode(&ctx, pk, &raw, NULL, NULL)) == MLCA_OK);
    CHECK(raw == pk);
    CHECK((kem ? mlca_kem_keypair_encode(&ctx, NULL, NULL, sk, &raw)
               : mlca_sig_keypair_encode(&ctx, NULL, NULL, sk, &raw)) == MLCA_OK);
    CHECK(raw == sk);
    CHECK((kem ? mlca_kem_keypair_decode(&ctx, pk, &raw, NULL, NULL)
               : mlca_sig_keypair_decode(&ctx, pk, &raw, NULL, NULL)) == MLCA_OK);
    CHECK(raw == pk);
    CHECK((kem ? mlca_kem_keypair_decode(&ctx, NULL, NULL, sk, &raw)
               : mlca_sig_keypair_decode(&ctx, NULL, NULL, sk, &raw)) == MLCA_OK);
    CHECK(raw == sk);
    CHECK(mlca_set_encoding_by_idx(&ctx, encoding) == MLCA_OK);
    size_t pkencbytes = kem ? mlca_kem_crypto_publickeybytes(&ctx) : mlca_sig_crypto_publickeybytes(&ctx);
    size_t skencbytes = kem ? mlca_kem_crypto_secretkeybytes(&ctx) : mlca_sig_crypto_secretkeybytes(&ctx);
    unsigned char* pkenc = malloc(pkencbytes);
    unsigned char* skenc = malloc(skencbytes);
    unsigned char* framing = malloc(skencbytes > pkencbytes ? skencbytes : pkencbytes);
    CHECK(pkenc && skenc && framing);
    CHECK((kem ? mlca_kem_keypair_encode(&ctx, pk, &pkenc, sk, &skenc)
               : mlca_sig_keypair_encode(&ctx, pk, &pkenc, sk, &skenc)) == MLCA_OK);
    for (int private_key = 0; private_key <= 1; ++private_key) {
        unsigned char* encoded = private_key ? skenc : pkenc;
        size_t bytes = private_key ? skencbytes : pkencbytes;
        CHECK((kem ? mlca_kem_keypair_decode(&ctx, private_key ? NULL : pkenc, &pkdec,
                                            private_key ? skenc : NULL, &skdec)
                   : mlca_sig_keypair_decode(&ctx, private_key ? NULL : pkenc, &pkdec,
                                            private_key ? skenc : NULL, &skdec)) == MLCA_OK);
        CHECK(!memcmp(pk, pkdec, pkbytes));
        if (private_key)
            CHECK(!memcmp(sk, skdec, skbytes));
        memset(framing, 0, bytes);
        CHECK(mark_encoding(encoded, framing, bytes, encoding == 2 ? 2 : 0, private_key) == 0);
        for (size_t i = 0; i < bytes; ++i) {
            if (!framing[i])
                continue;
            encoded[i] ^= 1;
            memset(pkdec, 0xa5, pkbytes);
            memset(skdec, 0xa5, skbytes);
            CHECK((kem ? mlca_kem_keypair_decode(&ctx, private_key ? NULL : pkenc, &pkdec,
                                                private_key ? skenc : NULL, &skdec)
                       : mlca_sig_keypair_decode(&ctx, private_key ? NULL : pkenc, &pkdec,
                                                private_key ? skenc : NULL, &skdec)) == MLCA_ESTRUCT);
            CHECK(filled_with(pkdec, pkbytes, 0xa5));
            CHECK(filled_with(skdec, skbytes, 0xa5));
            encoded[i] ^= 1;
        }
    }
    unsigned char* pk_inplace = malloc(pkencbytes);
    unsigned char* sk_inplace = malloc(skencbytes);
    CHECK(pk_inplace && sk_inplace);
    memcpy(pk_inplace, pk, pkbytes);
    memcpy(sk_inplace, sk, skbytes);
    CHECK((kem ? mlca_kem_keypair_encode(&ctx, pk_inplace, &pk_inplace, sk_inplace, &sk_inplace)
               : mlca_sig_keypair_encode(&ctx, pk_inplace, &pk_inplace, sk_inplace, &sk_inplace)) == MLCA_OK);
    CHECK(!memcmp(pkenc, pk_inplace, pkencbytes));
    CHECK(!memcmp(skenc, sk_inplace, skencbytes));
    CHECK((kem ? mlca_kem_keypair_decode(&ctx, pk_inplace, &pk_inplace, sk_inplace, &sk_inplace)
               : mlca_sig_keypair_decode(&ctx, pk_inplace, &pk_inplace, sk_inplace, &sk_inplace)) == MLCA_OK);
    CHECK(!memcmp(pk, pk_inplace, pkbytes));
    CHECK(!memcmp(sk, sk_inplace, skbytes));
    free(pk_inplace);
    free(sk_inplace);
    free(pk);
    free(sk);
    free(pkdec);
    free(skdec);
    free(pkenc);
    free(skenc);
    free(framing);
    mlca_ctx_free(&ctx);
    return 0;
}

static int test_allocation(void) {
    CHECK(mlca_calloc(SIZE_MAX / 2 + 1, 2) == NULL);
    CHECK(mlca_calloc(2, SIZE_MAX) == NULL);
    CHECK(mlca_calloc(SIZE_MAX, 1) == NULL);
    unsigned char* buf = mlca_calloc(7, 13);
    CHECK(buf && filled_with(buf, 91, 0));
    mlca_free(buf);
    return 0;
}

int main(int argc, char* argv[]) {
    const char* signatures[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Dilithium2", "Dilithium3",
                                "Dilithium5", "Dilithium54_R2", "Dilithium65_R2", "Dilithium87_R2"};
    const char* kems[] = {"ML-KEM-768", "ML-KEM-1024", "Kyber768", "Kyber1024", "Kyber768_R2", "Kyber1024_R2"};
    CHECK(argc == 2);
    if (!strcmp(argv[1], "signing")) {
        for (size_t i = 0; i < sizeof(signatures) / sizeof(signatures[0]); ++i)
            CHECK(test_signing(signatures[i], 0) == 0);
    } else if (!strcmp(argv[1], "decapsulation")) {
        for (size_t i = 0; i < sizeof(kems) / sizeof(kems[0]); ++i)
            CHECK(test_decapsulation(kems[i]) == 0);
    } else if (!strcmp(argv[1], "rng")) {
        for (size_t i = 0; i < 3; ++i)
            CHECK(test_signing(signatures[i], 1) == 0);
        for (size_t i = 0; i < 2; ++i)
            CHECK(test_keygen_rng(kems[i]) == 0);
    } else if (!strcmp(argv[1], "encoding")) {
        for (size_t i = 2; i < sizeof(kems) / sizeof(kems[0]); ++i)
            CHECK(test_encoding(kems[i], 1, 1) == 0);
        for (size_t i = 3; i < 6; ++i) {
            CHECK(test_encoding(signatures[i], 1, 0) == 0);
            CHECK(test_encoding(signatures[i], 2, 0) == 0);
        }
        unsigned char header[] = {CRS__ASN1_SEQUENCE, 0x82, 0x01, 0x00};
        CHECK(mlca_asn_something_validate(header + 4, 4, 256, CRS__ASN1_SEQUENCE) == 4);
        for (size_t bytes = 0; bytes < 4; ++bytes)
            CHECK(mlca_asn_something_validate(header + 4, bytes, 256, CRS__ASN1_SEQUENCE) < 0);
        CHECK(mlca_asn_something_validate(NULL, 4, 256, CRS__ASN1_SEQUENCE) < 0);
    } else if (!strcmp(argv[1], "allocation")) {
        CHECK(test_allocation() == 0);
    } else {
        return 1;
    }
    return 0;
}
