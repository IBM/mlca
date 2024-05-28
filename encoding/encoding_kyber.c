// SPDX-License-Identifier: Apache-2.0
#include <mlca2_encoding.h>
#include <string.h>

#define KYBER768_CRYPTO_PUBLICKEYBYTES 1184
#define KYBER768_CRYPTO_SECRETKEYBYTES 2400
#define KYBER768_CRYPTO_CIPHERTEXTBYTES 1088

#define KYBER768_T   1152
#define KYBER768_RHO 32
#define KYBER768_Z   32
#define KYBER768_S   1152
#define KYBER768_HPK 32
#define KYBER768_D   32

#define KYBER1024_CRYPTO_PUBLICKEYBYTES (1184+1216)
#define KYBER1024_CRYPTO_SECRETKEYBYTES (1568+1600)
#define KYBER1024_CRYPTO_CIPHERTEXTBYTES 1568

#define KYBER1024_T   1536
#define KYBER1024_RHO 32
#define KYBER1024_Z   32
#define KYBER1024_S   1536
#define KYBER1024_HPK 32
#define KYBER1024_D   32

// KyberPublicKey ::= SEQUENCE {
//   t           OCTET STRING,
//   rho         OCTET STRING
// }
#define KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) \
  CRS__ASN_TLLEN(KYBER##NAME##_CRYPTO_PUBLICKEYBYTES) + \
  CRS__ASN_TLLEN(KYBER##NAME##_T) + KYBER##NAME##_T + \
  CRS__ASN_TLLEN(KYBER##NAME##_RHO) + KYBER##NAME##_RHO


/**
 * @brief 
 * subjectPublicKeyInfo := SEQUENCE {
 *  algorithm          AlgorithmIdentifier  -- see chapter above
 *  subjectPublicKey   BIT STRING           -- see chapter below
 * }
 */
#define KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(NAME) \
  CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + \
  CRS__ASN_TLLEN(CRS__ASN_OIDLEN(MLCA_ALGORITHM_KEM_KYBER_##NAME##_R2_OID)) + \
  CRS__ASN_OIDLEN(MLCA_ALGORITHM_KEM_KYBER_##NAME##_R2_OID) + \
  CRS__ASN_TLLEN(0) + \
  CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)


// KyberPrivateKey ::= SEQUENCE {
//   Version     INTEGER {v0(0)}   -- version (round 3)
//   nonce       OCTET STRING,     -- z
//   s           OCTET STRING,     -- sample s
//   PublicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
//                                 -- see next section
//   hpk         OCTET STRING      -- H(pk)
// }
#define KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) \
  CRS__ASN_TLLEN(KYBER##NAME##_CRYPTO_SECRETKEYBYTES) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(KYBER##NAME##_Z) + KYBER##NAME##_Z + \
  CRS__ASN_TLLEN(KYBER##NAME##_S) + KYBER##NAME##_S + \
  KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) + \
  CRS__ASN_TLLEN(KYBER##NAME##_HPK) + KYBER##NAME##_HPK

  /**
 * @brief 
 * PrivateKeyInfo ::=  SEQUENCE {
 *   version               INTEGER             -- PKCS#8 syntax ver
 *   privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *   privateKey            OCTET STRING,       -- see chapter below
 *   attributes            [0]  IMPLICIT Attributes OPTIONAL
 * }
 */
#define KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(NAME) \
  CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(CRS__ASN_OIDLEN(MLCA_ALGORITHM_KEM_KYBER_##NAME##_R2_OID)) + \
  CRS__ASN_OIDLEN(MLCA_ALGORITHM_KEM_KYBER_##NAME##_R2_OID) + \
  CRS__ASN_TLLEN(0) + \
  CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)

#define KyberXXX_asntlp_pk_len 3

#define KYBER_ASNTLP_PK(NAME) \
  static const mlca_asntl_t Kyber##NAME##_asntlp_pk[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(KYBER##NAME##_CRYPTO_PUBLICKEYBYTES), \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_T, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_RHO, \
          .asndec_flag = 1 \
      } \
  };

KYBER_ASNTLP_PK(768);
KYBER_ASNTLP_PK(1024);

#define KyberXXX_asntlp_sk_len 8

    // KyberPrivateKey ::= SEQUENCE {
    //   Version     INTEGER {v0(0)}   -- version (round 3)
    //   s           OCTET STRING,     -- sample s
    //   PublicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
    //                                 -- see next section
    //   hpk         OCTET STRING      -- H(pk)
    //   nonce       OCTET STRING,     -- z
    // }
#define KYBER_ASNTLP_SK(NAME) \
  static const mlca_asntl_t Kyber##NAME##_asntlp_sk[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_S, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_T, \
          .asndec_flag = 3 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_RHO, \
          .asndec_flag = 3 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_HPK, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_Z, \
          .asndec_flag = 1 \
      } \
  };

KYBER_ASNTLP_SK(768);
KYBER_ASNTLP_SK(1024);

#define KYBER_ASNTLP_SK_PARTIAL(NAME) \
  static const mlca_asntl_t Kyber##NAME##_asntlp_sk_partial[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - CRS__ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_D \
      }, \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = 4 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
  };

KYBER_ASNTLP_SK_PARTIAL(768);
KYBER_ASNTLP_SK_PARTIAL(1024);

static const mlca_encoding_impl_t Kyber768_encoding_arr[2] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_768_R2_OID,
            .crypto_publickeybytes = 1184,
            .crypto_secretkeybytes = 2400,
            .crypto_ciphertextbytes = 1088,
            .crypto_bytes = 32,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        },
        {
            .encoding_name = "ASN.1", // ASN.1
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_768_R2_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(768),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(768),
            .crypto_ciphertextbytes = KYBER768_CRYPTO_CIPHERTEXTBYTES,
            .crypto_bytes = 32,
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber768_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber768_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01,
            .decode = mlca_decode_draft_uni_qsckeys_01
        }
};

static const mlca_encoding_impl_t Kyber1024_encoding_arr[2] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_1024_R2_OID,
            .crypto_publickeybytes = 1568,
            .crypto_secretkeybytes = 3168,
            .crypto_ciphertextbytes = 1568,
            .crypto_bytes = 32,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        },
        {
            .encoding_name = "ASN.1", // ASN.1
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_1024_R2_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(1024),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(1024),
            .crypto_ciphertextbytes = KYBER1024_CRYPTO_CIPHERTEXTBYTES,
            .crypto_bytes = 32,
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber1024_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber1024_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01,
            .decode = mlca_decode_draft_uni_qsckeys_01
        }
};

const mlca_encoding_t Kyber768_encoding = {
    .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_768_R2_OID,
    .encodings_len = 2,
    .encoding = Kyber768_encoding_arr
};

const mlca_encoding_t Kyber1024_encoding = {
    .algorithm_oid = MLCA_ALGORITHM_KEM_KYBER_1024_R2_OID,
    .encodings_len = 2,
    .encoding = Kyber1024_encoding_arr
};
