// SPDX-License-Identifier: Apache-2.0
#include <mlca2_encoding.h>
#include <string.h>

#define DILITHIUM_R3_4x4_CRYPTO_PUBLICKEYBYTES 1312
#define DILITHIUM_R3_4x4_CRYPTO_SECRETKEYBYTES 2528
#define DILITHIUM_R3_4x4_CRYPTO_BYTES 2420

#define DILITHIUM_R3_4x4_RHO 32
#define DILITHIUM_R3_4x4_T1  (320*4)
#define DILITHIUM_R3_4x4_KEY 32
#define DILITHIUM_R3_4x4_TR  32
#define DILITHIUM_R3_4x4_S1  (4*96)
#define DILITHIUM_R3_4x4_S2  (4*96)
#define DILITHIUM_R3_4x4_T0  (32*13*4)

#define DILITHIUM_R3_6x5_CRYPTO_PUBLICKEYBYTES 1952
#define DILITHIUM_R3_6x5_CRYPTO_SECRETKEYBYTES 4000
#define DILITHIUM_R3_6x5_CRYPTO_BYTES 3293

#define DILITHIUM_R3_6x5_RHO 32
#define DILITHIUM_R3_6x5_T1  (320*6)
#define DILITHIUM_R3_6x5_KEY 32
#define DILITHIUM_R3_6x5_TR  32
#define DILITHIUM_R3_6x5_S1  (6*128)
#define DILITHIUM_R3_6x5_S2  (5*128)
#define DILITHIUM_R3_6x5_T0  (32*13*6)

#define DILITHIUM_R3_8x7_CRYPTO_PUBLICKEYBYTES 2592
#define DILITHIUM_R3_8x7_CRYPTO_SECRETKEYBYTES 4864
#define DILITHIUM_R3_8x7_CRYPTO_BYTES 4595

#define DILITHIUM_R3_8x7_RHO 32
#define DILITHIUM_R3_8x7_T1  (320*8)
#define DILITHIUM_R3_8x7_KEY 32
#define DILITHIUM_R3_8x7_TR  32
#define DILITHIUM_R3_8x7_S1  (8*96)
#define DILITHIUM_R3_8x7_S2  (7*96)
#define DILITHIUM_R3_8x7_T0  (32*13*8)

#define DILITHIUM_R2_5x4_CRYPTO_PUBLICKEYBYTES 1472
#define DILITHIUM_R2_5x4_CRYPTO_SECRETKEYBYTES 3504
#define DILITHIUM_R2_5x4_CRYPTO_BYTES 2701

#define DILITHIUM_R2_6x5_CRYPTO_PUBLICKEYBYTES 1760
#define DILITHIUM_R2_6x5_CRYPTO_SECRETKEYBYTES 3856
#define DILITHIUM_R2_6x5_CRYPTO_BYTES 3366 

#define DILITHIUM_R2_8x7_CRYPTO_PUBLICKEYBYTES 2336
#define DILITHIUM_R2_8x7_CRYPTO_SECRETKEYBYTES 5136
#define DILITHIUM_R2_8x7_CRYPTO_BYTES 4668



//   DilithiumPublicKey ::= SEQUENCE {
//       rho         OCTET STRING,
//       t1          OCTET STRING
//   }
#define DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_CRYPTO_PUBLICKEYBYTES) + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_RHO) + DILITHIUM_##NAME##_RHO + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_T1) + DILITHIUM_##NAME##_T1


/**
 * @brief 
 * subjectPublicKeyInfo := SEQUENCE {
 *  algorithm          AlgorithmIdentifier  -- see chapter above
 *  subjectPublicKey   BIT STRING           -- see chapter below
 * }
 */
#define DILITHIUMXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(NAME) \
  CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + \
  CRS__ASN_TLLEN(CRS__ASN_OIDLEN(MLCA_ALGORITHM_SIG_DILITHIUM_##NAME##_OID)) + \
  CRS__ASN_OIDLEN(MLCA_ALGORITHM_SIG_DILITHIUM_##NAME##_OID) + \
  CRS__ASN_TLLEN(0) + \
  CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)


//   DilithiumPrivateKey ::= SEQUENCE {
//       version     INTEGER {v0(0)}     -- version (round 3)
//       nonce       BIT STRING,         -- rho
//       key         BIT STRING,         -- key/seed/D
//       tr          BIT STRING,         -- PRF bytes (CRH in spec)
//       s1          BIT STRING,         -- vector(L)
//       s2          BIT STRING,         -- vector(K)
//       t0          BIT STRING,
//       PublicKey  [0] IMPLICIT DilithiumPublicKey OPTIONAL
//                                       -- see next section
//   }
#define DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_RHO) + DILITHIUM_##NAME##_RHO + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_KEY) + DILITHIUM_##NAME##_KEY + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_TR) + DILITHIUM_##NAME##_TR + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_S1) + DILITHIUM_##NAME##_S1 + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_S2) + DILITHIUM_##NAME##_S2 + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_T0) + DILITHIUM_##NAME##_T0 + \
  DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

//   DilithiumPrivateKey ::= SEQUENCE {
//       version     INTEGER {v0(0)}     -- version (round 3)
//       nonce       BIT STRING,         -- rho
//       key         BIT STRING,         -- key/seed/D
//       tr          BIT STRING,         -- EMPTY
//       s1          BIT STRING,         -- EMPTY
//       s2          BIT STRING,         -- EMPTY
//       t0          BIT STRING,         -- EMPTY
//       PublicKey   [0] IMPLICIT DilithiumPublicKey OPTIONAL
//                                       -- see next section
//   }
#define DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL1(NAME) \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_RHO) + DILITHIUM_##NAME##_RHO + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_KEY) + DILITHIUM_##NAME##_KEY + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

//   DilithiumPrivateKey ::= SEQUENCE {
//       version     INTEGER {v0(0)}     -- version (round 3)
//       nonce       BIT STRING,         -- zeta
//       key         BIT STRING,         -- EMPTY
//       tr          BIT STRING,         -- EMPTY
//       s1          BIT STRING,         -- EMPTY
//       s2          BIT STRING,         -- EMPTY
//       t0          BIT STRING,         -- EMPTY
//       PublicKey   [0] IMPLICIT DilithiumPublicKey OPTIONAL
//                                      -- see next section
//   }
#define DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL2(NAME) \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(DILITHIUM_##NAME##_RHO) + DILITHIUM_##NAME##_RHO + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  CRS__ASN_TLLEN(0) + 0 + \
  DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

  /**
 * @brief 
 * PrivateKeyInfo ::=  SEQUENCE {
 *   version               INTEGER             -- PKCS#8 syntax ver
 *   privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *   privateKey            OCTET STRING,       -- see chapter below
 *   attributes            [0]  IMPLICIT Attributes OPTIONAL
 * }
 */
#define DILITHIUMXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(NAME) \
  CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + \
  CRS__ASN_TLLEN(1) + 1 + \
  CRS__ASN_TLLEN(CRS__ASN_OIDLEN(MLCA_ALGORITHM_SIG_DILITHIUM_##NAME##_OID)) + \
  CRS__ASN_OIDLEN(MLCA_ALGORITHM_SIG_DILITHIUM_##NAME##_OID) + \
  CRS__ASN_TLLEN(0) + \
  CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)

#define DilithiumXXX_asntlp_pk_len 3

#define DILITHIUM_ASNTLP_PK(NAME) \
  static const mlca_asntl_t Dilithium_##NAME##_asntlp_pk[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_T1, \
          .asndec_flag = 1 \
      } \
  };

DILITHIUM_ASNTLP_PK(R3_4x4);
DILITHIUM_ASNTLP_PK(R3_6x5);
DILITHIUM_ASNTLP_PK(R3_8x7);

#define DilithiumXXX_asntlp_sk_len 11

//   DilithiumPrivateKey ::= SEQUENCE {
//       version     INTEGER {v0(0)}     -- version (round 3)
//       nonce       BIT STRING,         -- rho
//       key         BIT STRING,         -- key/seed/D
//       tr          BIT STRING,         -- PRF bytes (CRH in spec)
//       s1          BIT STRING,         -- vector(L)
//       s2          BIT STRING,         -- vector(K)
//       t0          BIT STRING,
//       PublicKey  [0] IMPLICIT DilithiumPublicKey OPTIONAL
//                                       -- see next section
//   }
#define DILITHIUM_ASNTLP_SK(NAME) \
  static const mlca_asntl_t Dilithium_##NAME##_asntlp_sk[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_KEY, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_TR, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_S1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_S2, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_T0, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO, \
          .asndec_flag = 2, \
          .encpub = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_T1, \
          .asndec_flag = 2, \
          .encpub = 1 \
      } \
  };

DILITHIUM_ASNTLP_SK(R3_4x4);
DILITHIUM_ASNTLP_SK(R3_6x5);
DILITHIUM_ASNTLP_SK(R3_8x7);

#define DILITHIUM_ASNTLP_SK_PARTIAL1(NAME) \
  static const mlca_asntl_t Dilithium_##NAME##_asntlp_sk_partial1[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL1(NAME) -  CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL1(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_KEY \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO, \
          .asndecskip = 1, \
          .encpub = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_T1, \
          .asndecskip = 1, \
          .encpub = 1 \
      } \
  };

DILITHIUM_ASNTLP_SK_PARTIAL1(R3_4x4);
DILITHIUM_ASNTLP_SK_PARTIAL1(R3_6x5);
DILITHIUM_ASNTLP_SK_PARTIAL1(R3_8x7);

#define DILITHIUM_ASNTLP_SK_PARTIAL2(NAME) \
  static const mlca_asntl_t Dilithium_##NAME##_asntlp_sk_partial2[] = { \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL2(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES_PARTIAL2(NAME)) \
      }, \
      { \
          .asntag = CRS__ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_BITSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = CRS__ASN1_SEQUENCE, \
          .asnlen = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - CRS__ASN_TLLEN(DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_RHO, \
          .asndecskip = 1 \
      }, \
      { \
          .asntag = CRS__ASN1_OCTETSTRING, \
          .asnlen = DILITHIUM_##NAME##_T1, \
          .asndecskip = 1 \
      } \
  };

DILITHIUM_ASNTLP_SK_PARTIAL2(R3_4x4);
DILITHIUM_ASNTLP_SK_PARTIAL2(R3_6x5);
DILITHIUM_ASNTLP_SK_PARTIAL2(R3_8x7);

static const mlca_encoding_impl_t Dilithium_R3_4x4_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID,
            .crypto_publickeybytes = DILITHIUM_R3_4x4_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R3_4x4_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R3_4x4_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        },
        {
            .encoding_name = "ASN.1", // ASN.1
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_4x4),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(R3_4x4),
            .crypto_bytes = DILITHIUM_R3_4x4_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_4x4_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_4x4_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "ASN.1-inner", // ASN.1 without P8 / SPKI envelope
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_4x4),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(R3_4x4),
            .crypto_bytes = DILITHIUM_R3_4x4_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_4x4_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_4x4_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01_inner,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
};


static const mlca_encoding_impl_t Dilithium_R3_6x5_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID,
            .crypto_publickeybytes = DILITHIUM_R3_6x5_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R3_6x5_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R3_6x5_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        },
        {
            .encoding_name = "ASN.1", // ASN.1
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_6x5),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(R3_6x5),
            .crypto_bytes = DILITHIUM_R3_6x5_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_6x5_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_6x5_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "ASN.1-inner", // ASN.1 without P8 / SPKI envelope
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_6x5),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(R3_6x5),
            .crypto_bytes = DILITHIUM_R3_6x5_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_6x5_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_6x5_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01_inner,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
};

static const mlca_encoding_impl_t Dilithium_R3_8x7_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID,
            .crypto_publickeybytes = DILITHIUM_R3_8x7_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R3_8x7_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R3_8x7_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        },
        {
            .encoding_name = "ASN.1", // ASN.1
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_8x7),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(R3_8x7),
            .crypto_bytes = DILITHIUM_R3_8x7_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_8x7_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_8x7_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "ASN.1-inner", // ASN.1 without P8 / SPKI envelope
            .raw = 0,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID,
            .crypto_publickeybytes = DILITHIUMXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_8x7),
            .crypto_secretkeybytes = DILITHIUMXXX_CRYPTO_ASN1_SECRETKEYBYTES(R3_8x7),
            .crypto_bytes = DILITHIUM_R3_8x7_CRYPTO_BYTES,
            .pk_asntl_len = DilithiumXXX_asntlp_pk_len,
            .pk_asntl = Dilithium_R3_8x7_asntlp_pk,
            .sk_asntl_len = DilithiumXXX_asntlp_sk_len,
            .sk_asntl = Dilithium_R3_8x7_asntlp_sk,
            .encode = mlca_encode_draft_uni_qsckeys_01_inner,
            .decode = mlca_decode_draft_uni_qsckeys_01
        },
};

static const mlca_encoding_impl_t Dilithium_R2_5x4_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_5x4_OID,
            .crypto_publickeybytes = DILITHIUM_R2_5x4_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R2_5x4_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R2_5x4_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        }
};

static const mlca_encoding_impl_t Dilithium_R2_6x5_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_6x5_OID,
            .crypto_publickeybytes = DILITHIUM_R2_6x5_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R2_6x5_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R2_6x5_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        }
};

static const mlca_encoding_impl_t Dilithium_R2_8x7_encodings_arr[] = {
        {
            .encoding_name = "Raw", // RAW-NIST
            .raw = 1,
            .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID,
            .crypto_publickeybytes = DILITHIUM_R2_8x7_CRYPTO_PUBLICKEYBYTES,
            .crypto_secretkeybytes = DILITHIUM_R2_8x7_CRYPTO_SECRETKEYBYTES,
            .crypto_bytes = DILITHIUM_R2_8x7_CRYPTO_BYTES,
            .encode = mlca_encode_raw,
            .decode = mlca_decode_raw
        }
};

const mlca_encoding_t Dilithium_R3_4x4_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID,
    .encodings_len = 3,
    .encoding = Dilithium_R3_4x4_encodings_arr
};

const mlca_encoding_t Dilithium_R3_6x5_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID,
    .encodings_len = 3,
    .encoding = Dilithium_R3_6x5_encodings_arr
};

const mlca_encoding_t Dilithium_R3_8x7_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID,
    .encodings_len = 3,
    .encoding = Dilithium_R3_8x7_encodings_arr
};

const mlca_encoding_t Dilithium_R2_5x4_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_5x4_OID,
    .encodings_len = 1,
    .encoding = Dilithium_R2_5x4_encodings_arr
};

const mlca_encoding_t Dilithium_R2_6x5_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_6x5_OID,
    .encodings_len = 1,
    .encoding = Dilithium_R2_6x5_encodings_arr
};

const mlca_encoding_t Dilithium_R2_8x7_encodings = {
    .algorithm_oid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID,
    .encodings_len = 1,
    .encoding = Dilithium_R2_8x7_encodings_arr
};
