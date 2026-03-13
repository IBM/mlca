// SPDX-License-Identifier: Apache-2.0

#if !defined(CRYSTALS_OIDS_H__)
#define  CRYSTALS_OIDS_H__  1

/* Dilithium, round2, full ASN structs */

                                                  /* 1.3.6.1.4.1.2.267.1.5.4 */
#define CR_OID_DIL_R2_5x4        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x01\x05\x04"
#define CR_OID_DIL_R2_5x4_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.1.6.5 */
#define CR_OID_DIL_R2_6x5        \
	"\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x01\x06\x05"
#define CR_OID_DIL_R2_6x5_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.1.8.7 */
#define CR_OID_DIL_R2_8x7        \
	"\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x01\x08\x07"
#define CR_OID_DIL_R2_8x7_BYTES 13

/* Dilithium, round2, 'raw' ASN structs */

                                                  /* 1.3.6.1.4.1.2.267.6.5.4 */
#define CR_OID_DIL_R2RAW_5x4        \
	"\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x06\x05\x04"
#define CR_OID_DIL_R2RAW_5x4_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.6.6.5 */
#define CR_OID_DIL_R2RAW_6x5        \
	"\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x06\x06\x05"
#define CR_OID_DIL_R2RAW_6x5_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.6.8.7 */
#define CR_OID_DIL_R2RAW_8x7        \
	"\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x06\x08\x07"
#define CR_OID_DIL_R2RAW_8x7_BYTES 13


/* Dilithium, round3, 2020-10-01 */

                                                  /* 1.3.6.1.4.1.2.267.7.4.4 */
#define CR_OID_DIL_R3_4x4        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x04\x04"
#define CR_OID_DIL_R3_4x4_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.7.6.5 */
#define CR_OID_DIL_R3_6x5        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x06\x05"
#define CR_OID_DIL_R3_6x5_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.7.8.7 */
#define CR_OID_DIL_R3_8x7        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x08\x07"
#define CR_OID_DIL_R3_8x7_BYTES 13


/* Kyber, round2, full ASN structs */

                                                  /* 1.3.6.1.4.1.2.267.5.3.3 */
#define CR_OID_KYB_R2_3        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x05\x03\x03"
#define CR_OID_KYB_R2_3_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.5.4.4 */
#define CR_OID_KYB_R2_4        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x05\x04\x04"
#define CR_OID_KYB_R2_4_BYTES 13


/* Kyber, round3 */

                                                  /* 1.3.6.1.4.1.2.267.8.3.3 */
#define CR_OID_KYB_R3_3        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x08\x03\x03"
#define CR_OID_KYB_R3_3_BYTES 13

                                                  /* 1.3.6.1.4.1.2.267.8.4.4 */
#define CR_OID_KYB_R3_4        \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x08\x04\x04"
#define CR_OID_KYB_R3_4_BYTES 13


/* ML-DSA (FIPS 204) */

                                                  /* 2.16.840.1.101.3.4.3.17 */
#define CR_OID_MLDSA_44        \
        "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x11"
#define CR_OID_MLDSA_44_BYTES 11

                                                  /* 2.16.840.1.101.3.4.3.18 */
#define CR_OID_MLDSA_65        \
        "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x12"
#define CR_OID_MLDSA_65_BYTES 11

                                                  /* 2.16.840.1.101.3.4.3.19 */
#define CR_OID_MLDSA_87        \
        "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x13"
#define CR_OID_MLDSA_87_BYTES 11


/* ML-KEM (FIPS 203) */

                                                  /* 2.16.840.1.101.3.4.4.2 */
#define CR_OID_MLKEM_768        \
        "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x04\x02"
#define CR_OID_MLKEM_768_BYTES 11

                                                  /* 2.16.840.1.101.3.4.4.3 */
#define CR_OID_MLKEM_1024        \
        "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x04\x03"
#define CR_OID_MLKEM_1024_BYTES 11

/*-----  special purposes  -------------------------------------------------*/

                                                  /* 1.3.6.1.4.1.2.267.999.1 */
#define CR_OID_SPECIAL_PRV2PUB \
        "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x87\x67\x01"
#define CR_OID_SPECIAL_PRV2PUB_BYTES 13   /* extract public from private key */

#endif    /* !CRYSTALS_OIDS_H__ */

