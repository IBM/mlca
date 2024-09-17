// SPDX-License-Identifier: Apache-2.0
/**
 * @file mlca2_encoding.h
 * 
 * MLCA encoding related functions.
 * 
 */

#ifndef MLCA_ENCODING_H
#define MLCA_ENCODING_H

#include <mlca2_int.h>

#define CRS__ASN1_SEQUENCE     0x30
#define CRS__ASN1_BITSTRING    0x03
#define CRS__ASN1_OCTETSTRING  0x04
#define CRS__ASN1_NULL         0x05
#define CRS__ASN1_INT          0x02
#define CRS__ASN1_OID          0x06
#define CRS__ASN_NULL_BYTES    2

#define CRS__ASN_TLLEN(len) (len < 0x80 ? 2 : 4)
#define CRS__ASN_OIDLEN(oid) (sizeof(oid)-1)

/**
 * Encode to raw format.
 * 
 * @param[in] ctx_out Encoding context of output encoding.
 * @param[in] ctx_in Encoding context of input encoding.
 * @param[in/out] pk Input public key.
 * @param[out] pkenc Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skenc Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
MLCA_RC mlca_encode_raw(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc);

/**
 * Decode from raw format.
 * 
 * @param[in] ctx_out Encoding context of output encoding.
 * @param[in] ctx_in Encoding context of input encoding.
 * @param[in/out] pk Input public key.
 * @param[out] pkdec Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skdec Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
MLCA_RC mlca_decode_raw(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkdec, unsigned char* sk, unsigned char** skdec);

/**
 * Encode to draft-uni-qsckeys-01 format.
 * 
 * @param[in] ctx_out Encoding context of output encoding.
 * @param[in] ctx_in Encoding context of input encoding.
 * @param[in/out] pk Input public key.
 * @param[out] pkenc Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skenc Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
MLCA_RC mlca_encode_draft_uni_qsckeys_01(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc);

/**
 * Decode from draft-uni-qsckeys-01 format.
 * 
 * @param[in] ctx_out Encoding context of output encoding.
 * @param[in] ctx_in Encoding context of input encoding.
 * @param[in/out] pk Input public key.
 * @param[out] pkdec Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skdec Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
MLCA_RC mlca_decode_draft_uni_qsckeys_01(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkdec, unsigned char* sk, unsigned char** skdec);

/**
 * Encode to draft-uni-qsckeys-01 format.
 * For the private key, only the privateKey part of PublicKeyInfo.
 * For the private key, only the subjectPublicKey part of SubjectPublicKeyInfo.
 * 
 * @param[in] ctx_out Encoding context of output encoding.
 * @param[in] ctx_in Encoding context of input encoding.
 * @param[in/out] pk Input public key.
 * @param[out] pkenc Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skenc Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
MLCA_RC mlca_encode_draft_uni_qsckeys_01_inner(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc);


// ASN.1 functions
/**
 * ASN1 write BIT STRING frame at the end of (wire, wbytes).
 * 
 * @param[out] wire The BIT STRING frame is written before this address.
 * @param[in] wbytes Number of bytes available before wire.
 * @param[in] bstring_net_bytes Length in bytes of the BIT STRING.
 * @return Number of bytes written before wire.
 */
size_t mlca_asn_bitstr(unsigned char *wire, size_t wbytes,
                                                  size_t bstring_net_bytes);

/**
 * ASN1 write a frame identified by tag at the end of (wire, wbytes).
 * 
 * @param[out] wire The frame is written before this pointer.
 * @param[in] wbytes Number of bytes available before wire.
 * @param[in] bstring_net_bytes Length in bytes of the tag content.
 * @param[in] tag Tag byte.
 * @return Number of bytes written before wire.
 */                                                  
size_t mlca_asn_something(unsigned char *wire, size_t wbytes,
                                                     size_t seq_net_bytes,
                                              unsigned char tag);

/**
 * ASN1 validate a frame, identified by wire, wbytes, seq_net_bytes and tag.
 * 
 * @param[out] wire The frame is expected before this pointer
 * @param[in] wbytes Number of bytes available before wire.
 * @param[in] seq_net_bytes Length in bytes of the tag content.
 * @param[in] tag Tag byte. 
 * @return Number of bytes validated, or -1 if the validation failed.
 */
int mlca_asn_something_validate(unsigned char *wire, size_t wbytes,
                                                     size_t seq_net_bytes,
                                              unsigned char tag);

/**
 * ASN1 write SEQUENCE frame at the end of (wire, wbytes).
 * 
 * @param[out] wire The SEQUENCE frame is written before this address.
 * @param[in] wbytes Number of bytes available before wire.
 * @param[in] bstring_net_bytes Length in bytes of the SEQUENCE.
 * @return Number of bytes written before wire.
 */
size_t mlca_asn_sequence(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes);

/**
 * ASN1 write OCTET STRING frame at the end of (wire, wbytes).
 * 
 * @param[out] wire The OCTET STRING frame is written before this address.
 * @param[in] wbytes Number of bytes available before wire.
 * @param[in] bstring_net_bytes Length in bytes of the OCTET STRING.
 * @return Number of bytes written before wire.
 */
size_t mlca_asn_octetstr(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes);

/**
 * ASN write a single byte INT field.
 * 
 * @param wire The INT field is written before this address.
 * @param wbytes Number of bytes available before wire.
 * @param i The single byte INT to be written.
 * @return Number of bytes written before wire.
 */
size_t mlca_asn_int(unsigned char *wire, size_t wbytes,
                          unsigned char i);


/**
 * ASN write a NULL field.
 * 
 * @param wire The NULL field is written before this address.
 * @param wbytes Number of bytes available before wire.
 * @return Number of bytes written before wire. 
 */
size_t mlca_asn_null(unsigned char *wire, size_t wbytes);


/**
 * ASM writes OID bytes.
 * 
 * @param wire The NULL field is written before this address.
 * @param wbytes Number of bytes available before wire.
 * @param arcs OID input bytes.
 * @param arcslen Length of OID input bytes.
 * @return Number of bytes written before wire. 
 */
size_t mlca_gn_oid2wire(unsigned char *wire, size_t wbytes,
                              const char* arcs, size_t arcslen);


/**
 * Encoding structures of supported algorithms.
 */
extern const mlca_encoding_t Kyber768_encoding;
extern const mlca_encoding_t Kyber1024_encoding;

extern const mlca_encoding_t Mldsa_44_encodings;
extern const mlca_encoding_t Mldsa_65_encodings;
extern const mlca_encoding_t Mldsa_87_encodings;

extern const mlca_encoding_t Dilithium_R3_4x4_encodings;
extern const mlca_encoding_t Dilithium_R3_6x5_encodings;
extern const mlca_encoding_t Dilithium_R3_8x7_encodings;

extern const mlca_encoding_t Dilithium_R2_5x4_encodings;
extern const mlca_encoding_t Dilithium_R2_6x5_encodings;
extern const mlca_encoding_t Dilithium_R2_8x7_encodings;

#endif // MLCA_ENCODING_H
