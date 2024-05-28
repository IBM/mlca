// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <string.h>
#include <mlca2_encoding.h>

#define  CRS__ASN_NULL_BYTES  2

//----------------------------------------------------------------------------
// writes BIT STRING frame to end of (wire, wbytes)
// returns written bytecount
//
// opportunistic; assume result fits; restricted to 82 xx yy or single-byte Len
//
size_t mlca_asn_bitstr(unsigned char *wire, size_t wbytes,
                                                  size_t bstring_net_bytes)
{
	if (bstring_net_bytes < 0x80) {          // 03 ...len... 00
		if (wire && (wbytes >= 3)) {
			*(wire - 3) = CRS__ASN1_BITSTRING;
			*(wire - 2) = (unsigned char) bstring_net_bytes +1;
			*(wire - 1) = 0;
		}
		return 3;

	} else {                                 // assume  03 82 xx yy 00
		if (wire && (wbytes >= 5)) {
			*(wire - 5) = CRS__ASN1_BITSTRING;
			*(wire - 4) = 0x82;

			*(wire - 3) =
				(unsigned char) ((bstring_net_bytes +1) >>8);
			*(wire - 2) =
				(unsigned char)   bstring_net_bytes +1;

			*(wire - 1) = 0;
		}
		return 5;
	}
}

int mlca_asn_something_validate(unsigned char *wire, size_t wbytes,
                                                     size_t seq_net_bytes,
                                              unsigned char tag)
{
    int res = -1;
    int size = 0;

	if (seq_net_bytes < 0x80) {                   // [tag] ...len... 00
		if (wire && (wbytes >= 2)) {
			res &= 0 - (*(wire - 2) == tag);
			res &= 0 - (*(wire - 1) == (unsigned char) seq_net_bytes);
		}
        size = 2;
	} else {                                      // assume  [tag] 82 xx yy
		if (wire && (wbytes >= 4)) {
			res &= 0 - (*(wire - 4) == tag);
			res &= 0 - (*(wire - 3) == 0x82);
			res &= 0 - (*(wire - 2) ==
				(unsigned char) (seq_net_bytes >> 8));
			res &= 0 - (*(wire - 1) ==
				(unsigned char)  seq_net_bytes);
		}
        size = 4;
	}
    return res & size;
}

//--------------------------------------
size_t mlca_asn_something(unsigned char *wire, size_t wbytes,
                                                     size_t seq_net_bytes,
                                              unsigned char tag)
{
	if (seq_net_bytes < 0x80) {                   // [tag] ...len... 00
		if (wire && (wbytes >= 2)) {
			*(wire - 2) = tag;
			*(wire - 1) = (unsigned char) seq_net_bytes;
		}
		return 2;
	} else {                                      // assume  [tag] 82 xx yy
		if (wire && (wbytes >= 4)) {
			*(wire - 4) = tag;
			*(wire - 3) = 0x82;
			*(wire - 2) =
				(unsigned char) (seq_net_bytes >> 8);
			*(wire - 1) =
				(unsigned char)  seq_net_bytes;
		}
		return 4;
	}
}


/*------------------------------------*/
size_t mlca_asn_sequence(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes)
{
	return mlca_asn_something(wire, wbytes, seq_net_bytes,
	                         CRS__ASN1_SEQUENCE);
}



/*------------------------------------*/
size_t mlca_asn_octetstr(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes)
{
	return mlca_asn_something(wire, wbytes, seq_net_bytes,
	                         CRS__ASN1_OCTETSTRING);
}

/*--------------------------------------
 * used only for single-byte INT fields
 */
size_t mlca_asn_int(unsigned char *wire, size_t wbytes,
                          unsigned char i)
{
	if (wire && (wbytes >= 3)) {
		*(wire - 3) = CRS__ASN1_INT;
		*(wire - 2) = 1;
		*(wire - 1) = i;
	}

	return 3;
}


//--------------------------------------
size_t mlca_asn_null(unsigned char *wire, size_t wbytes)
{
	if (wire && (wbytes >= CRS__ASN_NULL_BYTES)) {
		*(wire - 2) = CRS__ASN1_NULL;
		*(wire - 1) = 0x00;
	}

	return CRS__ASN_NULL_BYTES;
}


size_t mlca_gn_oid2wire(unsigned char *wire, size_t wbytes,
                              const char* arcs, size_t arcslen)
{
	size_t wr;

	wr = arcslen;

	if (wire && (wr > wbytes))
		return 0;              // insufficient output

	if (wire) {
		wire -= wr;
		for (int i = 0; i < arcslen; ++i)
			*wire++ = (unsigned char) arcs[i];
	}

	return wr;
}

/**
 * 
 * The encoding for public keys.
 * 
 * subjectPublicKeyInfo := SEQUENCE {
 *     algorithm          AlgorithmIdentifier  -- see chapter above
 *     subjectPublicKey   BIT STRING           -- see chapter below
 * }
 * 
 * Expects that subkectPublicKey is already written after wire.
 * 
 * @param ctx 
 * @param wire 
 * @param wbytes 
 * @return size_t 
 */
static int mlca_asn_pubkey_draft_uni_qsckeys_00_encode(const mlca_encoding_impl_t* ctx, unsigned char* wire, size_t wbytes, size_t spkbytes) {
	size_t seqBytes, algBytes, algtlbytes, spkbitBytes, algnullBytes, algseqBytes;
	int wr;

	spkbitBytes = mlca_asn_something(wire, wbytes, spkbytes, CRS__ASN1_BITSTRING);
	if (spkbitBytes > wbytes) return -1;

	wr = spkbitBytes;
	wire -= spkbitBytes;
	wbytes -= spkbitBytes;

    algnullBytes = mlca_asn_null(wire, wbytes);
    if (algnullBytes > wbytes) return -1;

    wr += algnullBytes;
    wire -= algnullBytes;
    wbytes -= algnullBytes;

	algBytes = mlca_gn_oid2wire(wire, wbytes, ctx->algorithm_oid, strlen(ctx->algorithm_oid));
	if (!algBytes || algBytes > wbytes) return -1;

	wr += algBytes;
	wire -= algBytes;
	wbytes -= algBytes;

    algseqBytes = mlca_asn_sequence(wire, wbytes, algnullBytes + algBytes);
    if (algseqBytes > wbytes) return -1;

    wr += algseqBytes;
    wire -= algseqBytes;
    wbytes -= algseqBytes;

	seqBytes = mlca_asn_sequence(wire, wbytes, spkbytes + wr);
	if (seqBytes > wbytes) return -1;

	wr += seqBytes;
	wire -= seqBytes;
	wbytes -= seqBytes;

	return wr;
}

/**
 * @brief 
 * 
 * The encoding for private keys.
 * 
 *  PrivateKeyInfo ::=  SEQUENCE {
 *      version               INTEGER             -- PKCS#8 syntax ver
 *      privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *      privateKey            OCTET STRING,       -- see chapter below
 *      attributes            [0]  IMPLICIT Attributes OPTIONAL
 *  }
 * 
 * Expects that privateKey is already written after wire.
 * 
 * @param ctx 
 * @param wire 
 * @param wbytes 
 * @return size_t 
 */
static int mlca_asn_prikey_draft_uni_qsckeys_00_encode(const mlca_encoding_impl_t* ctx, unsigned char* wire, size_t wbytes, size_t pkbytes) {
	size_t seqBytes, algBytes, algtlBytes, pkbitBytes, versionBytes, algseqBytes, algnullBytes;
	int wr;

	pkbitBytes = mlca_asn_something(wire, wbytes, pkbytes, CRS__ASN1_OCTETSTRING);
	if (pkbitBytes > wbytes) return -1;

	wr = pkbitBytes;
	wire -= pkbitBytes;
	wbytes -= pkbitBytes;

    algnullBytes = mlca_asn_null(wire, wbytes);
    if (algnullBytes > wbytes) return -1;

    wr += algnullBytes;
    wire -= algnullBytes;
    wbytes -= algnullBytes;

	algBytes = mlca_gn_oid2wire(wire, wbytes, ctx->algorithm_oid, strlen(ctx->algorithm_oid));
	if (!algBytes || algBytes > wbytes) return -1;

	wr += algBytes;
	wire -= algBytes;
	wbytes -= algBytes;

    algseqBytes = mlca_asn_sequence(wire, wbytes, algnullBytes + algBytes);
    if (algseqBytes > wbytes) return -1;

    wr += algseqBytes;
    wire -= algseqBytes;
    wbytes -= algseqBytes;

	// Version = 0 (PKCS8)
    if (1 > wbytes) return -1;
	*(wire - 1) = 0;
	wr += 1;
	wire -= 1;
	wbytes -= 1;

	versionBytes = mlca_asn_something(wire, wbytes, 1, CRS__ASN1_INT);
	if (versionBytes > wbytes) return -1;

	wr += versionBytes;
	wire -= versionBytes;
	wbytes -= versionBytes;

	seqBytes = mlca_asn_sequence(wire, wbytes, pkbytes + wr);
	if (seqBytes > wbytes) return -1;

	wr += seqBytes;
	wire -= seqBytes;
	wbytes -= seqBytes;

	return wr;
}


// Key-specific functions
MLCA_RC mlca_encode_raw(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc) {
    *pkenc = pk;
    *skenc = sk;
    return MLCA_OK;
}

MLCA_RC mlca_decode_raw(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkdec, unsigned char* sk, unsigned char** skdec) {
    *pkdec = pk;
    *skdec = sk;
    return MLCA_OK;
}

static int validate_decode_asntl(const mlca_asntl_t* asntlstr, int asntllen, size_t obytes, unsigned char* k) {

    unsigned char* kin = k;

    size_t pkoutbytes = obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnopt = asntlstr[i].optional;
        int asnval = asntlstr[i].asnvalue;
        int asndecskip = asntlstr[i].asndecskip;

        if (asntag != CRS__ASN1_SEQUENCE)
            kin -= asnlen;

        if (!asndecskip && asntag != CRS__ASN1_SEQUENCE)
            pkoutbytes -= asnlen;

        int asntaglen = mlca_asn_something_validate(kin, pkoutbytes, asnlen, asntag);
        if (!asntaglen)
            return -1;

        kin -= asntaglen;
    }

    return pkoutbytes >= 0;
}

static int decode_asntl(const mlca_asntl_t* asntlstr, int asntllen, size_t obytes, unsigned char* k, unsigned char* kdec, char asndec_flag) {
    int wr = 0;
    unsigned char* kout = kdec, *kin = k;

    if (validate_decode_asntl(asntlstr, asntllen, obytes, k) <= 0) {
        return -1;
    }

    size_t pkoutbytes = obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnopt = asntlstr[i].optional;
        int asnval = asntlstr[i].asnvalue;
        int asndecskip = asntlstr[i].asndecskip || !(asntlstr[i].asndec_flag & asndec_flag);

        if (asntag == CRS__ASN1_INT) {
            if (!asndecskip) {
                *(kout - asnlen) = *(kin - asnlen);
                kout -= asnlen;
                pkoutbytes -= asnlen;
                wr += asnlen;
            }
            kin -= asnlen;
        } else if (asntag != CRS__ASN1_SEQUENCE) {
            if (!asndecskip) {
                memmove(kout - asnlen, kin - asnlen, asnlen);
                kout -= asnlen;
                pkoutbytes -= asnlen;
                wr += asnlen;
            }
            kin -= asnlen;
        }

        int asntaglen = mlca_asn_something(0, pkoutbytes, asnlen, asntag);
        if (asntaglen <= 0) return -1;

        kin -= asntaglen;
    }

    return wr;
}

static int encode_asntl(const mlca_asntl_t* asntlstr, int asntllen, size_t obytes, unsigned char* k, unsigned char* k2, unsigned char* kenc) {
    int wr = 0;
    unsigned char* kout = kenc, *kin = k, *k2in = k2;
    unsigned char* kinnow;
    size_t pkoutbytes = obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnopt = asntlstr[i].optional;
        int asnval = asntlstr[i].asnvalue;
        int asnpub = asntlstr[i].encpub;

        if (asntag == CRS__ASN1_INT) {
            *(kout - asnlen) = asnval;
            kout -= asnlen;
            pkoutbytes -= asnlen;
            wr += asnlen;
        } else if (asntag != CRS__ASN1_SEQUENCE) {
            if (asnpub) {
                memmove(kout - asnlen, k2in - asnlen, asnlen);
                k2in -= asnlen;
            } else {
                memmove(kout - asnlen, kin - asnlen, asnlen);
                kin -= asnlen;
            }
            kout -= asnlen;
            pkoutbytes -= asnlen;
            wr += asnlen;
        }

        int asntaglen = mlca_asn_something(kout, pkoutbytes, asnlen, asntag);
        if (asntaglen > pkoutbytes) return -1;

        kout -= asntaglen;
        pkoutbytes -= asntaglen;
        wr += asntaglen;
    }

    return wr;
}

static int encode_spki_PublicKey(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char* pkenc) {
    int wr = 0;
    unsigned char* pkout = pkenc, *pkin = pk;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;

    int espki = encode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, 0, pkout);
    if (espki <= 0) return -1;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    if (wr != ctx_out->crypto_publickeybytes) return -1;
    else return wr;
}

static int encode_SubjectPublicKeyInfo(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char* pkenc) {
    int wr = 0;
    unsigned char* pkout = pkenc, *pkin = pk;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;

    int espki = encode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, 0, pkout);
    if (espki <= 0) return -1;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    int qsckey00bytesPK = mlca_asn_pubkey_draft_uni_qsckeys_00_encode(ctx_out, pkout, pkoutbytes, espki);
    if (qsckey00bytesPK <= 0) return -1;

    pkout -= qsckey00bytesPK;
    pkoutbytes -= qsckey00bytesPK;
    wr += qsckey00bytesPK;

    if (wr != ctx_out->crypto_publickeybytes) return -1;
    else return wr;
}

static int decode_SubjectPublicKeyInfo(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char* pkdec) {
    int wr = 0;
    unsigned char* pkout = pkdec, *pkin = pk;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_in->pk_asntl;
    int asntllen_pk = ctx_in->pk_asntl_len;

    int espki = decode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, pkout, 1);
    if (espki <= 0) return -1;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    if (wr != ctx_out->crypto_publickeybytes) return -1;
    else return wr;
}


static int encode_p8_PrivateKey(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* sk, unsigned char* pk, unsigned char* skenc) {
    int wr = 0;
    unsigned char* skout = skenc, *pkin = pk, *skin = sk;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    const mlca_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;
    int asntllen_sk = ctx_out->sk_asntl_len;

    int skpart = encode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, pkin, skout);
    if (skpart <= 0) return -1;

    skout -= skpart;
    skoutbytes -= skpart;
    wr += skpart;

    if (wr != ctx_out->crypto_secretkeybytes) return -1;
    else return wr;
}

static int encode_PrivateKeyInfo(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* sk, unsigned char* pk, unsigned char* skenc) {
    int wr = 0;
    unsigned char* skout = skenc, *pkin = pk, *skin = sk;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    const mlca_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;
    int asntllen_sk = ctx_out->sk_asntl_len;

    int skpart = encode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, pkin, skout);
    if (skpart <= 0) return -1;

    skout -= skpart;
    skoutbytes -= skpart;
    wr += skpart;

    int qsckey00bytesSK = mlca_asn_prikey_draft_uni_qsckeys_00_encode(ctx_out, skout, skoutbytes, wr);
    if (qsckey00bytesSK <= 0) return -1;

    skout -= qsckey00bytesSK;
    skoutbytes -= qsckey00bytesSK;
    wr += qsckey00bytesSK;

    if (wr != ctx_out->crypto_secretkeybytes) return -1;
    else return wr;
}

static int decode_PrivateKeyInfo(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* sk, unsigned char* pkdec, unsigned char* skdec) {
    int wr = 0;
    unsigned char* skout = skdec, *pkout = pkdec, *skin = sk;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;

    const mlca_asntl_t* asntlstr_pk = ctx_in->pk_asntl;
    const mlca_asntl_t* asntlstr_sk = ctx_in->sk_asntl;
    int asntllen_pk = ctx_in->pk_asntl_len;
    int asntllen_sk = ctx_in->sk_asntl_len;

    int skpart = decode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, skout, 1);
    if (skpart <= 0) return -1;

    int pkpart = ctx_out->crypto_publickeybytes;

    if (pkout) {
        pkpart = decode_asntl(asntlstr_sk, asntllen_sk, pkoutbytes, skin, pkout, 2);
        if (pkpart <= 0) return -1;
    }

    if (skpart != ctx_out->crypto_secretkeybytes || pkpart != ctx_out->crypto_publickeybytes) return -1;
    return skpart;
}

int mlca_encode_draft_uni_qsckeys_01_inner(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc) {
    size_t wrpk = 0, wrsk = 0;
    unsigned char* pkout, *pkin;
    unsigned char* skout, *skin;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;

    if (pk && pkenc) {

        pkout = (*pkenc) + ctx_out->crypto_publickeybytes;
        pkin = pk + ctx_in->crypto_publickeybytes;

        int encpk = encode_spki_PublicKey(ctx_out, ctx_in, pkin, pkout);
        if (encpk <= 0) return -1;

        pkout -= encpk;
        pkoutbytes -= encpk;
        wrpk += encpk;

        if (wrpk != ctx_out->crypto_publickeybytes)
            return -1;
    }

    if (sk && skenc && pk) {

        skout = (*skenc) + ctx_out->crypto_secretkeybytes;
        skin = sk + ctx_in->crypto_secretkeybytes;
        pkin = pk + ctx_in->crypto_publickeybytes;

        int encprik = encode_p8_PrivateKey(ctx_out, ctx_in, skin, pkin, skout);
        if (encprik <= 0) return -1;
        skout -= encprik;
        skoutbytes -= encprik;
        wrsk += encprik;

        if (wrsk != ctx_out->crypto_secretkeybytes)
            return -1;
        
    }

    end:

    return 0;
}

MLCA_RC mlca_encode_draft_uni_qsckeys_01(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc) {
    size_t wrpk = 0, wrsk = 0;
    unsigned char* pkout, *pkin;
    unsigned char* skout, *skin;
    size_t pkoutbytes = ctx_out->crypto_publickeybytes;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;

    if (pk && pkenc) {
        pkout = (*pkenc) + ctx_out->crypto_publickeybytes;
        pkin = pk + ctx_in->crypto_publickeybytes;

        int encpk = encode_SubjectPublicKeyInfo(ctx_out, ctx_in, pkin, pkout);
        if (encpk <= 0) return -1;

        pkout -= encpk;
        pkoutbytes -= encpk;
        wrpk += encpk;

        if (wrpk != ctx_out->crypto_publickeybytes)
            return -1;
    }

    if (sk && skenc && pk) {
        skout = (*skenc) + ctx_out->crypto_secretkeybytes;
        skin = sk + ctx_in->crypto_secretkeybytes;
        pkin = pk + ctx_in->crypto_publickeybytes;

        int encprik = encode_PrivateKeyInfo(ctx_out, ctx_in, skin, pkin, skout);
        if (encprik <= 0) return -1;
        skout -= encprik;
        skoutbytes -= encprik;
        wrsk += encprik;

        if (wrsk != ctx_out->crypto_secretkeybytes)
            return -1;
    }

    end:
    
    return MLCA_OK;
}

MLCA_RC mlca_decode_draft_uni_qsckeys_01(const mlca_encoding_impl_t* ctx_out, const mlca_encoding_impl_t* ctx_in, unsigned char* pk, unsigned char** pkdec, unsigned char* sk, unsigned char** skdec) {

    size_t wrpk = 0, wrsk = 0;

    unsigned char *pkout = 0, *pkin = 0;
    unsigned char *skout = 0, *skin = 0;

    size_t pkoutbytes = ctx_out->crypto_publickeybytes;
    size_t skoutbytes = ctx_out->crypto_secretkeybytes;

    if (pk) {

        pkout = (*pkdec) + ctx_out->crypto_publickeybytes;
        pkin = pk + ctx_in->crypto_publickeybytes;

        int decspki = decode_SubjectPublicKeyInfo(ctx_out, ctx_in, pkin, pkout);
        if (decspki <= 0) return -1;

        pkout -= decspki;
        pkoutbytes -= decspki;
        wrpk += decspki;

        if (wrpk != ctx_out->crypto_publickeybytes)
            return -1;
        
    }

    if (sk) {

        skout = (*skdec) + ctx_out->crypto_secretkeybytes;
        if (pkdec && *pkdec)
            pkout = (*pkdec) + ctx_out->crypto_publickeybytes;
        skin = sk + ctx_in->crypto_secretkeybytes;

        int decprik = decode_PrivateKeyInfo(ctx_out, ctx_in, skin, pkout, skout);
        if (decprik <= 0) return -1;

        skout -= decprik;
        skoutbytes -= decprik;
        wrsk += decprik;

        if (wrsk != ctx_out->crypto_secretkeybytes)
            return -1;

    }

    return MLCA_OK;
}
