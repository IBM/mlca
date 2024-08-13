// SPDX-License-Identifier: Apache-2.0 and Unknown
// Modified on May 28, 2024 to accomodate the API and to support Chain-KAT.
/*
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
 
NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 
You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <random_ctrdrbg.h>
#include <mlca2.h>


#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_VERIFICATION_ERROR -2
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

#include <keccak.h>

static void print_uchar(const unsigned char* d, int dlen, const char* title) {
    printf("%s: ", title);
    for (int i = 0; i < dlen; ++i)
        printf("%02X", d[i]);
    printf("\n");
}

int
test_nist_kat(const mlca_ctx_t * params)
{
    char                fn_rsp[64];
    FILE                *fp_rsp;
    unsigned char       seed[48];
    unsigned char       *ct, *ss, *ss1, *ct_rsp, *ss_rsp;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk, *pk_rsp, *sk_rsp;
    int                 ret_val;

    ct = mlca_malloc(mlca_kem_crypto_ciphertextbytes(params));
    ct_rsp = mlca_malloc(mlca_kem_crypto_ciphertextbytes(params));
    ss = mlca_malloc(mlca_kem_crypto_bytes(params));
    ss1 = mlca_malloc(mlca_kem_crypto_bytes(params));
    ss_rsp = mlca_malloc(mlca_kem_crypto_bytes(params));

    pk = mlca_malloc(mlca_kem_crypto_publickeybytes(params));
    sk = mlca_malloc(mlca_kem_crypto_secretkeybytes(params));
    pk_rsp = mlca_malloc(mlca_kem_crypto_publickeybytes(params));
    sk_rsp = mlca_malloc(mlca_kem_crypto_secretkeybytes(params));

    const char* algname = mlca_algorithm_name(params);
    if (!algname) return KAT_DATA_ERROR;

    sprintf(fn_rsp, "../../KAT/%s/PQCkemKAT_%zu.rsp", algname, mlca_kem_crypto_secretkeybytes(params));
    if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    printf("# %s\n\n", algname);
    done = 0;
    int idx = 0;
    do {
        idx++;
        if ( FindMarker(fp_rsp, "count = ") ) {
            if (fscanf(fp_rsp, "%d", &count) != 1) {
                done = 1;
                break;
            }
        } else {
            done = 1;
            break;
        }


        if ( !ReadHex(fp_rsp, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        mlca_randombytes_init(&random_nist, seed, NULL, 256);

        // Generate the public/private keypair
        if ((ret_val = mlca_kem_keygen(params, pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        if ( !ReadHex(fp_rsp, pk_rsp, mlca_kem_crypto_publickeybytes(params), "pk = ") ) {
            printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        if ( !ReadHex(fp_rsp, sk_rsp, mlca_kem_crypto_secretkeybytes(params), "sk = ") ) {
            printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        //print_uchar(sk, CRYPTO_SECRETKEYBYTES, "sk");
        //print_uchar(pk, CRYPTO_PUBLICKEYBYTES, "pk");

        if(memcmp(pk, pk_rsp, mlca_kem_crypto_publickeybytes(params)) != 0){
            printf("ERROR: pk is different from <%s>, idx = %d\n", fn_rsp, idx);
            print_uchar(pk, mlca_kem_crypto_publickeybytes(params), "pk");
            print_uchar(pk_rsp, mlca_kem_crypto_publickeybytes(params), "pk_rsp");
            return KAT_VERIFICATION_ERROR;
        }
        if(memcmp(sk, sk_rsp, mlca_kem_crypto_secretkeybytes(params)) != 0){
            printf("ERROR: sk is different from <%s>, idx = %d\n", fn_rsp, idx);
            print_uchar(sk, mlca_kem_crypto_secretkeybytes(params), "sk");
            print_uchar(sk_rsp, mlca_kem_crypto_secretkeybytes(params), "sk_rsp");
            return KAT_VERIFICATION_ERROR;
        }

        if ( (ret_val = mlca_kem_enc(params, ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if ( !ReadHex(fp_rsp, ct_rsp, mlca_kem_crypto_ciphertextbytes(params), "ct = ") ) {
            printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        if ( !ReadHex(fp_rsp, ss_rsp, mlca_kem_crypto_bytes(params), "ss = ") ) {
            printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if(memcmp(ct, ct_rsp, mlca_kem_crypto_ciphertextbytes(params)) != 0){
            printf("ERROR: ct is different from <%s>\n", fn_rsp);
            return KAT_VERIFICATION_ERROR;
        }
        if(memcmp(ss, ss_rsp, mlca_kem_crypto_bytes(params)) != 0){
            printf("ERROR: ss is different from <%s>\n", fn_rsp);
            return KAT_VERIFICATION_ERROR;
        }

        if ( (ret_val = mlca_kem_dec(params, ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if ( memcmp(ss, ss1, mlca_kem_crypto_bytes(params)) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            return KAT_CRYPTO_FAILURE;
        }

    } while ( !done );

    fclose(fp_rsp);
    printf("Known Answer Tests PASSED. \n");
    printf("\n\n");

    mlca_secure_free(ct    , mlca_kem_crypto_ciphertextbytes(params));
    mlca_secure_free(ct_rsp, mlca_kem_crypto_ciphertextbytes(params));
    mlca_secure_free(ss    , mlca_kem_crypto_bytes(params));
    mlca_secure_free(ss1   , mlca_kem_crypto_bytes(params));
    mlca_secure_free(ss_rsp, mlca_kem_crypto_bytes(params));

    mlca_secure_free(pk, mlca_kem_crypto_publickeybytes(params));
    mlca_secure_free(sk, mlca_kem_crypto_secretkeybytes(params));
    mlca_secure_free(pk_rsp, mlca_kem_crypto_publickeybytes(params));
    mlca_secure_free(sk_rsp, mlca_kem_crypto_secretkeybytes(params));

    return KAT_SUCCESS;
}

int
test_chain_kat(const mlca_ctx_t * params, int fullkat)
{
    size_t CRYPTO_BYTES = mlca_kem_crypto_bytes(params);
    size_t CRYPTO_CIPHERTEXTBYTES = mlca_kem_crypto_ciphertextbytes(params);
    size_t CRYPTO_SECRETKEYBYTES = mlca_kem_crypto_secretkeybytes(params);
    size_t CRYPTO_PUBLICKEYBYTES = mlca_kem_crypto_publickeybytes(params);
    const char* ALGNAME = mlca_algorithm_name(params);

    char                fn_rsp[64];
    FILE                *fp_rsp;
    unsigned char       seed[48], shakeres[48];
    unsigned char       *ct, *ss, *ss1, *ct_rsp, *ss_rsp;
    int                 expcnt;
    int                 done;
    unsigned char       *pk, *sk, *pk_rsp, *sk_rsp;
    int                 ret_val;

    ct = mlca_malloc(mlca_kem_crypto_ciphertextbytes(params));
    ct_rsp = mlca_malloc(mlca_kem_crypto_ciphertextbytes(params));
    ss = mlca_malloc(mlca_kem_crypto_bytes(params));
    ss1 = mlca_malloc(mlca_kem_crypto_bytes(params));
    ss_rsp = mlca_malloc(mlca_kem_crypto_bytes(params));

    pk = mlca_malloc(mlca_kem_crypto_publickeybytes(params));
    sk = mlca_malloc(mlca_kem_crypto_secretkeybytes(params));
    pk_rsp = mlca_malloc(mlca_kem_crypto_publickeybytes(params));
    sk_rsp = mlca_malloc(mlca_kem_crypto_secretkeybytes(params));

    sprintf(fn_rsp, "../../KAT/%s/PQCkemKAT_%zu_ck%s.shake256", ALGNAME, CRYPTO_SECRETKEYBYTES, fullkat ? "_full" : "_kg");
    if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    printf("# %s\n\n", ALGNAME);
    done = 0;

    if ( !ReadHex(fp_rsp, seed, 48, "seed = ") ) {
        printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    if ( FindMarker(fp_rsp, "count = ") ) {
        if (fscanf(fp_rsp, "%d", &expcnt) != 1) {
            printf("ERROR: unable to read 'count' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
    } else {
        printf("ERROR: unable to read 'count' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    if ( !ReadHex(fp_rsp, shakeres, 48, "shake256-384 = ") ) {
        printf("ERROR: unable to read 'shake256-384' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    for (int count = 0; count < expcnt; ++count) {

        mlca_randombytes_init(&random_nist, seed, NULL, 384);
        if ((ret_val = mlca_kem_keygen(params, pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (fullkat) {
            if ( (ret_val = mlca_kem_enc(params, ct, ss, pk)) != 0) {
                printf("crypto_kem_enc returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }

            if ( (ret_val = mlca_kem_dec(params, ss1, ct, sk)) != 0) {
                printf("crypto_kem_dec returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }

            if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
                printf("crypto_kem_dec returned bad 'ss' value\n");
                return KAT_CRYPTO_FAILURE;
            }

            unsigned char *pkskctss = mlca_malloc(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + CRYPTO_CIPHERTEXTBYTES + 2*CRYPTO_BYTES);
            unsigned char *pptr = pkskctss;
            memcpy(pptr, pk, CRYPTO_PUBLICKEYBYTES);
            pptr += CRYPTO_PUBLICKEYBYTES;
            memcpy(pptr, sk, CRYPTO_SECRETKEYBYTES);
            pptr += CRYPTO_SECRETKEYBYTES;
            memcpy(pptr, ct, CRYPTO_CIPHERTEXTBYTES);
            pptr += CRYPTO_CIPHERTEXTBYTES;
            memcpy(pptr, ss, CRYPTO_BYTES);
            pptr += CRYPTO_BYTES;
            memcpy(pptr, ss1, CRYPTO_BYTES);

            shake256(seed, 48, pkskctss, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + CRYPTO_CIPHERTEXTBYTES + 2*CRYPTO_BYTES);
            mlca_secure_free(pkskctss, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + CRYPTO_CIPHERTEXTBYTES + 2*CRYPTO_BYTES);
        } else {
            unsigned char *pksk = mlca_malloc(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            unsigned char *pkskptr = pksk;
            memcpy(pkskptr, pk, CRYPTO_PUBLICKEYBYTES);
            pkskptr += CRYPTO_PUBLICKEYBYTES;
            memcpy(pkskptr, sk, CRYPTO_SECRETKEYBYTES);

            shake256(seed, 48, pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            mlca_secure_free(pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
        }
    }

    if (memcmp(seed, shakeres, 48) != 0) {
        printf("KAT verification FAILED. \n");
        return KAT_VERIFICATION_ERROR;
    }

    fclose(fp_rsp);
    printf("Known Answer Tests PASSED. \n");
    printf("\n\n");

    mlca_secure_free(ct    , mlca_kem_crypto_ciphertextbytes(params));
    mlca_secure_free(ct_rsp, mlca_kem_crypto_ciphertextbytes(params));
    mlca_secure_free(ss    , mlca_kem_crypto_bytes(params));
    mlca_secure_free(ss1   , mlca_kem_crypto_bytes(params));
    mlca_secure_free(ss_rsp, mlca_kem_crypto_bytes(params));

    mlca_secure_free(pk, mlca_kem_crypto_publickeybytes(params));
    mlca_secure_free(sk, mlca_kem_crypto_secretkeybytes(params));
    mlca_secure_free(pk_rsp, mlca_kem_crypto_publickeybytes(params));
    mlca_secure_free(sk_rsp, mlca_kem_crypto_secretkeybytes(params));

    return KAT_SUCCESS;
}

int
test_nist_kat_sign(const mlca_ctx_t * params)
{
    unsigned char       seed[48];
    unsigned char       msg[3300];
    unsigned char       entropy_input[48];
    unsigned char       *m, *sm, *m1, *m_rsp, *sm_rsp;
    size_t  mlen, smlen, mlen1;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk;
    int                 ret_val;
    
    char                fn_rsp[64];
    FILE                *fp_rsp;
    unsigned char       *pk_rsp, *sk_rsp;

    const char* algname = mlca_algorithm_name(params);
    if (!algname) return KAT_DATA_ERROR;

    pk = mlca_malloc(mlca_sig_crypto_publickeybytes(params));
    sk = mlca_malloc(mlca_sig_crypto_secretkeybytes(params));
    pk_rsp = mlca_malloc(mlca_sig_crypto_publickeybytes(params));
    sk_rsp = mlca_malloc(mlca_sig_crypto_secretkeybytes(params));
    
    sprintf(fn_rsp, "../../KAT/%s/PQCsignKAT_%zu.rsp", algname, mlca_sig_crypto_secretkeybytes(params));
    if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    
    done = 0;
    do {
        if ( FindMarker(fp_rsp, "count = ") )
            ret_val=fscanf(fp_rsp, "%d", &count);
        else {
            done = 1;
            break;
        }
        
        if ( !ReadHex(fp_rsp, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        
        //randombytes_init(seed, NULL, 256);
        mlca_randombytes_init(&random_nist, seed, NULL, 256);
        
        if ( FindMarker(fp_rsp, "mlen = ") )
            ret_val=fscanf(fp_rsp, "%zd", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        
        size_t smplusmlen = mlen+mlca_sig_crypto_bytes(params);
        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        sm = (unsigned char *)calloc(smplusmlen, sizeof(unsigned char));
        sm_rsp = (unsigned char *)calloc(smplusmlen, sizeof(unsigned char));

        if ( !ReadHex(fp_rsp, m, (int)mlen, "msg = ") ) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        
        // Generate the public/private keypair
        if ( (ret_val = mlca_sig_keygen(params, pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        if ( !ReadHex(fp_rsp, pk_rsp, mlca_sig_crypto_publickeybytes(params), "pk = ") ) {
            printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
	if ( !ReadHex(fp_rsp, sk_rsp, mlca_sig_crypto_secretkeybytes(params), "sk = ") ) {
            printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if(memcmp(pk,pk_rsp,mlca_sig_crypto_publickeybytes(params))!=0){
	    printf("ERROR: pk is different from <%s>\n", fn_rsp);
	    return KAT_VERIFICATION_ERROR;
	}
        if(memcmp(sk,sk_rsp,mlca_sig_crypto_secretkeybytes(params))!=0){
	    printf("ERROR: sk is different from <%s>\n", fn_rsp);
        print_uchar(sk, mlca_kem_crypto_secretkeybytes(params), "sk");
        print_uchar(sk_rsp, mlca_kem_crypto_secretkeybytes(params), "sk_rsp");
	    return KAT_VERIFICATION_ERROR;
	}
        smlen = mlca_sig_crypto_bytes(params);
        if ( (ret_val = mlca_sig_sign(params, sm, &smlen, m, mlen, sk)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (smlen != mlca_sig_crypto_bytes(params)) return KAT_CRYPTO_FAILURE;

        memcpy(sm + smlen, m, mlen);
        smlen += mlen;

        if (smlen != smplusmlen) return KAT_CRYPTO_FAILURE;

       	if ( !ReadHex(fp_rsp, sm_rsp, smlen, "sm = ") ) {
            printf("ERROR: unable to read 'sm' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if(memcmp(sm,sm_rsp,smlen)!=0){
            print_uchar(sm, smlen, "sm    ");
            print_uchar(sm_rsp, smlen, "sm_rsp");
	    printf("ERROR: sm is different from <%s>\n", fn_rsp);
	    return KAT_VERIFICATION_ERROR;
	}
    
        mlen1 = mlen;
        if ( (ret_val = mlca_sig_verify(params, m, mlen, sm, smlen - mlen, pk)) != 1) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        //if ( mlen != mlen1 ) {
        //    printf("crypto_sign_open returned bad 'mlen': Got <%zu>, expected <%zu>\n", mlen1, mlen);
        //    return KAT_CRYPTO_FAILURE;
        //}
        
        //if ( memcmp(m, m1, mlen) ) {
        //    printf("crypto_sign_open returned bad 'm' value\n");
        //    return KAT_CRYPTO_FAILURE;
        //}
        
        free(m);
        free(m1);
        free(sm);
	    free(sm_rsp);

    } while ( !done );
    
    fclose(fp_rsp);

    printf("Known Answer Tests PASSED. \n");
    printf("\n\n");

    mlca_secure_free(pk, mlca_sig_crypto_publickeybytes(params));
    mlca_secure_free(sk, mlca_sig_crypto_secretkeybytes(params));
    mlca_secure_free(pk_rsp, mlca_sig_crypto_publickeybytes(params));
    mlca_secure_free(sk_rsp, mlca_sig_crypto_secretkeybytes(params));

    return KAT_SUCCESS;
}

int
test_chain_kat_sign(const mlca_ctx_t * params, int fullkat)
{
    size_t CRYPTO_PUBLICKEYBYTES = mlca_sig_crypto_publickeybytes(params);
    size_t CRYPTO_SECRETKEYBYTES = mlca_sig_crypto_secretkeybytes(params);
    size_t CRYPTO_BYTES = mlca_sig_crypto_bytes(params);
    const char* ALGNAME = mlca_algorithm_name(params);

    unsigned char       seed[48], shakeres[48];
    unsigned char       msg[3300];
    unsigned char       entropy_input[48];
    unsigned char       *m, *sm, *m1, *m_rsp, *sm_rsp;
    size_t  mlen, smlen, mlen1;
    int                 expcnt;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk;
    int                 ret_val;
    
    char                fn_rsp[64];
    FILE                *fp_rsp;
    unsigned char       *pk_rsp, *sk_rsp;

    const char* algname = mlca_algorithm_name(params);
    if (!algname) return KAT_DATA_ERROR;

    pk = mlca_malloc(CRYPTO_PUBLICKEYBYTES);
    sk = mlca_malloc(CRYPTO_SECRETKEYBYTES);
    pk_rsp = mlca_malloc(CRYPTO_PUBLICKEYBYTES);
    sk_rsp = mlca_malloc(CRYPTO_SECRETKEYBYTES);

    sprintf(fn_rsp, "../../KAT/%s/PQCsignKAT_%zu_ck%s.shake256", mlca_algorithm_name(params), mlca_kem_crypto_secretkeybytes(params), fullkat ? "_full" : "_kg");
    if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    

    printf("# %s\n\n", ALGNAME);
    done = 0;

    if ( !ReadHex(fp_rsp, seed, 48, "seed = ") ) {
        printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    if ( FindMarker(fp_rsp, "count = ") ) {
        if (fscanf(fp_rsp, "%d", &expcnt) != 1) {
            printf("ERROR: unable to read 'count' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
    } else {
        printf("ERROR: unable to read 'count' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    if ( !ReadHex(fp_rsp, shakeres, 48, "shake256-384 = ") ) {
        printf("ERROR: unable to read 'shake256-384' from <%s>\n", fn_rsp);
        return KAT_DATA_ERROR;
    }

    for (int count = 0; count < expcnt; ++count) {

        mlca_randombytes_init(&random_nist, seed, NULL, 384);
        if ((ret_val = mlca_sig_keygen(params, pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (fullkat) {
            mlen = 33*(count+1);
            m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
            //m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
            sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));

            mlca_randombytes(&random_nist, m, mlen);
            smlen = CRYPTO_BYTES;
            if ( (ret_val = mlca_sig_sign(params, sm, &smlen, m, mlen, sk)) != 0) {
                printf("crypto_sign returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }


            if (smlen != mlca_sig_crypto_bytes(params)) return KAT_CRYPTO_FAILURE;

            memcpy(sm + smlen, m, mlen);
            smlen += mlen;

            if (smlen != mlen+CRYPTO_BYTES) return KAT_CRYPTO_FAILURE;
    
            mlen1 = mlen;
            if ( (ret_val = mlca_sig_verify(params, m, mlen, sm, smlen - mlen, pk)) != 1) {
                printf("crypto_sign_open returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }

            unsigned char *msgpksksm = mlca_malloc(mlen + CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + smlen);

            unsigned char *pptr = msgpksksm;
            
            memcpy(pptr, m, mlen);
            pptr += mlen;
            memcpy(pptr, pk, CRYPTO_PUBLICKEYBYTES);
            pptr += CRYPTO_PUBLICKEYBYTES;
            memcpy(pptr, sk, CRYPTO_SECRETKEYBYTES);
            pptr += CRYPTO_SECRETKEYBYTES;
            memcpy(pptr, sm, smlen);


            shake256(seed, 48, msgpksksm, mlen + CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + smlen);
                       
            free(m);
            free(sm);
            mlca_secure_free(msgpksksm, mlen + CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + smlen);
        } else {
            unsigned char *pksk = mlca_malloc(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            unsigned char *pkskptr = pksk;
            memcpy(pkskptr, pk, CRYPTO_PUBLICKEYBYTES);
            pkskptr += CRYPTO_PUBLICKEYBYTES;
            memcpy(pkskptr, sk, CRYPTO_SECRETKEYBYTES);

            shake256(seed, 48, pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            mlca_secure_free(pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
        }
    }

    if (memcmp(seed, shakeres, 48) != 0) {
        printf("KAT verification FAILED. \n");
        return KAT_VERIFICATION_ERROR;
    }

    fclose(fp_rsp);
    printf("Known Answer Tests PASSED. \n");
    printf("\n\n");

    mlca_secure_free(pk, CRYPTO_PUBLICKEYBYTES);
    mlca_secure_free(sk, CRYPTO_SECRETKEYBYTES);
    mlca_secure_free(pk_rsp, CRYPTO_PUBLICKEYBYTES);
    mlca_secure_free(sk_rsp, CRYPTO_SECRETKEYBYTES);


    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//

int
FindMarker(FILE *infile, const char *marker)
{
    char	line[MAX_MARKER_LEN];
    int		i, len;
    int curr_line;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
    {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF )
            return 0;
    }
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        curr_line = fgetc(infile);
        line[len-1] = curr_line;
        if (curr_line == EOF )
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int			i, ch, started;
    unsigned char	ich;

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
            ich = 0;

            for ( i=0; i<Length-1; i++ )
                A[i] = (A[i] << 4) | (A[i+1] >> 4);
            A[Length-1] = (A[Length-1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
