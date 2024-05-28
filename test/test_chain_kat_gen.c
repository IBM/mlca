// SPDX-License-Identifier: Apache-2.0 and Unknown
// Modified on May 28, 2024 to accomodate the API.
/*
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
 
NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 
You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <random_ctrdrbg.h>
#include <mlca2.h>
#include <keccak.h>

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

static void
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

int
test_chain_kat_gen(const mlca_ctx_t* params, int numkat, int fullkat)
{
    char                fn_rsp[128], fn_shake[128];
    FILE                *fp_shake, *fp_rsp;
    unsigned char       seed[48], seedinitial[48];
    unsigned char       entropy_input[48];
    unsigned char       *ct, *ss, *ss1;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk;
    int                 ret_val;

    ct = mlca_malloc(mlca_kem_crypto_ciphertextbytes(params));
    ss = mlca_malloc(mlca_kem_crypto_bytes(params));
    ss1 = mlca_malloc(mlca_kem_crypto_bytes(params));
    pk = mlca_malloc(mlca_kem_crypto_publickeybytes(params));
    sk = mlca_malloc(mlca_kem_crypto_secretkeybytes(params));

    sprintf(fn_rsp, "PQCkemKAT_%zu_ck%s.rsp", mlca_kem_crypto_secretkeybytes(params), fullkat ? "_full" : "_kg");
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    sprintf(fn_shake, "PQCkemKAT_%zu_ck%s.shake256", mlca_kem_crypto_secretkeybytes(params), fullkat ? "_full" : "_kg");
    if ( (fp_shake = fopen(fn_shake, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_shake);
        return KAT_FILE_OPEN_ERROR;
    }

    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    mlca_randombytes_init(&random_nist, entropy_input, NULL, 384);
    mlca_randombytes(&random_nist, seed, 48);

    memcpy(seedinitial, seed, 48);

    fprintf(fp_rsp, "# %s\n\n", mlca_algorithm_name(params));
    done = 0;
    for (int count = 0; count < numkat; ++count) {
        fprintf(fp_rsp, "count = %d\n", count);

        fprintBstr(fp_rsp, "seed = ", seed, 48);

        mlca_randombytes_init(&random_nist, seed, NULL, 384);
        if ((ret_val = mlca_kem_keygen(params, pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, mlca_kem_crypto_publickeybytes(params));
        fprintBstr(fp_rsp, "sk = ", sk, mlca_kem_crypto_secretkeybytes(params));

        if (fullkat) {
            if ( (ret_val = mlca_kem_enc(params, ct, ss, pk)) != 0) {
                printf("crypto_kem_enc returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }
            fprintBstr(fp_rsp, "ct = ", ct, mlca_kem_crypto_ciphertextbytes(params));
            fprintBstr(fp_rsp, "ss = ", ss, mlca_kem_crypto_bytes(params));

            fprintf(fp_rsp, "\n");

            if ( (ret_val = mlca_kem_dec(params, ss1, ct, sk)) != 0) {
                printf("crypto_kem_dec returned <%d>\n", ret_val);
                return KAT_CRYPTO_FAILURE;
            }

            if ( memcmp(ss, ss1, mlca_kem_crypto_bytes(params)) ) {
                printf("crypto_kem_dec returned bad 'ss' value\n");
                return KAT_CRYPTO_FAILURE;
            }

            unsigned char *pkskctssss = mlca_malloc(mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params) + mlca_kem_crypto_ciphertextbytes(params) + 2 *
                                                                                                                       mlca_kem_crypto_bytes(params));
            unsigned char *pptr = pkskctssss;
            memcpy(pptr, pk, mlca_kem_crypto_publickeybytes(params));
            pptr += mlca_kem_crypto_publickeybytes(params);
            memcpy(pptr, sk, mlca_kem_crypto_secretkeybytes(params));
            pptr += mlca_kem_crypto_secretkeybytes(params);
            memcpy(pptr, ct, mlca_kem_crypto_ciphertextbytes(params));
            pptr += mlca_kem_crypto_ciphertextbytes(params);
            memcpy(pptr, ss, mlca_kem_crypto_bytes(params));
            pptr += mlca_kem_crypto_bytes(params);
            memcpy(pptr, ss1, mlca_kem_crypto_bytes(params));

            shake256(seed, 48, pkskctssss,
                     mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params) + mlca_kem_crypto_ciphertextbytes(params) + 2 *
                                                                                                                             mlca_kem_crypto_bytes(
                                                                                                                           params));
            mlca_secure_free(pkskctssss, mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params) + mlca_kem_crypto_ciphertextbytes(params) + 2 *
                                                                                                                       mlca_kem_crypto_bytes(params));
        } else {
            unsigned char *pksk = mlca_malloc(mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params));
            unsigned char *pkskptr = pksk;
            memcpy(pkskptr, pk, mlca_kem_crypto_publickeybytes(params));
            pkskptr += mlca_kem_crypto_publickeybytes(params);
            memcpy(pkskptr, sk, mlca_kem_crypto_secretkeybytes(params));

            fprintf(fp_rsp, "\n");

            shake256(seed, 48, pksk, mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params));
            mlca_secure_free(pksk, mlca_kem_crypto_publickeybytes(params) + mlca_kem_crypto_secretkeybytes(params));
        }

    }

    fprintBstr(fp_rsp, "SHAKE256-384 = ", seed, 48);

    fprintBstr(fp_shake, "seed = ", seedinitial, 48);
    fprintf(fp_shake, "count = %d\n", numkat);
    fprintBstr(fp_shake, "shake256-384 = ", seed, 48);

    fclose(fp_rsp);
    fclose(fp_shake);

    mlca_secure_free(ct , mlca_kem_crypto_ciphertextbytes(params));
    mlca_secure_free(ss , mlca_kem_crypto_bytes(params));
    mlca_secure_free(ss1, mlca_kem_crypto_bytes(params));
    mlca_secure_free(pk , mlca_kem_crypto_publickeybytes(params));
    mlca_secure_free(sk , mlca_kem_crypto_secretkeybytes(params));

    return KAT_SUCCESS;
}

int
test_chain_kat_sign_gen(const mlca_ctx_t* params, int numkat, int fullkat)
{
    size_t CRYPTO_PUBLICKEYBYTES = mlca_sig_crypto_publickeybytes(params);
    size_t CRYPTO_SECRETKEYBYTES = mlca_sig_crypto_secretkeybytes(params);
    size_t CRYPTO_BYTES = mlca_sig_crypto_bytes(params);
    const char* CRYPTO_ALGNAME = mlca_algorithm_name(params);

    char                fn_rsp[128], fn_shake[128];
    FILE                *fp_rsp, *fp_shake;
    unsigned char       seed[48], seedinitial[48];
    //unsigned char       msg[3300];
    unsigned char       entropy_input[48];
    unsigned char       *m, *sm, *m1;
    size_t              mlen, smlen, mlen1;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk;
    int                 ret_val;

    pk = mlca_malloc(CRYPTO_PUBLICKEYBYTES);
    sk = mlca_malloc(CRYPTO_SECRETKEYBYTES);
    
    sprintf(fn_rsp, "PQCsignKAT_%zu_ck%s.rsp", CRYPTO_SECRETKEYBYTES, fullkat ? "_full" : "_kg");
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    sprintf(fn_shake, "PQCsignKAT_%zu_ck%s.shake256", CRYPTO_SECRETKEYBYTES, fullkat ? "_full" : "_kg");
    if ( (fp_shake = fopen(fn_shake, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_shake);
        return KAT_FILE_OPEN_ERROR;
    }
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    //randombytes_init(entropy_input, NULL, 256);
    mlca_randombytes_init(&random_nist, entropy_input, NULL, 384);
    mlca_randombytes(&random_nist, seed, 48);

    memcpy(seedinitial, seed, 48);
    
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    for (int count = 0; count < numkat; ++count) {
        fprintf(fp_rsp, "count = %d\n", count);

        fprintBstr(fp_rsp, "seed = ", seed, 48);
        
        mlca_randombytes_init(&random_nist, seed, NULL, 384);
        
        // Generate the public/private keypair
        if ( (ret_val = mlca_sig_keygen(params, pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
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

            fprintf(fp_rsp, "mlen = %zu\n", mlen);
            fprintBstr(fp_rsp, "msg = ", m, mlen);
            fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
            fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
            fprintf(fp_rsp, "smlen = %zu\n", smlen);
            fprintBstr(fp_rsp, "sm = ", sm, smlen);
            fprintf(fp_rsp, "\n");

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
            //free(m1);
            free(sm);
            mlca_secure_free(msgpksksm, mlen + CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + smlen);
        } else {
            // keygen only
            fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
            fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

            unsigned char *pksk = mlca_malloc(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            unsigned char *pkskptr = pksk;
            memcpy(pkskptr, pk, CRYPTO_PUBLICKEYBYTES);
            pkskptr += CRYPTO_PUBLICKEYBYTES;
            memcpy(pkskptr, sk, CRYPTO_SECRETKEYBYTES);

            fprintf(fp_rsp, "\n");

            shake256(seed, 48, pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
            mlca_secure_free(pksk, CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES);
        }

    }
    
    fprintBstr(fp_rsp, "SHAKE256-384 = ", seed, 48);

    fprintBstr(fp_shake, "seed = ", seedinitial, 48);
    fprintf(fp_shake, "count = %d\n", numkat);
    fprintBstr(fp_shake, "shake256-384 = ", seed, 48);

    fclose(fp_rsp);
    fclose(fp_shake);

    mlca_secure_free(pk, CRYPTO_PUBLICKEYBYTES);
    mlca_secure_free(sk, CRYPTO_SECRETKEYBYTES);

    return KAT_SUCCESS;
}
