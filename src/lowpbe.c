/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#ifdef HAVE_NSS
#include <plarena.h>
#include "lowpbe.h"
#include <openssl/sha.h>
#include <memory.h>
#include <stdio.h>
#include <hasht.h>
#include <secoidt.h>
#include <secerr.h>
#include "mozilla_des.h"
#include "alghmac.h"



// Added by FireMaster

SECItem secPreHash;
SECItem pkcs5_pfxpbe;
SHA_CTX ctx;

/* generate bits using any hash
 */
/*
SECItem *nsspkcs5_PBKDF1( const unsigned char *pwdHash)
{
    SECItem *preHash = &secPreHash;
	// copy password hash .....
	memcpy(preHash->data, pwdHash, SHA1_LENGTH);

	SHA_CTX *lctx = ctx;
	SHA1_Init(lctx);
    SHA1_Update(lctx, preHash->data, preHash->len);
    SHA1_Final(lctx, secHash.data);

    return &secHash;
}

  */
/* this bit generation routine is described in PKCS 12 and the proposed
 * extensions to PKCS 5.  an initial hash is generated following the
 * instructions laid out in PKCS 5.  If the number of bits generated is
 * insufficient, then the method discussed in the proposed extensions to
 * PKCS 5 in PKCS 12 are used.  This extension makes use of the HMAC
 * function.  And the P_Hash function from the TLS standard.
 */



unsigned char *computeKey(struct NSSPKCS5PBEParameter * pbe_param, const unsigned char *pwdHash)	//SECItem *init_hash);
{
	SECItem *ret_bits = &pkcs5_pfxpbe;

	unsigned char state[256];
	unsigned int state_len;

	unsigned char *saltData = pbe_param->salt.data;
	unsigned int saltLen = pbe_param->salt.len;


	// First compute pkcs5 hash
	unsigned char firstHash[SHA1_LENGTH];
	SECItem *preHash = &secPreHash;
	// copy password hash .....
	memcpy(preHash->data, pwdHash, SHA1_LENGTH);

	SHA_CTX *fctx = &ctx;
	SHA1_Init(fctx);
	SHA1_Update(fctx, preHash->data, preHash->len);
	SHA1_Final(firstHash, fctx);


	// Next compute pkcs5 extended hash


	ret_bits->len = SHA1_LENGTH << 1;	// (hash_iter * hash_size);
	state_len = SHA1_LENGTH;

	// this is important...you have to zero the contents before using it
	memset(state, 0, state_len);
	memcpy(state, saltData, saltLen);


	struct HMACContext cx;
	SHA_CTX lctx;

	memset(cx.ipad, 0x36, HMAC_PAD_SIZE);
	memset(cx.opad, 0x5c, HMAC_PAD_SIZE);

	/* fold secret into padding */
	int k;
	for (k = 0; k < SHA1_LENGTH; k++) {
		cx.ipad[k] ^= firstHash[k];
		cx.opad[k] ^= firstHash[k];
	}




	// Unrolled looop...........twice
	SHA_CTX ctx1, ctx2, ctx3;

	SHA1_Init(&lctx);
	SHA1_Update(&lctx, cx.ipad, HMAC_PAD_SIZE);

	// Stage1 : Store the current context for future use
	memcpy(&ctx1, &lctx, sizeof(SHA_CTX));


	SHA1_Update(&lctx, state, state_len);

	// Stage2 : Store this calculated data to avoid repeated copy....
	memcpy(&ctx2, &lctx, sizeof(SHA_CTX));

	SHA1_Update(&lctx, saltData, saltLen);
	unsigned char *ret_data = ret_bits->data;
	SHA1_Final(ret_data, &lctx);

	SHA1_Init(&lctx);
	SHA1_Update(&lctx, cx.opad, HMAC_PAD_SIZE);

	// Stage3 : Store this calculated data to avoid repeated copy....
	memcpy(&ctx3, &lctx, sizeof(SHA_CTX));


	SHA1_Update(&lctx, ret_data, SHA1_LENGTH);
	SHA1_Final(ret_data, &lctx);

	// generate new state
	// Just restore previous context from already calculated data..
	memcpy(&lctx, &ctx2, sizeof(SHA_CTX));

	SHA1_Final(state, &lctx);

	// Just restore previous context from already calculated data..
	memcpy(&lctx, &ctx3, sizeof(SHA_CTX));

	SHA1_Update(&lctx, state, state_len);
	SHA1_Final(state, &lctx);


	// Second loop....

	// Copy the previously stored data...
	memcpy(&lctx, &ctx1, sizeof(SHA_CTX));
	SHA1_Update(&lctx, state, state_len);
	SHA1_Update(&lctx, saltData, saltLen);

	SHA1_Final(ret_data + SHA1_LENGTH, &lctx);

	// Just restore previous context from already calculated data..
	memcpy(&lctx, &ctx3, sizeof(SHA_CTX));

	SHA1_Update(&lctx, ret_data + SHA1_LENGTH, SHA1_LENGTH);
	SHA1_Final(ret_data + SHA1_LENGTH, &lctx);


	return ret_bits->data;
}

/* generate bits for the key and iv determination.  if enough bits
 * are not generated using PKCS 5, then we need to generate more bits
 * based on the extension proposed in PKCS 12
 */
/*
SECItem *nsspkcs5_PBKDF1Extended(struct NSSPKCS5PBEParameter *pbe_param, SECItem *pwitem)
{
    SECItem * hash;
    int       bytes_needed;

    bytes_needed = pbe_param->ivLen + pbe_param->keyLen;
    hash = nsspkcs5_PBKDF1(&pbe_param->salt, pwitem);

    return nsspkcs5_PFXPBE(pbe_param, hash, bytes_needed);

}
*/

#define HMAC_BUFFER 64
#define NSSPBE_ROUNDUP(x,y) ((((x)+((y)-1))/(y))*(y))
#define NSSPBE_MIN(x,y) ((x) < (y) ? (x) : (y))


static SECStatus nsspkcs5_FillInParam(int algorithm, struct NSSPKCS5PBEParameter *pbe_param)
{

	pbe_param->hashType = 0;	//HASH_AlgSHA1;
	pbe_param->pbeType = NSSPKCS5_PBKDF1;
	pbe_param->is2KeyDES = PR_FALSE;

	pbe_param->ivLen = 8;
	pbe_param->keyLen = 24;
	pbe_param->encAlg = SEC_OID_DES_EDE3_CBC;

	/*
	   switch(algorithm)
	   {
	   // DES3 Algorithms
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC:
	   pbe_param->is2KeyDES = PR_TRUE;
	   // fall through
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC:
	   pbe_param->pbeType = NSSPKCS5_PKCS12_V2;
	   // fall through
	   case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC:
	   pbe_param->keyLen = 24;
	   pbe_param->encAlg = SEC_OID_DES_EDE3_CBC;
	   break;

	   // DES Algorithms
	   case SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC:
	   pbe_param->hashType = HASH_AlgMD2;
	   goto finish_des;
	   case SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC:
	   pbe_param->hashType = HASH_AlgMD5;
	   // fall through
	   case SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC:
	   finish_des:
	   pbe_param->keyLen = 8;
	   pbe_param->encAlg =  SEC_OID_DES_CBC;
	   break;

	   // RC2 Algorithms
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	   pbe_param->keyLen = 16;
	   // fall through
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	   pbe_param->pbeType = NSSPKCS5_PKCS12_V2;
	   break;
	   case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	   pbe_param->keyLen = 16;
	   // fall through
	   case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	   break;

	   // RC4 algorithms
	   case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4:
	   skipType = PR_TRUE;
	   // fall through
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4:
	   pbe_param->keyLen = 16;
	   // fall through
	   case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4:
	   if (!skipType) {
	   pbe_param->pbeType = NSSPKCS5_PKCS12_V2;
	   }
	   // fall through
	   case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4:
	   pbe_param->ivLen = 0;
	   pbe_param->encAlg =  SEC_OID_RC4;
	   break;
	   default:
	   return SECFailure;
	   }

	 */

	// Allocate here itself...
	// Added by FireMaster
//      secKey.data = (unsigned char*)malloc(pbe_param->keyLen);
//      secKey.len  = pbe_param->keyLen;

//    secIV.data  = (unsigned char*)malloc(pbe_param->ivLen);
//        secIV.len   = pbe_param->ivLen;
	secPreHash.data = (unsigned char *) malloc(256);
	pkcs5_pfxpbe.data = (unsigned char *) malloc(512);


	if (!secPreHash.data || !pkcs5_pfxpbe.data)
		return SECFailure;




	return SECSuccess;
}



/* decode the algid and generate a PKCS 5 parameter from it
 */
struct NSSPKCS5PBEParameter *nsspkcs5_NewParam(int alg, SECItem * salt, int iterator)
{
	struct NSSPKCS5PBEParameter *pbe_param = NULL;
	SECStatus rv = SECFailure;

	pbe_param = (struct NSSPKCS5PBEParameter *) malloc(sizeof(struct NSSPKCS5PBEParameter));

	if (pbe_param == NULL)
		return NULL;

	pbe_param->poolp = NULL;

	rv = nsspkcs5_FillInParam(alg, pbe_param);

	if (rv != SECSuccess)
		return NULL;

	pbe_param->iter = iterator;

	pbe_param->salt.data = (unsigned char *) malloc(salt->len);

	if (pbe_param->salt.data) {
		memcpy(pbe_param->salt.data, salt->data, salt->len);
		pbe_param->salt.len = salt->len;
	} else
		return NULL;

	// Initialize certain variables......
	pbe_param->keyID = pbeBitGenCipherKey;

	//ctx = SHA1_GetContext();

	// Initialize hash values....
	memcpy(secPreHash.data + SHA1_LENGTH, salt->data, salt->len);
	secPreHash.len = salt->len + SHA1_LENGTH;

	// Setup initial state value
	// Its important to initialize this to zero
	//memset(initialState, 0, 128);
	//memcpy(initialState, salt->data, salt->len);


	return pbe_param;
}



int sec_pkcs5_des(const unsigned char *hash, const unsigned char *encString)
{

	struct DESContext dctx;
	DES_CreateContext(&dctx, hash, hash + 32);
	return DES_EDE3CBCDe(&dctx, encString);
}




/* function pointer template for crypto functions */
typedef SECItem *(*pkcs5_crypto_func) (SECItem * key, SECItem * iv, SECItem * src, PRBool op1, PRBool op2);

/* performs the cipher operation on the src and returns the result.
 * if an error occurs, NULL is returned.
 *
 * a null length password is allowed.  this corresponds to encrypting
 * the data with ust the salt.
 */
/* change this to use PKCS 11? */
// Optimized for FireMaster....
int nsspkcs5_CipherData(struct NSSPKCS5PBEParameter * pbe_param, const unsigned char *pwhash, const unsigned char *encString)
{

	unsigned char *hashKey = computeKey(pbe_param, pwhash);

	struct DESContext dctx;
	DES_CreateContext(&dctx, hashKey, hashKey + 32);
	return DES_EDE3CBCDe(&dctx, encString);
}

#endif
