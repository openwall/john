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

#ifndef _SECPKCS5_H_
#define _SECPKCS5_H_

#include <plarena.h>
#include <openssl/sha.h>
#include <seccomon.h>
#include <hasht.h>


typedef SECItem *(*SEC_PKCS5GetPBEPassword) (void *arg);

/* used for V2 PKCS 12 Draft Spec */
    typedef enum {
	pbeBitGenIDNull = 0,
	pbeBitGenCipherKey = 0x01,
	pbeBitGenCipherIV = 0x02,
	pbeBitGenIntegrityKey = 0x03
} PBEBitGenID;

typedef enum {
	NSSPKCS5_PBKDF1 = 0,
	NSSPKCS5_PBKDF2 = 1,
	NSSPKCS5_PKCS12_V2 = 2
} NSSPKCS5PBEType;

//typedef struct NSSPKCS5PBEParameterStr NSSPKCS5PBEParameter;

struct NSSPKCS5PBEParameter {
	PRArenaPool *poolp;
	SECItem salt;		/* octet string */
	SECItem iteration;	/* integer */

	/* used locally */
	int iter;
	int keyLen;
	int ivLen;
	int hashType;
	NSSPKCS5PBEType pbeType;
	PBEBitGenID keyID;
	int encAlg;
	PRBool is2KeyDES;
};


SEC_BEGIN_PROTOS
/*
 * Convert an Algorithm ID to a PBE Param.
 * NOTE: this does not suppport PKCS 5 v2 because it's only used for the
 * keyDB which only support PKCS 5 v1, PFX, and PKCS 12.
 */
// My Mod
struct NSSPKCS5PBEParameter *nsspkcs5_NewParam(int alg, SECItem * salt, int iterator, struct NSSPKCS5PBEParameter *gpbe_param, unsigned char *salt_data);

/* Encrypt/Decrypt data using password based encryption.
 *  algid is the PBE algorithm identifier,
 *  pwitem is the password,
 *  src is the source for encryption/decryption,
 *  encrypt is PR_TRUE for encryption, PR_FALSE for decryption.
 * The key and iv are generated based upon PKCS #5 then the src
 * is either encrypted or decrypted.  If an error occurs, NULL
 * is returned, otherwise the ciphered contents is returned.
 */
extern int nsspkcs5_CipherData(struct NSSPKCS5PBEParameter * pbe_param, const unsigned char *pwhash,
    const unsigned char *encString, SECItem *pkcs5_pfxpbe, SECItem *secPreHash);

/* Destroys PBE parameter */
extern void nsspkcs5_DestroyPBEParameter(struct NSSPKCS5PBEParameter * param);

SEC_END_PROTOS
#endif
