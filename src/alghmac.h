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

#ifndef _ALGHMAC_H_
#define _ALGHMAC_H_

#include "seccomon.h"
#include <malloc.h>
#include <memory.h>
#include "alghmac.h"


#define HMAC_PAD_SIZE 64

struct HMACContext
{
    SHA_CTX *hash;
    const SECHashObject *hashobj;
    unsigned char ipad[HMAC_PAD_SIZE];
    unsigned char opad[HMAC_PAD_SIZE];
};


//SEC_BEGIN_PROTOS

/* destroy HMAC context */
extern void HMAC_Destroy(struct HMACContext *cx);

/* create HMAC context
 *  hashObj     hash object from SECRawHashObjects[]
 *  secret	the secret with which the HMAC is performed.
 *  secret_len	the length of the secret.
 *  isFIPS	true if conforming to FIPS 198.
 *
 * NULL is returned if an error occurs.
 */
extern struct HMACContext *HMAC_Create(const unsigned char *secret, unsigned int secret_len);

/* reset HMAC for a fresh round */
extern void HMAC_Begin(struct HMACContext *cx);

/* update HMAC
 *  cx		HMAC Context
 *  data	the data to perform HMAC on
 *  data_len	the length of the data to process
 */
extern void HMAC_Update(struct HMACContext *cx, const unsigned char *data, unsigned int data_len);

/* Finish HMAC -- place the results within result
 *  cx		HMAC context
 *  result	buffer for resulting hmac'd data
 *  result_len	where the resultant hmac length is stored
 *  max_result_len  maximum possible length that can be stored in result
 */
extern void HMAC_Finish(struct HMACContext *cx, unsigned char *result, unsigned int *result_len,
	    unsigned int max_result_len);


#endif
