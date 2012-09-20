/*
 *  des.h
 *
 *  header file for DES-150 library
 *
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
 * The Original Code is the DES-150 library.
 *
 * The Initial Developer of the Original Code is Nelson B. Bolyard,
 * nelsonb@iname.com.  Portions created by Nelson B. Bolyard are
 * Copyright (C) 1990, 2000  Nelson B. Bolyard, All Rights Reserved.
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
 * may use your version of this file under either the MPL or the GPL.
 */

#ifndef _DES_H_
#define _DES_H_ 1

//#include "blapit.h"
#include <seccomon.h>
#include <prtypes.h>
//#include <memory.h>
#include "KeyDBCracker.h"


#define NSS_DES			0
#define NSS_DES_CBC		1
#define NSS_DES_EDE3		2
#define NSS_DES_EDE3_CBC	3



typedef unsigned char BYTE;
typedef unsigned int  HALF;

#define HALFPTR(x) ((HALF *)(x))
#define SHORTPTR(x) ((unsigned short *)(x))
#define BYTEPTR(x) ((BYTE *)(x))

typedef enum _DESDirection
{
    DES_ENCRYPT = 0x5555,
    DES_DECRYPT = 0xAAAA
} DESDirection;


struct DESContext
{
    /* key schedule, 16 internal keys, each with 8 6-bit parts */
    HALF ks0 [32];
    HALF ks1 [32];
    HALF ks2 [32];
    HALF iv  [2];
    DESDirection direction;
    void *worker; // DESFunc* worker;

};

typedef void DESFunc(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len);

void DES_MakeSchedule( HALF * ks, const BYTE * key,   DESDirection direction);
void DES_Do1Block(     HALF * ks, const BYTE * inbuf, BYTE * outbuf);
struct DESContext *DES_CreateContext(struct DESContext *cx, const BYTE * key, const BYTE *iv); //, int mode);
void DES_DestroyContext(struct DESContext *cx, PRBool freeit);
SECStatus DES_Encrypt(struct DESContext *cx, BYTE *out, unsigned int *outLen, unsigned int maxOutLen, const BYTE *in, unsigned int inLen);
int DES_Decrypt(struct DESContext *cx, BYTE *out, unsigned int *outLen,unsigned int maxOutLen, const BYTE *in, unsigned int inLen);
int DES_EDE3CBCDe(struct DESContext *cx, const BYTE *in);

//not used...
void DES_EDE3CBCEn(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len);
void DES_CBCEn(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len);
void DES_EDE3_ECB(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len);
void DES_ECB(struct DESContext *cx, BYTE *out, const BYTE *in, unsigned int len);






#endif
