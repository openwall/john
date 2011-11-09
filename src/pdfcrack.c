/**
 * Copyright (C) 2006-2008 Henning Norén
 * Copyright (C) 1996-2005 Glyph & Cog, LLC.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "pdfcrack.h"
#include "pdfcrack_md5.h"
#include "pdfcrack_rc4.h"

#include "stdint.h"
#include "stdbool.h"

#ifndef __GNUC__
#define likely(x)       (x)
#define unlikely(x)     (x)
#else
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

/** sets the number of bytes to decrypt for partial test in revision 3.
    Three should be a good number for this as this mean a match should only
    happen every 256^3=16777216 check and that should be unique enough to
    motivate a full retry on that entry.
 */
#define PARTIAL_TEST_SIZE 3

static const uint8_t pad[32] = {
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
};

/** buffers for stuff that we can precompute before the actual cracking */
static uint8_t *encKeyWorkSpace;
static uint8_t password_user[33];
static uint8_t *rev3TestKey;
static unsigned int ekwlen;

/* flag used to make sure we do not clean up when we have not called init */
static int binitPDFCrack_called = 0;

/** points to the current password in clear-text */
static unsigned char *currPW;
/** current length of the password we are working with */
static unsigned int currPWLen;

/** pointer to the actual encoding-data from the pdf */
static const EncData *encdata;

/** some configuration switches */
static bool knownPassword;
static bool workWithUser;

/**
 * Initialisation of the encryption key workspace to manage a bit faster
 * switching between keys
 */
static unsigned int
initEncKeyWorkSpace(const int revision, const bool encMetaData,
    const int permissions, const uint8_t * ownerkey,
    const uint8_t * fileID, const unsigned int fileIDLen)
{
  /**
   *   Algorithm 3.2 Computing an encryption key (PDF Reference, v 1.7, p.125)
   *
   *   Make space for:
   *   field           | bytes
   *   -----------------------
   *   padded password | 32
   *   O entry         | 32
   *   P entry         |  4
   *   fileID          | <fileIDLEn>
   *   [extra padding] | [4] (Special for step 6)
   **/
	unsigned int size = (revision > 3 && !encMetaData) ? 72 : 68;
	encKeyWorkSpace = malloc(size + fileIDLen);

  /** Just to be sure we have no uninitalized stuff in the workspace */
	memcpy(encKeyWorkSpace, pad, 32);

  /** 3 */
	memcpy(encKeyWorkSpace + 32, ownerkey, 32);

  /** 4 */
	encKeyWorkSpace[64] = permissions & 0xff;
	encKeyWorkSpace[65] = (permissions >> 8) & 0xff;
	encKeyWorkSpace[66] = (permissions >> 16) & 0xff;
	encKeyWorkSpace[67] = (permissions >> 24) & 0xff;

  /** 5 */
	memcpy(encKeyWorkSpace + 68, fileID, fileIDLen);

  /** 6 */
	if (revision > 3 && !encMetaData) {
		encKeyWorkSpace[68 + fileIDLen] = 0xff;
		encKeyWorkSpace[69 + fileIDLen] = 0xff;
		encKeyWorkSpace[70 + fileIDLen] = 0xff;
		encKeyWorkSpace[71 + fileIDLen] = 0xff;
	}

	return size + fileIDLen;
}

#if 0
/** For debug */
static void printHexString(const uint8_t * str, const unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		printf("%x ", str[i]);
	printf("\n");
}

static void printString(const uint8_t * str, const unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		printf("%d ", str[i]);
	printf("\n");
}
#endif

/** Common handling of the key for all rev3-functions */
#define RC4_DECRYPT_REV3(n) {			\
    for(i = 19; i >= 0; --i) {			\
      for(j = 0; j < length; ++j)		\
	tmpkey[j] = enckey[j] ^ i;		\
      rc4Decrypt(tmpkey, test, n, test);	\
    }						\
  }

/** Checks if the rev2-password set up in encKeyWorkSpace is the correct one
    and return true if it is and false otherwise.
*/
static bool isUserPasswordRev2(void)
{
	uint8_t enckey[16];

	md5(encKeyWorkSpace, ekwlen, enckey);

	return rc4Match40b(enckey, encdata->u_string, pad);
}

/** Checks if the rev3-password set up in encKeyWorkSpace is the correct one
    and return true if it is and false otherwise.
*/
static bool isUserPasswordRev3(void)
{
	uint8_t test[16], enckey[16], tmpkey[16];
	int i;
	unsigned int length, j;

	length = encdata->length / 8;
	md5(encKeyWorkSpace, ekwlen, enckey);
	md5_50(enckey);
	memcpy(test, encdata->u_string, 16);

	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);

  /** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, rev3TestKey, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, encdata->u_string, 16);
		RC4_DECRYPT_REV3(16);
		if (memcmp(test, rev3TestKey, 16) == 0) {
			return true;
		}
	}
	return false;
}

bool runCrackRev2_o(void)
{
	uint8_t enckey[16];
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);

	rc4Decrypt(enckey, encdata->o_string, 32, encKeyWorkSpace);
	md5(encKeyWorkSpace, ekwlen, enckey);
	if (rc4Match40b(enckey, encdata->u_string, pad)) {
		memcpy(password_user, encKeyWorkSpace, 32);
		return true;
	}

	return false;
}

bool runCrackRev3_o(void)
{
	uint8_t test[32], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;

	length = encdata->length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);
	md5_50(enckey);

	memcpy(test, encdata->o_string, 32);
	RC4_DECRYPT_REV3(32);
	memcpy(encKeyWorkSpace, test, 32);

	if (isUserPasswordRev3()) {
		memcpy(password_user, encKeyWorkSpace, 32);
		return true;
	}

	return false;
}

bool runCrackRev2_of(void)
{
	uint8_t enckey[16];
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(encKeyWorkSpace, 32, enckey);

	/* Algorithm 3.4 reversed */
	if (rc4Match40b(enckey, encdata->o_string, password_user))
		return true;

	return false;
}

bool runCrackRev3_of(void)
{
	uint8_t test[32], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;

	length = encdata->length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(encKeyWorkSpace, 32, enckey);
	md5_50(enckey);

	memcpy(test, encdata->o_string, 32);
	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);

      /** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, password_user, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, encdata->o_string, 32);
		RC4_DECRYPT_REV3(32);
		if (memcmp(test, password_user, 32) == 0)
			return true;
	}
	return false;
}

bool runCrackRev3(void)
{
	uint8_t test[16], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;

	length = encdata->length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(encKeyWorkSpace, ekwlen, enckey);
	md5_50(enckey);
	memcpy(test, encdata->u_string, 16);

     /** Algorithm 3.5 reversed */
	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);

      /** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, rev3TestKey, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, encdata->u_string, 16);
		RC4_DECRYPT_REV3(16);
		if (memcmp(test, rev3TestKey, 16) == 0)
			return true;
	}
	return false;
}


bool runCrackRev2(void)
{
	uint8_t enckey[16];
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(encKeyWorkSpace, ekwlen, enckey);

	/* Algorithm 3.4 reversed */
	if (rc4Match40b(enckey, encdata->u_string, pad))
		return true;

	return false;
}

/** Start cracking and does not stop until it has either been interrupted by
    a signal or the password either is found or wordlist or charset is exhausted
*/
int runCrack(char *password)
{
	bool found = false;
	uint8_t cpw[32];
	if (strlen(password) < 32)
		strcpy((char*)currPW, password);
    else {
		strncpy((char*)currPW, password, 32);
    }

	if (!workWithUser && !knownPassword) {
		memcpy(cpw, pad, 32);
		currPW = cpw;
		if (encdata->revision == 2)
			found = runCrackRev2_o();
		else
			found = runCrackRev3_o();
	} else if (encdata->revision == 2) {
		if (workWithUser)
			found = runCrackRev2();
		else
	     /** knownPassword */
			found = runCrackRev2_of();
	} else {
		if (workWithUser)
			found = runCrackRev3();
		else
	     /** knownPassword */
			found = runCrackRev3_of();
	}
	return found;
}

/** cleans up everything as is needed to do a any initPDFCrack-calls after the
    first one.
*/
void cleanPDFCrack(void)
{
	if (!binitPDFCrack_called)
		return;
	binitPDFCrack_called = 0;
	if (rev3TestKey) {
    /** Do a really ugly const to non-const cast but this one time it should
	be safe
    */
		free((uint8_t *) rev3TestKey);
		rev3TestKey = NULL;
	}
	if (encKeyWorkSpace) {
		free(encKeyWorkSpace);
		encKeyWorkSpace = NULL;
	}
	knownPassword = false;
}

/** initPDFCrack is doing all the initialisations before you are able to call
    runCrack(). Make sure that you run cleanPDFCrack before you call this
    after the first time.
*/
bool initPDFCrack(const EncData * e, const uint8_t * upw, const bool user)
{
	uint8_t buf[128];
	unsigned int upwlen;
	uint8_t *tmp;

	/* cleans up before we start */
	cleanPDFCrack();
	/* set that we 'have' called init, and to allow cleanup to work next time */
	binitPDFCrack_called = 1;

	ekwlen =
	    initEncKeyWorkSpace(e->revision, e->encryptMetaData,
	    e->permissions, e->o_string, e->fileID, e->fileIDLen);

	encdata = e;
	currPW = encKeyWorkSpace;
	currPWLen = 0;
	workWithUser = user;
	setrc4DecryptMethod((unsigned int) e->length);
	if (upw) {
		upwlen = strlen((const char *) upw);
		if (upwlen > 32)
			upwlen = 32;
		memcpy(password_user, upw, upwlen);
		memcpy(password_user + upwlen, pad, 32 - upwlen);
		memcpy(encKeyWorkSpace, password_user, 32);
		knownPassword = true;
	}

	if (encdata->revision == 2) {
		if (knownPassword) {
			if (!isUserPasswordRev2())
				return false;
			memcpy(encKeyWorkSpace, pad, 32);
		} else {
			memcpy(password_user, pad, 32);
			knownPassword = isUserPasswordRev2();
		}
	} else if (e->revision >= 3) {
		memcpy(buf, pad, 32);
		memcpy(buf + 32, e->fileID, e->fileIDLen);
		tmp = malloc(sizeof(uint8_t) * 16);
		md5(buf, 32 + e->fileIDLen, tmp);
		rev3TestKey = tmp;
		if (knownPassword) {
			if (!isUserPasswordRev3())
				return false;
			memcpy(encKeyWorkSpace, pad, 32);
		} else {
			memcpy(password_user, pad, 32);
			knownPassword = isUserPasswordRev3();
		}
	}
	return true;
}
