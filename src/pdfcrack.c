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
#include "md5.h"

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

/**
 * Initialisation of the encryption key workspace to manage a bit faster
 * switching between keys
 */
static unsigned int
initEncKeyWorkSpace(const int revision, const bool encMetaData,
    const int permissions, const uint8_t * ownerkey,
    const uint8_t * fileID, const unsigned int fileIDLen, struct custom_salt *cs)
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

  /** Just to be sure we have no uninitalized stuff in the workspace */
	memcpy(cs->encKeyWorkSpace, pad, 32);

  /** 3 */
	memcpy(cs->encKeyWorkSpace + 32, ownerkey, 32);

  /** 4 */
	cs->encKeyWorkSpace[64] = permissions & 0xff;
	cs->encKeyWorkSpace[65] = (permissions >> 8) & 0xff;
	cs->encKeyWorkSpace[66] = (permissions >> 16) & 0xff;
	cs->encKeyWorkSpace[67] = (permissions >> 24) & 0xff;

  /** 5 */
	memcpy(cs->encKeyWorkSpace + 68, fileID, fileIDLen);

  /** 6 */
	if (revision > 3 && !encMetaData) {
		cs->encKeyWorkSpace[68 + fileIDLen] = 0xff;
		cs->encKeyWorkSpace[69 + fileIDLen] = 0xff;
		cs->encKeyWorkSpace[70 + fileIDLen] = 0xff;
		cs->encKeyWorkSpace[71 + fileIDLen] = 0xff;
	}
	return size + fileIDLen;
}

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
static bool isUserPasswordRev2(struct custom_salt *cs)
{
	uint8_t enckey[16];

	md5(cs->encKeyWorkSpace, cs->ekwlen, enckey);

	return rc4Match40b(enckey, cs->e.u_string, pad);
}

/** Checks if the rev3-password set up in encKeyWorkSpace is the correct one
    and return true if it is and false otherwise.
*/
static bool isUserPasswordRev3(struct custom_salt *cs, unsigned char *buf)
{
	uint8_t test[16], enckey[16], tmpkey[16];
	int i;
	unsigned int length, j;

	length = cs->e.length / 8;
	md5(buf, cs->ekwlen, enckey);
	md5_50(enckey);
	memcpy(test, cs->e.u_string, 16);

	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);
	/** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, cs->rev3TestKey, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, cs->e.u_string, 16);
		RC4_DECRYPT_REV3(16);
		if (memcmp(test, cs->rev3TestKey, 16) == 0) {
			return true;
		}
	}
	return false;
}

bool runCrackRev2_o(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t enckey[16];
	unsigned int currPWLen;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);

	rc4Decrypt(enckey, cs->e.o_string, 32, currPW);
	md5(currPW, cs->ekwlen, enckey);
	if (rc4Match40b(enckey, cs->e.u_string, pad)) {
		memcpy(cs->password_user, cs->encKeyWorkSpace, 32);
		return true;
	}

	return false;
}

bool runCrackRev3_o(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t test[32], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;
	unsigned int currPWLen;
	unsigned char buf[128];

	length = cs->e.length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);
	md5_50(enckey);

	memcpy(test, cs->e.o_string, 32);
	RC4_DECRYPT_REV3(32);
	// memcpy(cs->encKeyWorkSpace, test, 32);
	memcpy(buf, cs->encKeyWorkSpace, 128);
	memcpy(buf, test, 32);

	if (isUserPasswordRev3(cs, buf)) {
		memcpy(cs->password_user, cs->encKeyWorkSpace, 32);
		return true;
	}

	return false;
}

bool runCrackRev2_of(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t enckey[16];
	unsigned int currPWLen;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);

	/* Algorithm 3.4 reversed */
	if (rc4Match40b(enckey, cs->e.o_string, cs->password_user))
		return true;

	return false;
}

bool runCrackRev3_of(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t test[32], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;
	unsigned int currPWLen;

	length = cs->e.length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, 32, enckey);
	md5_50(enckey);

	memcpy(test, cs->e.o_string, 32);
	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);

	/** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, cs->password_user, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, cs->e.o_string, 32);
		RC4_DECRYPT_REV3(32);
		if (memcmp(test, cs->password_user, 32) == 0)
			return true;
	}
	return false;
}

bool runCrackRev3(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t test[16], enckey[16], tmpkey[16];
	unsigned int j, length;
	int i;
	unsigned int currPWLen;

	length = cs->e.length / 8;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);

	md5(currPW, cs->ekwlen, enckey);
	md5_50(enckey);
	memcpy(test, cs->e.u_string, 16);

	/** Algorithm 3.5 reversed */
	RC4_DECRYPT_REV3(PARTIAL_TEST_SIZE);

	/** if partial test succeeds we make a full check to be sure */
	if (unlikely(memcmp(test, cs->rev3TestKey, PARTIAL_TEST_SIZE) == 0)) {
		memcpy(test, cs->e.u_string, 16);
		RC4_DECRYPT_REV3(16);
		if (memcmp(test, cs->rev3TestKey, 16) == 0) {
			return true;
		}
	}
	return false;
}


bool runCrackRev2(struct custom_salt *cs, unsigned char *currPW)
{
	uint8_t enckey[16];
	unsigned int currPWLen;
	currPWLen = strlen((const char *)currPW);
	if(currPWLen > 32)
	    currPWLen = 32;
	memcpy(currPW + currPWLen, pad, 32 - currPWLen);
	md5(currPW, cs->ekwlen, enckey);
	/* Algorithm 3.4 reversed */
	if (rc4Match40b(enckey, cs->e.u_string, pad))
		return true;

	return false;
}

/** Start cracking and does not stop until it has either been interrupted by
    a signal or the password either is found or wordlist or charset is exhausted
*/
int runCrack(char *password, struct custom_salt *cs)
{
	bool found = false;
	uint8_t cpw[128];
	memcpy(cpw, cs->encKeyWorkSpace, 128);

	if (strlen(password) < 32)
		strcpy((char*)cpw, password);
	else {
		strncpy((char*)cpw, password, 32);
	}

	if (!cs->workWithUser && !cs->knownPassword) {
		memcpy(cpw, pad, 32);
		if (cs->e.revision == 2)
			found = runCrackRev2_o(cs, cpw);
		else
			found = runCrackRev3_o(cs, cpw);
	} else if (cs->e.revision == 2) {
		if (cs->workWithUser)
			found = runCrackRev2(cs, cpw);
		else
			/** knownPassword */
			found = runCrackRev2_of(cs, cpw);
	} else {
		if (cs->workWithUser)
			found = runCrackRev3(cs, cpw);
		else
			/** knownPassword */
			found = runCrackRev3_of(cs, cpw);
	}
	return found;
}

/** initPDFCrack is doing all the initialisations before you are able to call
    runCrack(). Make sure that you run cleanPDFCrack before you call this
    after the first time.
*/
bool initPDFCrack(struct custom_salt *cs)
{
	uint8_t buf[128];
	unsigned int upwlen;
	EncData *e = &cs->e;
	const uint8_t * upw = cs->userpassword;
	bool user = cs->e.work_with_user;

	cs->ekwlen = initEncKeyWorkSpace(e->revision, e->encryptMetaData,
			e->permissions, e->o_string, e->fileID, e->fileIDLen, cs);
	cs->workWithUser = user;
	setrc4DecryptMethod((unsigned int) e->length);
	if (upw) {
		upwlen = strlen((const char *) upw);
		if (upwlen > 32)
			upwlen = 32;
		memcpy(cs->password_user, upw, upwlen);
		memcpy(cs->password_user + upwlen, pad, 32 - upwlen);
		memcpy(cs->encKeyWorkSpace, cs->password_user, 32);
		cs->knownPassword = true;
	}
	if (cs->e.revision == 2) {
		if (cs->knownPassword) {
			if (!isUserPasswordRev2(cs))
				return false;
			memcpy(cs->encKeyWorkSpace, pad, 32);
		} else {
			memcpy(cs->password_user, pad, 32);
			cs->knownPassword = isUserPasswordRev2(cs);
		}
	} else if (e->revision >= 3) {
		memcpy(buf, pad, 32);
		memcpy(buf + 32, e->fileID, e->fileIDLen);
		md5(buf, 32 + e->fileIDLen, cs->rev3TestKey);
		if (cs->knownPassword) {
			if (!isUserPasswordRev3(cs, cs->encKeyWorkSpace))
				return false;
			memcpy(cs->encKeyWorkSpace, pad, 32);
		} else {
			memcpy(cs->password_user, pad, 32);
			cs->knownPassword = isUserPasswordRev3(cs, cs->encKeyWorkSpace);
		}
	}
	return true;
}

void loadPDFCrack(struct custom_salt *cs)
{
	setrc4DecryptMethod((unsigned int) cs->e.length);
}
