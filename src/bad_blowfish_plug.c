/* This file is part of the KDE project
   Copyright (C) 2001 George Staikos <staikos@kde.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this library; see the file COPYING.LIB.  If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "arch.h"

#include "bad_blowfish.h"

#define true 		1
#define false 		0

// BUG: output of this code matches that of OpenSSL running on LE when Q_BYTE_ORDER is 0
#if ARCH_LITTLE_ENDIAN
#define Q_BYTE_ORDER 	1 /* Use Little Endian order */
#else
#define Q_BYTE_ORDER 	0
#endif

#if Q_BYTE_ORDER == Q_BIG_ENDIAN
#define shuffle(x) do {				\
	uint32_t r = x;				\
		x  = (r & 0xff000000) >> 24;	\
		x |= (r & 0x00ff0000) >>  8;	\
		x |= (r & 0x0000ff00) <<  8;	\
		x |= (r & 0x000000ff) << 24;	\
	} while (0)
#endif

void BlowFish_constructor(struct BlowFish *bf)
{
	bf->_blksz 	= -1;
	bf->_blksz	= 8;
	bf->_init	= false;
}


int BlowFish_init(struct BlowFish *bf)
{
	int i, k, j = 0;
	uint32_t datal = 0;
	uint32_t datar = 0;
	uint32_t data = 0;

	/* Initialize the sboxes */
	for (i = 0; i < 256; i++) {
		bf->_S[0][i] = ks0[i];
		bf->_S[1][i] = ks1[i];
		bf->_S[2][i] = ks2[i];
		bf->_S[3][i] = ks3[i];
	}

	/* Update the sboxes and pbox. */
	for (i = 0; i < 18; i++) {
		data = 0;
		for (k = 0; k < 4; ++k) {
			data = (data << 8) | ((unsigned char *)(bf->_key))[j++];
			if (j >= bf->_keylen / 8) {
				j = 0;
			}
		}
		bf->_P[i] = P[i] ^ data;
	}

	for (i = 0; i < 18; i += 2) {
		BlowFish_encipher(bf, &datal, &datar);
		bf->_P[i] = datal;
		bf->_P[i+1] = datar;
	}

	for (j = 0; j < 4; j++) {
		for (i = 0; i < 256; i += 2) {
			BlowFish_encipher(bf, &datal, &datar);
			bf->_S[j][i] = datal;
			bf->_S[j][i+1] = datar;
		}
	}

	/* Nice code from gpg's implementation... */
	/* Check to see if the key is weak and return error if so */
	for (i = 0; i < 255; i++) {
		for (j = i + 1; j < 256; j++) {
			if ((bf->_S[0][i] == bf->_S[0][j]) || (bf->_S[1][i] == bf->_S[1][j]) ||
					(bf->_S[2][i] == bf->_S[2][j]) || (bf->_S[3][i] == bf->_S[3][j])) {
				return false;
			}
		}
	}

	bf->_init = true;

	return true;
}


int BlowFish_keyLen(void)
{
	return 448;
}


int BlowFish_variableKeyLen(void)
{
	return true;
}


int BlowFish_readyToGo(struct BlowFish *bf)
{
	return bf->_init;
}


int BlowFish_setKey(struct BlowFish *bf, void *key, int bitlength)
{
	if (bitlength <= 0 || bitlength > 448 || bitlength % 8 != 0) {
		return false;
	}

	memcpy(bf->_key, key, bitlength / 8);
	bf->_keylen = bitlength;

	return BlowFish_init(bf);
}


int BlowFish_encrypt(struct BlowFish *bf, void *block, int len)
{
	int i;
	uint32_t *d = (uint32_t *)block;

	if (!bf->_init || len % bf->_blksz != 0) {
		return -1;
	}

	for (i = 0; i < len / bf->_blksz; i++) {
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
		shuffle(*d);
		shuffle(*(d + 1));
#endif
		BlowFish_encipher(bf, d, d + 1);
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
		shuffle(*d);
		shuffle(*(d + 1));
#endif
		d += 2;
	}

	return len;
}


int BlowFish_decrypt(struct BlowFish *bf, void *block, int len)
{
	int i;
	uint32_t *d = (uint32_t *)block;

	if (!bf->_init || len % bf->_blksz != 0) {
		return -1;
	}

	for (i = 0; i < len / bf->_blksz; i++) {
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
		shuffle(*d);
		shuffle(*(d + 1));
#endif
		BlowFish_decipher(bf, d, d + 1);
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
		shuffle(*d);
		shuffle(*(d + 1));
#endif
		d += 2;
	}

	return len;
}


uint32_t BlowFish_F(struct BlowFish *bf, uint32_t x)
{
	unsigned short a, b, c, d;
	uint32_t y;

	d = x & 0x000000ff;
	x >>= 8;
	c = x & 0x000000ff;
	x >>= 8;
	b = x & 0x000000ff;
	x >>= 8;
	a = x & 0x000000ff;

	y = bf->_S[0][a] + bf->_S[1][b];
	y ^= bf->_S[2][c];
	y += bf->_S[3][d];

	return y;
}


void BlowFish_encipher(struct BlowFish *bf, uint32_t *xl, uint32_t *xr)
{
	int i;
	uint32_t Xl = *xl, Xr = *xr, temp;

	for (i = 0; i < 16; ++i) {
		Xl ^= bf->_P[i];
		Xr ^= BlowFish_F(bf, Xl);
		temp = Xl; Xl = Xr; Xr = temp;
	}

	temp = Xl; Xl = Xr; Xr = temp;

	Xr ^= bf->_P[16];
	Xl ^= bf->_P[17];

	*xl = Xl;
	*xr = Xr;
}


void BlowFish_decipher(struct BlowFish *bf, uint32_t *xl, uint32_t *xr)
{
	int i;
	uint32_t Xl = *xl, Xr = *xr, temp;

	for (i = 17; i > 1; --i) {
		Xl ^= bf->_P[i];
		Xr ^= BlowFish_F(bf, Xl);
		temp = Xl; Xl = Xr; Xr = temp;
	}

	temp = Xl; Xl = Xr; Xr = temp;

	Xr ^= bf->_P[1];
	Xl ^= bf->_P[0];

	*xl = Xl;
	*xr = Xr;
}


void CipherBlockChain_constructor(struct CipherBlockChain *cbc, struct BlowFish *bf)
{
	cbc->_next 	= 0L;
	cbc->_register 	= 0L;
	cbc->_len 	= -1;
	cbc->_reader 	= cbc->_writer = 0L;
	cbc->_cipher 	= bf;
	if (cbc->_cipher) {
		cbc->_cipher->_blksz = 8;
	}
}

int CipherBlockChain_setKey(struct CipherBlockChain *cbc, void *key, int bitlength) {
	if (cbc->_cipher) {
		return BlowFish_setKey(cbc->_cipher, key, bitlength);
	}
	return false;
}


int CipherBlockChain_keyLen(struct CipherBlockChain *cbc)
{
	if (cbc->_cipher) {
		return true;
	}
	return -1;
}


int CipherBlockChain_variableKeyLen(struct CipherBlockChain *cbc)
{
	if (cbc->_cipher) {
		return true;
	}
	return false;
}

int CipherBlockChain_encrypt(struct CipherBlockChain *cbc, void *block, int len)
{
	if (cbc->_cipher && !cbc->_reader) {
		int i, rc;
		char *tb;

		cbc->_writer |= 1;

		if (!cbc->_register) {
			cbc->_register = malloc(len);
			/* TODO: return value of malloc */
			cbc->_len = len;
			memset(cbc->_register, 0, len);
		} else if (len > cbc->_len) {
			return -1;
		}

		/* This might be optimizable */
		tb = (char *)block;
		for (i = 0; i < len; i++) {
			tb[i] ^= ((char *)(cbc->_register))[i];
		}

		rc = BlowFish_encrypt(cbc->_cipher, block, len);

		if (rc != -1) {
			memcpy(cbc->_register, block, len);
		}

		return rc;
	}
	return -1;
}


int CipherBlockChain_decrypt(struct CipherBlockChain *cbc, void *block, int len)
{
	if (cbc->_cipher && !cbc->_writer) {
		int i, rc;
		cbc->_reader |= 1;

		if (!cbc->_register) {
			cbc->_register = malloc(len);
			cbc->_len = len;
			memset(cbc->_register, 0, len);
		} else if (len > cbc->_len) {
			return -1;
		}

		if (!cbc->_next)
			cbc->_next = malloc(len);
		memcpy(cbc->_next, block, cbc->_len);

		rc = BlowFish_decrypt(cbc->_cipher, block, len);

		if (rc != -1) {
			/* This might be optimizable */
			char *tb = (char *)block;
			for (i = 0; i < len; i++) {
				tb[i] ^= ((char *)(cbc->_register))[i];
			}
		}

		/* removed buffer switch code */
		if(cbc->_next)
			free(cbc->_next);
		if(cbc->_register)
			free(cbc->_register);
		return rc;
	}
	return -1;
}
