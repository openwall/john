/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2007 Roy Hills,
 * NTA Monitor Ltd.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id: psk-crack.h 9884 2007-01-14 19:05:39Z rsh $
 *
 * psk-crack.h -- Header file for psk-crack
 *
 * Author:	Roy Hills
 * Date:	21 November 2006
 */

#ifndef PSK_CRACK_H
#define PSK_CRACK_H 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>

#include "misc.h"	// error()
#include "md5.h"
#include "sha.h"
#include "memory.h"
/* Defines */

#define MAXLINE 255		/* Max line length for input files */
#define MAXLEN 4096
#define HASH_TYPE_MD5 1
#define HASH_TYPE_SHA1 2
#define MD5_HASH_LEN 16
#define SHA1_HASH_LEN 20
#define PSK_REALLOC_COUNT 10	/* Number of PSK entries to allocate */

/* Structures */

/* PSK parameter entry */
typedef struct {
	unsigned char skeyid_data[MAXLEN];	/* Data for SKEYID calculation */
	unsigned char hash_r_data[MAXLEN];	/* Data for HASH_R calculation (must hold SHA1 in hex) */
	unsigned char hash_r[20];	/* HASH_R received from server */
	char hash_r_hex[44];	/* Server HASH_R as hex for display */
	char nortel_user[64];	/* User for nortel cracking, or NULL */
	size_t skeyid_data_len;	/* Length of skeyid_data field */
	size_t hash_r_data_len;	/* Length of hash_r_data field */
	size_t hash_r_len;	/* Length of hash_r field */
	int hash_type;		/* Hash algorithm used for hmac */
	int isnortel;
} psk_entry;


/* Functions */

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
static unsigned int hstr_i(const char *cptr)
{
	unsigned int i;
	unsigned int j = 0;
	int k;

	for (k = 0; k < 2; k++) {
		i = *cptr++ - '0';
		if (9 < i)
			i -= 7;
		j <<= 4;
		j |= (i & 0x0f);
	}
	return j;
}

/*
 *	hex2data -- Convert hex string to binary data
 *
 *	Inputs:
 *
 *	string		The string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data.
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the input string is not even, the function will return NULL and
 *	set data_len to 0.
 */

static unsigned char *hex2data(const char *string, size_t * data_len)
{
	unsigned char *data;
	unsigned char *cp;
	unsigned i;
	size_t len;

	if (strlen(string) % 2) {	/* Length is odd */
		*data_len = 0;
		return NULL;
	}

	len = strlen(string) / 2;
	data = mem_alloc(len);
	cp = data;
	for (i = 0; i < len; i++)
		*cp++ = hstr_i(&string[i * 2]);
	*data_len = len;
	return data;
}

/*
 *	hmac_md5 -- Calculate HMAC-MD5 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-MD5 digest
 *
 *	Returns:
 *
 *	The HMAC-MD5 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL MD5 functions or the
 *	built-in MD5 functions depending on whether HAVE_LIBCRYPTO is defined.
 *	This is faster than calling OpenSSL "HMAC" directly.
 */
inline static unsigned char *hmac_md5(unsigned char *text,
    size_t text_len, unsigned char *key, size_t key_len, unsigned char *md)
{
	static unsigned char m[16];
	MD5_CTX context;
	unsigned char k_ipad[65];	/* inner padding -  key XORd with ipad */
	unsigned char k_opad[65];	/* outer padding -  key XORd with opad */
	unsigned char tk[16];
	int i;

	if (md == NULL)		/* Use static storage if no buffer specified */
		md = m;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		MD5_CTX tctx;

		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);

		key = tk;
		key_len = 16;
	}
	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof k_ipad);
	memset(k_opad, 0x5c, sizeof k_opad);

	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}
	/*
	 * perform inner MD5
	 */
	MD5_Init(&context);	/* init context for 1st pass */
	MD5_Update(&context, k_ipad, 64);	/* start with inner pad */
	MD5_Update(&context, text, text_len);	/* then text of datagram */
	MD5_Final(md, &context);	/* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	MD5_Init(&context);	/* init context for 2nd pass */
	MD5_Update(&context, k_opad, 64);	/* start with outer pad */
	MD5_Update(&context, md, 16);	/* then results of 1st hash */
	MD5_Final(md, &context);	/* finish up 2nd pass */

	return md;
}

/*
 *	hmac_sha1 -- Calculate HMAC-SHA1 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-SHA1 digest
 *
 *	Returns:
 *
 *	The HMAC-SHA1 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL SHA1 functions or the
 *	built-in SHA1 functions depending on whether HAVE_LIBCRYPTO is defined.
 *	This is faster than calling OpenSSL "HMAC" directly.
 */
inline static unsigned char *hmac_sha1(const unsigned char *text,
    size_t text_len, const unsigned char *key, size_t key_len,
    unsigned char *md)
{
	static unsigned char m[20];
	SHA_CTX context;
	unsigned char k_ipad[65];	/* inner padding -  key XORd with ipad */
	unsigned char k_opad[65];	/* outer padding -  key XORd with opad */
	unsigned char tk[20];
	int i;

	if (md == NULL)		/* Use static storage if no buffer specified */
		md = m;

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {
		SHA_CTX tctx;

		SHA1_Init(&tctx);
		SHA1_Update(&tctx, key, key_len);
		SHA1_Final(tk, &tctx);
		key = tk;
		key_len = 20;
	}
	/*
	 * the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof k_ipad);
	memset(k_opad, 0x5c, sizeof k_opad);

	/* XOR key with ipad and opad values */
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}
	/*
	 * perform inner SHA1
	 */
	SHA1_Init(&context);	/* init context for 1st pass */
	SHA1_Update(&context, k_ipad, 64);	/* start with inner pad */
	SHA1_Update(&context, text, text_len);	/* then text of datagram */
	SHA1_Final(md, &context);	/* finish up 1st pass */
	/*
	 * perform outer SHA1
	 */
	SHA1_Init(&context);	/* init context for 2nd pass */
	SHA1_Update(&context, k_opad, 64);	/* start with outer pad */
	SHA1_Update(&context, md, 20);	/* then results of 1st hash */
	SHA1_Final(md, &context);	/* finish up 2nd pass */

	return md;
}

/*
 *	load_psk_params -- Load PSK parameters from data file
 *
 *	Inputs:
 *
 *	filename	The name of the data file
 *	nortel_user	The username for Nortel PSK cracking, or NULL
 *
 *	Returns:
 *
 *	The number of PSK parameters successfully loaded into the list.
 *
 *	This function loads the pre-shared key parameters from the input
 *	data file into the psk parameters list, which is an array of structs.
 *
 *	The array is created dynamically with malloc and realloc, as we don't
 *	know in advance how many PSK entries there will be in the file.
 */
static void
load_psk_params(const char *ciphertext, const char *nortel_user,
    psk_entry * pe)
{
	int n;			/* Number of fields read by sscanf() */
	unsigned char *cp;
	unsigned char *skeyid_data;	/* Data for SKEYID hash */
	size_t skeyid_data_len;	/* Length of skeyid data */
	unsigned char *hash_r_data;	/* Data for HASH_R hash */
	size_t hash_r_data_len;	/* Length of hash_r */
	char g_xr_hex[MAXLEN + 1];	/* Individual PSK params as hex */
	char g_xi_hex[MAXLEN + 1];
	char cky_r_hex[MAXLEN + 1];
	char cky_i_hex[MAXLEN + 1];
	char sai_b_hex[MAXLEN + 1];
	char idir_b_hex[MAXLEN + 1];
	char ni_b_hex[MAXLEN + 1];
	char nr_b_hex[MAXLEN + 1];
	char hash_r_hex[44];
	unsigned char *g_xr;	/* Individual PSK params as binary */
	unsigned char *g_xi;
	unsigned char *cky_r;
	unsigned char *cky_i;
	unsigned char *sai_b;
	unsigned char *idir_b;
	unsigned char *ni_b;
	unsigned char *nr_b;
	size_t g_xr_len;	/* Lengths of binary PSK params */
	size_t g_xi_len;
	size_t cky_r_len;
	size_t cky_i_len;
	size_t sai_b_len;
	size_t idir_b_len;
	size_t ni_b_len;
	size_t nr_b_len;
	n = sscanf(ciphertext,
	    "%[^*]*%[^*]*%[^*]*%[^*]*%[^*]*%[^*]*%[^*]*%[^*]*%[^*\r\n]",
	    g_xr_hex, g_xi_hex, cky_r_hex, cky_i_hex, sai_b_hex,
	    idir_b_hex, ni_b_hex, nr_b_hex, hash_r_hex);
	if (n != 9) {
		fprintf(stderr, "ERROR: Format error in PSK data file\n");
		error();
	}
	memset(pe, 0, sizeof(*pe));
/*
 *	Convert hex to binary representation, and construct SKEYID
 *	and HASH_R data.
 */
	g_xr = hex2data(g_xr_hex, &g_xr_len);
	g_xi = hex2data(g_xi_hex, &g_xi_len);
	cky_r = hex2data(cky_r_hex, &cky_r_len);
	cky_i = hex2data(cky_i_hex, &cky_i_len);
	sai_b = hex2data(sai_b_hex, &sai_b_len);
	idir_b = hex2data(idir_b_hex, &idir_b_len);
	ni_b = hex2data(ni_b_hex, &ni_b_len);
	nr_b = hex2data(nr_b_hex, &nr_b_len);

	/* print_hex(g_xr, g_xr_len);
	print_hex(g_xi, g_xi_len);
	print_hex(cky_r, cky_r_len);
	print_hex(cky_i, cky_i_len);
	print_hex(sai_b, sai_b_len);
	print_hex(idir_b, idir_b_len);
	print_hex(ni_b, ni_b_len);
	print_hex(nr_b, nr_b_len); */

/* skeyid_data = ni_b | nr_b */
	skeyid_data_len = ni_b_len + nr_b_len;
	skeyid_data = mem_alloc(skeyid_data_len);
	cp = skeyid_data;
	memcpy(cp, ni_b, ni_b_len);
	cp += ni_b_len;
	memcpy(cp, nr_b, nr_b_len);
	MEM_FREE(ni_b);
	MEM_FREE(nr_b);

/* hash_r_data = g_xr | g_xi | cky_r | cky_i | sai_b | idir_b */
	hash_r_data_len = g_xr_len + g_xi_len + cky_r_len + cky_i_len +
	    sai_b_len + idir_b_len;
	hash_r_data = mem_alloc(hash_r_data_len);
	cp = hash_r_data;
	memcpy(cp, g_xr, g_xr_len);
	cp += g_xr_len;
	memcpy(cp, g_xi, g_xi_len);
	cp += g_xi_len;
	memcpy(cp, cky_r, cky_r_len);
	cp += cky_r_len;
	memcpy(cp, cky_i, cky_i_len);
	cp += cky_i_len;
	memcpy(cp, sai_b, sai_b_len);
	cp += sai_b_len;
	memcpy(cp, idir_b, idir_b_len);
	MEM_FREE(g_xr);
	MEM_FREE(g_xi);
	MEM_FREE(cky_r);
	MEM_FREE(cky_i);
	MEM_FREE(sai_b);
	MEM_FREE(idir_b);
/*
 *	Store the PSK parameters in the current psk list entry.
 */
	memcpy(pe->skeyid_data, skeyid_data, skeyid_data_len);
	pe->skeyid_data_len = skeyid_data_len;
	memcpy(pe->hash_r_data, hash_r_data, hash_r_data_len);
	pe->hash_r_data_len = hash_r_data_len;
	{
		unsigned char *c = hex2data(hash_r_hex, &pe->hash_r_len);
		memcpy(pe->hash_r, c, pe->hash_r_len);
		MEM_FREE(c);
	}
	strncpy(pe->hash_r_hex, hash_r_hex, sizeof(pe->hash_r_hex));
	if (nortel_user)
		strcpy(pe->nortel_user, nortel_user);
/*
 *	Determine hash type based on the length of the hash, and
 *	store this in the current psk list entry.
 */
	if (pe->hash_r_len == MD5_HASH_LEN) {
		pe->hash_type = HASH_TYPE_MD5;
	} else if (pe->hash_r_len == SHA1_HASH_LEN) {
		pe->hash_type = HASH_TYPE_SHA1;
	} else {
		//err_msg("Cannot determine hash type from %u byte HASH_R",
		//      pe->hash_r_len);
	}
	MEM_FREE(skeyid_data);
	MEM_FREE(hash_r_data);
}

/*
 *	compute_hash	-- Compute the hash given a candidate password
 *
 *	Inputs:
 *
 *	psk_params	Pointer to PSK params structure
 *	password	The candidate password
 *
 *	Returns:
 *
 *	Pointer to the computed hash.
 *
 *	This function calculates a hash given the PSK parameters and
 *	a candidate password.
 *
 *	The standard process used to calculate the hash is detailed in
 *	RFC 2409.  The hash used by Nortel Contivity systems use a different,
 *	proprietary, method.
 *
 *	In all cases, the calculation of the hash is a two-stage process:
 *
 *	a) Calculate SKEYID using some of the PSK parameters and the password;
 *	b) Calculate HASH_R using SKEYID and the other PSK parameters.
 *
 */
inline static void compute_hash(const psk_entry * psk_params,
    char *password, unsigned char *hash_r)
{
	size_t password_len = strlen(password);
	unsigned char skeyid[SHA1_HASH_LEN];
/*
 *	Calculate SKEYID
 */
	if (psk_params->nortel_user[0] == 0) {	/* RFC 2409 SKEYID calculation */
		if (psk_params->hash_type == HASH_TYPE_MD5) {
			hmac_md5((unsigned char*)psk_params->skeyid_data,
			    psk_params->skeyid_data_len,
			    (unsigned char *) password, password_len, skeyid);
		} else {	/* SHA1 */
			hmac_sha1(psk_params->skeyid_data,
			    psk_params->skeyid_data_len,
			    (unsigned char *) password, password_len, skeyid);
		}
	} else {		/* Nortel proprietary SKEYID calculation */
		unsigned char nortel_psk[SHA1_HASH_LEN];
		unsigned char nortel_pwd_hash[SHA1_HASH_LEN];

		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, password, password_len);
		SHA1_Final(nortel_pwd_hash, &ctx);

		hmac_sha1((unsigned char *) psk_params->nortel_user,
		    strlen(psk_params->nortel_user), nortel_pwd_hash,
		    SHA1_HASH_LEN, nortel_psk);
		if (psk_params->hash_type == HASH_TYPE_MD5) {
			hmac_md5((unsigned char*)psk_params->skeyid_data,
			    psk_params->skeyid_data_len, nortel_psk,
			    SHA1_HASH_LEN, skeyid);
		} else {	/* SHA1 */
			hmac_sha1(psk_params->skeyid_data,
			    psk_params->skeyid_data_len, nortel_psk,
			    SHA1_HASH_LEN, skeyid);
		}
	}
/*
 *	Calculate HASH_R
 */
	if (psk_params->hash_type == HASH_TYPE_MD5) {
		hmac_md5((unsigned char*)psk_params->hash_r_data, psk_params->hash_r_data_len,
		    skeyid, psk_params->hash_r_len, hash_r);
	} else {		/* SHA1 */
		hmac_sha1(psk_params->hash_r_data, psk_params->hash_r_data_len,
		    skeyid, psk_params->hash_r_len, hash_r);
	}
}

#endif				/* PSK_CRACK_H */
