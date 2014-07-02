/* $NetBSD: crypt-sha1.c,v 1.8 2013/08/28 17:47:07 riastradh Exp $ */

/*
 * Copyright (c) 2004, Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// https://pythonhosted.org/passlib/lib/passlib.hash.sha1_crypt.html
// http://cvsweb.netbsd.org/bsdweb.cgi/src/lib/libcrypt/crypt-sha1.c

#if AC_BUILT
#include "autoconfig.h"
#endif

#define SHA1_MAGIC "$sha1$"
#define SHA1_SIZE 20

#include "sha.h"
#include <stdlib.h>
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "jumbo.h"
#include "gladman_hmac.h"

/*
 * The default iterations - should take >0s on a fast CPU
 * but not be insane for a slow CPU.
 */
#ifndef CRYPT_SHA1_ITERATIONS
#define CRYPT_SHA1_ITERATIONS 24680
#endif
/*
 * Support a reasonably? long salt.
 */
#ifndef CRYPT_SHA1_SALT_LENGTH
#define CRYPT_SHA1_SALT_LENGTH 64
#endif

/*
 * UNIX password using hmac_sha1
 * This is PBKDF1 from RFC 2898, but using hmac_sha1.
 *
 * The format of the encrypted password is:
 * $<tag>$<iterations>$<salt>$<digest>
 *
 * where:
 * 	<tag>		is "sha1"
 *	<iterations>	is an unsigned int identifying how many rounds
 * 			have been applied to <digest>.  The number
 * 			should vary slightly for each password to make
 * 			it harder to generate a dictionary of
 * 			pre-computed hashes.  See crypt_sha1_iterations.
 * 	<salt>		up to 64 bytes of random data, 8 bytes is
 * 			currently considered more than enough.
 *	<digest>	the hashed password.
 *
 * NOTE:
 * To be FIPS 140 compliant, the password which is used as a hmac key,
 * should be between 10 and 20 characters to provide at least 80bits
 * strength, and avoid the need to hash it before using as the
 * hmac key.
 */
void internal_crypt_sha1(const char *pw, const char *salt, unsigned char *inout)
{
	static const char *magic = SHA1_MAGIC;
	unsigned char hmac_buf[SHA1_SIZE];
	const char *sp;
	char *ep;
	int sl;
	int pl;
	int dl;
	unsigned int iterations;
	unsigned int i;

	// Salt format is $<tag>$<iterations>$salt[$]
	// XXX Move some of the validation code to valid()
	if (!strncmp(salt, magic, strlen(magic))) {
		salt += strlen(magic);
		/* and get the iteration count */
		iterations = strtoul(salt, &ep, 10);
		if (*ep != '$') {
			printf("[!] bad salt %s found, exiting!\n", salt);
			exit(-1);
		}
		salt = ep + 1;	/* skip over the '$' */
	} else {
		printf("[!] bad salt %s found, exiting!\n", salt);
		exit(-1);
	}

	/* It stops at the next '$', max CRYPT_SHA1_ITERATIONS chars */
	for (sp = salt; *sp && *sp != '$' && sp < (salt + CRYPT_SHA1_ITERATIONS); sp++)
		continue;

	/* Get the length of the actual salt */
	sl = sp - salt;
	pl = strlen(pw);

	// Prime the pump with <salt><magic><iterations>
	dl = snprintf((char*)inout, 32, "%.*s%s%u", sl, salt, magic, iterations);

	// Then hmac using <pw> as key, and repeat...
	hmac_sha1((unsigned char*)pw, pl, inout, dl, hmac_buf, SHA1_SIZE);
	for (i = 1; i < iterations; i++) {
		hmac_sha1((unsigned char*)pw, pl, hmac_buf, SHA1_SIZE, hmac_buf, SHA1_SIZE);
	}

	// Now output
	memcpy(inout, hmac_buf, SHA1_SIZE);
}
