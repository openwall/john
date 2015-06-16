/*-
 * Copyright 2013 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>

#undef TEST_PBKDF2_SHA256
#define TEST_SCRYPT
#define TEST_ESCRYPT_ENCODING

#ifdef TEST_PBKDF2_SHA256
#include <assert.h>

#include "sha256.h"

static void
print_PBKDF2_SHA256_raw(const char * passwd, size_t passwdlen,
    const char * salt, size_t saltlen, uint64_t c, size_t dkLen)
{
	uint8_t dk[64];
	int i;

	assert(dkLen <= sizeof(dk));

	/* XXX This prints the strings truncated at first NUL */
	printf("PBKDF2_SHA256(\"%s\", \"%s\", %llu, %lu) =",
	    passwd, salt, (unsigned long long)c, dkLen);

	PBKDF2_SHA256((const uint8_t *) passwd, passwdlen,
	    (const uint8_t *) salt, saltlen, c, dk, dkLen);

	for (i = 0; i < dkLen; i++)
		printf(" %02x", dk[i]);
	puts("");
}

static void
print_PBKDF2_SHA256(const char * passwd, const char * salt, uint64_t c,
    size_t dkLen)
{
	print_PBKDF2_SHA256_raw(passwd, strlen(passwd), salt, strlen(salt), c,
	    dkLen);
}
#endif

#if defined(TEST_SCRYPT) || defined(TEST_ESCRYPT_ENCODING)
#include "crypto_scrypt.h"
#endif

#ifdef TEST_SCRYPT
static void
print_scrypt(const char * passwd, const char * salt,
    uint64_t N, uint32_t r, uint32_t p)
{
	uint8_t dk[64];
	int i;

	printf("scrypt(\"%s\", \"%s\", %llu, %u, %u) =",
	    passwd, salt, (unsigned long long)N, r, p);

	if (crypto_scrypt((const uint8_t *) passwd, strlen(passwd),
	    (const uint8_t *) salt, strlen(salt), N, r, p, dk, sizeof(dk))) {
		puts(" FAILED");
		return;
	}

	for (i = 0; i < sizeof(dk); i++)
		printf(" %02x", dk[i]);
	puts("");
}
#endif

int
main(int argc, char *argv[])
{
#ifdef TEST_PBKDF2_SHA256
	print_PBKDF2_SHA256("password", "salt", 1, 20);
	print_PBKDF2_SHA256("password", "salt", 2, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 20);
	print_PBKDF2_SHA256("password", "salt", 16777216, 20);
	print_PBKDF2_SHA256("passwordPASSWORDpassword",
	    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
	print_PBKDF2_SHA256_raw("pass\0word", 9, "sa\0lt", 5, 4096, 16);
#if 0
	print_PBKDF2_SHA256("password", "salt", 1, 32);
	print_PBKDF2_SHA256("password", "salt", 2, 32);
	print_PBKDF2_SHA256("password", "salt", 4096, 32);
	print_PBKDF2_SHA256("password", "salt", 16777216, 32);
	print_PBKDF2_SHA256("passwordPASSWORDpassword",
	    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40);
	print_PBKDF2_SHA256("password", "salt", 4096, 16);
	print_PBKDF2_SHA256("password", "salt", 1, 20);
	print_PBKDF2_SHA256("password", "salt", 2, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 20);
	print_PBKDF2_SHA256("password", "salt", 16777216, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 25);
	print_PBKDF2_SHA256("password", "salt", 4096, 16);
#endif
#endif

#ifdef TEST_SCRYPT
	print_scrypt("", "", 16, 1, 1);
	print_scrypt("password", "NaCl", 1024, 8, 16);
	print_scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1);
	print_scrypt("pleaseletmein", "SodiumChloride", 1048576, 8, 1);
#endif

#ifdef TEST_ESCRYPT_ENCODING
	{
		uint8_t * setting = escrypt_gensalt(14, 8, 1,
		    (const uint8_t *)"binary data", 12);
		printf("'%s'\n", (char *)setting);
		if (setting) {
			uint8_t * hash = escrypt(
			    (const uint8_t *)"pleaseletmein", setting);
			printf("'%s'\n", (char *)hash);
			if (hash)
				printf("'%s'\n", (char *)escrypt(
				    (const uint8_t *)"pleaseletmein", hash));
		}
		printf("'%s'\n", (char *)escrypt(
		    (const uint8_t *)"pleaseletmein",
		    (const uint8_t *)"$7$C6..../....SodiumChloride"));
	}
#endif

	return 0;
}
