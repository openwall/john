/*
 * DNSSEC NSEC3 hash cracker. Developed as part of the nsec3map DNS zone
 * enumerator project (https://github.com/anonion0/nsec3map).
 *
 * This software is Copyright (c) 2016 Ralf Sager <nsec3map at 3fnc.org>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Some of this code was inspired by sha1_gen_fmt_plug.c by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_nsec3;
#elif FMT_REGISTERS_H
john_register_one(&fmt_nsec3);
#else

#include <ctype.h>
#include <string.h>
#include <stdint.h>

#include "sha.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL                    "nsec3"
#define FORMAT_NAME                     "DNSSEC NSEC3"
#define ALGORITHM_NAME                  "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                0x107
#define PLAINTEXT_LENGTH                125
#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              1
#define BINARY_SIZE                     20
#define BINARY_ALIGN                    sizeof(uint32_t)
#define NSEC3_MAX_SALT_SIZE             255
// max total length of a domainname in wire format
#define DOMAINNAME_MAX_SIZE             255
#define HASH_LENGTH                     20
#define SALT_SIZE                       sizeof(struct salt_t)
#define SALT_ALIGN                      sizeof(size_t)
#define FORMAT_TAG                      "$NSEC3$"
#define FORMAT_TAG_LENGTH               (sizeof(FORMAT_TAG) - 1)

struct salt_t {
	size_t salt_length;
	size_t zone_length;
	uint16_t iterations;
	unsigned char salt[NSEC3_MAX_SALT_SIZE];
	unsigned char zone_wf[DOMAINNAME_MAX_SIZE + 1];
};

static struct fmt_tests tests[] = {
	{ "$NSEC3$100$4141414141414141$8c2d583acbe22616c69bb457e0c2111ced0a6e77$example.com.", "www" },
	{ "$NSEC3$100$42424242$8fb38d13720815ed5b5fcefd973e0d7c3906ab02$example.com.", "mx" },
	{ "$NSEC3$0$$879ffda85c7cb08df1f93fb040b90a6869b205f1$example.com.", "ns1" },
	{ "$NSEC3$0$$c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4$example.com.", "" },
	{ "$NSEC3$1$$4ff4345669d70dc0ab7e76c230d97de3eff75059$example.com.", "" },
	{ "$NSEC3$0$42$e2d9498245ee0768923c1cd523959f18acbf11e7$example.com.", "ns2" },
	{ "$NSEC3$1$42$26d83a84e2dff76c714f4e76b60355adeb045bbe$example.com.", "cdn" },
	{ NULL }
};


static struct salt_t saved_salt;
/* length of the saved label, without the length field */
static int saved_key_length;
static unsigned char saved_key[PLAINTEXT_LENGTH + 1];
static unsigned char saved_wf_label[PLAINTEXT_LENGTH + 2];

static SHA_CTX sha_ctx;
static uint32_t crypt_out[5];

static void convert_label_wf(void)
{
	int last_dot = saved_key_length - 1;
	int i;
	unsigned char *out = saved_wf_label;
	if (saved_key_length == 0)
		return;
	++out;
	for (i = last_dot ; i >= 0;) {
		if (saved_key[i] == '.') {
			out[i] = (unsigned char)(last_dot - i);
			last_dot = --i;
		} else {
			out[i] = tolower(saved_key[i]);
			--i;
		}
	}
	*(--out) = (unsigned char)(last_dot - i);
}

static size_t parse_zone(char *zone, unsigned char *zone_wf_out)
{
	char *lbl_end, *lbl_start;
	unsigned int lbl_len;
	unsigned int index = 0;
	unsigned int zone_len = strlen(zone);

	/* TODO: unvis */
	if (zone_len == 0) {
		return 0;
	} else if (zone_len > DOMAINNAME_MAX_SIZE) {
		return 0;
	}

	lbl_end = strchr(zone, '.');
	lbl_start = zone;
	while (lbl_end != NULL) {
		lbl_len = lbl_end - lbl_start;
		zone_wf_out[index] = (unsigned char) lbl_len;
		if (lbl_len > 0) {
			memcpy(&zone_wf_out[++index], lbl_start, lbl_len);
		}
		index += lbl_len;
		lbl_start = lbl_end + 1;
		if (lbl_start - zone == zone_len) {
			zone_wf_out[index] = 0;
			break;
		} else {
			lbl_end = strchr(lbl_start, '.');
		}
	}
	if (lbl_end == NULL)
		return 0;
	return index + 1;
}


/* format:
 * $NSEC3$iter$salt$hash$zone
 */

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;
	int i;
	unsigned char zone[DOMAINNAME_MAX_SIZE + 1];
	int iter;
	char salt[NSEC3_MAX_SALT_SIZE * 2 + 1];
	char hash[HASH_LENGTH * 2 + 1];

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	p = ciphertext;
	for (i = 0; i < 4; ++i) {
		p = strchr(p, '$');
		if (p == NULL || *(++p) == 0)
			return 0;
		switch (i) {
		case 0:
			continue;
		case 1:
			/* iterations */
			iter = atoi(p);
			if (iter < 0 || iter > UINT16_MAX)
				return 0;
			break;
		case 2:
			/*  salt */
			q = p;
			while (atoi16[ARCH_INDEX(*q)] != 0x7F)
				++q;
			if (*q != '$' || q - p > NSEC3_MAX_SALT_SIZE * 2 || (q - p) % 2)
				return 0;
			strncpy(salt, p, q - p);
			salt[q - p] = 0;
			if (q - p > 0 && !ishexlc(salt))
				return 0;
			break;
		case 3:
			/* hash */
			q = p;
			while (atoi16[ARCH_INDEX(*q)] != 0x7F)
				++q;
			if (*q != '$' || q - p > HASH_LENGTH * 2 || (q - p) % 2)
				return 0;
			strncpy(hash, p, q - p);
			hash[q - p] = 0;
			if (!ishexlc(hash))
				return 0;
			p = q + 1;
			break;
		}
	}
	/* zone */
	if (*p == 0)
		return 0;
	if (parse_zone(p, zone) == 0) {
		return 0;
	}
	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = ciphertext;
	for (i = 0; i < 4; ++i) {
		p = strchr(p, '$') + 1;
	}

	for (i = 0; i < BINARY_SIZE; ++i) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
		         atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static void *salt(char *ciphertext)
{
	static struct salt_t out;
	unsigned int salt_length;
	int i;
	char *p, *q;

	memset(&out, 0, sizeof(out));
	p = ciphertext;
	for (i = 0; i < 2; ++i)
		p = strchr(p, '$') + 1;
	out.iterations = (uint16_t) atoi(p);

	p = strchr(p, '$') + 1;
	q = strchr(p, '$');
	salt_length = q - p;
	for (i = 0; i < salt_length; i += 2) {
		out.salt[i / 2] = (atoi16[ARCH_INDEX(*p)] << 4 |
		                   atoi16[ARCH_INDEX(p[1])]);
		p += 2;
	}
	out.salt_length = (unsigned char)((salt_length) / 2);

	p = strchr(q + 1, '$') + 1;
	out.zone_length =  parse_zone(p, out.zone_wf);

	return &out;
}

static int salt_hash(void *salt)
{
	unsigned int hash = 0;
	int i;

	for (i = 0; i < SALT_SIZE; ++i) {
		hash <<= 1;
		hash += ((unsigned char *)salt)[i];
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}
	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	saved_key_length = strnzcpyn((char *)saved_key, key, sizeof(saved_key));
	convert_label_wf();
}

static  char *get_key(int index)
{
	saved_key[saved_key_length] = 0;
	return (char *) saved_key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	uint16_t iterations = saved_salt.iterations;
	size_t salt_length =  saved_salt.salt_length;

	SHA1_Init(&sha_ctx);
	if (saved_key_length > 0)
		SHA1_Update(&sha_ctx, saved_wf_label, saved_key_length + 1);
	SHA1_Update(&sha_ctx, saved_salt.zone_wf, saved_salt.zone_length);
	SHA1_Update(&sha_ctx, saved_salt.salt, salt_length);
	SHA1_Final((unsigned char *)crypt_out, &sha_ctx);
	while (iterations--) {
		SHA1_Init(&sha_ctx);
		SHA1_Update(&sha_ctx, crypt_out, BINARY_SIZE);
		SHA1_Update(&sha_ctx, saved_salt.salt, salt_length);
		SHA1_Final((unsigned char *)crypt_out, &sha_ctx);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_nsec3 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_8_BIT | FMT_HUGE_INPUT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		{ FORMAT_TAG },
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};
#endif  /* plugin */
