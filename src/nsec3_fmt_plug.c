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
#define MAX_KEYS_PER_CRYPT              128
#define BINARY_SIZE                     20
#define BINARY_ALIGN                    sizeof(uint32_t)
#define NSEC3_MAX_SALT_SIZE             255
// max total length of a domainname in wire format
#define DOMAINNAME_MAX_SIZE             255
#define LABEL_MAX_SIZE                  63
#define SALT_SIZE                       sizeof(struct salt_t)
#define SALT_ALIGN                      sizeof(size_t)
#define FORMAT_TAG                      "$NSEC3$"
#define FORMAT_TAG_LENGTH               (sizeof(FORMAT_TAG) - 1)

struct salt_t {
	size_t salt_length;
	size_t zone_wf_length;
	uint16_t iterations;
	unsigned char salt[NSEC3_MAX_SALT_SIZE];
	unsigned char zone_wf[DOMAINNAME_MAX_SIZE];
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
/* length of the saved label, without the first length field */
static int (*saved_key_length);
static unsigned char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_wf_label)[PLAINTEXT_LENGTH + 2];

static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	saved_key_length = mem_calloc(self->params.max_keys_per_crypt,
	                              sizeof(*saved_key_length));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_wf_label = mem_calloc(self->params.max_keys_per_crypt,
	                            sizeof(*saved_wf_label));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(saved_key_length);
	MEM_FREE(saved_key);
	MEM_FREE(saved_wf_label);
	MEM_FREE(crypt_out);
}

/*
 * convert a sequence of DNS labels to wire format
 * out needs space for labels_length+1 bytes
 * If labels_length == 0, out remains untouched
 */
static void labels_to_wireformat(unsigned char *labels,
                                 int labels_length, unsigned char *out)
{
	int last_dot;
	int i;
	if (labels_length == 0)
		return;
	++out;
	last_dot = labels_length - 1;
	for (i = last_dot ; i >= 0;) {
		if (labels[i] == '.') {
			out[i] = (unsigned char)(last_dot - i);
			last_dot = --i;
		} else {
			out[i] = tolower(labels[i]);
			--i;
		}
	}
	*(--out) = (unsigned char)(last_dot - i);
}

/*
 * parses the DNS zone and converts it to wire format.
 * Similar to labels_to_wireformat(), but expects a final '.' and checks for
 * errors (such as labels longer than LABEL_MAX_SIZE octets)
 * Writes at most DOMAINNAME_MAX_SIZE bytes to zone_wf_out
 */
static size_t parse_zone(char *zone, unsigned char *zone_wf_out)
{
	int last_dot;
	int i;
	int len;
	size_t zone_len = strlen(zone);

	if (zone_len == 0 || zone_len > DOMAINNAME_MAX_SIZE - 1)
		return 0;

	last_dot = zone_len - 1;

	// we always expect the final '.'
	if (zone[last_dot] != '.')
		return 0;

	++zone_wf_out;
	for (i = last_dot ; i >= 0;) {
		if (zone[i] == '.') {
			if ((len = last_dot - i) > LABEL_MAX_SIZE) {
				return 0;
			}
			zone_wf_out[i] = (unsigned char)len;
			last_dot = --i;
		} else {
			zone_wf_out[i] = tolower(zone[i]);
			--i;
		}
	}
	if ((len = last_dot - i) > LABEL_MAX_SIZE) {
		return 0;
	}
	*(--zone_wf_out) = (unsigned char)len;

	return zone_len == 1 ? 1 : zone_len + 1;
}


/* format:
 * $NSEC3$iter$salt$hash$zone
 */
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;
	int i;
	unsigned char zone[DOMAINNAME_MAX_SIZE];
	int iter;
	char salt[NSEC3_MAX_SALT_SIZE * 2 + 1];
	char hash[BINARY_SIZE * 2 + 1];

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
			if (*q != '$' || q - p > BINARY_SIZE * 2 || (q - p) % 2)
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
	out.zone_wf_length =  parse_zone(p, out.zone_wf);

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
	saved_key_length[index] = strnzcpyn((char *)saved_key[index],
	                                    key, sizeof(*saved_key));
	labels_to_wireformat(saved_key[index],
	                     saved_key_length[index], saved_wf_label[index]);
}

static  char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
	return (char *) saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;

	for (i = 0; i < count; ++i) {
		uint16_t iterations = saved_salt.iterations;
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		if (saved_key_length[i] > 0)
			SHA1_Update(&ctx, saved_wf_label[i], saved_key_length[i] + 1);
		SHA1_Update(&ctx, saved_salt.zone_wf, saved_salt.zone_wf_length);
		SHA1_Update(&ctx, saved_salt.salt, saved_salt.salt_length);
		SHA1_Final((unsigned char *)crypt_out[i], &ctx);
		while (iterations--) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, crypt_out[i], BINARY_SIZE);
			SHA1_Update(&ctx, saved_salt.salt, saved_salt.salt_length);
			SHA1_Final((unsigned char *)crypt_out[i], &ctx);
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; ++i) {
		if (((uint32_t *)binary)[0] == crypt_out[i][0])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
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
		init,
		done,
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
		cmp_one,
		cmp_exact
	}
};
#endif  /* plugin */
