#ifndef JOHN_RAR5_COMMON_H
#define JOHN_RAR5_COMMON_H

#define SIZE_SALT50 16
#define SIZE_PSWCHECK 8
#define SIZE_PSWCHECK_CSUM 4
#define SIZE_INITV 16

#define FORMAT_TAG  		"$rar5$"
#define TAG_LENGTH  		(sizeof(FORMAT_TAG)-1)

#define BINARY_SIZE		SIZE_PSWCHECK

#define SHA256_DIGEST_SIZE	32
#define MaxSalt			64

#include "formats.h"

#define  Min(x,y) (((x)<(y)) ? (x):(y))

static struct fmt_tests tests[] = {
	{"$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$15$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653", "password"},
	/* "-p mode" test vectors */
	{"$rar5$16$92373e6493111cf1f2443dcd82122af9$15$011a3192b2f637d43deba9d0a08b7fa0$8$6862fcec47944d14", "openwall"},
	{"$rar5$16$92373e6493111cf1f2443dcd82122af9$15$a3af5246dd171431ac823cc79567e77e$8$16015b087c86964b", "password"},
	/* from CMIYC 2014 contest */
	{"$rar5$16$ed9bd88cc649bd06bfd7dc418fcf5fbd$15$21771e718815d6f23073ea294540ce94$8$92c584bec0ad2979", "rar"}, // 1798815729.rar
	{"$rar5$16$ed9bd88cc649bd06bfd7dc418fcf5fbd$15$21771e718815d6f23073ea294540ce94$8$5c4361e549c999e1", "win"}, // 844013895.rar
	{NULL}
};

static struct custom_salt {
	//int version;
	//int hp;
	int saltlen;
	//int ivlen;
	unsigned int iterations;
	unsigned char salt[32];
	//unsigned char iv[32];
} *cur_salt;

static int get_integer(char *int_str, int *output) // FIXME: replace by isdec() + atoi()?
{
	char *endptr;
	long val;

	errno = 0;
	val = strtol(int_str, &endptr, 10);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
		|| (0 != errno && 0 == val)) {
		return 0;
	}

	*output = (int) val;
	return 1;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // salt length
		goto err;
	if (!get_integer(p, &len))
		goto err;
	if (len > 32 || len < 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto err;
	if (hexlenl(p, &extra) != len * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // iterations (in log2)
		goto err;
	if (!get_integer(p, &len))
		goto err;
	if (atoi(p) < 0)
		goto err;
	if (len > 24 || len < 0) // CRYPT5_KDF_LG2_COUNT_MAX
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // AES IV
		goto err;
	if (hexlenl(p, &extra) != SIZE_INITV * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // pswcheck len (redundant)
		goto err;
	if (!get_integer(p, &len))
		goto err;
	if (len != BINARY_SIZE)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // pswcheck
		goto err;
	if (hexlenl(p, &extra) != BINARY_SIZE * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.iterations = 1 << atoi(p);
	p = strtokm(NULL, "$");
/* We currently do not use the IV */
#if 0
	for (i = 0; i < SIZE_INITV; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
#endif
	MEM_FREE(keeptr);

#ifdef RARDEBUG
	fprintf(stderr, "get_salt len %d iter %d\n", cs.saltlen, cs.iterations);
	dump_stuff(cs.salt, SIZE_SALT50);
#endif
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
		uint32_t swap[1];
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->iterations;
}

#endif /* JOHN_RAR5_COMMON_H */
