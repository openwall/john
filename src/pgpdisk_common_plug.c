/*
 * Common code for the PGP Disk format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "pgpdisk_common.h"
#include "sha.h"

struct fmt_tests pgpdisk_tests[] = {
	// Windows 7 + Symantec Encryption Desktop 10.4.1 MP1
	{"$pgpdisk$0*5*16000*3a1bfe10b9d17cf7b446cd94564fc594*1a1ce4453d81117830934495a2516ebc", "openwall"},
	{"$pgpdisk$0*5*16000*1786114971183410acfdc211cbf46230*7d94867264bc005a4a3c1dd211a13a91", "openwall"},
	{"$pgpdisk$0*4*16000*5197b63e47ea0254e719bce690d80fc2*7cbce8cfe5b1d15bb5d25126d76e7626", "openwall"}, // Twofish
	{"$pgpdisk$0*3*16000*3a3c3127fdfa2ea44318cac87c62d263*0a9f26421c5d78e50000000000000000", "openwall"}, // CAST5
	// macOS Sierra + Symantec Encryption Desktop 10.4.1 MP1
	{"$pgpdisk$0*5*16822*67a26aeb7d1f237214cce56527480d65*9eee4e08e8bd17afdddd45b19760823d", "12345678"},
	{"$pgpdisk$0*5*12608*72eacfad309a37bf169a4c7375a583d2*5725d6c36ded48b4309edb2e7fcdc69c", "äbc"},
	{"$pgpdisk$0*5*14813*72eacfad309a37bf169a4c7375a583d2*d3e61d400fecc177a100f576a5138570", "bar"},
	{"$pgpdisk$0*5*14792*72eacfad309a37bf169a4c7375a583d2*304ae364c311bbde2d6965ca3246a823", "foo"},
	{"$pgpdisk$0*7*17739*fb5de863aa2766aff5562db5a7b34ffd*9ca8d6b97c7ebea876f7db7fe35d9f15", "openwall"}, // EME2-AES
#if PLAINTEXT_LENGTH >= 125
	{"$pgpdisk$0*5*19193*5d535ca4089270b24e8cd32e2dc8f6c8*8094cde867c142452c1ed82c59655d0a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 125 a's
#endif
	{"$pgpdisk$0*5*14430*5619030d7bc7c94c760e0176ed440e29*1da77a2cc28aae2a8d2a756965462118", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 124 a's
	{"$pgpdisk$0*5*16932*c88df7c3e014c7c83b7fa8ae964c13c4*9e870109cff5a2e345ad5cd02a563c7e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 64 a's
	{"$pgpdisk$0*5*18666*f95723e935c6d2fb9766212563661c97*6356e9a0b9f86da750e02638a93fae7b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 60 a's
	// Windows XP SP3 + PGP 8.0
	{"$pgpdisk$0*3*16000*3248d14732ecfb671dda27fd614813bc*4829a0152666928f0000000000000000", "openwall"},
	{"$pgpdisk$0*4*16000*b47a66d9d4cf45613c3c73a2952d7b88*4e1cd2de6e986d999e1676b2616f5337", "openwall"},
	{NULL}
};

int pgpdisk_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // algorithm
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 7 && res != 6 && res != 5 && res != 4 && res != 3) // EME-AES, EME2-AES, AES-256, Twofish, CAST5
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) > 16 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // CheckBytes
		goto bail;
	if (hexlenl(p, &extra) > 16 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *pgpdisk_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	cs.algorithm = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_size = 16;
	for (i = 0; i < cs.salt_size; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

unsigned int pgpdisk_common_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int)cs->iterations;
}

unsigned int pgpdisk_common_algorithm(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int)my_salt->algorithm;
}
