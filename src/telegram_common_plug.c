/*
 * Common code for the Telegram Desktop format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "arch.h"
#include "telegram_common.h"
#include "jumbo.h"

struct fmt_tests telegram_tests[] = {
	// Telegram Desktop 1.3.9 on Ubuntu 18.04 LTS
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*d6fb7ebda06a23a9c42fc57c39e2c3128da4ee1ff394f17c2fc4290229e13d1c9e45c42ef1aee64903e5904c28cffd49498358fee96eb01888f2251715b7a5e71fa130918f46da5a2117e742ad7727700e924411138bb8d4359662da0ebd4f4357d96d1aa62955e44d4acf2e2ac6e0ce057f48fe24209090fd35eeac8a905aca649cafb2aade1ef7a96a7ab44a22bd7961e79a9291b7fea8749dd415f2fcd73d0293cdb533554f396625f669315c2400ebf6f1f30e08063e88b59b2d5832a197b165cdc6b0dc9d5bfa6d5e278a79fa101e10a98c6662cc3d623aa64daada76f340a657c2cbaddfa46e35c60ecb49e8f1f57bc170b8064b70aa2b22bb326915a8121922e06e7839e62075ee045b8c82751defcba0e8fb75c32f8bbbdb8b673258", "openwall123"},
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*7c04a5becb2564fe4400c124f5bb5f1896117327d8a21f610bd431171f606fa6e064c088aacc59d8eae4e6dce539abdba5ea552f5855412c26284bc851465d6b31949b276f4890fc212d63d73e2ba132d6098688f2a6408b9d9d69c3db4bcd13dcc3a5f80a7926bb11eb2c99c7f02b5d9fd1ced974d18ed9d667deae4be8df6a4a97ed8fae1da90d5131a7536535a9bfa8094ca7f7465deabef00ab4c715f151d016a879197b328c74dfad5b1f854217c741cf3e0297c63c3fb4d5d672d1e31d797b2c01cb8a254f80a37b6c9a011d864c21c4145091f22839a52b6daf23ed2f350f1deb275f1b0b4146285ada0f0b168ce54234854b19ec6657ad0a92ffb0f3b86547c8b8cc3655a29797c398721e740ed606a71018d16545c78ee240ff3635", "öye"},
	{NULL}
};

int telegram_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // rounds
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // encrypted_blob
		goto err;
	if (hexlenl(p, &extra) > ENCRYPTED_BLOB_LEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *telegram_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_length = strlen(p) / 2;
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.encrypted_blob_length = strlen(p) / 2;
	for (i = 0; i < cs.encrypted_blob_length; i++)
		cs.encrypted_blob[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

unsigned int telegram_iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iterations;
}
