/*
 * Common code for the BitLocker format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "bitlocker_common.h"
#include "hmac_sha.h"
#include "memdbg.h"
#include "johnswap.h"

struct fmt_tests bitlocker_tests[] = {
	// Windows 10 generated BitLocker image
	{"$bitlocker$0$16$134bd2634ba580adc3758ca5a84d8666$1048576$12$9080903a0d9dd20103000000$60$0c52fdd87f17ac55d4f4b82a00b264070f36a84ead6d4cd330368f7dddfde1bdc9f5d08fa526dae361b3d64875f76a077fe9c67f44e08d56f0131bb2", "openwall@123"},
	// Windows 10
	{"$bitlocker$0$16$73926f843bbb41ea2a89a28b114a1a24$1048576$12$30a81ef90c9dd20103000000$60$942f852f2dc4ba8a589f35e750f33a5838d3bdc1ed77893e02ae1ac866f396f8635301f36010e0fcef0949078338f549ddb70e15c9a598e80c905baa", "password@123"},
	// Windows 8.1
	{"$bitlocker$0$16$5e0686b4e7ce8a861b75bab3e8f1d424$1048576$12$90928da8c019d00103000000$60$ee5ce06cdc89b9fcdcd24bb854842fc8b715bb36c86c19e73ddb8a409718cac412f0416a51b1e0472fad8edb34d9208dd874dcadbf4779aaf01dfa74", "openwall@123"},
	// Windows 8.1
	{"$bitlocker$0$16$7b5c9407857f6d590a0d4dcf56d503a6$1048576$12$b02d06c0c019d00103000000$60$1af24981790bd0cc0d00b86b9893c0fdc63b20f0631e85f206b2af3c2c64f77bac2ec9379a4df51967c82033ed9661bace0e63c7dec4f9ef0cc27c5a", "openwall@12345"},
	// Windows 10 "BitLocker To Go"
	{"$bitlocker$0$16$9079aaee7be0923b529f069012f30b13$1048576$12$40ea50c2b79fd20103000000$60$caca601f042fae0eb697593e559760f8209d495ed0b61eda9c83a79f0abb3f598853b6f89cdffd3b5b66b90b321b822c90c8ef5dac464ef6edd06881", "weakpassword12345"},
	{NULL}
};

int bitlocker_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int salt_length;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version, for future purposes
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt length
		goto err;
	if (!isdec(p))
		goto err;
	salt_length = atoi(p);
	if (salt_length != SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != salt_length * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // nonce length
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 12) // iv or nonce length is known to be 12 for aes-ccm mode in bitlocker
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // nonce
		goto err;
	if (hexlenl(p, &extra) != value * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // length of data encrypted by aes_ccm key
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)   // data encrypted by aEs_ccm key, contains encrypted volume master key (vmk)
		goto err;
	if (hexlenl(p, &extra) != value * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *bitlocker_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static bitlocker_custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(bitlocker_custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // version
	p = strtokm(NULL, "$"); // salt length
	cs->salt_length = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iterations
	cs->iterations = atoi(p);
	p = strtokm(NULL, "$"); // nonce length
	p = strtokm(NULL, "$"); // nonce
	for (i = 0; i < IVLEN; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // data_size
	cs->data_size = atoi(p);
	p = strtokm(NULL, "$"); // data
	for (i = 0; i < cs->data_size; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	return (void *)cs;
}

unsigned int bitlocker_common_iteration_count(void *salt)
{
	bitlocker_custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
