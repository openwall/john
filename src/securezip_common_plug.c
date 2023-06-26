/*
 * Common code for the SecureZIP format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "securezip_common.h"

struct fmt_tests securezip_tests[] = {
	{"$zip3$*0*1*256*0*edb47a990800000000000000*32f884f9fbb54360920a50ec37cc0651fe7b0d9892de44eed17696186139a09c1530e0522abfd9777d18441739cdc7107fdfd252ecd0c8dbbba8181bd09436e9a6a918e385cbab26bee49cd0e3182e67df3fe8c3cdc9e58d6166a0f550969cc456b4a881524e6e66a14e30196b972e260c509fce918736465aea1d00bd5871876e263635be4700ef081117ed896e1504*0*0*0*secret.txt", "openwall"},
	// extracted from a multi-file archive, hash for a single file
	{"$zip3$*0*1*192*0*edb47a990800000000000000*ba4288c0572f6043b21eba768ca8854fbec62c644f29cdc9652f037b3600dcc761dd07645cbaa1ebec1140e21e19a1cf4b43a82cb47e71e6ac82d3387581996e3fb201328dd5ad8a5be841e2cc9bee7e940da5b55b8a385df87d2431e24baf9a050ea550bd8ea00d2271f9e9d06b32222b8e5815a9db7e75655937c8437332b5b5b08e4c1800976b528322df6ba9653e*0*0*0*secret.txt", "password"},
	// hash of an archive using central directory encryption, notice the weird "1" filename at the end of the hash
	{"$zip3$*0*1*192*0*a5763deec28f57f7c3218289*7c789a396b6935a2595da1045728aec01572ed0834bc0baa1ab43a186265be83135359ddf2e2f1a2c42f88879617922687131720e8238b006ba10f1caead1d6fbcabbacf32bc3aeda76747d26671f3a94f2037b330a3a790eb72564b05e064747e042c3112d42e739907fdded43c5c4fbf1a5f831cf77bb47f838c75d30a95215b6457a0d4ffc6d408da6be86a04c0d2*0*0*0*1", "openwall"},
	{"$zip3$*0*1*256*0*3f2f7f230e00000000000000*c75ed4a3ec89c22cda7aa3faa9a11cdcca9f5a2f45fe2844d963b2b76b8f98f43a907997557fc2b0eb8cb590b130c573ddfac3f5e70997d6a4539e10728317bdcd70eb74b82bafa2e4871488984db8522c4c4c8ff28fd2dd62c26be9d24246f80ddbdfa8d3b9e81b775dbdb84371446564df3effdbea48713dd223a2bb9afddffc9b8e60f41939f7577f9f30b0a28b78*0*0*0*code.txt", "mmx"},
	{NULL}
};

int securezip_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // unused
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // algorithm
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)  // AES
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // bit length
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 128 && value != 192 && value != 256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // unused
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // iv
		goto err;
	if (hexlenl(p, &extra) > IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // erd
		goto err;
	if (hexlenl(p, &extra) >= ERDLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // unused
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // unused
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // unused
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // unused
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *securezip_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);

	ctcopy += (TAG_LENGTH + 1);
	p = strtokm(ctcopy, "*");
	cur_salt->algorithm = atoi(p);
	p = strtokm(NULL, "*");
	cur_salt->bit_length = atoi(p);
	p = strtokm(NULL, "*");
	cur_salt->bit_length = atoi(p);
	p = strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	cur_salt->iv_length = strlen(p) / 2;
	for (i = 0; i < cur_salt->iv_length; i++) // iv
		cur_salt->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*"); // erd
	cur_salt->erd_length = strlen(p) / 2;
	for (i = 0; i < cur_salt->erd_length; i++)
		cur_salt->erd[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	return (void *)cur_salt;
}
