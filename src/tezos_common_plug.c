/*
 * Common code for cracking Tezos Keys.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "arch.h"
#include "tezos_common.h"
#include "jumbo.h"

struct fmt_tests tezos_tests[] = {
	// http://doc.tzalpha.net/introduction/zeronet.html, https://faucet.tzalpha.net/
	{"$tezos$1*2048*put guide flat machine express cave hello connect stay local spike ski romance express brass*jbzbdybr.vpbdbxnn@tezos.example.org*tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR*a19fce77caa0729c68072dc3eb274c7626a71880d926", "4FGU8MpuCo"},
	{"$tezos$1*2048*shove average clap front casino lawn segment dinosaur early solve hole dinner copy journey alley*kqdbxkwa.xvlnjlhg@tezos.example.org*tz1ZRcC58RDjA17Jmp2zDds6Hnk8UAjU8sxh*a19f97385132d6051136ef34d6a62a0bf5af9fecbe26", "XRknDmWXTm"},
	{NULL}
};

int tezos_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (strcmp(p, "1"))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // iterations
		goto err;
	if (strcmp(p, "2048"))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // mnemonic
		goto err;
	if (strlen(p) > 128)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // email
		goto err;
	if (strlen(p) >= 256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // address
		goto err;
	if (strlen(p) >= 62)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // raw address
		goto err;
/*
 * https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml says:
 * (* 20 *)
 * let ed25519_public_key_hash = "\006\161\159" (* tz1(36) *)
 * Since ed25519_public_key_hash is the only thing we support in code, it would
 * be wrong to accept other address types here (we'd have false negatives).
 */
	if (hexlenl(p, &extra) != 22 * 2 || extra || strncmp(p, "a19f", 4))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *tezos_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	strcpy(cs.mnemonic, p);
	cs.mnemonic_length = strlen(p);
	p = strtokm(NULL, "*");
	strcpy(cs.email, p);
	cs.email_length = strlen(p);
	p = strtokm(NULL, "*");
	strcpy(cs.address, p);
	p = strtokm(NULL, "*");
	cs.raw_address_length = strlen(p) / 2;
	for (i = 0; i < cs.raw_address_length; i++)
		cs.raw_address[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}
