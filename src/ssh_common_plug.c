/*
 * Common code for the SSH format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "ssh_common.h"

int ssh_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, cipher, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* cipher */
		goto err;
	if (!isdec(p))
		goto err;
	cipher = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt len */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16 || len < 8)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (hexlen(p, &extra) != len * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext */
		goto err;
	if (hexlen(p, &extra) / 2 != len || extra)
		goto err;
	if (cipher == 2) {
		if ((p = strtokm(NULL, "$")) == NULL)	/* rounds */
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext_begin_offset */
			goto err;
		if (!isdec(p))
			goto err;
		if (atoi(p) + 16 > len)
		       goto err;
	}

	if (cipher < 0 || cipher > 5) {
		fprintf(stderr, "[%s] cipher value of %d is not supported!\n",
		        self->params.label, cipher);
		goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *ssh_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(struct custom_salt));
	cs.rounds = 1;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$sshng$" */
	p = strtokm(ctcopy, "$");
	cs.cipher = atoi(p);
	p = strtokm(NULL, "$");
	cs.sl = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.sl; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.ctl = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.ctl; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (cs.cipher == 2) {
		p = strtokm(NULL, "$");
		cs.rounds = atoi(p);
		p = strtokm(NULL, "$");
		cs.ciphertext_begin_offset = atoi(p);
	}
	MEM_FREE(keeptr);

	return (void *)&cs;
}

unsigned int ssh_iteration_count(void *salt)
{
	struct custom_salt *cur_salt = salt;

	switch (cur_salt->cipher) {
	case 1:
	case 3:
		return 1; // generate 16 bytes of key + AES-128
	case 4:
		return 2; // generate 24 bytes of key + AES-192
	case 5:
		return 2; // generate 32 bytes of key + AES-256
	case 0:
		return 2; // generate 24 bytes of key + 3DES
	default:
		return cur_salt->rounds; // bcrypt KDF + AES-256 (ed25519)
	}
}

unsigned int ssh_kdf(void *salt)
{
	struct custom_salt *cur_salt = salt;

	switch (cur_salt->cipher) {
	case 0:
		return 1; // MD5 KDF + 3DES
	case 2:
		return 2; // bcrypt-pbkdf
	default:
		return 0; // MD5 KDF + AES
	}
}
