/*
 * Common code for the Apple Keychain format.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_OPENCL || HAVE_LIBCRYPTO

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "keychain_common.h"

struct fmt_tests keychain_tests[] = {
	{"$keychain$*10f7445c8510fa40d9ef6b4e0f8c772a9d37e449*f3d19b2a45cdcccb*8c3c3b1c7d48a24dad4ccbd4fd794ca9b0b3f1386a0a4527f3548bfe6e2f1001804b082076641bbedbc9f3a7c33c084b", "password"},
	// these were generated with pass_gen.pl.  NOTE, they ALL have the data (which gets encrypted) which was decrypted from the above hash.
	{"$keychain$*a88cd6fbaaf40bc5437eee015a0f95ab8ab70545*b12372b1b7cb5c1f*1f5c596bcdd015afc126bc86f42dd092cb9d531d14a0aafaa89283f1bebace60562d497332afbd952fd329cc864144ec", "password"},
	{"$keychain$*23328e264557b93204dc825c46a25f7fb1e17d4a*19a9efde2ca98d30*6ac89184134758a95c61bd274087ae0cffcf49f433c7f91edea98bd4fd60094e2936d99e4d985dec98284379f23259c0", "hhh"},
	{"$keychain$*927717d8509db73aa47c5e820e3a381928b5e048*eef33a4a1483ae45*a52691580f17e295b8c2320947968503c605b2784bfe4851077782139f0de46f71889835190c361870baa56e2f4e9e43", "JtR-Jumbo"},
	{"$keychain$*1fab88d0b8ea1a3d303e0aef519796eb29e46299*3358b0e77d60892f*286f975dcd191024227514ed9939d0fa94034294ba1eca6d5c767559e75e944b5a2fcb54fd696be64c64f9d069ce628a", "really long password -----------------------------"},
	/* Sample keychain from OS X El Capitan, November of 2015 */
	{"$keychain$*3a473dd308b1713ddc76fc976758eb543779a228*570b762ec2b177d0*a1f491231412ff74344244db4d98b1dab6e40a8fc63a11f0d5cdabf97fce5c4fa8ae0a1f95d0398d37e3d45e9fa07aa7", "El Capitan"},
	{NULL}
};

int keychain_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (hexlenl(p, &extra) != CTLEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *keychain_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < IVLEN; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < CTLEN; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

#endif /* HAVE_OPENCL || HAVE_LIBCRYPTO */
