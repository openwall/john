#include "arch.h"
#if !AC_BUILT && !__MIC__
#define HAVE_LIBZ 1 /* legacy build has -lz in LDFLAGS */
#endif
#if HAVE_LIBZ

#include <zlib.h>

#include "misc.h"
#include "common.h"
#include "aes.h"
#include "openssl_code.h"
#include "dashlane_common.h"

struct fmt_tests dashlane_tests[] = {
	// Dashlane v4.8.3 running on Windows 10 -> personaldataDatabase.aes
	{"$dashlane$1*523f57cffb40609f4a3b00288a1223cf8ec4b8c1610fe4afdea345a21563eae9*220*5e906e7dce3d12999bf7d627756e2267f3f5061e457a47736d1174959ed4f9e316a30fdee0a60493de83dd6f8b669ed420172ad9e2f1c1269aa9716d664cf2a005b44834f696c0473a8858647adc07d9b02ec3ece33eae250289bb1d2efbe9c4c181ae326dccabb552939f5fca72dc4b83c846e95a67eb3fbd04ca5fc216f4de16893bb434ba878e34e1870fb1814355e192488bb6bdab8e18f3c983e599800c458711a27ebeb595f6757a1393035b92bbc46bc9ccea75b77ea47b413e08b3aa9818ebf3369eb954d1fa44a202c2cd9e28d48b3dd5a185caa4674caf", "Openwall123"},
	// Dashlane v4.8.3 running on Windows 10 -> personalSettingsData.aes)
	{"$dashlane$1*50f99aaf4f84ed94f8310393ce0659f18a22596af5e875bb8bcf470e8072d396*220*085430d493c93128a11bf0fadeb305e468277383f18bc3868a869b307046b34b7e6bbafbb26617155efefb265061a1dccc1ea8efd9029607e960f54057ecd136ee5e7ab2fb261473f10afce16eb72c23f8265c73db0a911090ef1c822ffcc633da3d5f81062907be66184116a54ef4ff3705acca2b3d3d79abb885a74c8afef32311cef3bc3d75fd2cd29dc3c3c1c3722a14da7a639e4204e48ebb7cb79b4cc47aea072fd634671a39d1104b434e529ad8517be9b051d8b51073a5cb0b4746b193d20cf005cadc966a9b470a6904f4f31b3a5a52a3deeafd92a2a35a", "Openwall123"},
	// Dashlane v4.8.3 running on Windows 10 -> personaldataDatabase.aes
	{"$dashlane$1*2ab1bd367221dbe351ab6c966399dfaa8da1ef4fe4fc54308a2ecdca0236dcc6*220*8648ee3daf1067aaec0ebf47185bd4102bdb8702662e15cb6a4ed5396859716b9a2855117dae55607a5395cb8b9a4e2b496abaa6eb65904b6f206fd91a342d707ec9ce66426388107c70710025ccac73e3069fa1f3d15212d0678c98382e3ebb8a1408c63068cab030948af5d1fa438e91f2d2d4d18476a6d8f676e9589520cc8805e44c1dbd4f53f51a3fa306d003e59f3947670a80f699efcb607b1eb0aec899a16d76e35ff0d4826bcfb7875d23635610e1bed6dd31e58c26ad6de2ec853c774572fb55d8aa1e530cef9d60fb71b3a6aafa0555dcbc7ad5365de9", "Password123"},
	// Dashlane v4.8.3 running on macOS Sierra -> sharedData.aes (personaldataDatabase.aes also works)
	{"$dashlane$1*490394db60b4c630f239d59f8892abcdfbe532390c8d6764c3d3236df7c73bd7*96*c3152ee5485b39ad8d5dc699da383819335c7664c55a9fb04fa951c96ab9ebe4884408570040aed2b00ed3e949bc91896b822474743f6a0e4e1f034f7467f704715801b4511f525c60358876d16773c385084fa4609732ef2ad824ca6ec72e1b", "Password123"},
	// Dashlane v4.8.3 running on macOS Sierra -> "Dashlane Export.dash" (Dashlane secure archive)
	{"$dashlane$1*5350b43b32703342ee6a65a835e612d42933751c1e645b5bb7f43c1ab64d36ac*220*3c5a3060ed8dd0541f6182750b9b8252e23e2c578912cc0f7da1d73efb0ee657cd68db430ccce98016840efd49d1c9a52b83fbbc51c2aadfc7fa3dc0927674253eb6d474000fc091c72156127c08afdd9d2f141f24d518694ecbf8d78b072e492ed4f7a43ff8c5642a2d44c79c241d9387d06c763a15d0770e133c59727446456b8b32b615844e1a2e360ba64f0aeacf87f2b45706b000852222ad1d2adf7cd9d40527522834f7a2ba28d85067c0cc3442fff5c7ef922604e84956f66283210866db6e2e853e4f18cce1e6bbc2b96ee75a3c04e7cd74b8628f09197c", "Password123"},
	{NULL}
};

int dashlane_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra, length, value;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
                goto err;
        if (!isdec(p))
                goto err;
        value = atoi(p);
        // if (value != 1 && value != 0) // value = 0 code path isn't tested
        if (value != 1)
                goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto err;
	if (hexlenl(p, &extra) != 32 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // length
                goto err;
        if (!isdec(p))
                goto err;
        length = atoi(p);
	if (length > 512)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // encrypted data
		goto err;
	if (hexlenl(p, &extra) != length * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *dashlane_get_salt(char *ciphertext)
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
	for (i = 0; i < 32; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length; i++)
		cs.data[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

int dashlane_verify(struct custom_salt *cur_salt, unsigned char *pkey)
{
	unsigned char out[256] = { 0 };
	unsigned char fout[256] = { 0 };
	z_stream z;
	unsigned char iv[16];
	unsigned char key[32];
	AES_KEY aes_decrypt_key;

	// common zlib settings
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	z.avail_in = 128;
	z.avail_out = 128;
	z.next_out = fout;

	BytesToKey(256, sha1, cur_salt->salt, pkey, 32, 1, key, iv);

	if (cur_salt->type == 1) {
		AES_set_decrypt_key(pkey, 256, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->data, out, 128, &aes_decrypt_key, iv, AES_DECRYPT);
		z.next_in = out + 6; // ignore starting 6 bytes (quirk)
		inflateInit2(&z, -15);
		inflate(&z, Z_NO_FLUSH);
		inflateEnd(&z);
	} else { // untested code
		AES_set_decrypt_key(key, 256, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->data, fout, 128, &aes_decrypt_key, iv, AES_DECRYPT);
	}

	if (memmem(fout, 128, "<?xml version", 13))
		return 1;
	else
		return 0;
}

#endif /* HAVE_LIBZ */
