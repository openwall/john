/*
 * Common code for the PGP WDE format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "pgpwde_common.h"
#include "sha.h"

struct fmt_tests pgpwde_tests[] = {
	// The following "hashes" are from Symantec Encryption Desktop 10.4.1 MP1 (released in July, 2016) running on Ubuntu 12.04.5 LTS and Ubuntu 14.04 LTS (32-bit + 64-bit)
	{"$pgpwde$0*9*100*17*ecbf39c8978c4867568f2a58304ff00f*746dfc8106fc4e96a49543d2e1acdc31541dd7b341462289049038263b9f38cfebde0c004c87c664f2ad492311694bbe6ff3f940dac2b88c67054d8927a43fbd633659d1ba8d433dcfb1e824c344efecb6841690c05fec567068e022f04ece5e95220877d97503c352b86bf65bb1df14899b3b6eff9df38c50f2540c4fc2e242", "12345678"},
	{"$pgpwde$0*9*100*17*e6e1310c74fb0c6fb9eee4b315051113*14a0a91eb673c51df8da532262cc30f1bd3b52ea4cdb626be3afeba92cf23c751f953d6eb37369ebc207c8dc647931f0bc9fd68a91a307a9ae5066d49c3aa79b9508ba27ac5bc4fd5eef78d18ce1c6f4e0dc80fa24b4f3e767fa3fb57f2deca0487d043abe12149ada6c7f4bbb421dc0afe31af1b5a4a01aec743264197880a8", "12345678"},
	{"$pgpwde$0*9*100*17*2728fa809757cba079cfc1cbc665ab2b*79e7c8f91cefb2467afd574cd7f4a58e5c87bef97fbafcfe187f2184f2a3d03c7d5f77e1b9e5ab807d4abed34b06c6732fd6249a550e711c8e24d1e891f4968b85b3fb669cb23eae1048fb6065fff142ff3914de226f549f3add7c50d994e04d23db7ae9ba4ad254e827220b799561da7dad04ac8f8c906a5ceb0d002409597a", "openwall"},
	{"$pgpwde$0*9*100*17*cf5db4a93623b7161d4e884a8857e885*543cf9655eeab265ad61f165a6c8f2af53b7fe8cb88ebcf917e408063e2ac439094289fd1230850c30620761d77cb8b98b83b50f1bac44b558c44caf0b40663b89f999d6cd445cbacd237ad1cf95232502df21c8531d160062e5384a03b92ce472628dccc5e5974808667bd3937b2c48ef13a3b60d3472400001980f37bb262d", "openwall"},
	{"$pgpwde$0*9*100*17*30709e0bc231ca17a1209c72efca1f85*11aa93a6020cdb5735fabb6c275b0c69c3a4337ea0124e4bac991838a788368d58caa99f6bb7cc787eb4faeeab70a13917fc2ecf351fb1c9c386caf6e4edd54dc3a5058864be60938ecccbf2b71b5b5f63ec209098a1a420da16e2d09de8a9c3e7807d09a6ffaade3979f14bf52e8a35bc31279636c99e9dd628c931e4586e61", "password"},
	{"$pgpwde$0*9*100*17*72ac668f357b364790caedf3e32bf21b*966209a0d6b636ac4edcea40c3a26f88a7ed61de03fa3fcaae5dd740f9729655a756b5f87e4e296b854e93945c5125d046efdd5841115c6714d35a4f0955544e7440019a328b94194944f8bedf386868d4c7f0be692069c891840ac370dc34875dc42385b025ede6e7e7b40e50376c622e9502385b2ddca6d20bca818a2f4a47", "password"},
	{"$pgpwde$0*9*100*17*173f9532d6db02f8007ff33c100f0277*75f37121dffb84c32037968761ee0ef8f3fa6c63725722850899bc301a7ce2cbd607a49bc668ed9c916dd24ca5f7ec63a28995766eb89dc80a1324e4e5d0324aa1d54c35f5ef746981f2beff5a52646086f396aad3ed28e002b10250e813ef771f962a6124fc78f78e62358ca4dc00a2504ca1945d689ab115186ac4eceec651", "äbc"},
	// The following "hash" is from Symantec Encryption Desktop 10.4.1 MP1 running on Windows 7 SP1 64-bit
	{"$pgpwde$0*9*100*17*c048f97fa5cc9e03937d779f57e558ea*b1b10fc88935cef6f66bab55df1106c84747681fbe512c188496913063dc326bbc1998689083cf29d28f1c588fb0a57f24ecd61a2014eb732371aa95bd4d56018b53ab7f21dbe7d718b1c54b8a632bffddd4b438ea3543da3ef653a59febb11d054f7c0604f3416bee81b6653c1e22de8ab46eeb7fc153e843c9a32647897d74", "openwall"},
	{NULL}
};

#undef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20

// Licensing terms for the *original code* behind this function are not great.
// However, I believe that most of the original code has been re-written. Only
// the structure, and logic of the original code should be remaining.
//
// Can we use RSA_padding_check_PKCS1_OAEP from OpenSSL instead?
int PKCS1oaepMGF1Unpack(uint8_t *in, uint32_t inlen, unsigned char *p, uint32_t plen, unsigned char *msg, uint32_t *msglen)
{
	uint32_t hashlen;
	uint8_t hash[20];
	uint32_t l;
	uint32_t counter = 0;
	uint8_t counter_bytes[4];
	unsigned i, j;
	SHA_CTX ctx;

	*msglen = 0;
	SHA1_Init(&ctx);

	hashlen = SHA_DIGEST_LENGTH; // SHA1 always, hardcoded
	memcpy(msg, in + 1, inlen - 1); // remove leading zero, this can be used for a quick reject test after decryption!

	/* Get original seed */
	SHA1_Update(&ctx, in + 1 + hashlen, inlen - 1 - hashlen);
	memset(counter_bytes, 0, 4);
	SHA1_Update(&ctx, counter_bytes, 4);
	SHA1_Final(hash, &ctx); // MGF output is hash(masked_message 00 00 00 00)

	l = hashlen/sizeof(uint32_t);
	for (i = 0; i < l; i++)
		((uint32_t*)msg)[i] ^= ((uint32_t*)hash)[i];

	/* Unmask original message */
	i = hashlen / sizeof(uint32_t);
	while (i < inlen/sizeof(uint32_t))  {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, msg, hashlen); // hash(seed)
		counter_bytes[3] = (uint8_t)counter;
		counter_bytes[2] = (uint8_t)(counter>>8);
		counter_bytes[1] = (uint8_t)(counter>>16);
		counter_bytes[0] = (uint8_t)(counter>>24);
		counter++;
		SHA1_Update(&ctx, counter_bytes, 4);
		SHA1_Final(hash, &ctx); // hash(seed || counter)

		l = hashlen / sizeof(uint32_t);
		for (j = 0; j < l && i + j < inlen/sizeof(uint32_t); j++)
			((uint32_t*)msg)[i+j] ^= ((uint32_t*)hash)[j];
		i += l;
	}

	/* Determine the size of original message.
	 * We have seed || hash(p) || 0...0 || 01 || M */
	for (i = 2 * hashlen; i < inlen - 1; i++)  {
		if (msg[i])
			break;
	}

	if (i == inlen - 1 || msg[i] != 1)  {
		return -1; // corrupt data
	}

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, p, plen); // hash parameter
	SHA1_Final(hash, &ctx);

	// check parameters hash
	if (memcmp(hash, msg + hashlen, hashlen) != 0)  {
		return -1; // corrupt data
	}

	// memmove(msg, msg + i + 1, inlen - 1 - i); // we don't really use this data
	*msglen = inlen - 1 - i - 1;

	return 0; // success
}

int pgpwde_decrypt_and_verify(unsigned char *key, unsigned char *esk, int esklen)
{
	AES_KEY aes_key;
	unsigned char iv[16];
	unsigned char out[128];
	unsigned char msg[128];
	uint32_t length;

	memset(iv, 0, 16);
	iv[0] = 8; // by design, kPGPdiskUserWithSymType
	AES_set_decrypt_key(key, 256, &aes_key);
	AES_cbc_encrypt(esk, out, 128, &aes_key, iv, AES_DECRYPT);

	// Remove OAEP padding from ESK
	return PKCS1oaepMGF1Unpack(out, 128, (unsigned char*)"", 0, msg, &length);
}

int pgpwde_valid(char *ciphertext, struct fmt_main *self)
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
	if ((p = strtokm(NULL, "*")) == NULL) // symmAlg
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 9) // AES256
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // s2ktype
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 100)
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // hashIterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != 16 * 2 || extra)
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // ESK
		goto bail;
	if (hexlenl(p, &extra) != 128 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *pgpwde_get_salt(char *ciphertext)
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
	cs.symmAlg = atoi(p);
	p = strtokm(NULL, "*");
	cs.s2ktype = atoi(p);
	p = strtokm(NULL, "*");
	cs.hashIterations = atoi(p);
	if (cs.hashIterations == 0)
		cs.bytes = 1 << 16;
	else
		cs.bytes = 1 << cs.hashIterations;
	p = strtokm(NULL, "*");
	cs.salt_size = 16;
	for (i = 0; i < cs.salt_size; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 128; i++)
		cs.esk[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}
