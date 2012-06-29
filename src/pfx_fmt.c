/* pfx cracker patch for JtR. Hacked together during  June of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2021, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#undef MEM_FREE
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif
#include <string.h>
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "misc.h"

#define FORMAT_LABEL        "pfx"
#define FORMAT_NAME         "pfx"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	int len;
	PKCS12 pfx;
} *cur_salt;

static struct fmt_tests pfx_tests[] = {
	{"$pfx$*1702*308206a20201033082066806092a864886f70d010701a082065904820655308206513082032f06092a864886f70d010706a08203203082031c0201003082031506092a864886f70d010701301c060a2a864886f70d010c0103300e04086c933ea5111fd24602020800808202e83c56ad18c45e54aaca4d170750cfbfb3059d6cf161e49d379eab15e722216cb479eee8da7b6e6ffc89e01fbf30f4eb5e1b88ca146c166c700a68473d25a0979344cc60d1e58230a12d24b8be6e9174d3afecdf111cd7d96527831ac9c8f4bf3817cda021f34b61899f2a75fe511e8dedfb70367fa9902d2d3e500f853cc5a99ec8672a44713d24ae49382a20db6349bc48b23ad8d4be3aa31ba7e6d720590b5e4f6b0b5d84b7789ae9da7a80bfa3c27e507fc87e7bc943cff967db6b76f904ac52c1db5cfe9915fa3493cd42b8db6deae62bc01593e34bc8598f27a24cdfd242701ff72d997f959f3a933ab5a2762df33849c116715b78cb0d83267aff913619cbbdf003e13318e4b188a8a4f851b9f59ae2c71ab215c565f7872e5d54c06f92d6f59eaf19d95f9b4526d52d289cd17bc0c2079f9f13c20a70a566773d90ca6d888386d909b6362cb79e15cf547dceab1fe793c577b70f72463969f7b416fb5a6228053363558df18588b53406343ab320a1bbf1757b67ef8e3075f44dee4521f4a461d37ea894c940bc87f9bd33276f2843ff5922fd8e61d22a8619ad23154880fd7d957c0f151458fc4f686d96695a823b08c1795daaf79e41118a3c57ee065a693853a9c4b2004440662f51d63bb9973dc4bb8c541d424416c57d01a825be4d31dab7c7f4b2b738e4bbfdda1e3d3b95e026dadee4dfe155c0f4a24991693f679b452516bc19eab7cf7eb41b476358583d46630e8cda55974b8fcbe25b93e91e73f584a913149137c1c20d13f38826d8dba9bcf5504b8cee77e20a19d6fb050e9213b8aeb11c26a871c600701aea352ba2dcea15d8010d25034f64aa488b580b8282d226f8203bba6aa424b0a25bcceb9c7c718b6c276022d988ca063d2e88350d68903f95aa3265b44d909c07fa9477a5dfcfe3b5ed49b789d6e1c13aca012630343021dbc0c0f17dae6688eae495b76d21be49ced2c2e98e1068d8725d8a581958fb2530871dff1b3f910ae8beb3bc07bfb4b1d2d73fc5d440dc9bcd32ba656c32e357051bef3082031a06092a864886f70d010701a082030b0482030730820303308202ff060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408749558ace83617660202080004820280ef790b9cd427ec99a350a6e3afb1727cf3dd859d5377897805a7093e1ca42ab8cccc6c52d2b86d61ed55b5bd743fb2a4ec556b438933a9d97a55e5ad1fb3f9967e550be3d708feb5c7287e31afed165a4a91bd5a80292a1e061f97a8c11339963843348badf3fd898e89fd92bda5ad0195d8d4f75e7bce9f0518eeb85365860cd32ad5cea0958efef02bfb74aec0af0765729dae079f5eb08b099d3b06a9b9c6cd6f1e1e4170208ebec3c61ae3421e90cef0f2b5cd2187e43cc4ceecf4aec06340f886efb94f517e578d13659392246a69505de3914b719fba74709ef0f03f010429f899dbddab950f6e58462b2fe2663986a5e0c8ff235e89bca3bb6e41fcd602a0277a83822ac1a14101c83fd1cafdc45c1980ecf54ef092deb2fea736b428158e0847256fc1211f94ea8075145be5a5fb26206e125d55f45500844f1a83f063d0be19b60427dadbd89109bb9ee31a1ac79c863204e8e80c044b8b6bc45c756c26be514e4270a293faf4608065a27b4a51253cb9f831614d5c7f25ec1d4e36063e68e4e405c1f4deb98a786c57a376609441f2dcbe6393487b884624570f6cbb02b53f58ea4acb0faedd2931293dc87664a0c589322480686f6613ffb794c3b3b1872cd7a418712a35666b53bd8383f2e7aa6e8a9e20dd3d46cc3aaaaf17841732dde708ba5611ebcc8777fb3f7b65f2cf95992fdf4f5a17ddf01f3ebe5fb6c9cd58cb74553865cbec3c9d391dcc3e96e654faf7be7fdc8d5fb5dff98799e740147d2ca4b6df47560a4a20bd8f30cf5b495f4e919c9efad3aa59491a3e2ba4e53606e2016ce13e8271e70ccd5b57eec99a8604caf5997e648f3eb541769267f9cdf76aa84917ebd8a1f60a973ed22cca9fa0d3589bb77dafed82ea4f8cd19d3146301f06092a864886f70d01091431121e10006f00700065006e00770061006c006c302306092a864886f70d01091531160414a38a6be4b090be5e29259879b75e0e482f4a4dd830313021300906052b0e03021a05000414a790274918578289d80aa9fd0d526923f7b8f4d40408e861d3357729c35f02020800", "openwall"},
	{NULL}
};

struct fmt_main fmt_pfx;

static void init(struct fmt_main *pFmt)
{
	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
	if (SSLeay() < 0x10000000) {
		fprintf(stderr, "Warning: compiled against OpenSSL 1.0+, "
		    "but running with an older version -\n"
		    "disabling OpenMP for pfx because of thread-safety issues "
		    "of older OpenSSL\n");
		fmt_pfx.params.min_keys_per_crypt =
		    fmt_pfx.params.max_keys_per_crypt = 1;
		fmt_pfx.params.flags &= ~FMT_OMP;
	}
	else {
		int omp_t = 1;
		omp_t = omp_get_max_threads();
		pFmt->params.min_keys_per_crypt *= omp_t;
		omp_t *= OMP_SCALE;
		pFmt->params.max_keys_per_crypt *= omp_t;
	}
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * pFmt->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$pfx$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *decoded_data;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	PKCS12 *p12 = NULL;
	BIO *bp;
	ctcopy += 6;	/* skip over "$pfx$*" */
	p = strtok(ctcopy, "*");
	cs.len = atoi(p);
	decoded_data = (char *) malloc(cs.len + 1);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.len; i++)
		decoded_data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
    			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	decoded_data[cs.len] = 0;
	/* load decoded data into OpenSSL structures */
	bp = BIO_new(BIO_s_mem());
	if (!bp) {
		fprintf(stderr, "OpenSSL BIO allocation failure\n");
		exit(-2);
	}
	BIO_write(bp, decoded_data, cs.len);
	if(!(p12 = d2i_PKCS12_bio(bp, NULL))) {
		perror("Unable to create PKCS12 object from bio\n");
		exit(-3);
	}
	/* save custom_salt information */
	memset(&cs, 0, sizeof(cs));
	memcpy(&cs.pfx, p12, sizeof(PKCS12));
	BIO_free(bp);
	if (decoded_data)
		free(decoded_data);
	free(keeptr);
	return (void *) &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *) salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void pfx_set_key(char *key, int index)
{
	int len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
	saved_key[index][len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int index = 0;
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
#pragma omp parallel for default(none) private(index) shared(count, any_cracked, cracked, saved_key, restored_custom_salt)
	for (index = 0; index < count; index++)
#endif
	{
		if(PKCS12_verify_mac(&cur_salt->pfx, saved_key[index], -1))
			any_cracked = cracked[index] = 1;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_pfx = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		pfx_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		pfx_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};
