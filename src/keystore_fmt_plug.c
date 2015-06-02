/* Java KeyStore cracker. Written by Dhiru Kholia <dhiru at openwall.com> and
 * Narendra Kangralkar <narendrakangralkar at gmail.com>.
 *
 * Input Format: $keystore$target$data_length$data$hash$nkeys$keylength$keydata$keylength$keydata...
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Narendra Kangralkar <narendrakangralkar at gmail.com> and it is hereby
 * released to the general public under the following terms: *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keystore;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keystore);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"keystore"
#define FORMAT_NAME		"Java KeyStore"
#define ALGORITHM_NAME		"SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		20
#define BINARY_ALIGN		4
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define SZ			819200

static struct fmt_tests keystore_tests[] = {
	{"$keystore$0$2126$feedfeed000000020000000100000001000f616e64726f696464656275676b65790000013c3ea72ab000000501308204fd300e060a2b060104012a021101010500048204e9e76fea55eed58e4257c253b670948abb18093fbbb667f00807560242f17a4b3cd8b90d0e2a5c6c96f758f45e0e2320039c10af4ecc95e56930fd85713318da506bb48fa586b5caf7c286cf3b66134cb0e13dcdbc665680fb1214d9db2405ccb297acdefd4f5f7cb1c1babd5b77414223b45ae11ab0ec0a2ce5423a6ab69f372adb79a38973a0fde89f9b1e8ef62de04a5e6b35008ce3191c350f98a98ed917ccfc3524f9a4786a3ab055cee25efb118f67d73cacfdd5a3f0ca04399d2b31acfffc63ab6b47f371ff879768ef84bc8c58bcfaab1539e6343cf7b81d0446f57abbeb84fb20b540616aabbfd4c823acb2124ea25538c7531609b72b8da90327a8a3845bcfd69d659a1a77c35efb0d62651e4178459dfde9e165edc6d52cc3d8fee78e3132346588b09e3d27e1400421d33e88748ed1c01af1dc6064a71c991e0322e72c55ed5bcd8c232048bddfecd299d4d9c296639866dd21ad073a4993733b44bac4d6a77eec05cda65d5d9ad0a42a5aa9d443e3ba7ea5744e7fdc2617f527cd9cf480bce033bd5eec6746b2a58328aeed26757664109e1046c93e2377db18c58c35828916f4a42964aae2fe75ad944896bd321ae92cd5723735b37f85250a635a8d1875d3efb2ffbcabc3602ea3b6952da060ec1d1c0a961b1a50836dee911a166e09a33d036d6ef7dc988545b580841945a8718b178bb06ef8e78c6703a496cf66990d57b696b2117922ee1855dff439b2bda3201b145fdb4533b7d2cfa22291a79bac67bb6b3d963dd4137b6208931f02c3ee30bfd0731443edadd5bfffec0147f5f2bd13930deace26fec0ebf0c1befe1294875fb9d8a08919fdc1697ec78d1b86c03a0db4e61bd6a9db6803fdd8e2547ead44bd48cf223b964b0c6903ede0fc0e1b7d02b83ba18ed649bc0e40896ff7cde1d092a9f30314da8fc67d113c79fe7046da75bc090b08b3f31a5d0feb33abab2c608e3afaca1521f2809ae79c14e5ab16d7fa319ddc4dbae61cf41bd15829055970f26361fc1ae22a15e401b25eb500411e70a3cacca38e0d59a6add6513c02d0e6a766303e231d8adf8368b1579e7d58a7d3a5981542c9b8fec0b1780713031fefa60d93755215cbbc34f27634537b6c4fe391578be1a3547fc97d1eeb3e8b11444e8ad99902911fba55034a2796d791039bb29bd193406f05b942f69d47a4a236a64f610e7808387586f4a96a84059e93b11355ecd9125e7a805503e41f4097893b043c7d539d76933515c8fbde11f2a69a6f47aebbac3ed29b0231b3a74ecc9a5421ad61c995a039e44c0a8717dd6e5efbdc2f6ab8daefbc58867ca2e852780c66d1163a03662c34b5365983405093452bb004f78eb973a804edb1b4e8214ab982ed9c81992cc508d8852288fee4ced3af41cca7baaddb828830f3e7dd7c92610def60bbaf6a866e84ea81bd4e88a5b5a035b15b370f942af17f213706c681a59da20b150697c188edb4ac8b59b3babf9c895078f268940aa805c15a2712042c22ce5c44a62554d5f2efb6db179e1db29570b6b063d00349a0273277751e6adf32b6d36b02cb81025d80e620b61a418b0584441c087ce75ed03c871dfe8463a9a3641b036e849fd0fdc9b381ebe43e067353642f182d67ef6bef43463dc6b8d7abd035677b443440c7624d91baa11002e193d86a76974eef4f6fb44a8c440b73ddb323e9eb8f7fdd67aa368ce6aefdff1060e6a519d48b28718b1548e4665360f141d5e16027f0e7c41d07c582dd2a29fa55a00f000000010005582e353039000003113082030d308201f5a00302010202043e310348300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3133303131353134343030385a170d3133303431353134343030385a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a02820101009116fccceb121c8951fb12992ef59393a8c2aeab4ec76a30a71d3aca40a277ab1500613c30bda5472bc15812bdbe9395b4a6009edaf94ca7427cd94ca840c0ac9d42ab8246a401628dbba7acb408738929b75f319d496e8594afd75423c07299ec195efce351b7f2b730ad5e61ab292a4783611cdad41139302ada3e239656c2ec842a59418efc711072e75193cfba1105a1980a631f4a513e4116a89806a47f8b308c03684e2ce83e03c40c438445143fa3fab756909e101f89410a35bb6e6a5cbdcef19d0359c8ed7862fe7ae7f81c32a9a75f72419f89eddbe4acc4373e45a390fd185ae3b28adb8445c4e38e30773acad396788428b0321936f241e905c50203010001a321301f301d0603551d0e041604148c2df598ae53bebe11c4e4696abc6cad6bce4286300d06092a864886f70d01010b05000382010100507e62f723154b2e818140fbc47547c8a600f97a580de244afdf6cdc02977aa7fb990c77a0d79d3ef53aadcf9d7705b385c365e3e06bf15de1a9d3f5c6b6b40fc4b629f763da8f12fc16a005b66026de2be8f1144d37ef14fc1c99dc13dd33fc750898a7ac9e2a12543402ba5021432a8453d38b4879a95736f65956d13d92d96b6f546b853c92f0cc51a98dcd233076ae285d5ed44601f1fe361974c74067eb263386fe8e085e8b20c3cd72768d4265bd9bf4937b2aeae3323c6289dfe75e820907ba38e85b3fc2ceb44e770b91babfdf1d003bbc56ed7066f97ba86e0648ff0874a31c1563d52f42f38005b3698f800be11257f405b185ca421113072f8531$a8ab7a46059faddb183f66d4aef78f47911c88aa$1$1281$308204fd300e060a2b060104012a021101010500048204e9e76fea55eed58e4257c253b670948abb18093fbbb667f00807560242f17a4b3cd8b90d0e2a5c6c96f758f45e0e2320039c10af4ecc95e56930fd85713318da506bb48fa586b5caf7c286cf3b66134cb0e13dcdbc665680fb1214d9db2405ccb297acdefd4f5f7cb1c1babd5b77414223b45ae11ab0ec0a2ce5423a6ab69f372adb79a38973a0fde89f9b1e8ef62de04a5e6b35008ce3191c350f98a98ed917ccfc3524f9a4786a3ab055cee25efb118f67d73cacfdd5a3f0ca04399d2b31acfffc63ab6b47f371ff879768ef84bc8c58bcfaab1539e6343cf7b81d0446f57abbeb84fb20b540616aabbfd4c823acb2124ea25538c7531609b72b8da90327a8a3845bcfd69d659a1a77c35efb0d62651e4178459dfde9e165edc6d52cc3d8fee78e3132346588b09e3d27e1400421d33e88748ed1c01af1dc6064a71c991e0322e72c55ed5bcd8c232048bddfecd299d4d9c296639866dd21ad073a4993733b44bac4d6a77eec05cda65d5d9ad0a42a5aa9d443e3ba7ea5744e7fdc2617f527cd9cf480bce033bd5eec6746b2a58328aeed26757664109e1046c93e2377db18c58c35828916f4a42964aae2fe75ad944896bd321ae92cd5723735b37f85250a635a8d1875d3efb2ffbcabc3602ea3b6952da060ec1d1c0a961b1a50836dee911a166e09a33d036d6ef7dc988545b580841945a8718b178bb06ef8e78c6703a496cf66990d57b696b2117922ee1855dff439b2bda3201b145fdb4533b7d2cfa22291a79bac67bb6b3d963dd4137b6208931f02c3ee30bfd0731443edadd5bfffec0147f5f2bd13930deace26fec0ebf0c1befe1294875fb9d8a08919fdc1697ec78d1b86c03a0db4e61bd6a9db6803fdd8e2547ead44bd48cf223b964b0c6903ede0fc0e1b7d02b83ba18ed649bc0e40896ff7cde1d092a9f30314da8fc67d113c79fe7046da75bc090b08b3f31a5d0feb33abab2c608e3afaca1521f2809ae79c14e5ab16d7fa319ddc4dbae61cf41bd15829055970f26361fc1ae22a15e401b25eb500411e70a3cacca38e0d59a6add6513c02d0e6a766303e231d8adf8368b1579e7d58a7d3a5981542c9b8fec0b1780713031fefa60d93755215cbbc34f27634537b6c4fe391578be1a3547fc97d1eeb3e8b11444e8ad99902911fba55034a2796d791039bb29bd193406f05b942f69d47a4a236a64f610e7808387586f4a96a84059e93b11355ecd9125e7a805503e41f4097893b043c7d539d76933515c8fbde11f2a69a6f47aebbac3ed29b0231b3a74ecc9a5421ad61c995a039e44c0a8717dd6e5efbdc2f6ab8daefbc58867ca2e852780c66d1163a03662c34b5365983405093452bb004f78eb973a804edb1b4e8214ab982ed9c81992cc508d8852288fee4ced3af41cca7baaddb828830f3e7dd7c92610def60bbaf6a866e84ea81bd4e88a5b5a035b15b370f942af17f213706c681a59da20b150697c188edb4ac8b59b3babf9c895078f268940aa805c15a2712042c22ce5c44a62554d5f2efb6db179e1db29570b6b063d00349a0273277751e6adf32b6d36b02cb81025d80e620b61a418b0584441c087ce75ed03c871dfe8463a9a3641b036e849fd0fdc9b381ebe43e067353642f182d67ef6bef43463dc6b8d7abd035677b443440c7624d91baa11002e193d86a76974eef4f6fb44a8c440b73ddb323e9eb8f7fdd67aa368ce6aefdff1060e6a519d48b28718b1548e4665360f141d5e16027f0e7c41d07c582dd2a29fa55a00f", "android"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int target;
	int data_length;
	int count;
	int keysize;
	unsigned char data[SZ];
	unsigned char keydata[SZ];
} *cur_salt;

/* To guard against tampering with the keystore, we append a keyed
 * hash with a bit of whitener. */
static inline void getPreKeyedHash(char *password, SHA_CTX *ctxp)
{
	int i, j;
        unsigned char passwdBytes[PLAINTEXT_LENGTH * 2];
	char *magic = "Mighty Aphrodite";
        for (i=0, j=0; i < strlen(password); i++) {
            passwdBytes[j++] = (password[i] >> 8);
            passwdBytes[j++] = password[i];
        }
	SHA1_Init(ctxp);
	SHA1_Update(ctxp, passwdBytes, strlen(password) * 2);
	SHA1_Update(ctxp, magic, 16);
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int target;
	int v;
	if (strncmp(ciphertext, "$keystore$", 10) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 10;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto bail;
	target = atoi(p);
	if (target != 1 && target != 0)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto bail;
	v = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)
		goto bail;
	if (strlen(p) != v * 2)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) /* number of keys */
		goto bail;
	/* currently we support only 1 key */
	if(atoi(p) != 1)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) /* key length */
		goto bail;
	v = atoi(p);
	if (v > SZ)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) /* key data */
		goto bail;
	if (strlen(p) != v * 2)
		goto bail;
	MEM_FREE(keeptr);
	return 1;
bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	/* NOTE: do we need dynamic allocation because of underlying large object size? */
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 10; /* skip over "$keystore$" */
	p = strtokm(ctcopy, "$");
	cs.target = atoi(p);
	p = strtokm(NULL, "$");
	cs.data_length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.data_length; i++)
		cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); /* skip hash */
	p = strtokm(NULL, "$");
	cs.count = atoi(p);
	p = strtokm(NULL, "$");
	cs.keysize = atoi(p);
	for (i = 0; i < cs.keysize; i++)
		cs.keydata[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	ctcopy += 10; /* skip over "$keystore$" */
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$"); /* at hash now */
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		SHA_CTX ctx;
		getPreKeyedHash(saved_key[index], &ctx);
		SHA1_Update(&ctx, cur_salt->data, cur_salt->data_length);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void keystore_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_keystore = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		/* FIXME: report cur_salt->data_length as tunable cost? */
		{ NULL },
#endif
		keystore_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		keystore_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
