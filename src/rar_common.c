/*
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012-2020, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "misc.h"	// error()
#include "john.h"
#include "loader.h"
#if AC_BUILT
#include "autoconfig.h"
#else
#define HAVE_UNRAR 1
#endif

#define BINARY_SIZE     sizeof(fmt_data)
#define BINARY_ALIGN    sizeof(size_t)
#define SALT_SIZE       8
#define SALT_ALIGN      MEM_ALIGN_WORD

static int threads = 1;
static unsigned char *saved_salt;
static unsigned char *saved_key;
static int (*cracked);
static unpack_data_t (*unpack_data);
static int new_keys;

static unsigned int *saved_len;
#ifndef RAR_OPENCL_FORMAT
static unsigned char *aes_key;
static unsigned char *aes_iv;
#endif

#define FORMAT_TAG          "$RAR3$*"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

#define YEL	"\x1b[0;33m"
#define NRM	"\x1b[0m"

static struct fmt_tests cpu_tests[] = {
	{"$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121", "test"},
	{"$RAR3$*0*42ff7e92f24fb2f8*9d8516c8c847f1b941a0feef064aaf0d", "1234"},
	{"$RAR3$*0*56ce6de6ddee17fb*4c957e533e00b0e18dfad6accc490ad9", "john"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*c47c5bef0bbd1e98*965f1453*48*47*1*c5e987f81d316d9dcfdb6a1b27105ce63fca2c594da5aa2f6fdf2f65f50f0d66314f8a09da875ae19d6c15636b65c815*30", "test"},
#if HAVE_UNRAR
	{"$RAR3$*1*b4eee1a48dc95d12*965f1453*64*47*1*0fe529478798c0960dd88a38a05451f9559e15f0cf20b4cac58260b0e5b56699d5871bdcc35bee099cc131eb35b9a116adaedf5ecc26b1c09cadf5185b3092e6*33", "test"},
	/* issue #2899 unrar bug */
	{"$RAR3$*1*00d7bc908cd4ad64*cc4b574e*16*7*1*58b582307dd07e0082a742d3f5d91ad3*33", "abc"},
	//{"$RAR3$*1*fa0d20d2d9868510*cc4b574e*16*7*1*48a4b1de0795cd2adb2fab5f89b4d916*33", "1я1"}, /* UTF-8 needed */
#endif /* HAVE_UNRAR */
#ifdef DEBUG
#if HAVE_UNRAR
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*1*0f263dd52eead558*834015cd*384*693*1*e28e9648f51b59e32f573b302f0e94aadf1050678b90c38dd4e750c7dd281d439ab4cccec5f1bd1ac40b6a1ead60c75625666307171e0fe2639d2397d5f68b97a2a1f733289eac0038b52ec6c3593ff07298fce09118c255b2747a02c2fa3175ab81166ebff2f1f104b9f6284a66f598764bd01f093562b5eeb9471d977bf3d33901acfd9643afe460e1d10b90e0e9bc8b77dc9ac40d40c2d211df9b0ecbcaea72c9d8f15859d59b3c85149b5bb5f56f0218cbbd9f28790777c39e3e499bc207289727afb2b2e02541b726e9ac028f4f05a4d7930efbff97d1ffd786c4a195bbed74997469802159f3b0ae05b703238da264087b6c2729d9023f67c42c5cbe40b6c67eebbfc4658dfb99bfcb523f62133113735e862c1430adf59c837305446e8e34fac00620b99f574fabeb2cd34dc72752014cbf4bd64d35f17cef6d40747c81b12d8c0cd4472089889a53f4d810b212fb314bf58c3dd36796de0feeefaf26be20c6a2fd00517152c58d0b1a95775ef6a1374c608f55f416b78b8c81761f1d*33:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*1*9759543e04fe3a22*834015cd*384*693*1*cdd2e2478e5153a581c47a201490f5d9b69e01584ae488a2a40203da9ba8c5271ed8edc8f91a7bd262bb5e5de07ecbe9e2003d054a314d16caf2ea1de9f54303abdee1ed044396f7e29c40c38e638f626442efd9f511b4743758cd4a6025c5af81d1252475964937d80bfd50d10c171e7e4041a66c02a74b2b451ae83b6807990fb0652a8cdab530c5a0c497575a6e6cbe2db2035217fe849d2e0b8693b70f3f97b757229b4e89c8273197602c23cc04ff5f24abf3d3c7eb686fc3eddce1bfe710cc0b6e8bd012928127da38c38dd8f056095982afacb4578f6280d51c6739739e033674a9413ca88053f8264c5137d4ac018125c041a3489daaf175ef75e9282d245b92948c1bbcf1c5f25b7028f6d207d87fe9598c2c7ccd1553e842a91ab8ca9261a51b14601a756070388d08039466dfa36f0b4c7ea7dd9ff25c9d98687203c58f9ec8757cafe4d2ed785d5a9e6d5ea838e4cc246a9e6d3c30979dcce56b380b05f9103e6443b35357550b50229c47f845a93a48602790096828d9d6bef0*33:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*1*79e17c26407a7d52*834015cd*384*693*1*6844a189e732e9390b5a958b623589d5423fa432d756fd00940ac31e245214983507a035d4e0ee09469491551759a66c12150fe6c5d05f334fb0d8302a96d48ef4da04954222e0705507aaa84f8b137f284dbec344eee9cea6b2c4f63540c64df3ee8be3013466d238c5999e9a98eb6375ec5462869bba43401ec95077d0c593352339902c24a3324178e08fe694d11bfec646c652ffeafbdda929052c370ffd89168c83194fedf7c50fc7d9a1fbe64332063d267a181eb07b5d70a5854067db9b66c12703fde62728d3680cf3fdb9933a0f02bfc94f3a682ad5e7c428d7ed44d5ff554a8a445dea28b81e3a2631870e17f3f3c0c0204136802c0701590cc3e4c0ccd9f15e8be245ce9caa6969fab9e8443ac9ad9e73e7446811aee971808350c38c16c0d3372c7f44174666d770e3dd321e8b08fb2dc5e8a6a5b2a1720bad66e54abc194faabc5f24225dd8fee137ba5d4c2ed48c6462618e6333300a5b8dfc75c65608925e786eb0988f7b3a5ab106a55168d1001adc47ce95bba77b38c35b*33:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*1*e1df79fd9ee1dadf*771a163b*64*39*1*edc483d67b94ab22a0a9b8375a461e06fa1108fa72970e16d962092c311970d26eb92a033a42f53027bdc0bb47231a12ed968c8d530a9486a90cbbc00040569b*33", "333"},
	{"$RAR3$*1*c83c00534d4af2db*771a163b*64*39*1*05244526d6b32cb9c524a15c79d19bba685f7fc3007a9171c65fc826481f2dce70be6148f2c3497f0d549aa4e864f73d4e4f697fdb66ff528ed1503d9712a414*33", "11eleven111"},
#endif /* HAVE_UNRAR */
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif /* DEBUG */
	{NULL}
};

#ifdef RAR_OPENCL_FORMAT
static struct fmt_tests gpu_tests[] = {
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*c47c5bef0bbd1e98*965f1453*48*47*1*c5e987f81d316d9dcfdb6a1b27105ce63fca2c594da5aa2f6fdf2f65f50f0d66314f8a09da875ae19d6c15636b65c815*30", "test"},
#if HAVE_UNRAR
	{"$RAR3$*1*b4eee1a48dc95d12*965f1453*64*47*1*0fe529478798c0960dd88a38a05451f9559e15f0cf20b4cac58260b0e5b56699d5871bdcc35bee099cc131eb35b9a116adaedf5ecc26b1c09cadf5185b3092e6*33", "test"},
	/* issue #2899 unrar bug */
	{"$RAR3$*1*00d7bc908cd4ad64*cc4b574e*16*7*1*58b582307dd07e0082a742d3f5d91ad3*33", "abc"},
	//{"$RAR3$*1*fa0d20d2d9868510*cc4b574e*16*7*1*48a4b1de0795cd2adb2fab5f89b4d916*33", "1я1"}, /* UTF-8 needed */
#endif /* HAVE_UNRAR */
#ifdef DEBUG
	{"$RAR3$*0*af24c0c95e9cafc7*e7f207f30dec96a5ad6f917a69d0209e", "magnum"},
	{"$RAR3$*0*2653b9204daa2a8e*39b11a475f486206e2ec6070698d9bbc", "123456"},
	{"$RAR3$*0*63f1649f16c2b687*8a89f6453297bcdb66bd756fa10ddd98", "abc123"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*575b083d78672e85*965f1453*48*47*1*cd3d8756438f43ab70e668792e28053f0ad7449af1c66863e3e55332bfa304b2c082b9f23b36cd4a8ebc0b743618c5b2*30", "magnum"},
#if HAVE_UNRAR
	{"$RAR3$*1*6f5954680c87535a*965f1453*64*47*1*c9bb398b9a5d54f035fd22be54bc6dc75822f55833f30eb4fb8cc0b8218e41e6d01824e3467475b90b994a5ddb7fe19366d293c9ee305316c2a60c3a7eb3ce5a*33", "magnum"},
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*1*0f263dd52eead558*834015cd*384*693*1*e28e9648f51b59e32f573b302f0e94aadf1050678b90c38dd4e750c7dd281d439ab4cccec5f1bd1ac40b6a1ead60c75625666307171e0fe2639d2397d5f68b97a2a1f733289eac0038b52ec6c3593ff07298fce09118c255b2747a02c2fa3175ab81166ebff2f1f104b9f6284a66f598764bd01f093562b5eeb9471d977bf3d33901acfd9643afe460e1d10b90e0e9bc8b77dc9ac40d40c2d211df9b0ecbcaea72c9d8f15859d59b3c85149b5bb5f56f0218cbbd9f28790777c39e3e499bc207289727afb2b2e02541b726e9ac028f4f05a4d7930efbff97d1ffd786c4a195bbed74997469802159f3b0ae05b703238da264087b6c2729d9023f67c42c5cbe40b6c67eebbfc4658dfb99bfcb523f62133113735e862c1430adf59c837305446e8e34fac00620b99f574fabeb2cd34dc72752014cbf4bd64d35f17cef6d40747c81b12d8c0cd4472089889a53f4d810b212fb314bf58c3dd36796de0feeefaf26be20c6a2fd00517152c58d0b1a95775ef6a1374c608f55f416b78b8c81761f1d*33:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*1*9759543e04fe3a22*834015cd*384*693*1*cdd2e2478e5153a581c47a201490f5d9b69e01584ae488a2a40203da9ba8c5271ed8edc8f91a7bd262bb5e5de07ecbe9e2003d054a314d16caf2ea1de9f54303abdee1ed044396f7e29c40c38e638f626442efd9f511b4743758cd4a6025c5af81d1252475964937d80bfd50d10c171e7e4041a66c02a74b2b451ae83b6807990fb0652a8cdab530c5a0c497575a6e6cbe2db2035217fe849d2e0b8693b70f3f97b757229b4e89c8273197602c23cc04ff5f24abf3d3c7eb686fc3eddce1bfe710cc0b6e8bd012928127da38c38dd8f056095982afacb4578f6280d51c6739739e033674a9413ca88053f8264c5137d4ac018125c041a3489daaf175ef75e9282d245b92948c1bbcf1c5f25b7028f6d207d87fe9598c2c7ccd1553e842a91ab8ca9261a51b14601a756070388d08039466dfa36f0b4c7ea7dd9ff25c9d98687203c58f9ec8757cafe4d2ed785d5a9e6d5ea838e4cc246a9e6d3c30979dcce56b380b05f9103e6443b35357550b50229c47f845a93a48602790096828d9d6bef0*33:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*1*79e17c26407a7d52*834015cd*384*693*1*6844a189e732e9390b5a958b623589d5423fa432d756fd00940ac31e245214983507a035d4e0ee09469491551759a66c12150fe6c5d05f334fb0d8302a96d48ef4da04954222e0705507aaa84f8b137f284dbec344eee9cea6b2c4f63540c64df3ee8be3013466d238c5999e9a98eb6375ec5462869bba43401ec95077d0c593352339902c24a3324178e08fe694d11bfec646c652ffeafbdda929052c370ffd89168c83194fedf7c50fc7d9a1fbe64332063d267a181eb07b5d70a5854067db9b66c12703fde62728d3680cf3fdb9933a0f02bfc94f3a682ad5e7c428d7ed44d5ff554a8a445dea28b81e3a2631870e17f3f3c0c0204136802c0701590cc3e4c0ccd9f15e8be245ce9caa6969fab9e8443ac9ad9e73e7446811aee971808350c38c16c0d3372c7f44174666d770e3dd321e8b08fb2dc5e8a6a5b2a1720bad66e54abc194faabc5f24225dd8fee137ba5d4c2ed48c6462618e6333300a5b8dfc75c65608925e786eb0988f7b3a5ab106a55168d1001adc47ce95bba77b38c35b*33:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*1*e1df79fd9ee1dadf*771a163b*64*39*1*edc483d67b94ab22a0a9b8375a461e06fa1108fa72970e16d962092c311970d26eb92a033a42f53027bdc0bb47231a12ed968c8d530a9486a90cbbc00040569b*33", "333"},
	{"$RAR3$*1*c83c00534d4af2db*771a163b*64*39*1*05244526d6b32cb9c524a15c79d19bba685f7fc3007a9171c65fc826481f2dce70be6148f2c3497f0d549aa4e864f73d4e4f697fdb66ff528ed1503d9712a414*33", "11eleven111"},
#endif /* HAVE_UNRAR */
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif /* DEBUG */
	{NULL}
};
#endif

typedef struct {
	uint64_t pack_size;
	uint64_t unp_size;
#ifdef RAR_OPENCL_FORMAT
	uint64_t gpu_size;
	unsigned char last_iv[16];
	unsigned char last_data[16];
#endif
	int type;	/* 0 = -hp, 1 = -p */
	/* for rar -p mode only: */
	union {
		unsigned int w;
		unsigned char c[4];
	} crc;
	int method;
	unsigned char data[1];
} rar_file;

static void set_key(char *key, int index)
{
	int plen;
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	/* UTF-16LE encode the password, encoding aware */
	plen = enc_to_utf16(buf, PLAINTEXT_LENGTH, (UTF8*) key, strlen(key));

	if (plen < 0)
		plen = strlen16(buf);

	memcpy(&saved_key[UNICODE_LENGTH * index], buf, UNICODE_LENGTH);

	saved_len[index] = plen << 1;

	new_keys = 1;
}

static void *get_binary(char *ciphertext)
{
	static fmt_data out;
	rar_file *file = NULL;
	unsigned int i, type, ex_len;
	char *saltcopy = xstrdup(ciphertext);
	char *keep_ptr = saltcopy;
	int inlined = 1;

	memset(&out, 0, sizeof(out));

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return &out;

	saltcopy += FORMAT_TAG_LEN;		/* skip over "$RAR3$*" */
	type = atoi(strtokm(saltcopy, "*"));
	strtokm(NULL, "*");

	if (type == 0) {	/* rar-hp mode */
		char *encoded_ct = strtokm(NULL, "*");

		ex_len = 16;
		out.size = sizeof(rar_file) + ex_len;
		out.flags = FMT_DATA_TINY;
		file = mem_calloc_tiny(out.size, BINARY_ALIGN);
		out.blob = file;

		file->type = type;

		for (i = 0; i < 16; i++)
			file->data[i] = atoi16[ARCH_INDEX(encoded_ct[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_ct[i * 2 + 1])];

		file->pack_size = 16;
#ifdef RAR_OPENCL_FORMAT
		file->gpu_size = 16;
#endif
	}
	else {
		char *p = strtokm(NULL, "*");
		char crc_c[4];
		uint64_t pack_size;
		uint64_t unp_size;

		for (i = 0; i < 4; i++)
			crc_c[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
		pack_size = atoll(strtokm(NULL, "*"));
		unp_size = atoll(strtokm(NULL, "*"));
		inlined = atoi(strtokm(NULL, "*"));
		ex_len = pack_size;

		/* load ciphertext. We allocate and load all files
		   here, and they are freed when password found. */
		out.size = sizeof(rar_file) + ex_len;
		out.flags = FMT_DATA_ALLOC;
		file = mem_calloc(1, out.size);
		out.blob = file;

		file->type = type;
		file->pack_size = pack_size;
		file->unp_size = unp_size;
		memcpy(file->crc.c, crc_c, 4);

		if (inlined) {
			unsigned char *d = file->data;

			p = strtokm(NULL, "*");
			for (i = 0; i < file->pack_size; i++)
				*d++ = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
					atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
		else {
			FILE *fp;
			char *archive_name = strtokm(NULL, "*");
			long long pos = atoll(strtokm(NULL, "*"));
			size_t count;

			if (!(fp = fopen(archive_name, "rb"))) {
				fprintf(stderr, "! %s: %s\n", archive_name, strerror(errno));
				error();
			}
			jtr_fseek64(fp, pos, SEEK_SET);
			count = fread(file->data, 1, file->pack_size, fp);
			if (count != file->pack_size) {
				fprintf(stderr, "Error loading file from archive '%s', expected %"PRIu64" bytes, got "Zu". Archive possibly damaged.\n", archive_name, file->pack_size, count);
				error();
			}
			fclose(fp);
		}
#ifdef RAR_OPENCL_FORMAT
		if (file->pack_size > 16)
			memcpy(file->last_iv, file->data + file->pack_size - 32, 16);
		memcpy(file->last_data, file->data + file->pack_size - 16, 16);
#endif
		p = strtokm(NULL, "*");
		file->method = atoi16[ARCH_INDEX(p[0])] * 16 + atoi16[ARCH_INDEX(p[1])];

#ifdef RAR_OPENCL_FORMAT
		if (file->method == 0x30) {
			int pad_size = (16 - (unp_size & 15)) & 15;
			unsigned int speed = opencl_speed_index(gpu_id) / 100;
			size_t max_gpu_mem = get_max_mem_alloc_size(gpu_id) - sizeof(rar_file);
			size_t mem_threshold;

			mem_threshold = MIN(speed * pad_size, max_gpu_mem);

			file->gpu_size = (pack_size > mem_threshold) ? 16 : pack_size;
		} else
			file->gpu_size = 16;
#endif
		if (file->method != 0x30)
#if ARCH_LITTLE_ENDIAN
			file->crc.w = ~file->crc.w;
#else
			file->crc.w = JOHNSWAP(~file->crc.w);
#endif
	}

#ifdef RAR_OPENCL_FORMAT
	max_blob_size = MAX(max_blob_size, sizeof(rar_file) + file->gpu_size);

	if (!ocl_autotune_running)
#endif
	if (options.verbosity > VERB_DEFAULT && john_main_process && !ldr_in_pot && !bench_or_test_running) {
		if (file->method == 0x30) {
			fprintf(stderr, YEL "%.32s(...) 0x30 size %"PRIu64", pad size %d\n" NRM,
			        ciphertext, file->unp_size, (int)(16 - (file->unp_size & 15)) & 15);
		} else if (file->type == 0)
			fprintf(stderr, YEL "%.32s(...) solid\n" NRM, ciphertext);
		else
			fprintf(stderr, YEL "%.32s(...) 0x%02x size %"PRIu64"\n" NRM, ciphertext, file->method, file->pack_size);
	}


	MEM_FREE(keep_ptr);
	return &out;
}

static void *get_salt(char *ciphertext)
{
	static union {
		uint8_t tmp_salt[8];
		uint32_t dummy[2];
	} out;
	unsigned int i;
	char *p;

	ciphertext += FORMAT_TAG_LEN;	/* skip over "$RAR3$*" */
	p = strchr(ciphertext , '*');

	if (p++)
		for (i = 0; i < 8; i++)
			out.tmp_salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
	else
		memset(&out, 0, sizeof(out));

	return out.tmp_salt;
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, 8);

#ifdef RAR_OPENCL_FORMAT
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE,
	                                    0, 8, saved_salt, 0, NULL, NULL),
	               "failed in clEnqueueWriteBuffer saved_salt");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int mode, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	if (!(ctcopy = xstrdup(ciphertext))) {
		fprintf(stderr, "Memory allocation failed in %s, unable to check if hash is valid!", FORMAT_LABEL);
		return 0;
	}
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* -p or -h mode */
		goto error;
	if (strlen(ptr) != 1 || !isdec(ptr))
		goto error;
	mode = atoi(ptr);
	if (mode > 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlenl(ptr, &extra) != 16 || extra) /* 8 bytes of salt */
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (mode == 0) {
		if (hexlenl(ptr, &extra) != 32 || extra) /* 16 bytes of encrypted known plain */
			goto error;
		MEM_FREE(keeptr);
		return 1;
	} else {
		int inlined;
		long long plen, ulen;

		if (hexlenl(ptr, &extra) != 8 || extra) /* 4 bytes of CRC */
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* pack_size */
			goto error;
		if (strlen(ptr) > 12) { // pack_size > 1 TB? Really?
			static int warn_once_pack_size = 1;
			if (warn_once_pack_size) {
				fprintf(stderr, "pack_size > 1TB not supported (%s)\n", FORMAT_NAME);
				warn_once_pack_size = 0;
			}
			goto error;
		}
		if ((plen = atoll(ptr)) < 16)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* unp_size */
			goto error;
		if (strlen(ptr) > 12) {
			static int warn_once_unp_size = 1;
			if (warn_once_unp_size) {
				fprintf(stderr, "unp_size > 1TB not supported (%s)\n", FORMAT_NAME);
				warn_once_unp_size = 0;
			}
			goto error;
		}
		if ((ulen = atoll(ptr)) < 1)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* inlined */
			goto error;
		if (strlen(ptr) != 1 || !isdec(ptr))
			goto error;
		inlined = atoi(ptr);
		if (inlined > 1)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* pack_size / archive_name */
			goto error;
		if (inlined) {
			if (hexlenl(ptr, &extra) != plen * 2 || extra)
				goto error;
		} else {
			FILE *fp;
			char *archive_name;
			archive_name = ptr;
			if (!(fp = fopen(archive_name, "rb"))) {
				if (!ldr_in_pot)
				fprintf(stderr, "! %s: %s, skipping.\n", archive_name, strerror(errno));
				goto error;
			}
			if (!(ptr = strtokm(NULL, "*"))) /* pos */
				goto error;
			/* We could go on and actually try seeking to pos
			   but this is enough for now */
			fclose(fp);
		}
		if (!(ptr = strtokm(NULL, "*"))) /* method */
			goto error;
#if !HAVE_UNRAR
		if (atoi(ptr) != 30) {
			static int warned;

			if (!warned++ && john_main_process)
				fprintf(stderr, "Warning: Packed RAR hash(es) seen but ignored, this build does not support them.\n");
			goto error;
		}
#endif
	}
	MEM_FREE(keeptr);
	return 1;

error:
#ifdef RAR_DEBUG
	{
		char buf[68];
		strnzcpy(buf, ciphertext, sizeof(buf));
		fprintf(stderr, "rejecting %s\n", buf);
	}
#endif
	MEM_FREE(keeptr);
	return 0;
}

static char *get_key(int index)
{
	UTF16 tmpbuf[PLAINTEXT_LENGTH + 1];

	memcpy(tmpbuf, &((UTF16*) saved_key)[index * PLAINTEXT_LENGTH], saved_len[index]);
	memset(&tmpbuf[saved_len[index] >> 1], 0, 2);
	return (char*) utf16_to_enc(tmpbuf);
}

#define ADD_BITS(n)	\
	{ \
		if (bits < 9) { \
			hold |= ((unsigned int)*next++ << (24 - bits)); \
			bits += 8; \
		} \
		hold <<= n; \
		bits -= n; \
	}

#if HAVE_UNRAR
/*
 * This function is loosely based on JimF's check_inflate_CODE2() from
 * pkzip_fmt. Together with the other bit-checks, we are rejecting over 96%
 * of the candidates without resorting to a slow full check (which in turn
 * may reject semi-early, especially if it's a PPM block)
 *
 * Input is first 16 bytes of RAR buffer decrypted, as-is. It also contain the
 * first 2 bits, which have already been decoded, and have told us we had an
 * LZ block (RAR always use dynamic Huffman table) and keepOldTable was not set.
 *
 * RAR use 20 x (4 bits length, optionally 4 bits zerocount), and reversed
 * byte order.
 */
static MAYBE_INLINE int check_huffman(unsigned char *next) {
	unsigned int bits, hold, i;
	int left;
	unsigned int ncount[4];
	unsigned char *count = (unsigned char*)ncount;
	unsigned char bit_length[20];

#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
	hold = JOHNSWAP(*(unsigned int*)next);
#else
	hold = next[3] + (((unsigned int)next[2]) << 8) + (((unsigned int)next[1]) << 16) + (((unsigned int)next[0]) << 24);
#endif
	next += 4;	// we already have the first 32 bits
	hold <<= 2;	// we already processed 2 bits, PPM and keepOldTable
	bits = 32 - 2;

	/* First, read 20 pairs of (bitlength[, zerocount]) */
	for (i = 0 ; i < 20 ; i++) {
		int length, zero_count;

		length = hold >> 28;
		ADD_BITS(4);
		if (length == 15) {
			zero_count = hold >> 28;
			ADD_BITS(4);
			if (zero_count == 0) {
				bit_length[i] = 15;
			} else {
				zero_count += 2;
				while (zero_count-- > 0 && i < sizeof(bit_length) / sizeof(bit_length[0]))
					bit_length[i++] = 0;
				i--;
			}
		} else {
			bit_length[i] = length;
		}
	}

	/* Count the number of codes for each code length */
	memset(count, 0, 16);
	for (i = 0; i < 20; i++) {
		++count[bit_length[i]];
	}

	count[0] = 0;
	if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3])
		return 0; /* No codes at all */

	left = 1;
	for (i = 1; i < 16; ++i) {
		left <<= 1;
		left -= count[i];
		if (left < 0) {
			return 0; /* over-subscribed */
		}
	}
	if (left) {
		return 0; /* incomplete set */
	}
	return 1; /* Passed this check! */
}
#endif

inline static void check_rar(rar_file *cur_file, int index, unsigned char *key, const unsigned char *_iv)
{
	AES_KEY aes_ctx;
	unsigned char iv[16];
	unsigned char plain[16 + 8]; /* Some are safety margin for check_huffman() */

	memcpy(iv, _iv, 16);

	/* AES decrypt, uses aes_iv, aes_key and blob */
	if (cur_file->type == 0) {	/* rar-hp mode */
		AES_set_decrypt_key(key, 128, &aes_ctx);
		AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, iv, AES_DECRYPT);

		cracked[index] = !memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);
		return;
	} else {
		if (cur_file->method == 0x30) {	/* stored, not deflated */
			CRC32_t crc;
			unsigned char crc_out[4];
			uint64_t size = cur_file->unp_size;
			unsigned char *cipher = cur_file->data;

			/* Check padding for early rejection, when possible */
			if (cur_file->unp_size % 16) {
				const char zeros[16] = { 0 };
				const int pad_start = cur_file->unp_size % 16;
				const int pad_size = 16 - pad_start;
				unsigned char last_iv[16];

				AES_set_decrypt_key(key, 128, &aes_ctx);

				if (cur_file->pack_size < 32) {
					memcpy(last_iv, iv, 16);
					AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, last_iv, AES_DECRYPT);
				} else {
					memcpy(last_iv, cur_file->data + cur_file->pack_size - 32, 16);
					AES_cbc_encrypt(cur_file->data + cur_file->pack_size - 16, plain,
					                16, &aes_ctx, last_iv, AES_DECRYPT);
				}
				if (!(cracked[index] = !memcmp(&plain[pad_start], zeros, pad_size)))
					return;
			}

			/* Use full decryption with CRC check.
			   Compute CRC of the decompressed plaintext */
			CRC32_Init(&crc);
			AES_set_decrypt_key(key, 128, &aes_ctx);

			while (size) {
				unsigned int inlen = (size > 16) ? 16 : size;

				AES_cbc_encrypt(cipher, plain, 16, &aes_ctx, iv, AES_DECRYPT);
				CRC32_Update(&crc, plain, inlen);

				size -= inlen;
				cipher += inlen;
			}
			CRC32_Final(crc_out, crc);

			/* Compare computed CRC with stored CRC */
			cracked[index] = !memcmp(crc_out, &cur_file->crc.c, 4);
			return;
		}
#if HAVE_UNRAR
		else {
			const int solid = 0;
			unpack_data_t *unpack_t;
			unsigned char pre_iv[16];

			memcpy(pre_iv, iv, 16);

			/* Decrypt just one block for early rejection */
			AES_set_decrypt_key(key, 128, &aes_ctx);
			AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, pre_iv, AES_DECRYPT);

			/* Early rejection */
			if (plain[0] & 0x80) {
				// PPM checks here.
				if (!(plain[0] & 0x20) ||    // Reset bit must be set
				    (plain[1] & 0x80)) {     // MaxMB must be < 128
					cracked[index] = 0;
					return;
				}
			} else {
				// LZ checks here.
				if ((plain[0] & 0x40) ||     // KeepOldTable can't be set
				    !check_huffman(plain)) { // Huffman table check
					cracked[index] = 0;
					return;
				}
			}

#ifdef _OPENMP
			unpack_t = &unpack_data[omp_get_thread_num()];
#else
			unpack_t = unpack_data;
#endif
			unpack_t->max_size = cur_file->unp_size;
			unpack_t->dest_unp_size = cur_file->unp_size;
			unpack_t->pack_size = cur_file->pack_size;
			unpack_t->iv = iv;
			unpack_t->ctx = &aes_ctx;
			unpack_t->key = key;

			/* Reset key for full deflate check */
			AES_set_decrypt_key(key, 128, &aes_ctx);
			if (rar_unpack29(cur_file->data, solid, unpack_t))
				cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
			else
				cracked[index] = 0;
		}
#endif /* HAVE_UNRAR */
	}
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int salt_hash(void *salt)
{
	unsigned char *s = (unsigned char*)salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}
