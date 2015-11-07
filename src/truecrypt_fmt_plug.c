/* TrueCrypt volume support to John The Ripper
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2012.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2012 Alain Espinosa and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 * Updated in Dec, 2014 by JimF.  This is a ugly format, and was converted
 * into a more standard (using crypt_all) format.  The PKCS5_PBKDF2_HMAC can
 * be replaced with faster pbkdf2_xxxx functions (possibly with SIMD usage).
 * this has been done for sha512.  ripemd160  and Whirlpool pbkdf2 header
 * files have been created.  Also, proper decrypt is now done, (in cmp_exact)
 * and we test against the 'TRUE' signature, and against 2 crc32's which
 * are computed over the 448 bytes of decrypted data.  So we now have a
 * full 96 bits of hash.  There will be no way we get false positives from
 * this slow format. EVP_AES_XTS removed. Also, we now only pbkdf2 over
 * 64 bytes of data (all that is needed for the 2 AES keys), and that sped
 * up the crypts A LOT (~3x faster)
 *
 */

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_truecrypt;
extern struct fmt_main fmt_truecrypt_ripemd160;
extern struct fmt_main fmt_truecrypt_sha512;
extern struct fmt_main fmt_truecrypt_whirlpool;
#elif FMT_REGISTERS_H
john_register_one(&fmt_truecrypt);
john_register_one(&fmt_truecrypt_ripemd160);
john_register_one(&fmt_truecrypt_sha512);
john_register_one(&fmt_truecrypt_whirlpool);
#else

#include "aes.h"
#include <string.h>
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "crc32.h"
#include "johnswap.h"
#define PBKDF2_HMAC_SHA512_ALSO_INCLUDE_CTX
#include "pbkdf2_hmac_sha512.h"
#include "pbkdf2_hmac_ripemd160.h"
#include "pbkdf2_hmac_whirlpool.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#ifdef __MIC__
#define OMP_SCALE               4
#else
#define OMP_SCALE               1
#endif // __MIC__
#endif // OMP_SCALE
#endif // _OPENMP
#include "memdbg.h"

/* 64 is the actual maximum used by Truecrypt software as of version 7.1a */
#define PLAINTEXT_LENGTH	64
#define MAX_CIPHERTEXT_LENGTH	(512*2+32)
#define SALT_SIZE		sizeof(struct cust_salt)
#define SALT_ALIGN		4
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static unsigned char (*key_buffer)[PLAINTEXT_LENGTH + 1];
static unsigned char (*first_block_dec)[16];

#define TAG_WHIRLPOOL "truecrypt_WHIRLPOOL$"
#define TAG_SHA512    "truecrypt_SHA_512$"
#define TAG_RIPEMD160 "truecrypt_RIPEMD_160$"
#define TAG_WHIRLPOOL_LEN (sizeof(TAG_WHIRLPOOL)-1)
#define TAG_SHA512_LEN    (sizeof(TAG_SHA512)-1)
#define TAG_RIPEMD160_LEN (sizeof(TAG_RIPEMD160)-1)

#define IS_SHA512 1
#define IS_RIPEMD160 2
#define IS_WHIRLPOOL 3

// borrowed from https://github.com/bwalex/tc-play
#define MAX_PASSSZ              64
#define PASS_BUFSZ              256
#define KPOOL_SZ                64
#define MAX_KFILE_SZ            1048576 /* 1 MB */
#define MAX_KEYFILES            256

// keyfile(s) data
unsigned char (*keyfiles_data)[MAX_KFILE_SZ];
int (*keyfiles_length);

struct cust_salt {
	unsigned char salt[64];
	// I 'thought' that bin[] could be removed, so that only salt[] was used
	// for salt dupe-removal. That was wrong, bin[] must also be part of the
	// salt dupe logic, or we will get wrong passwords found, if there is
	// hashes with the same salts.  bin[] array really is part of the salt
	// since we decrypt it, to do the final check. So there is no real way
	// to have any duplicate salts. in essense, we have a 'fixed' binary
	// and the salt is the entire input hash. The fixed binary can be
	// thought of as 'TRUE' (but it is more than this).  It is simply we
	// do not know the real binary until after we correctly decrypt.
	// Initially I moved bin[] and ported to dyna_salt. All hashes in a
	// test suite cracked, BUT the same password was used for all of them,
	// the first password in the file.  Not what we wanted.
	unsigned char bin[512-64];
	int loop_inc;
	int num_iterations;
	int hash_type;
	int nkeyfiles;
} *psalt;

static struct fmt_tests tests_ripemd160[] = {
{"truecrypt_RIPEMD_160$b9f118f89d2699cbe42cad7bc2c61b0822b3d6e57e8d43e79f55666aa30572676c3aced5f0900af223e9fcdf43ac39637640977f546eb714475f8e2dbf5368bfb80a671d7796d4a88c36594acd07081b7ef0fbead3d3a0ff2b295e9488a5a2747ed97905436c28c636f408b36b0898aad3c4e9566182bd55f80e97a55ad9cf20899599fb775f314067c9f7e6153b9544bfbcffb53eef5a34b515e38f186a2ddcc7cd3aed635a1fb4aab98b82d57341ec6ae52ad72e43f41aa251717082d0858bf2ccc69a7ca00daceb5b325841d70bb2216e1f0d4dc936b9f50ebf92dbe2abec9bc3babea7a4357fa74a7b2bcce542044552bbc0135ae35568526e9bd2afde0fa4969d6dc680cf96f7d82ec0a75b6170c94e3f2b6fd98f2e6f01db08ce63f1b6bcf5ea380ed6f927a5a8ced7995d83ea8e9c49238e8523d63d6b669ae0d165b94f1e19b49922b4748798129eed9aa2dae0d2798adabf35dc4cc30b25851a3469a9ee0877775abca26374a4176f8d237f8191fcc870f413ffdbfa73ee22790a548025c4fcafd40f631508f1f6c8d4c847e409c839d21ff146f469feff87198bc184db4b5c5a77f3402f491538503f68e0116dac76344b762627ad678de76cb768779f8f1c35338dd9f72dcc1ac337319b0e21551b9feb85f8cac67a2f35f305a39037bf96cd61869bf1761abcce644598dad254990d17f0faa4965926acb75abf", "password" },
{"truecrypt_RIPEMD_160$6ab053e5ebee8c56bce5705fb1e03bf8cf99e2930232e525befe1e45063aa2e30981585020a967a1c45520543847cdb281557e16c81cea9d329b666e232eeb008dbe3e1f1a181f69f073f0f314bc17e255d42aaa1dbab92231a4fb62d100f6930bae4ccf6726680554dea3e2419fb67230c186f6af2c8b4525eb8ebb73d957b01b8a124b736e45f94160266bcfaeda16b351ec750d980250ebb76672578e9e3a104dde89611bce6ee32179f35073be9f1dee8da002559c6fab292ff3af657cf5a0d864a7844235aeac441afe55f69e51c7a7c06f7330a1c8babae2e6476e3a1d6fb3d4eb63694218e53e0483659aad21f20a70817b86ce56c2b27bae3017727ff26866a00e75f37e6c8091a28582bd202f30a5790f5a90792de010aebc0ed81e9743d00518419f32ce73a8d3f07e55830845fe21c64a8a748cbdca0c3bf512a4938e68a311004538619b65873880f13b2a9486f1292d5c77116509a64eb0a1bba7307f97d42e7cfa36d2b58b71393e04e7e3e328a7728197b8bcdef14cf3f7708cd233c58031c695da5f6b671cc5066323cc86bb3c6311535ad223a44abd4eec9077d70ab0f257de5706a3ff5c15e3bc2bde6496a8414bc6a5ed84fe9462b65efa866312e0699e47338e879ae512a66f3f36fc086d2595bbcff2e744dd1ec283ba8e91299e62e4b2392608dd950ede0c1f3d5b317b2870ead59efe096c054ea1", "123" },
	{NULL}
};
static struct fmt_tests tests_sha512[] = {
{"truecrypt_SHA_512$aa582afe64197a3cfd4faf7697673e5e14414369da3f716400414f63f75447da7d3abdc65a25ea511b1772d67370d6c349d8000de66d65861403093fecfb85719e1d46158d24324e5a2c0ee598214b1b2e7eac761dbde8cb85bcb33f293df7f30c9e44a3fa97bf1c70e9986677855873fa2435d9154ccaed8f28d68f16b10adcce7032d7c1742d322739d02c05457859abdaa176faa95c674d2a1092c30832dd2afd9a319599b4d1db92ffe6e48b3b29e566d5c51af091839699f5ad1715730fef24e94e39a6f40770b8320e30bf972d810b588af88ce3450337adbec0a10255b20230bcfca93aa5a0a6592cd6038312181c0792c59ec9e5d95a6216497d39ae28131869b89368e82371718970bf9750a7114c83d87b1b0cd16b6e8d41c4925d15ec26107e92847ec1bb73363ca10f3ad62afa8b0f95ff13cdbe217a1e8a74508ef439ed2140b26d5538b8d011a0d1e469f2a6962e56964adc75b90d9c6a16e88ad0adb59a337f8abb3f9d76f7f9acad22853e9dbbce13a4f686c6a802243b0901972af3c6928511609ac7b957b352452c4347acd563a72faa86a46522942fdc57f32d48c5148a2bb0bc2c3dbc9851385f816f2ece958957082c0a8fe69f647be675d87fcb8244912abc277a3242ee17e1d522f85598417559cb3a9f60b755e5b613069cb54c05a4c5d2fbd3ca6ba793320aeb0e109f8b21852daf2d9ed74dd9", "password"},
{"truecrypt_SHA_512$73f6b08614dc4ffbd77d27a0815b0700d6b612f573ccd6c8937e8d154321e3c1c1c67dd348d4d3bc8304e94a3a6ec0c672de8396a9a6b26b12393195b7daa4225a9d3a134229be011f8179791bb00c31b5c132c8dbad5a6f8738487477c409b3c32d90b07be8d7a3a9faa95d37ab6faccc459d47f029e25adcea48cee83eaa35b7acc3f849717000421d92ac46e6f16ec3dccacd3ffae76a48280977d2a6727027d9d6ff9c4c98405359ee382f6dd1eca0d7007cbe804b81485c1085e74b58d3eb1e3c7ebdc1e1ab1384e4440ab6ca7beed7e0ef7d1e0da5ffc3cd89f7b6ac8a9257ee369d397ac1e112f75382ddbe6f7317ec20c46cb7b2111d0d91570e90b4c01a0b8205fcdf4d0cadcf4a067b8f285a541f1d649894fb3ade29a2ee0575524455d489c299dde215bea3254f7d43aa4e4011a39bdb6e7473bc29f588e659fdbf065cc4a336ba42f2b6c07479cf3e544978150fb013da7db22afcb4f8384e39e2edfa30a4cbe5e84a07c54ba66663bb9284836cc5a8ba7489d3f7f92aec6d9f4e264c90c2af6181082bd273197bc42c325cb1de31006dd55425e3f210d2ddd7973978eec865d3226bb1e30a9897146d90d79a73070e87f0182981ea85f15f948ae1958af7704fabecd6f07e20be70be9f9c38a5c5e5c8b17be648f011b2c40f62d6ac51de932add5bdb47bb428fd510b004a7aa79321b03ed7aa202be439fbf", "password" },
{"truecrypt_SHA_512$cfd9e5757da139b32d117cd60f86f649400615dc218981106dfadd44598599a7ec0ace42de61506fe8d81b5c885861cdb26e0c38cb9adfcff27ba88872220ccd0914d4fa44bab5a708fe6864e0f665ac71d87e7e97b3724d610cf1f6ec09fa99da40126f63868654fed3381eaa8176f689e8e292c3cb68e43601d5804bc2e19d86722c21d42204e158b26b720e7b8f7580edce15469195dd7ed711b0fcb6c8abc253d0fd93cc784d5279de527fbdcfb357780635a5c363b773b55957d7efb472f6e6012489a9f0d225573446e5251cfb277a1365eed787e0da52f02d835667d74cc41fa4002cc35ad1ce276fbf9d73d6553ac0f8ab6961901d292a66df814a2cbda1b41f29aeec88ed15e7d37fe84ac5306b5a1b8d2e1f2c132e5c7d40ca7bb76d4ff87980ca4d75eaac5066b3ed50b53259554b9f922f7cee8e91847359d06e448da02cbeeecc78ca9bee2899a33dfa04a478ca131d33c64d6de5f81b219f11bed6ff3c0d56f26b3a27c79e7c55b6f76567a612166ce71028e3d3ae7e5abd25faec5e2e9dc30719baa2c138e26d6f8e3799a72b5e7b1c2a07c12cea452073b72f6e429bb17dd23fe3934c9e406bb4060083f92aa100c2e82ca40664f65c02cbc800c5696659f8df84db17edb92de5d4f1ca9e5fe71844e1e8c4f8b19ce7362fb3ca5467bf65122067c53f011648a6663894b315e6c5c635bec5bd39da028041", "123" },
	/* test vector with single keyfile, with data "1234567" */
	{NULL}
};
static struct fmt_tests tests_whirlpool[] = {
{"truecrypt_WHIRLPOOL$5724ba89229d705010ec56af416b16155682a0cab9cf48ac5a5fdd2086c9a251ae4bbea6cfb8464321a789852f7812095b0e0c4c4f9c6d14ba7beedaf3484b375ac7bc97b43c3e74bf1a0c259b7ac8725d990d2ff31935ca3443f2ce8df59de86515da3e0f53f728882b71c5cc704df0c87c282a7413db446e9a2e516a144311dd25092eb0a2c5df0240d899708289fc7141abd8538fa5791d9f96c39129cce9fe8a6e58e84364e2f4acc32274147431cb2d2480b1b54bffee485acee0925852b8a6ee71d275f028b92e540be595448e5f1d78560a3b8ad209962dd5981d7ca98db9a678a588a9296157d44502cd78f9e32f022dddc9bc8111b5704ee39a9b56d30b89898ae340e90f2e6c73be6ac64de97e32fc2eed0b66dcd5c1553eeab3950cf851624a5a4439435a6fd5717fda6d5f939f4a902321341964c16bda8975752ba150fb9d858d8eaff2a2086cb50d30abff741ee20223b4223b1783f0ed537a609a081afed952395ef0b5de6883db66cbb5a8bac70f2f757c7b6e6bb5d863672820f0d3d61b262b2b6c2ca0dc8e7137851aa450da1c1d915e005bff0e849a89bf67693ef97f5c17bf8d07a18c562dc783274f9ec580f9519a6dd1429b66160ddb04549506ad616dd0695da144fa2ad270eac7163983e9036f1bde3c7634b8a246b8dcd518ce3e12b881c838fbce59a0cfdffa3b21447e3f28124f63549c3962", "password" },
{"truecrypt_WHIRLPOOL$0650595770851981d70b088ff6ef4bf90573e08d03c8cac8b2dfded22e1653f5c45103758c68be344fdccae42b4683087da083a3841b92fb79856798eaee793c04cd95ae556d9616684da17e47bd2f775d8128f94b80b781e4cab4921b12c620721cf719ca72d3997cea829fd29b429282b597d5719c13423cdf7bd717fa12a56b8eddcf7b1ad2796c4ad078ab3a9bd944a694aa4b0078ed160440dd3db13dd1d04a7aaaa4dc016a95bd1cfafcd833ae933c627bf5512ae55c76069af7190823dba0133d6fe02e4421d3684ff2a2493da990a3cc5eed40a9e8c48c7a89a2f47030d45c324a3d78b941e772e24b285af6739ae1f5953ff838edaa69e79939f55d0fe00cd0e3a20a46db3a232009eabc800711342f7e580ba909f16c2039d4900fd4025845a385641a6037ceb6420fe7d37868e8c06e6146eddec9e6cb97e71048da5fa5898dac08152516ea1c6729e85d31596cd226aa218ce693989efb9fa8b05404bcc2debbc75c429a03fe31bfc49f10d595b898436ff6b02fc01d745b91280f26ae94a4969ce7f86c12e6b562c7b5377e3fb3247a8cda11a930c2a9e80f24966925de01afad5987ebee9c3de1d41667c6dc35cebbbc963f263c700d06a647ab7020385e3a7e30406f3e7a9b3142d39e0439c98948134d11166b621dfd3ea9d3a84d985b2aa7732b7ad9beba44334dd86292b0c94befb2cb8aa72a823129cb", "123" },
	{NULL}
};
static struct fmt_tests tests_all[] = {
{"truecrypt_SHA_512$aa582afe64197a3cfd4faf7697673e5e14414369da3f716400414f63f75447da7d3abdc65a25ea511b1772d67370d6c349d8000de66d65861403093fecfb85719e1d46158d24324e5a2c0ee598214b1b2e7eac761dbde8cb85bcb33f293df7f30c9e44a3fa97bf1c70e9986677855873fa2435d9154ccaed8f28d68f16b10adcce7032d7c1742d322739d02c05457859abdaa176faa95c674d2a1092c30832dd2afd9a319599b4d1db92ffe6e48b3b29e566d5c51af091839699f5ad1715730fef24e94e39a6f40770b8320e30bf972d810b588af88ce3450337adbec0a10255b20230bcfca93aa5a0a6592cd6038312181c0792c59ec9e5d95a6216497d39ae28131869b89368e82371718970bf9750a7114c83d87b1b0cd16b6e8d41c4925d15ec26107e92847ec1bb73363ca10f3ad62afa8b0f95ff13cdbe217a1e8a74508ef439ed2140b26d5538b8d011a0d1e469f2a6962e56964adc75b90d9c6a16e88ad0adb59a337f8abb3f9d76f7f9acad22853e9dbbce13a4f686c6a802243b0901972af3c6928511609ac7b957b352452c4347acd563a72faa86a46522942fdc57f32d48c5148a2bb0bc2c3dbc9851385f816f2ece958957082c0a8fe69f647be675d87fcb8244912abc277a3242ee17e1d522f85598417559cb3a9f60b755e5b613069cb54c05a4c5d2fbd3ca6ba793320aeb0e109f8b21852daf2d9ed74dd9", "password"},
{"truecrypt_SHA_512$73f6b08614dc4ffbd77d27a0815b0700d6b612f573ccd6c8937e8d154321e3c1c1c67dd348d4d3bc8304e94a3a6ec0c672de8396a9a6b26b12393195b7daa4225a9d3a134229be011f8179791bb00c31b5c132c8dbad5a6f8738487477c409b3c32d90b07be8d7a3a9faa95d37ab6faccc459d47f029e25adcea48cee83eaa35b7acc3f849717000421d92ac46e6f16ec3dccacd3ffae76a48280977d2a6727027d9d6ff9c4c98405359ee382f6dd1eca0d7007cbe804b81485c1085e74b58d3eb1e3c7ebdc1e1ab1384e4440ab6ca7beed7e0ef7d1e0da5ffc3cd89f7b6ac8a9257ee369d397ac1e112f75382ddbe6f7317ec20c46cb7b2111d0d91570e90b4c01a0b8205fcdf4d0cadcf4a067b8f285a541f1d649894fb3ade29a2ee0575524455d489c299dde215bea3254f7d43aa4e4011a39bdb6e7473bc29f588e659fdbf065cc4a336ba42f2b6c07479cf3e544978150fb013da7db22afcb4f8384e39e2edfa30a4cbe5e84a07c54ba66663bb9284836cc5a8ba7489d3f7f92aec6d9f4e264c90c2af6181082bd273197bc42c325cb1de31006dd55425e3f210d2ddd7973978eec865d3226bb1e30a9897146d90d79a73070e87f0182981ea85f15f948ae1958af7704fabecd6f07e20be70be9f9c38a5c5e5c8b17be648f011b2c40f62d6ac51de932add5bdb47bb428fd510b004a7aa79321b03ed7aa202be439fbf", "password" },
{TAG_SHA512"cfd9e5757da139b32d117cd60f86f649400615dc218981106dfadd44598599a7ec0ace42de61506fe8d81b5c885861cdb26e0c38cb9adfcff27ba88872220ccd0914d4fa44bab5a708fe6864e0f665ac71d87e7e97b3724d610cf1f6ec09fa99da40126f63868654fed3381eaa8176f689e8e292c3cb68e43601d5804bc2e19d86722c21d42204e158b26b720e7b8f7580edce15469195dd7ed711b0fcb6c8abc253d0fd93cc784d5279de527fbdcfb357780635a5c363b773b55957d7efb472f6e6012489a9f0d225573446e5251cfb277a1365eed787e0da52f02d835667d74cc41fa4002cc35ad1ce276fbf9d73d6553ac0f8ab6961901d292a66df814a2cbda1b41f29aeec88ed15e7d37fe84ac5306b5a1b8d2e1f2c132e5c7d40ca7bb76d4ff87980ca4d75eaac5066b3ed50b53259554b9f922f7cee8e91847359d06e448da02cbeeecc78ca9bee2899a33dfa04a478ca131d33c64d6de5f81b219f11bed6ff3c0d56f26b3a27c79e7c55b6f76567a612166ce71028e3d3ae7e5abd25faec5e2e9dc30719baa2c138e26d6f8e3799a72b5e7b1c2a07c12cea452073b72f6e429bb17dd23fe3934c9e406bb4060083f92aa100c2e82ca40664f65c02cbc800c5696659f8df84db17edb92de5d4f1ca9e5fe71844e1e8c4f8b19ce7362fb3ca5467bf65122067c53f011648a6663894b315e6c5c635bec5bd39da028041", "123" },
{"truecrypt_RIPEMD_160$b9f118f89d2699cbe42cad7bc2c61b0822b3d6e57e8d43e79f55666aa30572676c3aced5f0900af223e9fcdf43ac39637640977f546eb714475f8e2dbf5368bfb80a671d7796d4a88c36594acd07081b7ef0fbead3d3a0ff2b295e9488a5a2747ed97905436c28c636f408b36b0898aad3c4e9566182bd55f80e97a55ad9cf20899599fb775f314067c9f7e6153b9544bfbcffb53eef5a34b515e38f186a2ddcc7cd3aed635a1fb4aab98b82d57341ec6ae52ad72e43f41aa251717082d0858bf2ccc69a7ca00daceb5b325841d70bb2216e1f0d4dc936b9f50ebf92dbe2abec9bc3babea7a4357fa74a7b2bcce542044552bbc0135ae35568526e9bd2afde0fa4969d6dc680cf96f7d82ec0a75b6170c94e3f2b6fd98f2e6f01db08ce63f1b6bcf5ea380ed6f927a5a8ced7995d83ea8e9c49238e8523d63d6b669ae0d165b94f1e19b49922b4748798129eed9aa2dae0d2798adabf35dc4cc30b25851a3469a9ee0877775abca26374a4176f8d237f8191fcc870f413ffdbfa73ee22790a548025c4fcafd40f631508f1f6c8d4c847e409c839d21ff146f469feff87198bc184db4b5c5a77f3402f491538503f68e0116dac76344b762627ad678de76cb768779f8f1c35338dd9f72dcc1ac337319b0e21551b9feb85f8cac67a2f35f305a39037bf96cd61869bf1761abcce644598dad254990d17f0faa4965926acb75abf", "password" },
{TAG_RIPEMD160"6ab053e5ebee8c56bce5705fb1e03bf8cf99e2930232e525befe1e45063aa2e30981585020a967a1c45520543847cdb281557e16c81cea9d329b666e232eeb008dbe3e1f1a181f69f073f0f314bc17e255d42aaa1dbab92231a4fb62d100f6930bae4ccf6726680554dea3e2419fb67230c186f6af2c8b4525eb8ebb73d957b01b8a124b736e45f94160266bcfaeda16b351ec750d980250ebb76672578e9e3a104dde89611bce6ee32179f35073be9f1dee8da002559c6fab292ff3af657cf5a0d864a7844235aeac441afe55f69e51c7a7c06f7330a1c8babae2e6476e3a1d6fb3d4eb63694218e53e0483659aad21f20a70817b86ce56c2b27bae3017727ff26866a00e75f37e6c8091a28582bd202f30a5790f5a90792de010aebc0ed81e9743d00518419f32ce73a8d3f07e55830845fe21c64a8a748cbdca0c3bf512a4938e68a311004538619b65873880f13b2a9486f1292d5c77116509a64eb0a1bba7307f97d42e7cfa36d2b58b71393e04e7e3e328a7728197b8bcdef14cf3f7708cd233c58031c695da5f6b671cc5066323cc86bb3c6311535ad223a44abd4eec9077d70ab0f257de5706a3ff5c15e3bc2bde6496a8414bc6a5ed84fe9462b65efa866312e0699e47338e879ae512a66f3f36fc086d2595bbcff2e744dd1ec283ba8e91299e62e4b2392608dd950ede0c1f3d5b317b2870ead59efe096c054ea1", "123" },
{"truecrypt_WHIRLPOOL$5724ba89229d705010ec56af416b16155682a0cab9cf48ac5a5fdd2086c9a251ae4bbea6cfb8464321a789852f7812095b0e0c4c4f9c6d14ba7beedaf3484b375ac7bc97b43c3e74bf1a0c259b7ac8725d990d2ff31935ca3443f2ce8df59de86515da3e0f53f728882b71c5cc704df0c87c282a7413db446e9a2e516a144311dd25092eb0a2c5df0240d899708289fc7141abd8538fa5791d9f96c39129cce9fe8a6e58e84364e2f4acc32274147431cb2d2480b1b54bffee485acee0925852b8a6ee71d275f028b92e540be595448e5f1d78560a3b8ad209962dd5981d7ca98db9a678a588a9296157d44502cd78f9e32f022dddc9bc8111b5704ee39a9b56d30b89898ae340e90f2e6c73be6ac64de97e32fc2eed0b66dcd5c1553eeab3950cf851624a5a4439435a6fd5717fda6d5f939f4a902321341964c16bda8975752ba150fb9d858d8eaff2a2086cb50d30abff741ee20223b4223b1783f0ed537a609a081afed952395ef0b5de6883db66cbb5a8bac70f2f757c7b6e6bb5d863672820f0d3d61b262b2b6c2ca0dc8e7137851aa450da1c1d915e005bff0e849a89bf67693ef97f5c17bf8d07a18c562dc783274f9ec580f9519a6dd1429b66160ddb04549506ad616dd0695da144fa2ad270eac7163983e9036f1bde3c7634b8a246b8dcd518ce3e12b881c838fbce59a0cfdffa3b21447e3f28124f63549c3962", "password" },
{TAG_WHIRLPOOL"0650595770851981d70b088ff6ef4bf90573e08d03c8cac8b2dfded22e1653f5c45103758c68be344fdccae42b4683087da083a3841b92fb79856798eaee793c04cd95ae556d9616684da17e47bd2f775d8128f94b80b781e4cab4921b12c620721cf719ca72d3997cea829fd29b429282b597d5719c13423cdf7bd717fa12a56b8eddcf7b1ad2796c4ad078ab3a9bd944a694aa4b0078ed160440dd3db13dd1d04a7aaaa4dc016a95bd1cfafcd833ae933c627bf5512ae55c76069af7190823dba0133d6fe02e4421d3684ff2a2493da990a3cc5eed40a9e8c48c7a89a2f47030d45c324a3d78b941e772e24b285af6739ae1f5953ff838edaa69e79939f55d0fe00cd0e3a20a46db3a232009eabc800711342f7e580ba909f16c2039d4900fd4025845a385641a6037ceb6420fe7d37868e8c06e6146eddec9e6cb97e71048da5fa5898dac08152516ea1c6729e85d31596cd226aa218ce693989efb9fa8b05404bcc2debbc75c429a03fe31bfc49f10d595b898436ff6b02fc01d745b91280f26ae94a4969ce7f86c12e6b562c7b5377e3fb3247a8cda11a930c2a9e80f24966925de01afad5987ebee9c3de1d41667c6dc35cebbbc963f263c700d06a647ab7020385e3a7e30406f3e7a9b3142d39e0439c98948134d11166b621dfd3ea9d3a84d985b2aa7732b7ad9beba44334dd86292b0c94befb2cb8aa72a823129cb", "123" },
	{NULL}
};

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	key_buffer = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*key_buffer));
	first_block_dec = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*first_block_dec));
	keyfiles_data = mem_calloc(MAX_KEYFILES,
			sizeof(*keyfiles_data));
	keyfiles_length = mem_calloc(MAX_KEYFILES,
			sizeof(int));
}

static void done(void)
{
	MEM_FREE(first_block_dec);
	MEM_FREE(key_buffer);
	MEM_FREE(keyfiles_data);
	MEM_FREE(keyfiles_length);
}

static int valid(char* ciphertext, int pos)
{
	unsigned int i;
	char *p, *q;
	int nkeyfiles = -1;

	p = ciphertext + pos;
	q = strchr(p, '$');

	if (!q) { /* no keyfiles */
		if(pos + 512*2 != strlen(ciphertext))
			return 0;
	} else {
		if (q - p != 512 * 2)
			return 0;
		/* check keyfile(s) */
		p = q + 1;
		nkeyfiles = atoi(p);
		if (nkeyfiles > MAX_KEYFILES || nkeyfiles < 1)
			return 0;
	}

	// Not hexadecimal characters
	for (i = 0; i < 512*2; i++) {
		if (atoi16l[ARCH_INDEX((ciphertext+pos)[i])] == 0x7F)
			return 0;
	}

	return 1;
}

static int valid_ripemd160(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, TAG_RIPEMD160, TAG_RIPEMD160_LEN))
		return 0;
	return valid(ciphertext, TAG_RIPEMD160_LEN);
}
static int valid_sha512(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, TAG_SHA512, TAG_SHA512_LEN))
		return 0;
	return valid(ciphertext, TAG_SHA512_LEN);
}
static int valid_whirlpool(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, TAG_WHIRLPOOL, TAG_WHIRLPOOL_LEN))
		return 0;
	return valid(ciphertext, TAG_WHIRLPOOL_LEN);
}
static int valid_truecrypt(char *ciphertext, struct fmt_main *self) {
	if (valid_sha512(ciphertext, self) ||
		valid_ripemd160(ciphertext, self) ||
		valid_whirlpool(ciphertext, self))
		return 1;
	return 0;
}

static void set_salt(void *salt)
{
	psalt = salt;
}

static void* get_salt(char *ciphertext)
{
	static char buf[sizeof(struct cust_salt)+4];
	struct cust_salt *s = (struct cust_salt *)mem_align(buf, 4);
	unsigned int i;
	char tpath[PATH_BUFFER_SIZE] = {0};
	char *p, *q;
	int idx;
	FILE *fp;
	size_t sz;

	memset(s, 0, sizeof(struct cust_salt));

	s->num_iterations = 1000;
	s->loop_inc = 1;
	if (!strncmp(ciphertext, TAG_WHIRLPOOL, TAG_WHIRLPOOL_LEN)) {
		ciphertext += TAG_WHIRLPOOL_LEN;
		s->hash_type = IS_WHIRLPOOL;
	} else if (!strncmp(ciphertext, TAG_SHA512, TAG_SHA512_LEN)) {
		ciphertext += TAG_SHA512_LEN;
		s->hash_type = IS_SHA512;
#if SSE_GROUP_SZ_SHA512
		s->loop_inc = SSE_GROUP_SZ_SHA512;
#endif
	} else if (!strncmp(ciphertext, TAG_RIPEMD160, TAG_RIPEMD160_LEN)) {
		ciphertext += TAG_RIPEMD160_LEN;
		s->hash_type = IS_RIPEMD160;
		s->num_iterations = 2000;
	} else {
		// should never get here!  valid() should catch all lines that do not have the tags.
		fprintf(stderr, "Error, unknown type in truecrypt::get_salt(), [%s]\n", ciphertext);
		error();
	}

	// Convert the hexadecimal salt in binary
	for(i = 0; i < 64; i++)
		s->salt[i] = (atoi16[ARCH_INDEX(ciphertext[2*i])] << 4) | atoi16[ARCH_INDEX(ciphertext[2*i+1])];
	for(; i < 512; i++)
		s->bin[i-64] = (atoi16[ARCH_INDEX(ciphertext[2*i])] << 4) | atoi16[ARCH_INDEX(ciphertext[2*i+1])];

	p = ciphertext;
	q = strchr(p, '$');
	if (!q) /* no keyfiles */
		return s;

	// process keyfile(s)
	p = q + 1;
	s->nkeyfiles = atoi(p);

	for (idx = 0; idx < s->nkeyfiles; idx++) {
		p = strchr(p, '$') + 1; // at first filename
		q = strchr(p, '$');

		if (!q) { // last file
			memset(tpath, 0, sizeof(tpath) - 1);
			strncpy(tpath, p, sizeof(tpath));
		} else {
			memset(tpath, 0, sizeof(tpath) - 1);
			strncpy(tpath, p, q-p);
		}
		/* read this into keyfiles_data[idx] */
		fp = fopen(tpath, "rb");
		if (!fp)
			pexit("fopen %s", p);

		if (fseek(fp, 0L, SEEK_END) == -1)
			pexit("fseek");

		sz = ftell(fp);

		if (fseek(fp, 0L, SEEK_SET) == -1)
			pexit("fseek");

		if (fread(keyfiles_data[idx], 1, sz, fp) != sz)
			pexit("fread");

		keyfiles_length[idx] = sz;
		fclose(fp);
	}

	return s;
}

/*****************************************************************************
 * we know first sector has Tweak value of 0. For this, we just AES a null 16
 * bytes, then do the XeX using the results for our xor, then modular mult
 * GF(2) that value for the next round.  NOTE, len MUST be an even multiple of
 * 16 bytes.  We do NOT handle CT stealing.  But the way we use it in the TC
 * format we only decrypt 16 bytes, and later (if it looks 'good'), we decrypt
 * the whole first sector (512-64 bytes) both which are even 16 byte data.
 * This code has NOT been optimized. It was based on simple reference code that
 * I could get my hands on.  However, 'mostly' we do a single limb AES-XTS which
 * is just 2 AES, and the buffers xored (before and after). There is no mulmod
 * GF(2) logic done in that case.   NOTE, there was NO noticeable change in
 * speed, from using original oSSL EVP_AES_256_XTS vs this code, so this code
 * is deemed 'good enough' for usage in this location.
 *****************************************************************************/
static void AES_256_XTS_first_sector(const unsigned char *double_key,
                                     unsigned char *out,
                                     const unsigned char *data,
                                     unsigned len) {
	unsigned char tweak[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	unsigned char buf[16];
	int i, j, cnt;
	AES_KEY key1, key2;
	AES_set_decrypt_key(double_key, 256, &key1);
	AES_set_encrypt_key(&double_key[32], 256, &key2);

	// first aes tweak (we do it right over tweak
	AES_encrypt(tweak, tweak, &key2);

	cnt = len/16;
	for (j=0;;) {
		for (i = 0; i < 16; ++i) buf[i] = data[i]^tweak[i];
		AES_decrypt(buf, out, &key1);
		for (i = 0; i < 16; ++i) out[i]^=tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; //GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}
}

static int apply_keyfiles(unsigned char *pass, size_t pass_memsz, int nkeyfiles)
{
	int pl, k;
	unsigned char *kpool;
	unsigned char *kdata;
	int kpool_idx;
	size_t i, kdata_sz;
	uint32_t crc;

	if (pass_memsz < MAX_PASSSZ) {
		error();
	}

	pl = strlen((char *)pass);
	memset(pass+pl, 0, MAX_PASSSZ-pl);

	if ((kpool = mem_calloc(1, KPOOL_SZ)) == NULL) {
		error();
	}

	for (k = 0; k < nkeyfiles; k++) {
		kpool_idx = 0;
		kdata_sz = keyfiles_length[k];
		kdata = keyfiles_data[k];
		crc = ~0U;

		for (i = 0; i < kdata_sz; i++) {
			crc = jtr_crc32(crc, kdata[i]);
			kpool[kpool_idx++] += (unsigned char)(crc >> 24);
			kpool[kpool_idx++] += (unsigned char)(crc >> 16);
			kpool[kpool_idx++] += (unsigned char)(crc >> 8);
			kpool[kpool_idx++] += (unsigned char)(crc);

			/* Wrap around */
			if (kpool_idx == KPOOL_SZ)
				kpool_idx = 0;
		}
	}

	/* Apply keyfile pool to passphrase */
	for (i = 0; i < KPOOL_SZ; i++)
		pass[i] += kpool[i];

	MEM_FREE(kpool);

	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for(i = 0; i < count; i+=psalt->loop_inc)
	{
		unsigned char key[64];
#if SSE_GROUP_SZ_SHA512
		unsigned char Keys[SSE_GROUP_SZ_SHA512][64];
#endif
		int j;
		int ksz = strlen((char *)key_buffer[i]);

#if SSE_GROUP_SZ_SHA512
		if (psalt->hash_type != IS_SHA512)
#endif
		{
			strncpy((char*)key, (char*)key_buffer[i], 64);

			/* process keyfile(s) */
			if (psalt->nkeyfiles) {
				apply_keyfiles(key, 64, psalt->nkeyfiles);
				ksz = 64;
			}
		}

#if SSE_GROUP_SZ_SHA512
		if (psalt->hash_type == IS_SHA512) {
			int lens[SSE_GROUP_SZ_SHA512];
			unsigned char *pin[SSE_GROUP_SZ_SHA512];
			union {
				unsigned char *pout[SSE_GROUP_SZ_SHA512];
				unsigned char *poutc;
			} x;
			for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
				lens[j] = strlen((char*)(key_buffer[i+j]));

				strncpy((char*)Keys[j], (char*)key_buffer[i+j], 64);

				/* process keyfile(s) */
				if (psalt->nkeyfiles) {
					apply_keyfiles(Keys[j], 64, psalt->nkeyfiles);
					lens[j] = 64;
				}

				pin[j] = key_buffer[i+j];
				x.pout[j] = Keys[j];
			}
			pbkdf2_sha512_sse((const unsigned char **)pin, lens, psalt->salt, 64, psalt->num_iterations, &(x.poutc), sizeof(key), 0);
		}
#else
		if (psalt->hash_type == IS_SHA512) {
			pbkdf2_sha512((const unsigned char*)key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
		}
#endif
		else if (psalt->hash_type == IS_RIPEMD160)
			pbkdf2_ripemd160((const unsigned char*)key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
		else
			pbkdf2_whirlpool((const unsigned char*)key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
#if ARCH_LITTLE_ENDIAN==0
		if (psalt->hash_type == IS_SHA512) {
			uint64_t *p64 = (uint64_t *)key;
			for (j = 0; j < 8; ++j) {
				*p64 = JOHNSWAP64(*p64);
				++p64;
			}
		} else {
			uint32_t *p32 = (uint32_t *)key;
			for (j = 0; j < 16; ++j) {
				*p32 = JOHNSWAP(*p32);
				++p32;
			}
		}
#endif
		for (j = 0; j < psalt->loop_inc; ++j) {
#if SSE_GROUP_SZ_SHA512
			if (psalt->hash_type == IS_SHA512)
				memcpy(key, Keys[j], sizeof(key));
#endif
			// Try to decrypt using AES
			AES_256_XTS_first_sector(key, first_block_dec[i+j], psalt->bin, 16);
		}
	}
	return count;
}

static int cmp_all(void* binary, int count)
{
	int i;
	for (i = 0; i < count; ++i) {
		if (!memcmp(first_block_dec[i], "TRUE", 4))
			return 1;
	}
	return 0;
}

static int cmp_one(void* binary, int index)
{
	if (!memcmp(first_block_dec[index], "TRUE", 4))
		return 1;
	return 0;
}

// compare a BE string crc32, against crc32, and do it in a safe for non-aligned CPU way.
// this function is not really speed critical.
static int cmp_crc32s(unsigned char *given_crc32, CRC32_t comp_crc32) {
	return given_crc32[0] == ((comp_crc32>>24)&0xFF) &&
		given_crc32[1] == ((comp_crc32>>16)&0xFF) &&
		given_crc32[2] == ((comp_crc32>> 8)&0xFF) &&
		given_crc32[3] == ((comp_crc32>> 0)&0xFF);
}

static int cmp_exact(char *source, int idx)
{
#if 0
	if (!memcmp(first_block_dec[idx], "TRUE", 4) && !memcmp(&first_block_dec[idx][12], "\0\0\0\0", 4))
		return 1;
#else
	unsigned char key[64];
	unsigned char decr_header[512-64];
	CRC32_t check_sum;
#if DEBUG
	static int cnt;
	char fname[64];
	FILE *fp;
#endif
	int ksz = strlen((char *)key_buffer[idx]);
	strncpy((char*)key, (char*)key_buffer[idx], 64);

	/* process keyfile(s) */
	if (psalt->nkeyfiles) {
		apply_keyfiles(key, 64, psalt->nkeyfiles);
		ksz = 64;
	}

	if (psalt->hash_type == IS_SHA512)
		pbkdf2_sha512(key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
	else if (psalt->hash_type == IS_RIPEMD160)
		pbkdf2_ripemd160(key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
	else
		pbkdf2_whirlpool(key, ksz, psalt->salt, 64, psalt->num_iterations, key, sizeof(key), 0);
#if ARCH_LITTLE_ENDIAN==0
	if (psalt->hash_type == IS_SHA512) {
		int j;
		uint64_t *p64 = (uint64_t *)key;
		for (j = 0; j < 8; ++j) {
			*p64 = JOHNSWAP64(*p64);
			++p64;
		}
	} else {
		int j;
		uint32_t *p32 = (uint32_t *)key;
		for (j = 0; j < 16; ++j) {
			*p32 = JOHNSWAP(*p32);
			++p32;
		}
	}
#endif

	// we have 448 bytes of header (64 bytes unencrypted salt were the first 64 bytes).
	// decrypt it and look for 3 items.
	AES_256_XTS_first_sector(key, decr_header, psalt->bin, 512-64);

	// first item we look for is a contstant string 'TRUE' in the first 4 bytes
	if (memcmp(decr_header, "TRUE", 4))
		return 0;

	// now we look for 2 crc values.  At offset 8 is the first. This provided
	// CRC should be the crc32 of the last 256 bytes of the buffer.
	CRC32_Init(&check_sum);
	CRC32_Update(&check_sum, &decr_header[256-64], 256);
	if (!cmp_crc32s(&decr_header[8], ~check_sum))
		return 0;

	// now we compute crc of the first part of the buffer, up to 4 bytes less than
	// the start of that last 256 bytes (i.e. 188 bytes in total). Following this
	// buffer we compute crc32 over, should be a 4 byte block that is what we are
	// given as a match for this crc32 (of course, those 4 bytes are not part of
	// the crc32.  The 4 bytes of provided crc32 is the only 4 bytes of the header
	// which are not placed into 'some' CRC32 computation.
	CRC32_Init(&check_sum);
	CRC32_Update(&check_sum, decr_header, 256-64-4);
	if (!cmp_crc32s(&decr_header[256-64-4], ~check_sum))
		return 0;
#if DEBUG
	snprintf(fname, sizeof(fname), "tc_decr_header-%04d.dat", cnt++);
	fp = fopen(fname, "wb");
	fwrite(decr_header, 1, 512-64, fp);
	fclose(fp);
#endif

	// Passed 96 bits of tests.  This is the right password!
	return 1;
#endif
	return 0;
}

static void set_key(char* key, int index)
{
	strcpy((char*)(key_buffer[index]), key);
}

static char *get_key(int index)
{
	return (char*)(key_buffer[index]);
}

static int salt_hash(void *salt)
{
	unsigned v=0, i;
	struct cust_salt *psalt = (struct cust_salt *)salt;
	for (i = 0; i < 64; ++i) {
		v *= 11;
		v += psalt->salt[i];
	}
	return v & (SALT_HASH_SIZE - 1);
}

static unsigned int tc_hash_algorithm(void *salt)
{
	return (unsigned int)((struct cust_salt*)salt)->hash_type;
}

struct fmt_main fmt_truecrypt = {
	{
		"tc_aes_xts",                     // FORMAT_LABEL
		"TrueCrypt AES256_XTS", // FORMAT_NAME
#if SSE_GROUP_SZ_SHA512
		"SHA512 " SHA512_ALGORITHM_NAME " /RIPEMD160/WHIRLPOOL",
#else
#if ARCH_BITS >= 64
		"SHA512 64/" ARCH_BITS_STR " /RIPEMD160/WHIRLPOOL",
#else
		"SHA512 32/" ARCH_BITS_STR " /RIPEMD160/WHIRLPOOL",
#endif
#endif
		"",                               // BENCHMARK_COMMENT
		-1,                               // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
#if SSE_GROUP_SZ_SHA512
		SSE_GROUP_SZ_SHA512,
		SSE_GROUP_SZ_SHA512,
#else
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#endif
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"hash algorithm [1:SHA512 2:RIPEMD160 3:Whirlpool]",
		},
		tests_all
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_truecrypt,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			tc_hash_algorithm,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_truecrypt_ripemd160 = {
	{
		"tc_ripemd160",                   // FORMAT_LABEL
		"TrueCrypt AES256_XTS", // FORMAT_NAME
		"RIPEMD160 32/" ARCH_BITS_STR,    // ALGORITHM_NAME,
		"",                               // BENCHMARK_COMMENT
		-1,                               // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		tests_ripemd160
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_ripemd160,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_truecrypt_sha512 = {
	{
		"tc_sha512",                      // FORMAT_LABEL
		"TrueCrypt AES256_XTS",    // FORMAT_NAME
#if SSE_GROUP_SZ_SHA512
		"SHA512 " SHA512_ALGORITHM_NAME,            // ALGORITHM_NAME,
#else
#if ARCH_BITS >= 64
		"SHA512 64/" ARCH_BITS_STR,
#else
		"SHA512 32/" ARCH_BITS_STR,
#endif
#endif
		"",                               // BENCHMARK_COMMENT
		-1,                               // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
#if SSE_GROUP_SZ_SHA512
		SSE_GROUP_SZ_SHA512,
		SSE_GROUP_SZ_SHA512,
#else
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#endif
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		tests_sha512
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_sha512,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_truecrypt_whirlpool = {
	{
		"tc_whirlpool",                   // FORMAT_LABEL
		"TrueCrypt AES256_XTS", // FORMAT_NAME
#if ARCH_BITS >= 64
		"WHIRLPOOL 64/" ARCH_BITS_STR,    // ALGORITHM_NAME,
#else
		"WHIRLPOOL 32/" ARCH_BITS_STR,    // ALGORITHM_NAME,
#endif
		"",                               // BENCHMARK_COMMENT
		-1,                               // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		tests_whirlpool
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_whirlpool,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
