/*
 * TrueCrypt volume support for John The Ripper
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
 * this slow format. AES_XTS removed. Also, we now only pbkdf2 over
 * 64 bytes of data (all that is needed for the 2 AES keys), and that sped
 * up the crypts A LOT (~3x faster).
 */

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_truecrypt;
extern struct fmt_main fmt_truecrypt_ripemd160;
extern struct fmt_main fmt_truecrypt_ripemd160boot;
extern struct fmt_main fmt_truecrypt_sha512;
extern struct fmt_main fmt_truecrypt_whirlpool;
#elif FMT_REGISTERS_H
john_register_one(&fmt_truecrypt);
john_register_one(&fmt_truecrypt_ripemd160);
john_register_one(&fmt_truecrypt_ripemd160boot);
john_register_one(&fmt_truecrypt_sha512);
john_register_one(&fmt_truecrypt_whirlpool);
#else

#include "xts.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "crc32.h"
#include "johnswap.h"
#include "loader.h"
#include "pbkdf2_hmac_sha512.h"
#include "pbkdf2_hmac_ripemd160.h"
#include "pbkdf2_hmac_whirlpool.h"
#include "john.h"

/* 64 is the actual maximum used by Truecrypt software as of version 7.1a */
#define PLAINTEXT_LENGTH        64
#define MAX_CIPHERTEXT_LENGTH   (512*2+32)
#define SALT_SIZE               sizeof(struct cust_salt)
#define SALT_ALIGN              4
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

static unsigned char (*key_buffer)[PLAINTEXT_LENGTH + 1];
static unsigned char (*first_block_dec)[16];

#define TAG_WHIRLPOOL           "truecrypt_WHIRLPOOL$"
#define TAG_SHA512              "truecrypt_SHA_512$"
#define TAG_RIPEMD160           "truecrypt_RIPEMD_160$"
#define TAG_RIPEMD160BOOT       "truecrypt_RIPEMD_160_BOOT$"
#define TAG_WHIRLPOOL_LEN       (sizeof(TAG_WHIRLPOOL)-1)
#define TAG_SHA512_LEN          (sizeof(TAG_SHA512)-1)
#define TAG_RIPEMD160_LEN       (sizeof(TAG_RIPEMD160)-1)
#define TAG_RIPEMD160BOOT_LEN   (sizeof(TAG_RIPEMD160BOOT)-1)

#define IS_SHA512               1
#define IS_RIPEMD160            2
#define IS_WHIRLPOOL            3
#define IS_RIPEMD160BOOT        4

// borrowed from https://github.com/bwalex/tc-play
#define MAX_PASSSZ              64
#define PASS_BUFSZ              256
#define KPOOL_SZ                64
#define MAX_KFILE_SZ            1048576 /* 1 MB */
#define MAX_KEYFILES            256

static int *cracked;

static struct cust_salt {
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
	int num_iterations;
	int hash_type;
	int nkeyfiles;
	unsigned char kpool[KPOOL_SZ];
} *psalt;

static struct fmt_tests tests_ripemd160[] = {
	{"truecrypt_RIPEMD_160$b9f118f89d2699cbe42cad7bc2c61b0822b3d6e57e8d43e79f55666aa30572676c3aced5f0900af223e9fcdf43ac39637640977f546eb714475f8e2dbf5368bfb80a671d7796d4a88c36594acd07081b7ef0fbead3d3a0ff2b295e9488a5a2747ed97905436c28c636f408b36b0898aad3c4e9566182bd55f80e97a55ad9cf20899599fb775f314067c9f7e6153b9544bfbcffb53eef5a34b515e38f186a2ddcc7cd3aed635a1fb4aab98b82d57341ec6ae52ad72e43f41aa251717082d0858bf2ccc69a7ca00daceb5b325841d70bb2216e1f0d4dc936b9f50ebf92dbe2abec9bc3babea7a4357fa74a7b2bcce542044552bbc0135ae35568526e9bd2afde0fa4969d6dc680cf96f7d82ec0a75b6170c94e3f2b6fd98f2e6f01db08ce63f1b6bcf5ea380ed6f927a5a8ced7995d83ea8e9c49238e8523d63d6b669ae0d165b94f1e19b49922b4748798129eed9aa2dae0d2798adabf35dc4cc30b25851a3469a9ee0877775abca26374a4176f8d237f8191fcc870f413ffdbfa73ee22790a548025c4fcafd40f631508f1f6c8d4c847e409c839d21ff146f469feff87198bc184db4b5c5a77f3402f491538503f68e0116dac76344b762627ad678de76cb768779f8f1c35338dd9f72dcc1ac337319b0e21551b9feb85f8cac67a2f35f305a39037bf96cd61869bf1761abcce644598dad254990d17f0faa4965926acb75abf", "password" },
	{"truecrypt_RIPEMD_160$6ab053e5ebee8c56bce5705fb1e03bf8cf99e2930232e525befe1e45063aa2e30981585020a967a1c45520543847cdb281557e16c81cea9d329b666e232eeb008dbe3e1f1a181f69f073f0f314bc17e255d42aaa1dbab92231a4fb62d100f6930bae4ccf6726680554dea3e2419fb67230c186f6af2c8b4525eb8ebb73d957b01b8a124b736e45f94160266bcfaeda16b351ec750d980250ebb76672578e9e3a104dde89611bce6ee32179f35073be9f1dee8da002559c6fab292ff3af657cf5a0d864a7844235aeac441afe55f69e51c7a7c06f7330a1c8babae2e6476e3a1d6fb3d4eb63694218e53e0483659aad21f20a70817b86ce56c2b27bae3017727ff26866a00e75f37e6c8091a28582bd202f30a5790f5a90792de010aebc0ed81e9743d00518419f32ce73a8d3f07e55830845fe21c64a8a748cbdca0c3bf512a4938e68a311004538619b65873880f13b2a9486f1292d5c77116509a64eb0a1bba7307f97d42e7cfa36d2b58b71393e04e7e3e328a7728197b8bcdef14cf3f7708cd233c58031c695da5f6b671cc5066323cc86bb3c6311535ad223a44abd4eec9077d70ab0f257de5706a3ff5c15e3bc2bde6496a8414bc6a5ed84fe9462b65efa866312e0699e47338e879ae512a66f3f36fc086d2595bbcff2e744dd1ec283ba8e91299e62e4b2392608dd950ede0c1f3d5b317b2870ead59efe096c054ea1", "123" },
	{"truecrypt_RIPEMD_160$76707c2caebf50bdc10a0f010276302299fcd07358130a8c7ddc86bd31b816b957c69f8aae7422a3e1b8dff4853d9090a818aa25801b96ac584cb37190d7d5e376a62fd08629e6416b7ee24150f8e7b963a8e7f5e9b0b71c55e84977cf03c0215c48538229e6449ba6f7dddc0db1498d39661dee4bd48cf3652459591c5300b685335dde79c5e77023bba2fc5aec436f05e23966f97b097f7f9a5b985fb7b72dd2623c3a2df694b55298b6f4c4517d119d3782d8ee644c7206678e06ec4c6eb0dc7f5c89f633cf8f77310e5e5fb8163cf6ca720a29aec1bd22abeb9a1af0fbb009c3ad7579269e747bb400f66b93e3970bae417580deb5956849314e0db1a340f78e6a5a56bb763b98dbca504825d2be2232792ff659e62ca13f2839a15bebc403305a43092dd03d2cbb3e9acc68bdf1397c48f8675de11b9230401ee97ce5c2a9bd7c4eff3e5fba7ce37f6e4ce78669fb6d3eebb9af701f8e288db98a83d4c3fdc5d816fa12693f62fe75324d5e01de459ee5f53dab714d1cf6e6da6c49f04b78c2f5dc72adcaf1a51bf85da90b5a8afdbeceb788e547893a4c284d0699a9f48c866fad8c347ecfc1a37c01f5e6fd19cbfc391d1cf89d291a320a20547a52bdb015674c9913d38f61b673573a2570f1cdf3561309434252d867c86974e945fa703e74bcbf2431a2b55bb6b4e957af3a6acd71b8e55e17f29e5654e50dc5f137", "hashcat"}, // hashcat_ripemd160_twofish.tc
	{"truecrypt_RIPEMD_160$9450ade46ed2f40e1579c844dbe2c81298cd9dfd911d6c6e44eac4fb919198ce02f6ecbc70bb6fdddce4dcb834b6356b59fa974d5e30e32e4a53e552def9268a03f9bad1cd2d7ead53a9db15f08bb26b8bb3cda95976f73721b0b19e64f9fac2c9e3710c0e88e0a04ef112ab6b2190578873dfdaddd2f146eeb8378185b7f5ac8c9488b8cf2f794330a66b3f37614b702f3fe471bed923cba59fd3845ddecce1da8557f06636f3e9ab5e87d71e2bfa61bd9bc29ee9d3ea27fe84aa8cd7f0b71069a8aaf64b0566ef126c9aec1d6380010cdf1e9da7982b99552503108286bd26ebb2638ca3f594277233b3c1c75361f9c2df448d247dc62c0050cbea7427a48d4bcfc78f227cc38c4b3bdd61c7538de91f6c20728e8af42eb2d92a7b1b0de8469ccb2fadbb60dc4d23b6707482c95b4b4f68c7d7037f52b9a16f80fe643541b11f756c8c3d9a3f231898d71b326455e3719863a78fed5264ea71c6223b58eeebfb2b0ea1c831557e9efe4bd684694a4e79f565fb2615b705bad692314a0519943a718b253bf920453d36382eb04f5adf4cf3e8f471934bd9a39997d8a2418e7320ac32a6470637f22b66b9e72e3d43f26cd5083ac6fb80d20c799dcc01127ba19659b5188644df41071b30de743df3c9670bb86e37f1751c8c02d21c9eda60c2653293b7d3f9480fc13d46d5d89c8737d541c385fea823a147c96a129047e127", "hashcat"}, // hashcat_ripemd160_serpent.tc
	{NULL}
};
static struct fmt_tests tests_ripemd160boot[] = {
	{"truecrypt_RIPEMD_160_BOOT$2b5da9924119fde5270f712ba3c3e4974460416e8465f222149499908c2fca0a4753b581f26625d11c4d3f49bdeb1c95bc3e17629d7e19ffb66175e5feab90a4fd670194f95d578266f3f54e61b82dc00efc2bb4438e19c3f6d7a92825a7625d88ec6286ab4e1761749edc83dad4340fd167544f09913fd6b03775013ff232fc4dad6f726ef82ad4bd1c5227a7796d7db35a912beeda5b0cdd798bc34d3ac24403c87dc672a983687dd64f920c991840a56105a6311797eed9976014909700366420673f6455242c71151ac75903a353538ec24b4feb967e2b46886395cf3e934e83a6a58ef2c0180273a0c33ba2bd870b1d84afb03d5558dc17bc7fb586404ad9a7e506ed859540110c6ad73f0f1d2be47829bc666e1838ec3f1dc1f610206241ce07fbf2542ecef9348b37aa460815794ca582709697cbf0c90c3dae4cb9dd97b29d3c7d82bd8d0c81d708e74c7007468c6c55a40fd4f803a4f5a75818d7da0d1ef333b8622e7de516fa62a6fa2b8d6d5d23653dfcedffec771456ee204e5c85ee88defbe195462fbe8ce0e2a5a455dab66478b877ec37dfa66f19ab5201c56cd707ba7bee1b10360965d3868c1fdf91dda124b1b0994fee75848083d19369735905bd2864b496c6e35ecf96f6dd4728570a45746bcf8d7d0ec0b9b0b112b28fdc53efcfa7d0558c132cd683a742d62b34304d9f991029c8aedc3d8767da8c", "hashcat"}, // hashcat_ripemd160_aes_boot.tc
	{"truecrypt_RIPEMD_160_BOOT$3f6e7171e8c7d0f6ba03defcfbdef5de8d43984b21c3422bbce2357e1434334ac8af920e736ba4006094ad426524ceb491248a381ea154c37889a916f40c4823b4c68bcfbf8548b93830411a8b27746c6dd99c2a1ed0920947139a54fcf6315965730e85f9b8ced69a7f1c4336c63a351606ea577b8a5caa6b86cdac846534ba62735170350ad89c1f355165690439c4d0d8f6c6b2d0ef5f68958a10edac4b553d070f27e34291141b85e4502ae12721a8e7cb8bb1e8b8bfd57e4a92ab5364d4bb3415cfb1d12620ec17a6de1b050df122c03210b723fffc477c4d5b65319a269ae9dc18bd2fa55d2bc00b23b3824ddbfa7941fdee4a99afda93bb34bd7b613a9f2db7ec5f2947dfadf8fec021e9cb6d5acd2d23bf86f9fb699eb7faed555ff32be301f0ac35020221528808f1c00c95b14b791bf678dc234a339ac0c7c1c8131caecfabd2778e26503a967a592b5f36173e763b2d7db7f826a36368e7e88eb8c7d587b6a1eae544800f499ff0b4937cfa07861331e699265e61081a612c0075ff95f77ea9be731cc2aa285024548c506d2e89acd07f39250238e2f4e319b789ca7d4163482211839787c9cdd3189c7a4525d4e2e38d7f5affb2ed5d7cf3de9ea14c50f51a2f307248758e6eca8179cb8e2d7397f6b1818a9c25131b7fac5c12efc5e952e8e04af9fb3432548378b4a20471fad934cd7c9983af7830e2f6a202", "hashcat"}, // hashcat_ripemd160_twofish_boot.tc
	{"truecrypt_RIPEMD_160_BOOT$e4cad3bc157ded7d28b8111f6967617a1e920bc4238fd2293b0f6f943d692e97b9b4ab9f75df7010cdbd1d20cf9775b85aad6101ac2ca499c7d592ce8c47fb16c01146d61f54457b15d9a70683713437671fd8ca0b83175058072d34f5737b59caf8b63f6244cb95d748cea3589111d20b73d2750d7fd18a791dd85aa96a6c65d5387f08c80f735824833314ca98ac5d1a52e055fb2bac663457b248aec33773fbb0b73586d62d2e44991ebf68af4fab38954385d9addd88e03f819ccf959d502888a70edc01d0a924f957fd3f8db037f0c65068ab46ccd00ac12df649c9735e20bd3d5411d0285918926a23a6d9b8dff315d245b6156fe49ef5ebcc35b98c43568cdf4585e9d96d9b3e9d252df2f34528a9bc9739ca4c906bbcea34f6704cf417493067839183c85c6553ab1ecbb552b85434c892154f0fe341f7b7f21a4052619b77db2be345ddd01b6ecc72eb424a78fc10379785fba362a2a86f1a9660fc0bb5408516571c103983ea5d43f7fae5688a59ef1ac913c96012c66dbb67f86aaff82fe52dc4ac3ba4c7737efbfae84de2138bc41650bb62fa41232f5e7a51f3a07316234d1ebe2cfee38380902aae2d338653bff0fd97f83d971c9193870734a2b0f16ac52aaa4c4f1c29fc7e6619cacbf72fed79f3ad3db214b0e32a56c5283865c3af8d8c17f76e608309ab266abd4abad72d0cc96e4c6453a4633ee86aa9", "hashcat"}, // hashcat_ripemd160_serpent_boot.tc
	{NULL},
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
	omp_autotune(self, OMP_SCALE);

	key_buffer = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*key_buffer));
	first_block_dec = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*first_block_dec));
	cracked = mem_calloc(sizeof(*cracked),
			self->params.max_keys_per_crypt);
	Twofish_initialise();
}

static void done(void)
{
	MEM_FREE(first_block_dec);
	MEM_FREE(key_buffer);
	MEM_FREE(cracked);
}

static int valid(char* ciphertext, int pos)
{
	unsigned int i;
	char *p, *q;
	int nkeyfiles, idx;
	char tpath[PATH_BUFFER_SIZE];
	size_t len;

	p = ciphertext + pos;
	q = strchr(p, '$');

	if (!q) { /* no keyfiles */
		if (pos + 512 * 2 != strlen(ciphertext))
			return 0;
	} else {
		if (q - p != 512 * 2)
			return 0;
		/* check number of keyfile(s) */
		p = q + 1;
		q = strchr(p, '$');
		if (!q) /* number implies at least 1 filename */
			return 0;
		/* We use same buffer for number. */
		len = q - p;
		if (len > sizeof(tpath) - 1)
			return 0;
		memcpy(tpath, p, len);
		tpath[len] = '\0';
		if (!isdec(tpath))
			return 0;
		nkeyfiles = atoi(p);
		if (nkeyfiles > MAX_KEYFILES || nkeyfiles < 1)
			return 0;
		/* check keyfile(s) */
		for (idx = 0; idx < nkeyfiles; idx++) {
			p = strchr(p, '$') + 1;
			q = strchr(p, '$');

			if (!q) { // last file
				if (idx != nkeyfiles - 1)
					return 0;
				len = strlen(p);
			} else {
				len = q - p;
			}
			if (len > sizeof(tpath) - 1)
				return 0;
		}
		if (q) // last expected filename is not last
			return 0;
	}

	// Not hexadecimal characters
	for (i = 0; i < 512 * 2; i++) {
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
static int valid_ripemd160boot(char* ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, TAG_RIPEMD160BOOT, TAG_RIPEMD160BOOT_LEN))
		return 0;
	return valid(ciphertext, TAG_RIPEMD160BOOT_LEN);
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
		valid_ripemd160boot(ciphertext, self) ||
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
	char tpath[PATH_BUFFER_SIZE];
	char *p, *q;
	int i, idx, kpool_idx;
	FILE *fp;
	size_t sz, len;
	uint32_t crc;
	unsigned char *keyfile_data;

	memset(s, 0, sizeof(struct cust_salt));

	s->num_iterations = 1000;
	if (!strncmp(ciphertext, TAG_WHIRLPOOL, TAG_WHIRLPOOL_LEN)) {
		ciphertext += TAG_WHIRLPOOL_LEN;
		s->hash_type = IS_WHIRLPOOL;
	} else if (!strncmp(ciphertext, TAG_SHA512, TAG_SHA512_LEN)) {
		ciphertext += TAG_SHA512_LEN;
		s->hash_type = IS_SHA512;
	} else if (!strncmp(ciphertext, TAG_RIPEMD160, TAG_RIPEMD160_LEN)) {
		ciphertext += TAG_RIPEMD160_LEN;
		s->hash_type = IS_RIPEMD160;
		s->num_iterations = 2000;
	} else if (!strncmp(ciphertext, TAG_RIPEMD160BOOT, TAG_RIPEMD160BOOT_LEN)) {
		ciphertext += TAG_RIPEMD160BOOT_LEN;
		s->hash_type = IS_RIPEMD160BOOT;
		s->num_iterations = 1000;
	} else {
		// should never get here!  valid() should catch all lines that do not have the tags.
		fprintf(stderr, "Error, unknown type in truecrypt::get_salt(), [%s]\n", ciphertext);
		error();
	}

	// Convert the hexadecimal salt in binary
	for (i = 0; i < 64; i++)
		s->salt[i] = (atoi16[ARCH_INDEX(ciphertext[2*i])] << 4) | atoi16[ARCH_INDEX(ciphertext[2*i+1])];
	for (; i < 512; i++)
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
			len = strlen(p);
		} else {
			len = q - p;
		}
		if (len > sizeof(tpath) - 1) {
			// should never get here!  valid() should catch all lines with overly long paths
			if (john_main_process)
				fprintf(stderr, "Error, path is too long in truecrypt::get_salt(), [%.10s...]\n", p);
			error();
		}
		memcpy(tpath, p, len);
		tpath[len] = '\0';
		/* read this into keyfile_data */
		fp = fopen(tpath, "rb");
		if (!fp)
			pexit("fopen %s", tpath);

		if (fseek(fp, 0L, SEEK_END) == -1)
			pexit("fseek");

		sz = ftell(fp);

		if (sz == 0) {
			fclose(fp);
			continue;
		}

		if (sz > MAX_KFILE_SZ) {
			if (john_main_process)
				fprintf(stderr, "Error: keyfile '%s' is bigger than maximum size (MAX_KFILE_SZ is %d).\n", tpath, MAX_KFILE_SZ);
			error();
		}

		if (fseek(fp, 0L, SEEK_SET) == -1)
			pexit("fseek");

		keyfile_data = mem_alloc(sz);
		if (fread(keyfile_data, 1, sz, fp) != sz)
			pexit("fread");

		fclose(fp);

		/* Mix keyfile into kpool */
		kpool_idx = 0;
		crc = ~0U;
		for (i = 0; i < sz; i++) {
			crc = jtr_crc32(crc, keyfile_data[i]);
			s->kpool[kpool_idx++] += (unsigned char)(crc >> 24);
			s->kpool[kpool_idx++] += (unsigned char)(crc >> 16);
			s->kpool[kpool_idx++] += (unsigned char)(crc >> 8);
			s->kpool[kpool_idx++] += (unsigned char)(crc);
			/* Wrap around */
			if (kpool_idx == KPOOL_SZ)
				kpool_idx = 0;
		}

		free(keyfile_data);
	}

	/* Once kpool is ready, number of keyfiles does not matter. */
	s->nkeyfiles = 1;

	return s;
}

// compare a BE string crc32, against crc32, and do it in a safe for non-aligned CPU way.
// this function is not really speed critical.
static int cmp_crc32s(unsigned char *given_crc32, CRC32_t comp_crc32) {
	return given_crc32[0] == ((comp_crc32>>24)&0xFF) &&
		given_crc32[1] == ((comp_crc32>>16)&0xFF) &&
		given_crc32[2] == ((comp_crc32>> 8)&0xFF) &&
		given_crc32[3] == ((comp_crc32>> 0)&0xFF);
}

static int decrypt_and_verify(unsigned char *key, int algorithm)
{
	unsigned char decr_header[512-64];
	CRC32_t check_sum;

	// We have 448 bytes of header (64 bytes unencrypted salt were the
	// first 64 bytes). Decrypt it and look for 3 items.
	switch (algorithm) {
		case 0:
			XTS_decrypt(key, decr_header, psalt->bin, 512-64, 256, 0);
			break;
		case 1:
			XTS_decrypt(key, decr_header, psalt->bin, 512-64, 256, 1);
			// Twofish_XTS_decrypt(key, decr_header, psalt->bin, 512-64, 256);
			break;
		case 2:
			XTS_decrypt(key, decr_header, psalt->bin, 512-64, 256, 2);
			// Serpent_XTS_decrypt(key, decr_header, psalt->bin, 512-64, 256);
			break;
	}

	// First item we look for is a contstant string 'TRUE' in the first 4 bytes.
	if (memcmp(decr_header, "TRUE", 4))
		return 0;

	// Now we look for 2 crc values. At offset 8 is the first. This provided
	// CRC should be the crc32 of the last 256 bytes of the buffer.
	CRC32_Init(&check_sum);
	CRC32_Update(&check_sum, &decr_header[256-64], 256);
	if (!cmp_crc32s(&decr_header[8], ~check_sum))
		return 0;

	// Now we compute crc of the first part of the buffer, up to 4 bytes less than
	// the start of that last 256 bytes (i.e. 188 bytes in total). Following this
	// buffer we compute crc32 over, should be a 4 byte block that is what we are
	// given as a match for this crc32 (of course, those 4 bytes are not part of
	// the crc32. The 4 bytes of provided crc32 is the only 4 bytes of the header
	// which are not placed into 'some' CRC32 computation.
	CRC32_Init(&check_sum);
	CRC32_Update(&check_sum, decr_header, 256-64-4);
	if (!cmp_crc32s(&decr_header[256-64-4], ~check_sum))
		return 0;

	// Passed 96 bits of tests.  This is the right password!
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#if SSE_GROUP_SZ_SHA512
#define INNER_BATCH_MAX_SZ SSE_GROUP_SZ_SHA512
	int inner_batch_size = 1;
	if (psalt->hash_type == IS_SHA512)
		inner_batch_size = SSE_GROUP_SZ_SHA512;
#else
#define INNER_BATCH_MAX_SZ 1
#define inner_batch_size 1
#endif

	memset(cracked, 0, sizeof(cracked[0]) * count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i += inner_batch_size) {
		unsigned char keys[INNER_BATCH_MAX_SZ][64];
		int lens[INNER_BATCH_MAX_SZ];
		int j;

		for (j = 0; j < inner_batch_size; ++j) {
			lens[j] = strlen((char *)key_buffer[i+j]);
			/* zeroing of end by strncpy is important for keyfiles */
			strncpy((char*)keys[j], (char*)key_buffer[i+j], 64);
			/* process keyfile(s) */
			if (psalt->nkeyfiles) {
				int t;
				/* Apply keyfile pool to passphrase */
				for (t = 0; t < KPOOL_SZ; t++)
					keys[j][t] += psalt->kpool[t];
				lens[j] = 64;
			}
		}

		if (psalt->hash_type == IS_SHA512) {
#if SSE_GROUP_SZ_SHA512
			unsigned char *pin[SSE_GROUP_SZ_SHA512];
			unsigned char *pout[SSE_GROUP_SZ_SHA512];
			for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
				pin[j] = keys[j];
				pout[j] = keys[j];
			}
			pbkdf2_sha512_sse((const unsigned char **)pin, lens, psalt->salt, 64, psalt->num_iterations, pout, sizeof(keys[0]), 0);
#else
			pbkdf2_sha512((const unsigned char*)keys[0], lens[0], psalt->salt, 64, psalt->num_iterations, keys[0], sizeof(keys[0]), 0);
#endif
		}
		else if (psalt->hash_type == IS_RIPEMD160 || psalt->hash_type == IS_RIPEMD160BOOT)
			pbkdf2_ripemd160((const unsigned char*)keys[0], lens[0], psalt->salt, 64, psalt->num_iterations, keys[0], sizeof(keys[0]), 0);
		else
			pbkdf2_whirlpool((const unsigned char*)keys[0], lens[0], psalt->salt, 64, psalt->num_iterations, keys[0], sizeof(keys[0]), 0);

		for (j = 0; j < inner_batch_size; ++j) {
			cracked[i+j] = 0;
			if (decrypt_and_verify(keys[j], 0) // AES
			    || decrypt_and_verify(keys[j], 1) // Twofish
			    || decrypt_and_verify(keys[j], 2)) // Serpent
				cracked[i+j] = 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int idx)
{
	return 1;
}

static void set_key(char* key, int index)
{
	strnzcpy((char*)key_buffer[index], key, sizeof(*key_buffer));
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
		"SHA512/RIPEMD160/WHIRLPOOL " SHA512_ALGORITHM_NAME,
#else
		"SHA512/RIPEMD160/WHIRLPOOL 32/" ARCH_BITS_STR,
#endif
		"",                               // BENCHMARK_COMMENT
		0x107,                            // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
#if SSE_GROUP_SZ_SHA512
		SSE_GROUP_SZ_SHA512,
		(SSE_GROUP_SZ_SHA512 * 4),
#else
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#endif
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"hash algorithm [1:SHA512 2:RIPEMD160 3:Whirlpool]",
		},
		{
			TAG_WHIRLPOOL,
			TAG_SHA512,
			TAG_RIPEMD160
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
		0x107,                            // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ TAG_RIPEMD160 },
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

struct fmt_main fmt_truecrypt_ripemd160boot = {
	{
		"tc_ripemd160boot", // FORMAT_LABEL
		"TrueCrypt AES/Twofish/Serpent", // FORMAT_NAME
		"RIPEMD160 32/" ARCH_BITS_STR, // ALGORITHM_NAME,
		"", // BENCHMARK_COMMENT
		0x107, // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ TAG_RIPEMD160BOOT },
		tests_ripemd160boot
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_ripemd160boot,
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
		0x107,                            // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
#if SSE_GROUP_SZ_SHA512
		SSE_GROUP_SZ_SHA512,
		(SSE_GROUP_SZ_SHA512 * 8),
#else
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#endif
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ TAG_SHA512 },
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
		"WHIRLPOOL 32/" ARCH_BITS_STR,    // ALGORITHM_NAME,
		"",                               // BENCHMARK_COMMENT
		0x107,                            // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ TAG_WHIRLPOOL },
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
