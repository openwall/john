/*
 * This software is Copyright (c) 2017 Dhiru Kholia and it is hereby released
 * to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pbkdf2_hmac_sha512_fmt_plug.c file.
 */

#include "arch.h"
#if !AC_BUILT
#define HAVE_LIBZ 1
#endif
#if HAVE_LIBZ
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_electrum_modern;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_electrum_modern);
#else

#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <openssl/bn.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"
#include "johnswap.h"
#include "secp256k1.h"
#include "aes.h"
#include "sha2.h"
#include "hmac_sha.h"
#include "pbkdf2_hmac_common.h"

#undef FORMAT_NAME
#define FORMAT_NAME             "Electrum Wallet 2.8+"
#define FORMAT_LABEL            "electrum-modern-opencl"
#define FORMAT_TAG              "$electrum$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "PBKDF2-SHA512 OpenCL"
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        110
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define KERNEL_NAME             "pbkdf2_sha512_kernel"
#define SPLIT_KERNEL_NAME       "pbkdf2_sha512_loop"
#define CONFIG_NAME             "pbkdf2_sha512"

#define HASH_LOOPS              250
#define ITERATIONS              10000

static struct fmt_tests electrum_tests[] = {
	// Electrum 2.8.0+ encrypted wallets
	{"$electrum$4*03c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864*4249453103c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864355ed45b963901b56cd6c483468247c7c8c76ba11c9cb94633575838cffb8f0cebfc9af91ba402c06cca5c08238c643a0291e66e1a849eb66a9eda17e1496d09f46bfe6f63bfdcd591c260f31b92bd5958ce85c7719983a7395c88570946a59d5dcc2188680aba439cde0dbdfeaba985fe3d1a97d25b81573a92f72aea8c60fa3a4228acb789d7f307f6a19d1025fa6ac81d91d45ef07c0b26d9f85fc6ba07246b8b19d641929aac16ff1c942a3d69b824e3e39a122402aed63d3d12ca299416500459e7353bd56db92102c93f045ccc719cee90d2f891ff6b128886ec90768364bcc89c3393f21a5b57915f4eaf4e3b9c7a3958124b43956a47572ae38df2a11b84f6dc25ddc3d3b1968e3adadc756507118301e8cc490d249dc603f4f46c3bf0b214fd3bfb8dab6f048ba7d60dbee031d386a5aeec6664d2891abbeb0201b437d6e37c140be3e6210078e76afafbd78a8acaf45f21cf83c69218f9bfd3abb0211d57ab1874e9d645171cdaad4887a9fea86003b9948d22d9e7bfaec4c4bd0786cd4d191c82c61e83c61bae06a7c9936af46f8fa121ab696aba24ad8fd8f69537aa713bf271e4be567e7e3ccd141511c96ce634175f845ff680f71bbd595ef5d45d9cfd9a7e099fbab7964add7a76c4820b20952121e5621cb53c9476dc23860a5bc4ba3ecf636dc224503202dc11bf3bc88c70dcc2005684f7d3ebe6a7ea1487423a5145442f8f3d806d5d219560b4bce272ef9d6e32849b692cd91d4c60462b0f813603a52dc84b959051e787d890661e9f439a11fa8819c4fb947ff8dd0a5b7e5e63605f4e9f6eac6f8b2bfd7a9098dd2201c2f4cdaa2d7d0691ccf42b2761a8bb2a08c755077a753a41bcf305c83da8cd9ebaeee0360afb4be00827e167b2c1a3d5975d3a4a1e3b3b56794a155253437710ee3c0d0a2de0c4d631b48808fa946146f09e8ea9888d6c6bad104ebed814e79bdc26be38e8580d8fff6324405c128627079d1e3bafc2479274a3bc4f8196e923c835204e91ce8a9cb235c5349056415ad58a83b41254eda57839cd2e0bb66f125e32c76671f6447b2b0321d021c60706ff6f103ce483986fe0f1cc62307f6a1e89c4b2f334fc6f1f2597f5d68b3948c7655025a04ea858bc33eb341de09bdb4862701abcbc4c907270856de6072ee8d0c9e46e19c50eac454d4ca5fcd1a35f5d239aadc82543deafcd17f0eae2145561b8834dd80d337c574d3e931365db294d66aa4b47669f92784325b85abae49a8447a2afeb4cac460cba2a9d7b298bd3f69ac31862b92a970ed8d3241227858b0c40b2f6793cdd733020987beb7e6f01826fa2dae2b345f4e8e96da885a00901b20308f37c8613cf28ef997a6f25c741af917a547b38cff7577d2cac2654d5cdac2d0f1135ac6db3d70174b03c4149d134325f1b805ef11cd62531c13436ad1c7cb73f488dc411d349be34523d477953e8b47848e31ec85230a99ecd88c9cbc5d33de132aacd04877123cff599bea3b2e7b931347673cca605b3bc129496d5e80b06ae0eb3fce5c24ea0f8d2ecd4cfb9ed5034b26ed18b564731c78f5344ec863bd78797ad7de722c7a88e047af0364f69a303dc5f716ebda1de9ca21cb49e4091cb975c17f098932e884f36bded1fab34814931b0aeb72b1bc90747f7f5ebe73c547681f7a8d6d74e7acde2ba6e5e998bd6b035ade5fa64171dde4a82ed5ed7f273220d47bbd5a1c2ed4359d02392b746ba653d1c30f63bce161d0555ebc4775262036be51d4a50113bbac6823fd6a0d387a32673dc454c4d9d018cc25885a0d15d3f7488bbe18398d758cbbf1a24eaf71bd1560ff216e342e09efdbfae2872cfdf59ed802420ba8522edfd74f6d728ffa1683e586b53cbec80f00be6478a44d8df1c69a5cdbb50aa75da2f2dd0a679b037b4173f20b9514064d15ff50f1e9beb0112a41cdc0ecf7fb3028fe6f4c7339bb79d50cb7d43cabd8ae198741677d41e411c811c6267e9b4e41d944b035e47406d5120f1ee192db810cf6774*40c7a179573d57c54d0da0a1c4d71e306e1eea823f637f29c3e43b9792469d15", "openwall123"},
	{"$electrum$4*0328e536dd1fbbb85d78de1a8c21215d4646cd87d6b6545afcfb203e5bb32e0de4*424945310328e536dd1fbbb85d78de1a8c21215d4646cd87d6b6545afcfb203e5bb32e0de461b1e287a5acff4b40e4abd73ff62dc233c1c7a6a54b3270949281b9d44bc6e746743733360500718826e50bb28ea99a6378dc0b0c578e9d0bf09c667671c82a1bd71c8121edbb4c9cbca93ab0e17e218558ead81755e62b0d4ad547aa1b3beb0b9ee43b11270261c9b38502f00e7f6f096811b7fdae6f3dce85c278d3751fec044027054218ccf20d404bab24380b303f094704e626348a218f44ab88ce2ac5fa7d450069fca3bb53f9359dbbaad0ea1b3859129b19c93ed7888130f8a534f84a629c67edc150a1c5882a83cb0add4615bb569e8dc471de4d38fc8b1e0b9b28040b5ea86093fcdeceaedb6b8f073f6f0ee5541f473a4b1c2bfae4fc91e4bbb40fa2185ecfa4c72010bcf8df05b1a7db45f64307dbc439f8389f0e368e38960b6d61ac88c07ce95a4b03d6d8b13f4c7dc7d7c447097865235ab621aeef38dc4172bf2dc52e701132480127be375fe98834f16d9895dce7f6cdfe900a2ce57eaa6c3036c1b9a661c3c9adbf84f4adfe6d4d9fa9f829f2957cfb353917dc77fd8dd4872b7d90cb71b7d3a29c9bfe3440e02449220acba410fa0af030f51aa2438f7478dbb277d62613112e4eebc66d5d7bdba793fb2073d449954f563284819189ffb5dbcdeb6c95c64bc24e0ef986bce07bafe96ab449ae2b6edaf4f98ffbd392a57bd93c2359444ec4046ae65b440adb96b6e4eef9d06bb04d2f3fa2e4175165bcadbf7e13cc3b6e65e67df901f96a2f154bc763b56b3736a335e1d1bc16e99736f757a4ae56c099645c917360b1ecf8dcefc7281541c6ff65d87cadab4a48f1f6b7b73a3e5a67e2e032abb56b499e73a9f3b69ce065e43b0174639785ae30635d105ebcc827dcf9b19bdd1a92879a5d4bc4e12b5630c188b1b96e3c586e19901b8f96084bcd59b2f4b201a3a8b6e633a5c194901d4609add9671b0bcc12b2b94ae873d201258b36315484e4b9c5f5d6289656baa93eec9e92aec88e2d73d86b9e3d1f24294e3d8ebe9a9f2f6edfbf28f530670c5b086fc4f74df89b4e4cbe06ee7e45cbd238b599d19c2d5da5523b12b1e7050ea0a9b47a5d22c6c3fc476f814f9705dc7ed3aeb1b44fc6b4d69f02a74963dce5057c3c049f92e595a4da5035cffc303a4cb162803aa3f816527a7e466b8424789a0d77e26819615662420c370457e29fcc1938fd754f3acfd21416ce3ab27e9febbc0e24fc7055eddc31e48faa014f9f3695c2e956f0e6c94c507a8d2f8c3aeb4b98b69b6340b6a3acb1acdde9581279f78ee10687616360c018e9f67d6c8bb5950e8fdabd3d0d5808824975aa4a50f88581472212f24ad58a700fe4787642b973924575fe71d1ecd7b2b6acd363f48c40bdd55f35f60a06dee544c266e608fd5a6d263f745e8b11d1160638eb301adfd1a88eddf6d0ccb9e1021e0bde9cf5163583a202b3dc95c255c8cc245a425391163b387c5312d07637272621b94bfde151238c5f55371774ca07603fe3e0a43e92b5cf46096c4c8014e03e730555b61bb544a3998ccd8e45e0f9427c66ce1da1e8cc86d5414fe0d0d49d0a048fb55b76eb3a0a0ba2f1a94227eb6b7b58ff3d410bcd782970689dd026350cbde243de749c27f4647ede96996767354aaf14e336bec47b7498774a519d999f15d424ab34c05254ac835c6df8482c3b6e72b879205392f02f2a666185250ab3b0dd70d219de936495f873b3fe8722026b167437d5fc8fd21aa67ba642da8ca68a5823bc8f6da6fd1a50996a3e4d9fb2bd15909a91f217c512561a502d26c4f0baa0145b4acbcdea8adecbeaeff956e0ec6ae77d35872d2d6351e70c6bb101d824f41a2b7029f16708cd4c8b7a894453f82e79523765de14c82106f74a146c8f76cf20caeb35475e881be1c74a1dc0783b0ff9a40060e362ec3bb5e3dc3919914787893b0dc80123f44a44744f107268eb85437bf3116efa5bb03d6903ebd987291e8574344cadffa7f960789a3ef6c933305e6a80319c9cd9a49d208c4d4070f47c44edea53476b7779cec179af985f7c8b4b91efb56e0a35d4ecb1ff684a1fd0ee8a2d473e00cd8fe3a752cf7b62fffda4ebe90c992caacbee70c7d912d360e5dd24074430cb2b694ff2fcca6eb77d10b1b22a26841af36501d9a066e280d25ca215378e7635fda9ce865ca6af9ae962a3b6039dbba483a5ab7bee69d891c9809483744a0b0ab94498d1ada452e3a90a19decee6bf2b97de274413f78bd896fc2634d3e26d4bde265143deebf580693aa1925aea6f6ce003f195a226b04377e662e0d87b4a09299061f13c4b0ad2d4281eac386c03f533b1d2a9fb466814817bf27aa737cdeda708b1db19f550b2bdc8360a6e4a7ded415d5ef826f67a8c3623c01751af885a428c2b504f12d04d8c673b1ec69a8a6f001951e442cecd11aae4fbc77a5c18f065574d4a28ee1bc5a987903b00dc61e6760695c627437bc7bed48e4fa16eccea6fa878e74dbb010fc52af27f36b6e81e70444ce0f4a83f5aeca326d5a842adba562a0d39410f4f700934b1881b2bebac2215261422b8f474673ef583e5431b183199faa764e1e340f873a104b6d4a0c39ab970e2d77e5f8e7335ea3c68e87a85fd45113eb53acfbc8feb3955f971df7cadafb2c4c9cb789c1de9468329915afe521681af9007e1388d5cca660d9b13325ac31242e0403c1d82d871d2efc0706d58532c4609502a807ebd95e64653e3a631f469c01c89cd70247b11bbb61eb15347023b8280ab44d4ca21d455a913889a541325dec2ef257e6cd3bb3d7830ff465240d132aa6ee0b9146682d86c093b5f1f40ce5368f43198968d85070609a178797300e57291ea0c967e2dbe874136406b58f163e68be4325db28b3c684c020be278a7d126efd215c1fb84350864f18926d9f394b109a308468ead25bf2475e79843bbd7f323219ecb2ab658da2d9ded21953f25383a9952fe2e47c3ed3f11c61b85e388c553a59d896a2eceaaf2d0e826bb77b1bb3e0f8ddbb3e04ec0f811063dd3775423d71f8632a3af2cda84d789afe92d710fd35305abcf1f2dd608ef3319eb4e2b21e94352d06836d83caaf8088ce9bbf78b4c16a962581e8766f4c08bdfbc9920f3ab47fe372816a4e8d0f7d78a622ff16af7d71651e4abb8cc0dd920b4e089df5399b2e1a7d06dbc75870ca1498a045c35bde9938361005cca7ba2bb8573e365406f7e12ba2de2d060a6a794fcc22c4f8289f772c309e3a79df55ca3869b010754e89d596de5aa70c779ec8ecf15788827b565c0abb43bb38c036ce987638a6654294efcbaf7b772fbbd9b00b62f4a898854a67a55006ece2fa37dd2ed18d29fc98343a5f166b2df1c5f1caec075987857286a6b782f529ea0fac91c5d5988813bc5c39201bcc236d51932a1545d30b147d743ce399b2e0c4e3a44b4888b16aff1e4c347ea6caee511424a14fe8bb0d6e8e0eb31be05de81b739f6f2646d0a6bf0dfc1859121402b1cca3b052671c5074796b0a87404b07518ad6b423bde12366e110d842dce8639778163f2f8c895abe32a2320593b4e4c51ed94a325d23c7cc02e46a3bed4b1bc322a6924e14705a4f1d5abf3a7f8853270edf58e0aeb7fd124550729570658752f3e9872e43abeddc8dd226761030a26b25203fd5b053dfebbea0f93835df44b2fcd5ce0a2463df58c88f7bf1798*ec90c1ff54632e7c8cfb812eeb14d7ec49ddaf576dca10bfb16f965e6106ce48", "btcr-test-password"},
	// Electrum 2.8.0+ encrypted wallet with truncated hash, "electrum28-wallet" from btcrecover project
	{"$electrum$5*0328e536dd1fbbb85d78de1a8c21215d4646cd87d6b6545afcfb203e5bb32e0de4*61b1e287a5acff4b40e4abd73ff62dc233c1c7a6a54b3270949281b9d44bc6e746743733360500718826e50bb28ea99a6378dc0b0c578e9d0bf09c667671c82a1bd71c8121edbb4c9cbca93ab0e17e218558ead81755e62b0d4ad547aa1b3beb0b9ee43b11270261c9b38502f00e7f6f096811b7fdae6f3dce85c278d3751fec044027054218ccf20d404bab24380b303f094704e626348a218f44ab88ce2ac5fa7d450069fca3bb53f9359dbbaad0ea1b3859129b19c93ed7888130f8a534f84a629c67edc150a1c5882a83cb0add4615bb569e8dc471de4d38fc8b1e0b9b28040b5ea86093fcdeceaedb6b8f073f6f0ee5541f473a4b1c2bfae4fc91e4bbb40fa2185ecfa4c72010bcf8df05b1a7db45f64307dbc439f8389f0e368e38960b6d61ac88c07ce95a4b03d6d8b13f4c7dc7d7c447097865235ab621aeef38dc4172bf2dc52e701132480127be375fe98834f16d9895dce7f6cdfe900a2ce57eaa6c3036c1b9a661c3c9adbf84f4adfe6d4d9fa9f829f2957cfb353917dc77fd8dd4872b7d90cb71b7d3a29c9bfe3440e02449220acba410fa0af030f51aa2438f7478dbb277d62613112e4eebc66d5d7bdba793fb2073d449954f563284819189ffb5dbcdeb6c95c64bc24e0ef986bce07bafe96ab449ae2b6edaf4f98ffbd392a57bd93c2359444ec4046ae65b440adb96b6e4eef9d06bb04d2f3fa2e4175165bcadbf7e13cc3b6e65e67df901f96a2f154bc763b56b3736a335e1d1bc16e99736f757a4ae56c099645c917360b1ecf8dcefc7281541c6ff65d87cadab4a48f1f6b7b73a3e5a67e2e032abb56b499e73a9f3b69ce065e43b0174639785ae30635d105ebcc827dcf9b19bdd1a92879a5d4bc4e12b5630c188b1b96e3c586e19901b8f96084bcd59b2f4b201a3a8b6e633a5c194901d4609add9671b0bcc12b2b94ae873d201258b36315484e4b9c5f5d6289656baa93eec9e92aec88e2d73d86b9e3d1f24294e3d8ebe9a9f2f6edfbf28f530670c5b086fc4f74df89b4e4cbe06ee7e45cbd238b599d19c2d5da5523b12b1e7050ea0a9b47a5d22c6c3fc476f814f9705dc7ed3aeb1b44fc6b4d69f02a74963dce5057c3c049f92e595a4da5035cffc303a4cb162803aa3f816527a7e466b8424789a0d77e26819615662420c370457e29fcc1938fd754f3acfd21416ce3ab27e9febbc0e24fc7055eddc31e48faa014f9f3695c2e956f0e6c94c507a8d2f8c3aeb4b98b69b6340b6a3acb1acdde9581279f78ee10687616360c018e9f67d6c8bb5950e8fdabd3d0d5808824975aa4a50f88581472212f24ad58a700fe4787642b973924575fe71d1ecd7b2b6acd363f48c40bdd55f35f60a06dee544c266e608fd5a6d263f745e8b11d1160638eb301adfd1a88eddf6d0ccb9e1021e0bde9cf5163583a202b3dc95c255c8cc24*ec90c1ff54632e7c8cfb812eeb14d7ec49ddaf576dca10bfb16f965e6106ce48", "btcr-test-password"},
	{NULL}
};

static struct custom_salt {
	uint32_t type;
	unsigned char salt[8]; // fake salt
	uint32_t saltlen;
	unsigned char ephemeral_pubkey[128];
	unsigned char data[16384]; // is 16 KiB enough?
	uint32_t datalen;
	unsigned char mac[32];
	secp256k1_pubkey pubkey;
} *cur_salt;

typedef struct {
	// for plaintext, we must make sure it is a full uint64_t width.
	uint64_t v[(PLAINTEXT_LENGTH + 7) / 8]; // v must be kept aligned(8)
	uint64_t length; // keep 64 bit aligned, length is overkill, but easiest way to stay aligned.
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	// for salt, we append \x00\x00\x00\x01\x80 and must make sure it is a full uint64 width
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE + 1 + 4 + 7) / 8]; // salt must be kept aligned(8)
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	uint64_t ipad[8];
	uint64_t opad[8];
	uint64_t hash[8];
	uint64_t W[8];
	cl_uint rounds;
} state_t;

static pass_t *host_pass;			      /** plain ciphertexts **/
static salt_t *host_salt;			      /** salt **/
static crack_t *host_crack;			      /** cracked or no **/
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel;
static cl_int cl_error;
static struct fmt_main *self;
static uint32_t (*crypt_out)[BINARY_SIZE * 2 / sizeof(uint32_t)];

#define STEP			0
#define SEED			256

static const char *warn[] = {
        "xfer: ",  ", init: " , ", crypt: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t min_lws =
		autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(min_lws, autotune_get_task_max_work_group_size(FALSE, 0,
	                                                          split_kernel));
}

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(crack_t));
	host_salt = mem_calloc(1, sizeof(salt_t));
	crypt_out = mem_calloc(kpc, sizeof(*crypt_out));
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)	  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error); \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)	  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
			"Cannot allocate mem in");
	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(salt_t),
			"Cannot allocate mem salt");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
			"Cannot allocate mem out");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
			"Cannot allocate mem state");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1, mem_out, "Error while setting mem_out");
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
		         HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha512_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       2, self, create_clobj, release_clobj,
		                       sizeof(state_t), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static void release_clobj(void)
{
	if (host_pass) {
		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);

		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 4 && value != 5)
		goto err;

	if ((p = strtokm(NULL, "*")) == NULL) // ephemeral_pubkey
		goto err;
	if (hexlenl(p, &extra) > 128 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // data
		goto err;
	if (hexlenl(p, &extra) > 16384 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // data
		goto err;
	if (hexlenl(p, &extra) > 32 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	secp256k1_context *ctx;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i, length;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	length = strlen(p) / 2;

	for (i = 0; i < length; i++)
		cs.ephemeral_pubkey[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	p = strtokm(NULL, "*");
	cs.datalen = strlen(p) / 2;
	for (i = 0; i < cs.datalen; i++)
		cs.data[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.mac[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	secp256k1_ec_pubkey_parse(ctx, &cs.pubkey, cs.ephemeral_pubkey, length);
	secp256k1_context_destroy(ctx);

	// we append the count and EOM here, one time.
	memcpy(cs.salt, "\x0\x0\x0\x1\x80", 5);
	cs.saltlen = 5; // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;

	memcpy(host_salt->salt, cur_salt->salt, cur_salt->saltlen);
	host_salt->length = cur_salt->saltlen;
	host_salt->rounds = 1024; // fixed

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, NULL),
		"Copy salt to gpu");
}

void *electrum_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static const char *group_order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

// The decypted and decompressed wallet should start with one of these two, // Christopher Gurnee
#define EXPECTED_BYTES_1 "{\n    \""
#define EXPECTED_BYTES_2 "{\r\n    \""

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	int index;
	int loops = (host_salt->rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		global_work_size * sizeof(pass_t), host_pass, 0, NULL,
		multi_profilingEvent[0]), "Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
				NULL, &global_work_size, lws, 0, NULL,
				multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					split_kernel, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
				global_work_size * sizeof(crack_t), host_crack,
				0, NULL, multi_profilingEvent[3]), "Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++) {
			BIGNUM *p, *q, *r;
			BN_CTX *ctx;
			uint64_t u[8];
			unsigned char static_privkey[64];
			unsigned char shared_pubkey[33];
			unsigned char keys[128];
			unsigned char cmac[32];
			secp256k1_context *sctx;
			SHA512_CTX md_ctx;
			int shared_pubkeylen= 33;
			int j;

			memcpy(u, host_crack[index].hash, 64);
			for (j = 0; j < 8; j++)
				u[j] = JOHNSWAP64(u[j]);
			memcpy(static_privkey, u, 64);
			// do static_privkey % GROUP_ORDER
			p = BN_bin2bn(static_privkey, 64, NULL);
			q = BN_new();
			r = BN_new();
			BN_hex2bn(&q, group_order);
			ctx = BN_CTX_new();
			BN_mod(r, p, q, ctx);
			BN_CTX_free(ctx);
			BN_free(p);
			BN_free(q);
			BN_bn2bin(r, static_privkey);
			BN_free(r);
			sctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
			// multiply point with a scaler, shared_pubkey is compressed representation
			secp256k1_mul(sctx, shared_pubkey, &cur_salt->pubkey, static_privkey);
			secp256k1_context_destroy(sctx);
			SHA512_Init(&md_ctx);
			SHA512_Update(&md_ctx, shared_pubkey, shared_pubkeylen);
			SHA512_Final(keys, &md_ctx);
			if (cur_salt->type == 4) {
				// calculate mac of data
				hmac_sha256(keys + 32, 32, cur_salt->data, cur_salt->datalen, cmac, 32);
				memcpy(crypt_out[index], cmac, BINARY_SIZE);
			} else if (cur_salt->type == 5) {
				z_stream z;
				unsigned char iv[16];
				unsigned char out[512] = { 0 };
				unsigned char fout[512] = { 0 };
				AES_KEY aes_decrypt_key;

				// common zlib settings
				z.zalloc = Z_NULL;
				z.zfree = Z_NULL;
				z.opaque = Z_NULL;
				z.avail_in = 512;
				z.avail_out = 512;
				z.next_out = fout;

				memcpy(iv, keys, 16);
				memset(crypt_out[index], 0, BINARY_SIZE);
				// fast zlib based rejection test, is this totally safe?
				AES_set_decrypt_key(keys + 16, 128, &aes_decrypt_key);
				AES_cbc_encrypt(cur_salt->data, out, 16, &aes_decrypt_key, iv, AES_DECRYPT);
				if ((memcmp(out, "\x78\x9c", 2) != 0) || (out[2] & 0x7) != 0x5) {
				} else {
					AES_set_decrypt_key(keys + 16, 128, &aes_decrypt_key);
					AES_cbc_encrypt(cur_salt->data + 16, out + 16, 512 - 16, &aes_decrypt_key, iv, AES_DECRYPT);
					z.next_in = out;
					inflateInit2(&z, 15);
					inflate(&z, Z_NO_FLUSH);
					inflateEnd(&z);
					if ((memcmp(fout, EXPECTED_BYTES_1, 7) == 0) || (memcmp(fout, EXPECTED_BYTES_2, 8) == 0))
						memcpy(crypt_out[index], cur_salt->mac, BINARY_SIZE); // dirty hack!
				}
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void set_key(char *key, int index)
{
	int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);
	// make sure LAST uint64 that has any key in it gets null, since we simply
	// ^= the whole uint64 with the ipad/opad mask
	strncpy((char*)host_pass[index].v, key, PLAINTEXT_LENGTH);
	host_pass[index].length = saved_len;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[host_pass[index].length] = 0;
	return ret;
}

struct fmt_main fmt_opencl_electrum_modern = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		electrum_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		electrum_get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

#endif /* HAVE_OPENCL */

#endif /* HAVE_LIBZ */
