/* GPG cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and is based on,
 *
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/> */

#include <string.h>
#include <openssl/aes.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include "sha.h"
#include "sha2.h"
#include "stdint.h"

#define FORMAT_LABEL        "gpg"
#define FORMAT_NAME         "OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#if defined (_OPENMP)
static int omp_t = 1;
#endif

#define KEYBUFFER_LENGTH 8192
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};


enum {
	PKA_UNKOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17,
	PKA_EG = 20
};

enum {
	CIPHER_UNKOWN = -1,
	CIPHER_CAST5 = 3,
	CIPHER_BLOWFISH = 4,
	CIPHER_AES128 = 7,
	CIPHER_AES192 = 8,
	CIPHER_AES256 = 9,
	CIPHER_IDEA = 1,
};

enum {
	HASH_UNKOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2,
	HASH_RIPEMD160 = 3,
	HASH_SHA256 = 8,
	HASH_SHA384 = 9,
	HASH_SHA512 = 10,
	HASH_SHA224 = 11
};

static struct custom_salt {
	int datalen;
	unsigned char data[4096];
	char spec;
	char pk_algorithm;
	char hash_algorithm;
	char cipher_algorithm;
	int usage;
	int bits;
	unsigned char salt[8];
	unsigned char iv[16];
	int ivlen;
	int count;
	void (*s2kfun)(char *, unsigned char*, int);
	unsigned char p[4096];
	unsigned char q[4096];
	unsigned char g[4096];
	unsigned char y[4096];
	unsigned char x[4096];
	int pl;
	int ql;
	int gl;
	int yl;
	int xl;
} *cur_salt;



// Returns the block size (in bytes) of a given cipher
static uint32_t blockSize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_BLOCK;
		case CIPHER_BLOWFISH:
			return BF_BLOCK;
		case CIPHER_IDEA:
			return 8; // XXX
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256:
			return AES_BLOCK_SIZE;
		default:
			break;
	}
	return 0;
}

// Returns the key size (in bytes) of a given cipher
static uint32_t keySize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_KEY_LENGTH; // 16
		case CIPHER_BLOWFISH:
			return 16;
		case CIPHER_AES128:
			return 16;
		case CIPHER_AES192:
			return 24;
		case CIPHER_AES256:
			return 32;
		case CIPHER_IDEA:
			return 16;
		default: break;
	}
	assert(0);
	return 0;
}

// Returns the digest size (in bytes) of a given hash algorithm
#if 0 // now unused
static uint32_t digestSize(char algorithm)
{
	switch (algorithm) {
		case HASH_MD5:
			return 16;
		case HASH_SHA1:
			return 20;
		case HASH_SHA512:
			return 64;
		case HASH_SHA256:
			return 32;
		case HASH_RIPEMD160:
			return 20;
		default: break;
	}
	assert(0);
}
#endif

static struct fmt_tests gpg_tests[] = {
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*667*2048*387de4c9e2c1018aed84af75922ecaa92d1bc68d48042144c77dfe168de1fd654e4db77bfbc60ec68f283483382413cbfddddcfad714922b2d558f8729f705fbf973ab1839e756c26207a4bc8796eeb567bf9817f73a2a81728d3e4bc0894f62ad96e04e60752d84ebc01316703b0fd0f618f6120289373347027924606712610c583b25be57c8a130bc4dd796964f3f03188baa057d6b8b1fd36675af94d45847eeefe7fff63b755a32e8abe26b7f3f58bb091e5c7b9250afe2180b3d0abdd2c1db3d4fffe25e17d5b7d5b79367d98c523a6c280aafef5c1975a42fd97242ba86ced73c5e1a9bcab82adadd11ef2b64c3aad23bc930e62fc8def6b1d362e954795d87fa789e5bc2807bfdc69bba7e66065e3e3c2df0c25eab0fde39fbe54f32b26f07d88f8b05202e55874a1fa37d540a5af541e28370f27fe094ca8758cd7ff7b28df1cbc475713d7604b1af22fd758ebb3a83876ed83f003285bc8fdc7a5470f7c5a9e8a93929941692a9ff9f1bc146dcc02aab47e2679297d894f28b62da16c8baa95cd393d838fa63efc9d3f88de93dc970c67022d5dc88dce25decec8848f8e6f263d7c2c0238d36aa0013d7edefd43dac1299a54eb460d9b82cb53cf86fcb7c8d5dba95795a1adeb729a705b47b8317594ac3906424b2c0e425343eca019e53d927e6bc32688bd9e87ee808fb1d8eeee8ab938855131b839776c7da79a33a6d66e57eadb430ef04809009794e32a03a7e030b8792be5d53ceaf480ffd98633d1993c43f536a90bdbec8b9a827d0e0a49155450389beb53af5c214c4ec09712d83b175671358d8e9d54da7a8187f72aaaca5203372841af9b89a07b8aadecafc0f2901b8aec13a5382c6f94712d629333b301afdf52bdfa62534de2b10078cd4d0e781c88efdfe4e5252e39a236af449d4d62081cee630ab*3*254*2*3*8*b1fdf3772bb57e1f*65536*2127ccd55e721ba0", "polished"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*e5f3ef815854f90dfdc3ad61c9c92e512a53d7203b8a5665a8b00ac5ed92340a6ed74855b976fc451588cc5d51776b71657830f2c311859022a25412ee6746622febff8184824454c15a50d64c18b097af28d3939f5c5aa9589060f25923b8f7247e5a2130fb8241b8cc07a33f70391de7f54d84703d2537b4d1c307bdf824c6be24c6e36501e1754cc552551174ed51a2f958d17c6a5bd3b4f75d7979537ee1d5dcd974876afb93f2bcda7468a589d8dba9b36afbe019c9086d257f3f047e3ff896e52783f13219989307bf277e04a5d949113fc4efcc747334f307a448b949ee61b1db326892a9198789f9253994a0412dd704d9e083000b63fa07096d9d547e3235f7577ecd49199c9c3edfa3e43f65d6c506363d23c21561707f790e17ea25b7a7fce863b3c952218a3ac649002143c9b02df5c47ed033b9a1462d515580b10ac79ebdca61babb020400115f1e9fad26318a32294034ea4cbaf681c7b1de12c4ddb99dd4e39e6c8f13a322826dda4bb0ad22981b17f9e0c4d50d7203e205fb2ee6ded117a87e47b58f58f442635837f2debc6fcfbaebba09cff8b2e855d48d9b96c9a9fb020f66c97dffe53bba316ef756c797557f2334331eecaedf1ab331747dc0af6e9e1e4c8e2ef9ed2889a5facf72f1c43a24a6591b2ef5128ee872d299d32f8c0f1edf2bcc35f453ce27c534862ba2c9f60b65b641e5487f5be53783d79e8c1e5f62fe336d8854a8121946ea14c49e26ff2b2db36cef81390da7b7a8d31f7e131dccc32e6828a32b13f7a56a28d0a28afa8705adbf60cb195b602dd8161d8b6d8feff12b16eb1ac463eaa6ae0fd9c2d906d43d36543ef33659a04cf4e69e99b8455d666139e8860879d7e933e6c5d995dd13e6aaa492b21325f23cbadb1bc0884093ac43651829a6fe5fe4c138aff867eac253569d0dc6*3*254*2*3*8*e318a03635a19291*65536*06af8a67764f5674", "blingbling"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*8487ca407790457c30467936e109d968bdff7fa4f4d87b0af92e2384627ca546f2898e5f77c00300db87a3388476e2de74f058b8743c2d59ada316bc81c79fdd31e403e46390e3e614f81187fb0ae4ca26ed53a0822ace48026aa8a8f0abdf17d17d72dfa1eba7a763bbd72f1a1a8c020d02d7189bd95b12368155697f5e4e013f7c81f671ca320e72b61def43d3e2cb3d23d105b19fe161f2789a3c81363639b4258c855c5acd1dd6596c46593b2bfec23d319b58d4514196b2e41980fbb05f376a098049f3258f9cdf1628c6ff780963e2c8dc26728d33c6733fbac6e415bd16d924a087269e8351dd1c6129d1ac7925f19d7c9a9ed3b08a53e207ffbfba1d43891da68e39749775b38cbe9e6831def4b4297ce7446d09944583367f58205a4f986d5a84c8cf3871a7e2b6c4e2c94ff1df51cd94aecf7a76cd6991a785c66c78f686e6c47add9e27a6b00a2e709f1383f131e3b83b05c812b2ec76e732d713b780c381b0785f136cd00de7afa0276c95c5f0bb3a4b6ad484d56e390c11f9d975729ae1665189190fd131f49109f899735fd2c2efbafd8b971b196d18aeff70decc9768381f0b2243a05db99bd5911d5b94770ee315e1fe3ab0e090aa460d2c8d06a06fef254fd5fa8967386f1f5d37ea6f667215965eefe3fc6bc131f2883c02925a2a4f05dabc48f05867e68bb68741b6fb3193b7c51b7d053f6fd45108e496b9f8f2810fa75ffe454209e2249f06cc1bfc838a97436ebd64001b9619513bcb519132ce39435ed0d7c84ec0c6013e786eef5f9e23738debc70a68a389040e8caad6bd5bb486e43395e570f8780d3f1d837d2dc2657bbded89f76b06c28c5a58ecaa25a225d3d4513ee8dc8655907905590737b971035f690ac145b2d4322ecc86831f36b39d1490064b2aa27b23084a3a0b029e49a52b6a608219*3*254*2*3*8*0409f810febe5e05*65536*ce0e64511258eecc", "njokuani."},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*348*1024*e5fbff62d94b41de7fc9f3dd93685aa6e03a2c0fcd75282b25892c74922ec66c7327933087304d34d1f5c0acca5659b704b34a67b0d8dedcb53a10aee14c2615527696705d3ab826d53af457b346206c96ef4980847d02129677c5e21045abe1a57be8c0bf7495b2040d7db0169c70f59994bba4c9a13451d38b14bd13d8fe190cdc693ee207d8adfd8f51023b7502c7c8df5a3c46275acad6314d4d528df37896f7b9e53adf641fe444e18674d59cf46d5a6dffdc2f05e077346bf42fe35937e95f644a58a2370012d993c5008e6d6ff0c66c6d0d0b2f1c22961b6d12563a117897675f6b317bc71e4f2dbf6b9fff23186da2724a584d70401136e8c500784df462ea6548db4eecc782e79afe52fd8c1106c7841c085b8d44465d7a1910161d6c707a377a72f85c39fcb4ee58e6b2f617b6c4b173a52f171854f0e1927fa9fcd9d5799e16d840f06234698cfc333f0ad42129e618c2b9c5b29b17b7*3*254*2*3*8*7353cf09958435f9*9961472*efadea6cd5f3e5a7", "openwall"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*97b296b60904f6d505344b5b0aa277b0f40de05788a39cd9c39b14a56b607bd5db65e8da6111149a1725d06a4b52bdddf0e467e26fe13f72aa5570a0ea591eec2e24d3e9dd7534f26ec9198c8056ea1c03a88161fec88afd43474d31bf89756860c2bc6a6bc9e2a4a2fc6fef30f8cd2f74da6c301ccd5863f3240d1a2db7cbaa2df3a8efe0950f6200cbc10556393583a6ebb2e041095fc62ae3a9e4a0c5c830d73faa72aa8167b7b714ab85d927382d77bbfffb3f7c8184711e81cf9ec2ca03906e151750181500238f7814d2242721b2307baa9ea66e39b10a4fdad30ee6bff50d79ceac604618e74469ae3c80e7711c16fc85233a9eac39941a564b38513c1591502cde7cbd47a4d02a5d7d5ceceb7ff920ee40c29383bd7779be1e00b60354dd86ca514aa30e8f1523efcffdac1292198fe96983cb989a259a4aa475ed9b4ce34ae2282b3ba0169b2e82f9dee476eff215db33632cdcc72a65ba2e68d8e3f1fed90aaa68c4c886927b733144fb7225f1208cd6a108e675cc0cb11393db7451d883abb6adc58699393b8b7b7e19c8584b6fc95720ced39eabaa1124f423cc70f38385c4e9c4b4eeb39e73e891da01299c0e6ce1e97e1750a5c615e28f486c6a0e4da52c15285e7cf26ac859f5f4190e2804ad81ba4f8403e6358fbf1d48c7d593c3bac20a403010926877db3b9d7d0aaacd713a2b9833aff88d1e6b4d228532a66fe68449ad0d706ca7563fe8c2ec77062cc33244a515f2023701c052f0dd172b7914d497fdaefabd91a199d6cb2b62c71472f52c65d6a67d97d7713d39e91f347d2bc73b421fb5c6c6ba028555e5a92a535aabf7a4234d6ea8a315d8e6dcc82087cc76ec8a7b2366cecf176647538968e804541b79a1b602156970d1b943eb2641f2b123e45d7cace9f2dc84b704938fa8c7579a859ef87eca46*3*254*2*3*8*d911a3f73b050340*2097152*347e15bee29eb77d", "password"},
	/* SHA256-AES256 salt-iter */
	{"$gpg$*1*348*1024*8f58917c41a894a4a3cdc138161c111312e404a1a27bb19f3234656c805ca9374bbfce59750688c6d84ba2387a4cd48330f504812cf074eba9c4da11d057d0a2662e3c7d9969e1256e40a56cce925fba29f4975ddb8619004def3502a0e7cf2ec818695c158243f21da34440eea1fec20418c7cf7dbe2230279ba9858201c00ae1d412aea1f59a66538fb739a15297ff9de39860e2782bf60a3979a5577a448925a0bc2d24c6bf3d09500046487a60bf5945e1a37b73a93eebb15cfd08c5279a942e150affbbe0d3084ab8aef2b6d9f16dc37b84334d91b80cf6f7b6c2e82d3c2be42afd39827dac16b4581be2d2f01d9703f2b19c16e149414fdfdcf8794aa90804e4b1dac8725bd0b0be52513848973eeadd5ec06d8a1da8ac072800fcc9c579172b58d39db5bc00bc0d7a21cf85fb6c7ce10f64edde425074cb9d1b4b078790aed2a46e79dc7fa4b8f3751111a2ff06f083a20c7d73d6bbc747e0*3*254*8*9*16*5b68d216aa46f2c1ed0f01234ebb6e06*131072*6c18b4661b884405", "openwall"},
	/* RIPEMD160-AES256 salt-iter */
	{"$gpg$*1*348*1024*7fc751702c5b678089bbd667000172649b029906ed59ba163bb4418cf384f6e39d07cd4763f874f1afbdacf1ed33544321ad9e664d6428c1865b8ea7d9026b558cc1f9c139ca771c6ceca03d57af635fc9140a3f5d2bec7117a98e6561cbe7efedcee129cf7dc1de39a7b92b7d3e17f45c54bba8ce8b0c8eb73611af8f44d5551c101ebe3d7466e1ae393fbf928bb297de0ce7e64f180bc76c770e72ca5da0c27a3abaf208d51c831f9f9f885269d28aa73a93c2be0185cc71f99381635a8e7c4c48fbe77620bb19a829c62dfed5e9e088fad12ea99003117886715c88a2f9926580d47d99a7f2b38f518bc011051c57c6c6c407bf9944b279db8456a6a4d1d5811558aaf8c108c6157cbeb297d26ab407c8c5d6a0038374f903a93e78ba857d97dc71d709faf0824d7bf092a36c4df2932bb4fd2c967fcbeb296a4ee3f45e550de04e62371ed9874068d9025e0fcf136a823ef0af9ce24f7ed4cc8b*3*254*3*9*16*3a9305fd67934b258d749739a360a6dd*131072*316217f7c4782365", "openwall"},
	/* SHA1-CAST5 salt-iter, DSA key */
	{"$gpg$*17*42*1024*d974ae70cfbf8ab058b2e1d898add67ab1272535e8c4b9c5bd671adce22d08d5db941a60e0715b4f0c9d*3*254*2*3*8*a9e85673bb9199d8*11534336*71e35b85cddfe2af", "crackme"},
	/* MD5-CAST5 salt-iter */
	{"$gpg$*17*42*1024*002170c3c5778fdbeedd788a1eda3827ef7d6d73491c022d5b76d33ff70ccae8d243aab7e2f40afcb4a4*3*254*1*3*8*019e084555546803*65536*49afdb670acda6c6", "MD5-CAST5-openwall"},
	/* gpg --s2k-mode 0 --gen-key*/
	{"$gpg$*1*668*2048*98515325c60af7a5f9466fd3c51fb49e6001567145dba5bb60a23d3c108a86b83793617b63e3fdfd94a07886782feb555e92366aeecb172ad7614ad6a6bbf137aa75a1d44dc550485b2103d194c691f1bf44301fc0d337e00d2b319958f709b4ca0b5cb7af119931abd99dfb75650210fc66be32af0b3dddaf362ef3504ef76cda787b28e17bc173d9c4ff4829713c9ee5d5282df443c7fc112e79da47091cf671b87179b8ce900873321c180ebc45d11a95aaf27610231b6abf1f22f71fdddd694334a752662ae4d62de122f1ff2ba95ba5fab7e5a498edd389d014926dd91c1769bfdd00d65123a8ec3e31d70e0ffe04eb8ef69648b9895c4cd5afc1e0ec81fa032e1b17c876b30241d1f5464535dfd7cf13f31c1bc1aa6150070afb491cca8afe4af9df174a49d1b8ebffe65298fc85ada9cf1ec61db243792d878bf4fdb12592f1a493912340010b173b4ccd49be7f1bc3565e9bdc601c5ecb01253979f64282fb34970d1d7ad1d13987032cda00a74d1d3117393a0cee73c2303fe4c5ba3938959956abfde9f5f24a7590a8d2224c2f2ca2bbc699841bf23f04e9a2a2974dfdd091462b1e93f47b8e3fcd75009f2f50839b3720f33cabc41adf17b4353ec8bc997f449b5fe4f320b8bf0e5e392386e0ef9b665a3680405e7c022a37e2ebeb2c41294455d97783f22137d4051f07ea215f91fa417d378496f5930cbc13dd942249d265c3d4a36e1e1fbed147153f2c3e3d4a43bec4606fcba57e2e4783240062285757ba39e1cc01b8506314a438fb99306a2dbb0cae1dbb5410965a8342cffa4ffcae8e79198404507c4f8d39cc3979c3f407d5d91ed6335e069087a975221c78b02726f234e64ff746a5e814997bbaa11f2885c0d00f242dff3138ff2556d577c125765f0fd08dfa66795ba810e3bb90efcfd9f5c3cb643bdf*0*254*2*3*8*01942c062e4b5eb0", "openwall@12345"},
	/* gpg --s2k-mode 1 --gen-key, old GnuPG versions (e.g GnuPG 1.0.3), uses *new* hash format */
	{"$gpg$*17*24*1024*b0d0b23529f968c0d05fa8caf38445c5bca5c2523ae6cc87*1*255*2*3*8*c5efc5bab719aa63*0*a0ccc71dedfce4d3*128*bb0ccf0f171fbb6438d94fdf24b749461c63902c4dca06f2d5580bca5837899431f1cbc7ccd56db8c9136a4ac7230a21eb6ab51a7c7a24fe23e99dd546eeb07cadb96372b0cb4a7dc2ba31e399d779e8ffa87f6f16c22ab54226a8a565550cfe98bee81001a810749327dca46f4ce7eb4f9726a00069026cb89f9533599cacdb*20*ec99ac865efa5aa7a9f1da411107e02e8e41daf5*128*16ed223362bb289889bf15c0ef3ce88b94892d57ea486f7cd63a1f8f83da3c28a6ee3879787c654c97e4824c75b0efd7f36db36947dfb8c9b1cfe0562c4e7d8b2b600973b9b379a1891200941b3a17361e49ccf157b0797a9d2f7535da0455c8d822b669ed6fc5fec56c71ad5df6fd9d4a4b67458b2e576a144ba2d0f49eff72*128*7991ba80eae8aa9d8adb38ae3c91fe771b7dc0a6f30fdc45d357acd5fcae1176245807972c39748880080d609f4c7e11a6c30d7ad144d848838e4ace2d9716c6e27edb6ef6ca453d7a8a3b0320fe721bc094e891b73f4515f3e34f52dfbf002108b0412bf54142b4d2c411fee99fd0b459de0a3825dc5be078b6e48d7aa5ceae", "wtf@123"},
	/* gpg --s2k-mode 1 --gen-key, old GnuPG versions (e.g GnuPG 1.0.3), uses *new* hash format, ElGamal */
	{"$gpg$*16*36*1024*0a4c2fb9d1ff24b817212a9cc0d3f2d84184a368ff3a04c337566812d037e5fe28933eaa*1*255*2*3*8*b312f3046fdb046c*0*a0ccc71dedfce4d3*128*f9235c132a796b0fd67f59567cf01dcf0a4ebbc8607a1033cefd2d52be40334e8cfba60737751b1bf16e36399340698656255917ca65f1f6f7806f05f686889ef7dc7030dd17dc9b45a1e1f01ab8d8a676d5a1759ac65bd1e2e50282f9926b44a156f7fea5e4ae5883e10f533efb9cd857efb84d23062f9741b4bd2ba70abcb3*1*05*128*e67deba19288e87c93829194698d10169e1f42eb43bba46b563037177ee09801a824fc9be2796fd24f4438c1a72f2e8587e6507ab1a408695a46709b87cc171366eef9ee86bd7935dd0ef6d4efdba738d7d8cb40dfe0f3dec996ebe2153fec9c091b5be0d31e398d8de75de4e346e299a07603242846b87f2b90ed82f9143786", "wtf@123"},
	{NULL}
};

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid_cipher_algorithm(int cipher_algorithm)
{
	switch(cipher_algorithm)
	{
	  case CIPHER_CAST5: return 1;
	  case CIPHER_BLOWFISH: return 1;
	  case CIPHER_AES128: return 1;
	  case CIPHER_AES192: return 1;
	  case CIPHER_AES256: return 1;
	  case CIPHER_IDEA: return 1;
	}
	return 0;
}

static int valid_hash_algorithm(int hash_algorithm, int spec)
{
      if(spec == SPEC_SIMPLE || spec == SPEC_SALTED)
	switch(hash_algorithm)
	{
	  case HASH_SHA1: return 1;
	  case HASH_MD5: return 1;
	}
      if(spec == SPEC_ITERATED_SALTED)
	switch(hash_algorithm)
	{
	  case HASH_SHA1: return 1;
	  case HASH_MD5: return 1;
	  case HASH_SHA256: return 1;
	  case HASH_RIPEMD160: return 1;
	  case HASH_SHA512: return 1;
	}
      return 0;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int res,i,spec;
	if (strncmp(ciphertext, "$gpg$", 5) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 5;	/* skip over "$gpg$" marker */
	if ((p = strtok(ctcopy, "*")) == NULL)	/* algorithm */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* datalen */
		goto err;
	res = atoi(p);
	if (res > 4096)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* bits */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* data */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	for(i = 0; i < strlen(p); i++)
		if(atoi16[ARCH_INDEX(p[i])] == 0x7F)
			goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* spec */
		goto err;
	spec = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* usage */
		goto err;
	res = atoi(p);
	if(res != 0 && res != 254 && res != 255)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* hash_algorithm */
		goto err;
	res = atoi(p);
	if(!valid_hash_algorithm(res,spec))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* cipher_algorithm */
		goto err;
	res = atoi(p);
	if(!valid_cipher_algorithm(res))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* ivlen */
		goto err;
	res = atoi(p);
	if (res != 8 && res != 16)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	for(i = 0; i < strlen(p); i++)
		if(atoi16[ARCH_INDEX(p[i])] == 0x7F)
			goto err;
	/* handle "SPEC_SIMPLE" correctly */
	if (spec == 0) {
		MEM_FREE(keeptr);
		return 1;
	}
	if ((p = strtok(NULL, "*")) == NULL)	/* count */
		goto err;
	res = atoi(p);
	if(res < 0)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != 8 * 2)
		goto err;
	for(i = 0; i < strlen(p); i++)
		if(atoi16[ARCH_INDEX(p[i])] == 0x7F)
			goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void S2KSimpleSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

static void S2KSimpleMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}


void S2KSaltedSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, cur_salt->salt, 8);
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

void S2KSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, cur_salt->salt, 8);
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA1Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);

	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			SHA1_Update(&ctx, keybuf, bs);
		}
		SHA1_Update(&ctx, keybuf, cur_salt->count % bs);
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}


static void S2KItSaltedSHA256Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA256_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);

	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		SHA256_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA256_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			SHA256_Update(&ctx, keybuf, bs);
		}
		SHA256_Update(&ctx, keybuf, cur_salt->count % bs);
		SHA256_Final(key + (i * SHA256_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA512Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA512_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA512_DIGEST_LENGTH - 1) / SHA512_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);

	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		SHA512_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA512_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			SHA512_Update(&ctx, keybuf, bs);
		}
		SHA512_Update(&ctx, keybuf, cur_salt->count % bs);
		SHA512_Final(key + (i * SHA512_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedRIPEMD160Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	RIPEMD160_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + RIPEMD160_DIGEST_LENGTH - 1) / RIPEMD160_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);

	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		RIPEMD160_Init(&ctx);
		for (j = 0; j < i; j++) {
			RIPEMD160_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			RIPEMD160_Update(&ctx, keybuf, bs);
		}
		RIPEMD160_Update(&ctx, keybuf, cur_salt->count % bs);
		RIPEMD160_Final(key + (i * RIPEMD160_DIGEST_LENGTH), &ctx);
	}
}
static void S2KItSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	unsigned char keybuf[KEYBUFFER_LENGTH];
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);
	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}

		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			MD5_Update(&ctx, keybuf, bs);
		}
		MD5_Update(&ctx, keybuf, cur_salt->count % bs);
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 5;	/* skip over "$gpg$" marker */
	p = strtok(ctcopy, "*");
	cs.pk_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.datalen = atoi(p);
	p = strtok(NULL, "*");
	cs.bits = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.datalen; i++)
		cs.data[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.spec = atoi(p);
	p = strtok(NULL, "*");
	cs.usage = atoi(p);
	p = strtok(NULL, "*");
	cs.hash_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.cipher_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.ivlen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	/* handle "SPEC_SIMPLE" correctly */
	if (cs.spec != 0) {
		cs.count = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < 8; i++)
			cs.salt[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (cs.usage == 255 && cs.spec == 1 && cs.pk_algorithm == 17) {
		/* old hashes will crash!, "gpg --s2k-mode 1 --gen-key" */
		p = strtok(NULL, "*");
		cs.pl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.ql = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.q[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.gl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.yl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (cs.usage == 255 && cs.spec == 1 && cs.pk_algorithm == 16) {
		/* ElGamal */
		p = strtok(NULL, "*");
		cs.pl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.gl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.yl = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);

	// Set up the key generator
	switch(cs.spec) {
		case SPEC_ITERATED_SALTED:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KItSaltedSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KItSaltedMD5Generator;
						break;
					case HASH_SHA256:
						cs.s2kfun = S2KItSaltedSHA256Generator;
						break;
					case HASH_RIPEMD160:
						cs.s2kfun = S2KItSaltedRIPEMD160Generator;
						break;
					case HASH_SHA512:
						cs.s2kfun = S2KItSaltedSHA512Generator;
						break;
					default: break;
				}
			}
			break;
		case SPEC_SALTED:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KSaltedSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KSaltedMD5Generator;
						break;
					default: break;
				}
			}
			break;
		case SPEC_SIMPLE:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KSimpleSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KSimpleMD5Generator;
						break;
					default: break;
				}
			}
			break;
	}
	assert(cs.s2kfun != NULL);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void gpg_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

// borrowed from "passe-partout" project
static int check_dsa_secret_key(DSA *dsa)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_dsa_secret_key()\n");
		exit(-1);
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in check_dsa_secret_key()\n");
		exit(-1);
	}

	error = BN_mod_exp(res, dsa->g, dsa->priv_key, dsa->p, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, dsa->pub_key);

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(dsa->g);
	BN_free(dsa->q);
	BN_free(dsa->p);
	BN_free(dsa->pub_key);
	BN_free(dsa->priv_key);

	return rc;
}

typedef struct {
	BIGNUM *p;          /* prime */
	BIGNUM *g;          /* group generator */
	BIGNUM *y;          /* g^x mod p */
	BIGNUM *x;          /* secret exponent */
} ElGamal_secret_key;

// borrowed from GnuPG
static int check_elg_secret_key(ElGamal_secret_key *elg)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_elg_secret_key()\n");
		exit(-1);
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in chec_elg_secret_key()\n");
		exit(-1);
	}

	error = BN_mod_exp(res, elg->g, elg->x, elg->p, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, elg->y);

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(elg->g);
	BN_free(elg->p);
	BN_free(elg->y);
	BN_free(elg->x);

	return rc;
}

static int check(unsigned char *keydata, int ks)
{
	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
	unsigned char ivec[32];
	unsigned char out[4096] = { 0 };
	int tmp = 0;
	uint32_t num_bits;
	int checksumOk;
	int i;

	// Quick Hack
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   idea_set_encrypt_key(keydata, &iks);
					   idea_cfb64_encrypt(cur_salt->data, out, 8, &iks, ivec, &tmp, IDEA_DECRYPT);
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, CAST_BLOCK, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, BF_BLOCK, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, AES_BLOCK_SIZE, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    printf("(check) Unknown Cipher Algorithm %d ;(\n", cur_salt->cipher_algorithm);
				    break;
	}
	num_bits = ((out[0] << 8) | out[1]);
	if (num_bits < MIN_BN_BITS || num_bits > cur_salt->bits) {
		return 0;
	}
	// Decrypt all data
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	tmp = 0;
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   idea_set_encrypt_key(keydata, &iks);
					   idea_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &iks, ivec, &tmp, IDEA_DECRYPT);
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}
	// Verify
	checksumOk = 0;
	switch (cur_salt->usage) {
		case 254: {
				  uint8_t checksum[SHA_DIGEST_LENGTH];
				  SHA_CTX ctx;
				  SHA1_Init(&ctx);
				  SHA1_Update(&ctx, out, cur_salt->datalen - SHA_DIGEST_LENGTH);
				  SHA1_Final(checksum, &ctx);
				  if (memcmp(checksum, out + cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0)
					  return 1;  /* we have a 20 byte verifier ;) */
				  else
					  return 0;
			  } break;
		case 0:
		case 255: {
				  // https://tools.ietf.org/html/rfc4880#section-3.7.2
				  uint16_t sum = 0;
				  for (i = 0; i < cur_salt->datalen - 2; i++) {
					  sum += out[i];
				  }
				  if (sum == ((out[cur_salt->datalen - 2] << 8) | out[cur_salt->datalen - 1])) {
					  checksumOk = 1;
				  }
			  } break;
		default:
			  break;
	}
	// If the checksum is ok, try to parse the first MPI of the private key
	// Stop relying on checksum altogether, GnuPG ignores it (after
	// documenting why though!)
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (num_bits + 7) / 8;
		int ret;
		if (cur_salt->datalen == 24 && blen != 20)  /* verifier 1 */
			return 0;
		if (blen < cur_salt->datalen && ((b = BN_bin2bn(out + 2, blen, NULL)) != NULL)) {
			char *str = BN_bn2hex(b);
			DSA dsa;
			ElGamal_secret_key elg;
			if (strlen(str) != blen * 2) { /* verifier 2 */
				free(str);
				return 0;
			}
			free(str);

			if (cur_salt->pk_algorithm == 17) { /* DSA check */
				dsa.p = BN_bin2bn(cur_salt->p, cur_salt->pl, NULL);
				// puts(BN_bn2hex(dsa.p));
				dsa.q = BN_bin2bn(cur_salt->q, cur_salt->ql, NULL);
				// puts(BN_bn2hex(dsa.q));
				dsa.g = BN_bin2bn(cur_salt->g, cur_salt->gl, NULL);
				// puts(BN_bn2hex(dsa.g));
				dsa.priv_key = b;
				dsa.pub_key = BN_bin2bn(cur_salt->y, cur_salt->yl, NULL);
				// puts(BN_bn2hex(dsa.pub_key));
				ret = check_dsa_secret_key(&dsa); /* verifier 3 */
				if (ret != 0)
					return 0;
			}
			if (cur_salt->pk_algorithm == 16) { /* ElGamal check */
				elg.p = BN_bin2bn(cur_salt->p, cur_salt->pl, NULL);
				// puts(BN_bn2hex(elg.p));
				elg.g = BN_bin2bn(cur_salt->g, cur_salt->gl, NULL);
				// puts(BN_bn2hex(elg.g));
				elg.x = b;
				// puts(BN_bn2hex(elg.x));
				elg.y = BN_bin2bn(cur_salt->y, cur_salt->yl, NULL);
				// puts(BN_bn2hex(elg.y));
				ret = check_elg_secret_key(&elg); /* verifier 3 */
				if (ret != 0)
					return 0;
			}
			return 1;
		}
	}
	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		// allocate string2key buffer
		int res;
		int ks = keySize(cur_salt->cipher_algorithm);
		//int ds = digestSize(cur_salt->hash_algorithm);
		unsigned char keydata[64 * ((32 + 64 - 1) / 64)];

		cur_salt->s2kfun(saved_key[index], keydata, ks);
		res = check(keydata, ks);
		if(res)
			any_cracked = cracked[index] = 1;
	}
	return count;
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

struct fmt_main fmt_gpg = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		gpg_tests
	},
	{
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		gpg_set_key,
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
