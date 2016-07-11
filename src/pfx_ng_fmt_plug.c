/*
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pfx_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pfx_ng);
#else

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "hmac_sha.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif
#include "pkcs12.h"
#include "twofish.h"
#include "sha.h"
#include "loader.h"
#include "memdbg.h"

#define FORMAT_LABEL            "pfx-ng"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(ARCH_WORD_32)
#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$pfxng$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#define MAX_DATA_LENGTH         8192 // XXX ensure this is large enough

static struct fmt_tests tests[] = {
	{"$pfxng$1$20$2048$8$e861d3357729c35f$308206513082032f06092a864886f70d010706a08203203082031c0201003082031506092a864886f70d010701301c060a2a864886f70d010c0103300e04086c933ea5111fd24602020800808202e83c56ad18c45e54aaca4d170750cfbfb3059d6cf161e49d379eab15e722216cb479eee8da7b6e6ffc89e01fbf30f4eb5e1b88ca146c166c700a68473d25a0979344cc60d1e58230a12d24b8be6e9174d3afecdf111cd7d96527831ac9c8f4bf3817cda021f34b61899f2a75fe511e8dedfb70367fa9902d2d3e500f853cc5a99ec8672a44713d24ae49382a20db6349bc48b23ad8d4be3aa31ba7e6d720590b5e4f6b0b5d84b7789ae9da7a80bfa3c27e507fc87e7bc943cff967db6b76f904ac52c1db5cfe9915fa3493cd42b8db6deae62bc01593e34bc8598f27a24cdfd242701ff72d997f959f3a933ab5a2762df33849c116715b78cb0d83267aff913619cbbdf003e13318e4b188a8a4f851b9f59ae2c71ab215c565f7872e5d54c06f92d6f59eaf19d95f9b4526d52d289cd17bc0c2079f9f13c20a70a566773d90ca6d888386d909b6362cb79e15cf547dceab1fe793c577b70f72463969f7b416fb5a6228053363558df18588b53406343ab320a1bbf1757b67ef8e3075f44dee4521f4a461d37ea894c940bc87f9bd33276f2843ff5922fd8e61d22a8619ad23154880fd7d957c0f151458fc4f686d96695a823b08c1795daaf79e41118a3c57ee065a693853a9c4b2004440662f51d63bb9973dc4bb8c541d424416c57d01a825be4d31dab7c7f4b2b738e4bbfdda1e3d3b95e026dadee4dfe155c0f4a24991693f679b452516bc19eab7cf7eb41b476358583d46630e8cda55974b8fcbe25b93e91e73f584a913149137c1c20d13f38826d8dba9bcf5504b8cee77e20a19d6fb050e9213b8aeb11c26a871c600701aea352ba2dcea15d8010d25034f64aa488b580b8282d226f8203bba6aa424b0a25bcceb9c7c718b6c276022d988ca063d2e88350d68903f95aa3265b44d909c07fa9477a5dfcfe3b5ed49b789d6e1c13aca012630343021dbc0c0f17dae6688eae495b76d21be49ced2c2e98e1068d8725d8a581958fb2530871dff1b3f910ae8beb3bc07bfb4b1d2d73fc5d440dc9bcd32ba656c32e357051bef3082031a06092a864886f70d010701a082030b0482030730820303308202ff060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408749558ace83617660202080004820280ef790b9cd427ec99a350a6e3afb1727cf3dd859d5377897805a7093e1ca42ab8cccc6c52d2b86d61ed55b5bd743fb2a4ec556b438933a9d97a55e5ad1fb3f9967e550be3d708feb5c7287e31afed165a4a91bd5a80292a1e061f97a8c11339963843348badf3fd898e89fd92bda5ad0195d8d4f75e7bce9f0518eeb85365860cd32ad5cea0958efef02bfb74aec0af0765729dae079f5eb08b099d3b06a9b9c6cd6f1e1e4170208ebec3c61ae3421e90cef0f2b5cd2187e43cc4ceecf4aec06340f886efb94f517e578d13659392246a69505de3914b719fba74709ef0f03f010429f899dbddab950f6e58462b2fe2663986a5e0c8ff235e89bca3bb6e41fcd602a0277a83822ac1a14101c83fd1cafdc45c1980ecf54ef092deb2fea736b428158e0847256fc1211f94ea8075145be5a5fb26206e125d55f45500844f1a83f063d0be19b60427dadbd89109bb9ee31a1ac79c863204e8e80c044b8b6bc45c756c26be514e4270a293faf4608065a27b4a51253cb9f831614d5c7f25ec1d4e36063e68e4e405c1f4deb98a786c57a376609441f2dcbe6393487b884624570f6cbb02b53f58ea4acb0faedd2931293dc87664a0c589322480686f6613ffb794c3b3b1872cd7a418712a35666b53bd8383f2e7aa6e8a9e20dd3d46cc3aaaaf17841732dde708ba5611ebcc8777fb3f7b65f2cf95992fdf4f5a17ddf01f3ebe5fb6c9cd58cb74553865cbec3c9d391dcc3e96e654faf7be7fdc8d5fb5dff98799e740147d2ca4b6df47560a4a20bd8f30cf5b495f4e919c9efad3aa59491a3e2ba4e53606e2016ce13e8271e70ccd5b57eec99a8604caf5997e648f3eb541769267f9cdf76aa84917ebd8a1f60a973ed22cca9fa0d3589bb77dafed82ea4f8cd19d3146301f06092a864886f70d01091431121e10006f00700065006e00770061006c006c302306092a864886f70d01091531160414a38a6be4b090be5e29259879b75e0e482f4a4dd8$a790274918578289d80aa9fd0d526923f7b8f4d4", "openwall"},
	{"$pfxng$1$20$1024$20$456a2344e138862de7ad2e0b274952ef566e2b63$308209cb3082057806092a864886f70d010701a082056904820565308205613082055d060b2a864886f70d010c0a0102a08204fa308204f63028060a2a864886f70d010c0103301a0414e9a49f4190a3084e02ceba2f049303750f6646da02020400048204c8cd40bb89c287b9fe70a88825e33a648c76aa1b35d93131d445e48943ee50ff8a0aee6a0483a289fbacf21290a8553e3414ea6bd6b305407d709bbaf915a99430c998d9ba68e71f4036d42feb386061d645433390658df91bd4e9750a39f9288f7cf8001e2adc8e4d7480f1a5e2d63799df20d9eb956f86b33330ec2c206b1ae47cf54d9cf2cdd970664c251e64cc725456e2c14506cfd7d9ff1d2894a50093fff4f29d5967a0f788ed707ade93cb3ad7e87d96dad844d2037f4d5e863ec5170c0f1d4514d752a266cd4db49b63c5d86646e54a68187ddc99b00499286f79e2e7c54e30d3a1b1f035d7113180d072c7218d399f8b5427dc2d6fcb42518bd6bb97f74c97ea2358ef39fb176397fe7729cd5c3a474423f0a0e74a91c77bb27b24f82463081fed53bdf216840b2c60482846010b654e2c74db4abfb07936e0cc9d0d133ac7a4baa03091de25f6eea70d85fe9376349731ecc03fe437175101fd6698929f43a94835c6453b68335f478cfa1fab1ddf0236570ca5a07cebf1aa3c36d7804654a5eac8328377abba3b81627fcac7f1dbdb56ba1f0f861af9967c5d245459a81891fb5dd833f0bca633eb616cf10397b295d857c63501e85fb9f11f1fd3dd80baac425ecf0efa012817ca9b23e06575a3942613fad67b4bda4fabfd29bd1897b0623d6d47ec000bd656f5b7c78b9a4808ac022524b17a8df676b86dc29b6d008d09cb1148110bd07464c071504d7dae5803602247da1e4cd5d490771322d7eb568d0ad0293f4d2626ac0f60f568a92eccd097f6d5247e043b7cdb52ddfef0516e7053fb42b7d1b16564f1c862c1bf45436290a5dab1f0e90b24bdd4433ce0cbcc7b0eafc445dcc6fe8a52e606d3977ce6d9e44f037ea8dbf36bce63a877aaafde13b1bb5005856d315f30fd4feaf26ef8eeef899802aa2442364c147b074c64878a696a1f2cadd9bacb187b62c239c16f163d6c44e157dd8daa4610142eb40dadbc3405c4ade7d127db20bc4384bd1d4c2a2a5dc907aa0468c2485654bceeee3d4011d74e6e85ed88811ccf1cd6b3d5540c5709b8e14fb9e610b552502343ec739e8c9c6d6459062f76275de1fa1b24ed8a9924ea9176dfb89520b7fbec9e9968bd0320afc513e560966b524a82ef5a206f1823742e820bbbe6dca6b0a33c8f04208376bfd01f049f666c735b1efe2550a8601b1839bf045c56a9772a3e25235d2fb61f9007713ff57ae47f6335a44e6730bdaaebe833996aaaa78138ddb7d8719570a429debb8183fbd07f71a037335ec5b1d40c62f7163b85dc71d8db536c9092f155429b65ea81f8ff3c7892ebf881c107ea2c167df47d044ae7ed3fb5328d673753450c82d7049dfeaf1dde821a0ee0d6676a1656584cdbd4532f8d2493ea4794d88acacb147f19ca15777a67fe5031991ebc45ea43e87574f9d2f52de0722d6cc7f5b7a378a461148f1f7c5ee8bc7c7ae4fe80b4eed13b35d16906a084120c645812db0bd70e419c004512f284ab7635f17ee2ecc728aef2cda256b86fb4cc9d3e21736249735962d6ccd307a67fdbdb0815184f116eb1747de19449c6fb9410cb669fa2a3f2ab5ca16c3cca918555b583f61f2126aa0895ccdac7a5604ca1e84a76c15c508d620bb9037e5e5acf97e94438a059bc771d84dc1f63fd3f4780274a2f0a03f9b09a0cf4638e0c317f6ebb24f9062fe8c7023d4c06f3c67c9ac2008e8da33150302b06092a864886f70d010914311e1e1c006d0079005f00630065007200740069006600690063006100740065302106092a864886f70d0109153114041254696d6520313334303937373036353139303082044b06092a864886f70d010706a082043c308204380201003082043106092a864886f70d0107013028060a2a864886f70d010c0106301a04147d79e2d2b2986ea4d929b3ba8b956739a393b00802020400808203f82c0ebc2a236e5ffc4dff9e02344449f642fdf3b16da9b2e56d5a5e35f323b23b8ff915fbaf2ff70705465170ccd259a70bb1cde9f76e593f9a7a0d4764806dad2fa5c3b1ee2711e9dbbcaa874f8985f1b6c2ca1d55c919cf9e88aababe7826107cdb937e7cca57809b20a6351504ab688327e4df957a3c167772cf66aed6a2007ead81896465d4931efe7c3291a49761f1428c766fd82e1736218e90d9f8592475d164d9a79f3424cb6a543f7040d3f0dba6996d496f4f603b7d59527e5c9c89b3f96c55fa73b72385629cbd606cf9f88833db66bb1519dee62a0cd4989d93457fa1162b594b86bc7134c9aa530fe10d62b914f1818395f82d5224c3bc793a04b0ab41dc98694535f5bfbf2aa943d6c794f407e02248be842c55789091d1cc28bbfdf86bc1346142b057558ce1e64e38f8b2d7d68d539150f3de23f43d59637ae678f3687e69b52fdf46f54c32b84a658a2a69fb16da7ebb45ea84c9e38d6cedfc1227b86a6ea3094d0908d588213834192849fa5c25b2460bb22fdd9d9e317efaca646ea582ecb50f6a466f55ae38573afe904eadf42b6c596c8740dbf92cbd38c347624f3399ac2d20d0727f897f38417901dfdaa798631af8992fcad5d708882576036531d2deb867fe46d63921dc50b8c73fbc59586a861d7ae47c2a5ff892e9dffc6d8e6e8161506819ebc020cfb7bc4c1708832d53f8cc864012ab8379a1323e23b0edb5ffe48a942411cef6197f5545ae6822a3096db972f96d4d200ba600a1e95595d4532e7a9861b233f71ff37ea3c19143c87dd6d4a3f3186a7693dc11067c7b4c967984d4bbbf9d88acacb1ff3ba4536ea265a0503865d86af408748fe8191119cd7b570b5352f190265d5d468e911ba0020b526d3892119fda21243568cfa638251c9044c91a88d2f8a05dd0d90088b0b79ac2a2ca263aa108160a7f6943ce709a02743afb6e4ec9a7f7535635f839c2baf938418accec3d5c1ad2bbcec69ab337155bd0bb1b45c7e16e32f251d4da7796f013d6d502581853da6ab9736382115141886c14512fb5ca22e3e9e20366257579eb4225a6a3716457b9b1c0df63cb71a34b888de021f3520d62e96675ea8767e23d55b50e9aa40babafe398f5482c83f8caa57d7ed3486ce7dedace7158067194892defe38af28c1695cd6f14a1ddae959541fab3b59e72c17d2a67d980c749ef00b1f61ece68d81c79b4ec4f4d9eeaad43895a0dc9d86f4d7fe114f01189b3db72ee92963d4403c3aca8bf6d60ef7ee7fcd8102b3247048b4d517cd0ab76a0f8d68d33733934cb35a8e40d7de70c4f166c453fda74553069c51dd33f6f513bb9ef0a983187fc7d896c668590577a4e269688cc7b9fbd1f3fe77d3f431cf002043c43e1cae82b22018931f1337ee276d49c19163a866ef10a64ac5b013db1cb1c$501f5cd8e454e44b6925715c4d2605a8d4ce70d0", "my_password"},
	{"$pfxng$1$20$2048$8$c70bc3c11be46232$308205f9308202cf06092a864886f70d010706a08202c0308202bc020100308202b506092a864886f70d010701301c060a2a864886f70d010c0103300e0408aeab408a953dae400202080080820288eac5f49ac4a3c50ec87cfd7592cd19e7deafbd62f58eb68ec542bf073778bf238533fc1363ff41e87dc72e75d97fbbd9707ca0fa171216f5c5d56906efc96f15883138b31a151b40ae2d72e7d4310095f03c85d75672d983566db3cae50c59613a26b64d54fcaa5cd8c328854359868eae40e66c7f527ce213d3a8645d012afa3fbb9ddab6c6dd1bc3863cc2c0014380e606da2f7f7ede8ef1c8a35d48b4f150651387461cf1327f12629411b3b3f7b0d8e3dce9e03b5ef52b1cb911b469685b491ceec0276a6c3a2e64beab805fa67cea73c0ed6bd498d563a89b874032fed141857f0a80342442d20af18a084877df28b3abd4c9d7218551bef523c17b4729d0689b0833e190e3e60995ca3fe5075629ea4ffde3e65f20777086d5cbcfe742cc22ef46d06e9ba35e4017eb35fec30cb7ddc37fa22daa9e77e202d864f6d34541d854f00f9e8c1445ac432bff67a5a00b6cd0da5eb796c7a44e92b5c67f55de92ebcef8f690d7b3892362d884f2d8c657db5dc308c95a43cc42bfc5449b45c05e9e60ca5d88d0c07b9cbe6b76da91f7c572e1c02ef71a18833e6779df711a4104e21d5939a982e19e22292df280adc3f0b10339f53fdbc44356a95c27eb23932302678b86094d5f4d60e028af61c01d7fcd83ab9f78c4499c3e7bd29507c397ca43d397b90cb267a6ec15f37b50cf4f2d82d4a4fe8f56355c27c20cfd93ed5f84f321244c7a7dc404619b3f9bb83affbf4d1d702b336ac3e504ccb86c18a979354faf0bf4e725fe1ef051dca8ce0209b7905f8f19c5ec51fbede48f57cbb90d14d666ca09fb4d0b92c6e2a54e8ad1b51cc20cbe17c86901f76d509bcbf0d6ecbf08685da20ec75c11d8c509cf2ab9842e2be34aa24920d4a035e1641cf3d5b1669d46ac9531514d3082032206092a864886f70d010701a08203130482030f3082030b30820307060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e040806de2bcadc588fa502020800048202800d03f420c35a4b8e1b3b0592306996feb16d41001d0aace08d4dadc51fb2498f504c4bf57a54eec39102d76665eed9c46006c9a181bca37c64e96f11b0c7c24bea8bdcdab174ec1aa2f85b6a0ae4ba082516e977a212ee8ecb5d79b7431f951749046ffad4fbb2106016cb024da53894b7f2c7e0b8d2af6a4823d57d30b884fba32bebb88c0bf53f370663f37a4276750ee22c2a76fb428f888dbc1bba10bc0976c7a5e73181dd84aaccfe98e2fee04212f1dea2284bbd0fb990646fb276610198eaf210d44c63d245234fd6c7486d2b899395d75ca569f4cc7f1c1b9583d2e5a3310ffd7826fcf206cca0fd2557b9317ef638e5d553ffff917e41c6a3f184ca72a1581725a954f5ed157dc9b04b1f2f044bc267f9de7e4d80aef84b91a94b66dacf86ab78928c873b2b8963ef1b2fac24a603011edb223aa8aa22bf3784e6938edf7811516ae4862a77693b1c254a4ed30dc85bf4b5a79942f841dc09db799eaa89051fc51eb917d9faa9781af961ec34e2df5ba531628d777437b282a2548d9f64eb72069f0325cbc65123c67606c0812920862480457d0df6ea547a9f778d48b24b6ca72d47bfd4cc6431e126a43c8d14ecae263da06bcb73413091d154c0e67fb6f629131c2d4a0d1b750941b0ab8a188ddb4cd427396d83f922bee0f3a85383d5bcb8ec89338b933d181aba79d7f2566e74b9a01ecd755ca4ab38963fcf36c985f5513ea678a822cf8acab673234bcc3d7b210da1b762814a0cf658e5d8ec9305b887d444131278f790fb8c77f3737c5f8f864ac7554bbf4ee8c3d78523462628faac312e2d37062c72d05ba2fed1a51c9017a75160cd267897802463e638a8e02c2a2230f518365470aca7e8c418bfe99227ad13f0bf2bf6d4124724af314e302306092a864886f70d0109153116041467a3f379b2dd87441f6abf68c9a9f8429a92c044302706092a864886f70d010914311a1e1800740065007300740069006e006700310032003300340035$585f5cfb43702b6d02b55418ce3925d04cdbcc63", "testing12345"},
	{NULL}
};

static struct custom_salt {
	int mac_algo;
	int key_length;
	int iteration_count;
	int saltlen;
	unsigned char salt[20];
	int data_length;
	unsigned char data[MAX_DATA_LENGTH];
	unsigned char stored_hmac[20];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int mac_algo, saltlen;

	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	/* handle 'chopped' .pot lines */
	if (ldr_isa_pot_source(ciphertext))
		return 1;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // mac_algo
		goto bail;
	if (!isdec(p))
		goto bail;
	mac_algo = atoi(p);
	if (mac_algo != 1) // 1 -> SHA1
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // key_length
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iteration_count
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // saltlen
		goto bail;
	if (!isdec(p))
		goto bail;
	saltlen = atoi(p);
	if (saltlen > 20)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p) > saltlen * 2)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // data
		goto bail;
	if (hexlenl(p) > MAX_DATA_LENGTH * 2)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // stored_hmac
		goto bail;
	if (hexlenl(p) != 20*2)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	p = strrchr(ciphertext, '$');
	if (!p)
		goto bail;
	p = p + 1;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.mac_algo = atoi(p);
	p = strtokm(NULL, "$");
	cs.key_length = atoi(p);
	p = strtokm(NULL, "$");
	cs.iteration_count = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for(i = 0; i < cs.saltlen; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.data_length = hexlenl(p) / 2;
	for(i = 0; i < cs.data_length; i++)
		cs.data[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");

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
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
		if (cur_salt->mac_algo == 1) {
			unsigned char mackey[20] = { 0 };
			int mackeylen = cur_salt->key_length;

			pkcs12_pbe_derive_key(0, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			hmac_sha1(mackey, mackeylen, cur_salt->data,
					cur_salt->data_length,
					(unsigned char*)crypt_out[index],
					BINARY_SIZE);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
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
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_pfx_ng = {
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
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
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
		set_key,
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
