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
#include "twofish.h"
#include "sha.h"
#include "loader.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"
#include "memdbg.h"

#define FORMAT_LABEL            "pfx-ng"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) " SHA1_ALGORITHM_NAME
#define PLAINTEXT_LENGTH        30
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(ARCH_WORD_32)
#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#if !defined(SIMD_COEF_32)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#else
// FIXME.  We have to handle this in some other manner (in init).  We need to
// find the LCM of all possible 'groups'.  So if we have 2 8 and 24 as our
// groups, this count needs to be 24.  If it was 2 8 24 and 32, then we would
// need min/max keys to be 96
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#endif
#define FORMAT_TAG              "$pfxng$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#define MAX_DATA_LENGTH         8192 // XXX ensure this is large enough

static struct fmt_tests tests[] = {
	{"$pfxng$1$20$2048$8$e861d3357729c35f$308206513082032f06092a864886f70d010706a08203203082031c0201003082031506092a864886f70d010701301c060a2a864886f70d010c0103300e04086c933ea5111fd24602020800808202e83c56ad18c45e54aaca4d170750cfbfb3059d6cf161e49d379eab15e722216cb479eee8da7b6e6ffc89e01fbf30f4eb5e1b88ca146c166c700a68473d25a0979344cc60d1e58230a12d24b8be6e9174d3afecdf111cd7d96527831ac9c8f4bf3817cda021f34b61899f2a75fe511e8dedfb70367fa9902d2d3e500f853cc5a99ec8672a44713d24ae49382a20db6349bc48b23ad8d4be3aa31ba7e6d720590b5e4f6b0b5d84b7789ae9da7a80bfa3c27e507fc87e7bc943cff967db6b76f904ac52c1db5cfe9915fa3493cd42b8db6deae62bc01593e34bc8598f27a24cdfd242701ff72d997f959f3a933ab5a2762df33849c116715b78cb0d83267aff913619cbbdf003e13318e4b188a8a4f851b9f59ae2c71ab215c565f7872e5d54c06f92d6f59eaf19d95f9b4526d52d289cd17bc0c2079f9f13c20a70a566773d90ca6d888386d909b6362cb79e15cf547dceab1fe793c577b70f72463969f7b416fb5a6228053363558df18588b53406343ab320a1bbf1757b67ef8e3075f44dee4521f4a461d37ea894c940bc87f9bd33276f2843ff5922fd8e61d22a8619ad23154880fd7d957c0f151458fc4f686d96695a823b08c1795daaf79e41118a3c57ee065a693853a9c4b2004440662f51d63bb9973dc4bb8c541d424416c57d01a825be4d31dab7c7f4b2b738e4bbfdda1e3d3b95e026dadee4dfe155c0f4a24991693f679b452516bc19eab7cf7eb41b476358583d46630e8cda55974b8fcbe25b93e91e73f584a913149137c1c20d13f38826d8dba9bcf5504b8cee77e20a19d6fb050e9213b8aeb11c26a871c600701aea352ba2dcea15d8010d25034f64aa488b580b8282d226f8203bba6aa424b0a25bcceb9c7c718b6c276022d988ca063d2e88350d68903f95aa3265b44d909c07fa9477a5dfcfe3b5ed49b789d6e1c13aca012630343021dbc0c0f17dae6688eae495b76d21be49ced2c2e98e1068d8725d8a581958fb2530871dff1b3f910ae8beb3bc07bfb4b1d2d73fc5d440dc9bcd32ba656c32e357051bef3082031a06092a864886f70d010701a082030b0482030730820303308202ff060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408749558ace83617660202080004820280ef790b9cd427ec99a350a6e3afb1727cf3dd859d5377897805a7093e1ca42ab8cccc6c52d2b86d61ed55b5bd743fb2a4ec556b438933a9d97a55e5ad1fb3f9967e550be3d708feb5c7287e31afed165a4a91bd5a80292a1e061f97a8c11339963843348badf3fd898e89fd92bda5ad0195d8d4f75e7bce9f0518eeb85365860cd32ad5cea0958efef02bfb74aec0af0765729dae079f5eb08b099d3b06a9b9c6cd6f1e1e4170208ebec3c61ae3421e90cef0f2b5cd2187e43cc4ceecf4aec06340f886efb94f517e578d13659392246a69505de3914b719fba74709ef0f03f010429f899dbddab950f6e58462b2fe2663986a5e0c8ff235e89bca3bb6e41fcd602a0277a83822ac1a14101c83fd1cafdc45c1980ecf54ef092deb2fea736b428158e0847256fc1211f94ea8075145be5a5fb26206e125d55f45500844f1a83f063d0be19b60427dadbd89109bb9ee31a1ac79c863204e8e80c044b8b6bc45c756c26be514e4270a293faf4608065a27b4a51253cb9f831614d5c7f25ec1d4e36063e68e4e405c1f4deb98a786c57a376609441f2dcbe6393487b884624570f6cbb02b53f58ea4acb0faedd2931293dc87664a0c589322480686f6613ffb794c3b3b1872cd7a418712a35666b53bd8383f2e7aa6e8a9e20dd3d46cc3aaaaf17841732dde708ba5611ebcc8777fb3f7b65f2cf95992fdf4f5a17ddf01f3ebe5fb6c9cd58cb74553865cbec3c9d391dcc3e96e654faf7be7fdc8d5fb5dff98799e740147d2ca4b6df47560a4a20bd8f30cf5b495f4e919c9efad3aa59491a3e2ba4e53606e2016ce13e8271e70ccd5b57eec99a8604caf5997e648f3eb541769267f9cdf76aa84917ebd8a1f60a973ed22cca9fa0d3589bb77dafed82ea4f8cd19d3146301f06092a864886f70d01091431121e10006f00700065006e00770061006c006c302306092a864886f70d01091531160414a38a6be4b090be5e29259879b75e0e482f4a4dd8$a790274918578289d80aa9fd0d526923f7b8f4d4", "openwall"},
	{"$pfxng$1$20$1024$20$456a2344e138862de7ad2e0b274952ef566e2b63$308209cb3082057806092a864886f70d010701a082056904820565308205613082055d060b2a864886f70d010c0a0102a08204fa308204f63028060a2a864886f70d010c0103301a0414e9a49f4190a3084e02ceba2f049303750f6646da02020400048204c8cd40bb89c287b9fe70a88825e33a648c76aa1b35d93131d445e48943ee50ff8a0aee6a0483a289fbacf21290a8553e3414ea6bd6b305407d709bbaf915a99430c998d9ba68e71f4036d42feb386061d645433390658df91bd4e9750a39f9288f7cf8001e2adc8e4d7480f1a5e2d63799df20d9eb956f86b33330ec2c206b1ae47cf54d9cf2cdd970664c251e64cc725456e2c14506cfd7d9ff1d2894a50093fff4f29d5967a0f788ed707ade93cb3ad7e87d96dad844d2037f4d5e863ec5170c0f1d4514d752a266cd4db49b63c5d86646e54a68187ddc99b00499286f79e2e7c54e30d3a1b1f035d7113180d072c7218d399f8b5427dc2d6fcb42518bd6bb97f74c97ea2358ef39fb176397fe7729cd5c3a474423f0a0e74a91c77bb27b24f82463081fed53bdf216840b2c60482846010b654e2c74db4abfb07936e0cc9d0d133ac7a4baa03091de25f6eea70d85fe9376349731ecc03fe437175101fd6698929f43a94835c6453b68335f478cfa1fab1ddf0236570ca5a07cebf1aa3c36d7804654a5eac8328377abba3b81627fcac7f1dbdb56ba1f0f861af9967c5d245459a81891fb5dd833f0bca633eb616cf10397b295d857c63501e85fb9f11f1fd3dd80baac425ecf0efa012817ca9b23e06575a3942613fad67b4bda4fabfd29bd1897b0623d6d47ec000bd656f5b7c78b9a4808ac022524b17a8df676b86dc29b6d008d09cb1148110bd07464c071504d7dae5803602247da1e4cd5d490771322d7eb568d0ad0293f4d2626ac0f60f568a92eccd097f6d5247e043b7cdb52ddfef0516e7053fb42b7d1b16564f1c862c1bf45436290a5dab1f0e90b24bdd4433ce0cbcc7b0eafc445dcc6fe8a52e606d3977ce6d9e44f037ea8dbf36bce63a877aaafde13b1bb5005856d315f30fd4feaf26ef8eeef899802aa2442364c147b074c64878a696a1f2cadd9bacb187b62c239c16f163d6c44e157dd8daa4610142eb40dadbc3405c4ade7d127db20bc4384bd1d4c2a2a5dc907aa0468c2485654bceeee3d4011d74e6e85ed88811ccf1cd6b3d5540c5709b8e14fb9e610b552502343ec739e8c9c6d6459062f76275de1fa1b24ed8a9924ea9176dfb89520b7fbec9e9968bd0320afc513e560966b524a82ef5a206f1823742e820bbbe6dca6b0a33c8f04208376bfd01f049f666c735b1efe2550a8601b1839bf045c56a9772a3e25235d2fb61f9007713ff57ae47f6335a44e6730bdaaebe833996aaaa78138ddb7d8719570a429debb8183fbd07f71a037335ec5b1d40c62f7163b85dc71d8db536c9092f155429b65ea81f8ff3c7892ebf881c107ea2c167df47d044ae7ed3fb5328d673753450c82d7049dfeaf1dde821a0ee0d6676a1656584cdbd4532f8d2493ea4794d88acacb147f19ca15777a67fe5031991ebc45ea43e87574f9d2f52de0722d6cc7f5b7a378a461148f1f7c5ee8bc7c7ae4fe80b4eed13b35d16906a084120c645812db0bd70e419c004512f284ab7635f17ee2ecc728aef2cda256b86fb4cc9d3e21736249735962d6ccd307a67fdbdb0815184f116eb1747de19449c6fb9410cb669fa2a3f2ab5ca16c3cca918555b583f61f2126aa0895ccdac7a5604ca1e84a76c15c508d620bb9037e5e5acf97e94438a059bc771d84dc1f63fd3f4780274a2f0a03f9b09a0cf4638e0c317f6ebb24f9062fe8c7023d4c06f3c67c9ac2008e8da33150302b06092a864886f70d010914311e1e1c006d0079005f00630065007200740069006600690063006100740065302106092a864886f70d0109153114041254696d6520313334303937373036353139303082044b06092a864886f70d010706a082043c308204380201003082043106092a864886f70d0107013028060a2a864886f70d010c0106301a04147d79e2d2b2986ea4d929b3ba8b956739a393b00802020400808203f82c0ebc2a236e5ffc4dff9e02344449f642fdf3b16da9b2e56d5a5e35f323b23b8ff915fbaf2ff70705465170ccd259a70bb1cde9f76e593f9a7a0d4764806dad2fa5c3b1ee2711e9dbbcaa874f8985f1b6c2ca1d55c919cf9e88aababe7826107cdb937e7cca57809b20a6351504ab688327e4df957a3c167772cf66aed6a2007ead81896465d4931efe7c3291a49761f1428c766fd82e1736218e90d9f8592475d164d9a79f3424cb6a543f7040d3f0dba6996d496f4f603b7d59527e5c9c89b3f96c55fa73b72385629cbd606cf9f88833db66bb1519dee62a0cd4989d93457fa1162b594b86bc7134c9aa530fe10d62b914f1818395f82d5224c3bc793a04b0ab41dc98694535f5bfbf2aa943d6c794f407e02248be842c55789091d1cc28bbfdf86bc1346142b057558ce1e64e38f8b2d7d68d539150f3de23f43d59637ae678f3687e69b52fdf46f54c32b84a658a2a69fb16da7ebb45ea84c9e38d6cedfc1227b86a6ea3094d0908d588213834192849fa5c25b2460bb22fdd9d9e317efaca646ea582ecb50f6a466f55ae38573afe904eadf42b6c596c8740dbf92cbd38c347624f3399ac2d20d0727f897f38417901dfdaa798631af8992fcad5d708882576036531d2deb867fe46d63921dc50b8c73fbc59586a861d7ae47c2a5ff892e9dffc6d8e6e8161506819ebc020cfb7bc4c1708832d53f8cc864012ab8379a1323e23b0edb5ffe48a942411cef6197f5545ae6822a3096db972f96d4d200ba600a1e95595d4532e7a9861b233f71ff37ea3c19143c87dd6d4a3f3186a7693dc11067c7b4c967984d4bbbf9d88acacb1ff3ba4536ea265a0503865d86af408748fe8191119cd7b570b5352f190265d5d468e911ba0020b526d3892119fda21243568cfa638251c9044c91a88d2f8a05dd0d90088b0b79ac2a2ca263aa108160a7f6943ce709a02743afb6e4ec9a7f7535635f839c2baf938418accec3d5c1ad2bbcec69ab337155bd0bb1b45c7e16e32f251d4da7796f013d6d502581853da6ab9736382115141886c14512fb5ca22e3e9e20366257579eb4225a6a3716457b9b1c0df63cb71a34b888de021f3520d62e96675ea8767e23d55b50e9aa40babafe398f5482c83f8caa57d7ed3486ce7dedace7158067194892defe38af28c1695cd6f14a1ddae959541fab3b59e72c17d2a67d980c749ef00b1f61ece68d81c79b4ec4f4d9eeaad43895a0dc9d86f4d7fe114f01189b3db72ee92963d4403c3aca8bf6d60ef7ee7fcd8102b3247048b4d517cd0ab76a0f8d68d33733934cb35a8e40d7de70c4f166c453fda74553069c51dd33f6f513bb9ef0a983187fc7d896c668590577a4e269688cc7b9fbd1f3fe77d3f431cf002043c43e1cae82b22018931f1337ee276d49c19163a866ef10a64ac5b013db1cb1c$501f5cd8e454e44b6925715c4d2605a8d4ce70d0", "my_password"},
	{"$pfxng$1$20$2048$8$c70bc3c11be46232$308205f9308202cf06092a864886f70d010706a08202c0308202bc020100308202b506092a864886f70d010701301c060a2a864886f70d010c0103300e0408aeab408a953dae400202080080820288eac5f49ac4a3c50ec87cfd7592cd19e7deafbd62f58eb68ec542bf073778bf238533fc1363ff41e87dc72e75d97fbbd9707ca0fa171216f5c5d56906efc96f15883138b31a151b40ae2d72e7d4310095f03c85d75672d983566db3cae50c59613a26b64d54fcaa5cd8c328854359868eae40e66c7f527ce213d3a8645d012afa3fbb9ddab6c6dd1bc3863cc2c0014380e606da2f7f7ede8ef1c8a35d48b4f150651387461cf1327f12629411b3b3f7b0d8e3dce9e03b5ef52b1cb911b469685b491ceec0276a6c3a2e64beab805fa67cea73c0ed6bd498d563a89b874032fed141857f0a80342442d20af18a084877df28b3abd4c9d7218551bef523c17b4729d0689b0833e190e3e60995ca3fe5075629ea4ffde3e65f20777086d5cbcfe742cc22ef46d06e9ba35e4017eb35fec30cb7ddc37fa22daa9e77e202d864f6d34541d854f00f9e8c1445ac432bff67a5a00b6cd0da5eb796c7a44e92b5c67f55de92ebcef8f690d7b3892362d884f2d8c657db5dc308c95a43cc42bfc5449b45c05e9e60ca5d88d0c07b9cbe6b76da91f7c572e1c02ef71a18833e6779df711a4104e21d5939a982e19e22292df280adc3f0b10339f53fdbc44356a95c27eb23932302678b86094d5f4d60e028af61c01d7fcd83ab9f78c4499c3e7bd29507c397ca43d397b90cb267a6ec15f37b50cf4f2d82d4a4fe8f56355c27c20cfd93ed5f84f321244c7a7dc404619b3f9bb83affbf4d1d702b336ac3e504ccb86c18a979354faf0bf4e725fe1ef051dca8ce0209b7905f8f19c5ec51fbede48f57cbb90d14d666ca09fb4d0b92c6e2a54e8ad1b51cc20cbe17c86901f76d509bcbf0d6ecbf08685da20ec75c11d8c509cf2ab9842e2be34aa24920d4a035e1641cf3d5b1669d46ac9531514d3082032206092a864886f70d010701a08203130482030f3082030b30820307060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e040806de2bcadc588fa502020800048202800d03f420c35a4b8e1b3b0592306996feb16d41001d0aace08d4dadc51fb2498f504c4bf57a54eec39102d76665eed9c46006c9a181bca37c64e96f11b0c7c24bea8bdcdab174ec1aa2f85b6a0ae4ba082516e977a212ee8ecb5d79b7431f951749046ffad4fbb2106016cb024da53894b7f2c7e0b8d2af6a4823d57d30b884fba32bebb88c0bf53f370663f37a4276750ee22c2a76fb428f888dbc1bba10bc0976c7a5e73181dd84aaccfe98e2fee04212f1dea2284bbd0fb990646fb276610198eaf210d44c63d245234fd6c7486d2b899395d75ca569f4cc7f1c1b9583d2e5a3310ffd7826fcf206cca0fd2557b9317ef638e5d553ffff917e41c6a3f184ca72a1581725a954f5ed157dc9b04b1f2f044bc267f9de7e4d80aef84b91a94b66dacf86ab78928c873b2b8963ef1b2fac24a603011edb223aa8aa22bf3784e6938edf7811516ae4862a77693b1c254a4ed30dc85bf4b5a79942f841dc09db799eaa89051fc51eb917d9faa9781af961ec34e2df5ba531628d777437b282a2548d9f64eb72069f0325cbc65123c67606c0812920862480457d0df6ea547a9f778d48b24b6ca72d47bfd4cc6431e126a43c8d14ecae263da06bcb73413091d154c0e67fb6f629131c2d4a0d1b750941b0ab8a188ddb4cd427396d83f922bee0f3a85383d5bcb8ec89338b933d181aba79d7f2566e74b9a01ecd755ca4ab38963fcf36c985f5513ea678a822cf8acab673234bcc3d7b210da1b762814a0cf658e5d8ec9305b887d444131278f790fb8c77f3737c5f8f864ac7554bbf4ee8c3d78523462628faac312e2d37062c72d05ba2fed1a51c9017a75160cd267897802463e638a8e02c2a2230f518365470aca7e8c418bfe99227ad13f0bf2bf6d4124724af314e302306092a864886f70d0109153116041467a3f379b2dd87441f6abf68c9a9f8429a92c044302706092a864886f70d010914311a1e1800740065007300740069006e006700310032003300340035$585f5cfb43702b6d02b55418ce3925d04cdbcc63", "testing12345"},
	{"$pfxng$256$32$2048$8$eda9c105494d9435$308205eb308202c706092a864886f70d010706a08202b8308202b4020100308202ad06092a864886f70d010701301c060a2a864886f70d010c0103300e04081e887b937597d33f02020800808202805b10b55d2c64713d8085b1b3633dcf1c87b8a20fa9a3c2728dd7ba8dcbe084539bca898b4c884e3a7ff15458b155c50e7a5ac6639c300b8234e4424819e167283160286d53f8ff9c78e05eeb250e16a7445e24ba87f0e3a111ee3803d56c038372fdf96311849b7a35513ab497be68edf0e306ae91b3a8790a0a6043e4051b4b2b90d9c2ca1b5d51fda2bbc6aa136576e7db2362af99c7be31947ac1ba4dade30c8a4c5dc9ae517528ae7d7e34e25ce2f7f3a42c9f0bf6ccf71d84a1117b6acfc95c3493f1937d42c019c7385b86028cd1795e5d991e208aa54d56499c3fe5b29ffe97f8194fed46062d89127553de7f73717435e6c27db8c9cb6a8f06083e9d17c00f5afc54c2d6c71d7f4c9b8747bb53539c40a5d3cc50c1c21eb30a28dad407cc31438337153db91c6b9dcabfbba121d976e9deb182b530e94b63799901f02642973e3ee41905f9cbbbcdecdc18bb4a7e5cd540031cdaca594602ef172c91ac4cee0c2e86cb34b177180e05171e22557201ad9376f5fe99119128dc32e1ceb728e8ef1a372c5bf2649ba379bb9ba300d6e9e3c7a37f5c02280489083b729c6beaa85aae2cab3b05c8543626118aa3ac42f09fac3b26898ac9762ed88ab4099aac653c2d54fa967179893408cd5b61e2ceda8e6f7789752d78357f1f9762afb621d2444b2e8ae5a09596d37ed8309276ffded09434616e88fe075d2c3d983f46b0e1b4f330fe2939bb9985ab8becefabb3929096c18ca8ab76d65eb7642454264c8617f11d3211a24b68a5cd146e88581567681f5db43d46dee2d3c3f0ae1dd6f194691331fd6166bc4ee9d076e571a30df4015037c7c831e5b837896d5132fdeaa4cbff9fa372f873cfd3e5a9037cc3b95d2b0d5fd2a07691b1fc27f604653082031c06092a864886f70d010701a082030d048203093082030530820301060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408751fbd442d0cf3ff0202080004820280fc073ddf174703f1be2d4e2927ef21318267a66f2d1c650ed82123a210f14ad8b8cc4f5dbdae189659fec6748f8b12977dbf586f313282ef3884a2eae3fe6df56a4b335c647764ede9160063baf0614d153ce5356fcb0c41ac97eaa30d49c5156064f56a481dddab298feaa96db78263251295013ac8c63a0958c60fff45301571598659ad292f3c85691696350a3d4c3661cfed45ae243c51e333872de4535ca30819b9b71cb70adb05853757ef3c26613ab622fa828e69ba99859b5272c853afaae61ca7787bb5a629ac7f4fb7d75a854545a559dc06743c7722e848dafe57bde7d2179453f618cbe194cef4a1a173656c765277ea0406ea030efc857668a11a62ae61f3972b46f324b46cb29f8b5bd7b54ee1dfbf3c87ebf1732af3c6304a3b6a3fbb8270ef8c3a8558c942fe018f94e0127cbd1e36fe346f46fdc68a9634ee3afdbd811254377b3e8f71c43c4f5e69bc3655ce8c8710da0ef576c2f6c00b649d32976eb5562b2c7df0c646a36f11b86946accd9bd018e81d5dc7369bdfc1ce8da7fdf39a5fa9732963c0cf81da9d0eeb476e824706151513d3f7b5b606085b900fec3a1e0fe673ed413ac6713c81db5db7080d8c3dbb426299841feb3fd58195218d01f598e2d4ac41376adc768c3f68110f1453bb30b293d98e980ecb325fbb3f87dce6e897f407a2b32c49e2329338ffe327d1c3fb28427af1c9dee4f7e5714ce6355357f8c9634c24922a70b0b7c7fa8ddc9bd55de97c768def9b04e694aa26a5f4f4f121fa24ee62baec2a1a70db99efda22c6975e11ecd9138747e6366ebaafa9abd02c61bb2b0189de5c315095bf371a397c654f0b0a8e4fec15e01bbaccd3fef22d6359270098af58e6c2f203c992fc093b08f932220d769700593148302106092a864886f70d01091431141e12007400650073007400310032003300340035302306092a864886f70d01091531160414ca1ff7ddc2ec65acd899d4ccabf13d4b72def78a$c47c2a58c174a8a3540d6103de3403d93b9c66b6769e74022b52981ff4ae529a", "test12345"},
	{"$pfxng$512$64$2048$8$d76feff5e054a36e$308205f9308202cf06092a864886f70d010706a08202c0308202bc020100308202b506092a864886f70d010701301c060a2a864886f70d010c0103300e04083babd1a7ed8725b802020800808202885a0ce329788b3c935db5ac040239817531e749b8e2e7eafe53c45e464cfbe27c6b2235fe934e8be0464dd0c8861b31a8781c74704f2c5c109771b7a3ac14c978d94a53115546df674e202cc4b051d2e094ee59afe3c81b20c0c9ca5c6fa0b51024919844b7c94aa61f4c7ed4bd238447f82657b9bdbb3925552c6692532fbc7ff775b71796118f7c5d6c243ae5b0f7d4587d9c079498be2b41105dca2a4375e5651dc1d3dd5a003a62a9669f3931221e71e2a1e9387dd35d866b3a81513be6134a4e192593447b6965d40e276853bed834e04d6aa68139e29a8c4981665cef6a1b3690f81add179a84f5bd5620093a36270dc3c4594d4e167b21b183ae5bac73484e7f2204288ec80521a0044730120b04334af45f391de13f8b29b9a2be2c9d7d252229d0e0ba3186f34b645b392efafe60c9a3a34b7f30e5fbf7078bcec794418ea2ec184699bae59f55734c47738b448b99d7f69815792642786e775491603ed921e45386892e182e5978fac39c37ca4953553a17dd549a065e7596720ebe6e01a87cea0b53210c540483a95bd08a8bd713667e27e37e54ad5bcbea66642e252c1f400ea8a1cb08907e80420b3778a56b55c154e420ad480dfb94fcbcb79a4f3b06f1cb41840de6d6a2f60513b69a5477bcc83f8b771fd40390b622ca1bb21d07df796360e72b2623f8628e45299ff45331a9ba80583665610ad82bd658e7e316f56f810751d95fbb574ed6d97dc65670fd076cd2092c63ceed5cb800c131a0971a74fef025cd3c3aa7a5aadd7724c2f84c879a26b40b7e5c6f0513c01cfb4a5bfea4132d7b25554d1a60e2cf73c96c9f10dce8014652f141e421dfe5e5386cbb0a6d22002bd86ac42ca542893973b497a431ba48d9bf5cbfe39ad0b980a4538e5cb15cf166643082032206092a864886f70d010701a08203130482030f3082030b30820307060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408c2fe6c7c551da0b802020800048202807903390797cba159723105cb53d25d5b1867c496d6005cf5370338c68d6078e105dff9f479f6402a7d1fb1c6c7ee7c5954990a6d83f5fee29cdf6f4bcb26b0ec09bb764bf3ddf2545e6569ade3fddb0f771cd832035c9ac3b4154af8f320e726907259c7a43fe1170e9244d2c314c055083da11860e1fc692fcd0144e6a38d3933e2801151e2cd4cb58211f4622dd8248c895823480ee77457e3ac86b23532e4e18a8f144a7906e80dacd3c2f4faea0df51e6e4f8175e45254e03996aa9838ad1b0e1537509416d75ab767e1f1d899afaf517219cce58bcce261da621863eef0a9ffb3e338760f76ffe46e48a6a4e911e85a1097023c6271f2c75b319c66c769ff16a75a0cc4bb542c74ad464eefd60d09ef83e390cefa532bf1104ecb5867a7e7e84feae114e0558425d3cd570f15447f461459ffdf1b1cce6efbb18abb734752066146f5aee630dca8ee8b77f6dbc9deb93282d7e6d559f3237bea628c440cb62bb950cf016b83c4160e386e5637cf35a15b695fc82ef4d86e5d559eff5572cb6c3f7cce02a256f96127333276199be9d187c8ebacbc2a284a365835c326aa38bdec0d0db2ca0cc8f576be802d4cc965d92a3fbf30179bbdfa913e6045ab3fdca5673cf899be130556d10cf6f6d0add3a5b622485e33cd765b95d94ee8f9a5146e6a9ed673d78c0c3ea2dbfca673fd3fbe9603ccc3f75788ab3ae6bbaa5fe547b2995d3593b30cd0efb0936e0cd5e525b539238edbaf7c0c0594f7f012581328fcd655d0710af1b83e4997535f9e99e9daf15fa51e521106de1a7757bf29c5af920fadd4540bedc06d6c123b5d9a99403ca7b4f4b7d422978055faa6aa7d046ebbe7653b8636ef13bb7a4c5909e52a238897a84af13d1393cf5a44b8b4b6c2314e302306092a864886f70d01091531160414ca1ff7ddc2ec65acd899d4ccabf13d4b72def78a302706092a864886f70d010914311a1e18007400650073007400310032003300340035003600370038$41fa1aff8851060cb5db172fc5b2143ae9a524148582d381599aabd96582ea1be2a6054dcf4e1a5c27566e7305a7b9a2a94ea83153f32c7c78efd57649812303", "test12345678"},
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
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr, *p2;
	int mac_algo, saltlen, hashhex;

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
	//if (mac_algo == 0)
	//	hashhex = 40;	// for sha0  (Note, not handled by ans1crypt.py)
	if (mac_algo == 1)	 // 1 -> SHA1, 256 -> SHA256
		hashhex = 40;		// hashhex is length of hex string of hash.
//	else if (mac_algo == 2)	// mdc2  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 4)	// md4  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 5)	//md5  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 160)	//ripemd160  (Note, not handled by ans1crypt.py)
//		hashhex = 40;
//	else if (mac_algo == 224)
//		hashhex = 48;
	else if (mac_algo == 256)
		hashhex = 64;
//	else if (mac_algo == 384)
//		hashhex = 96;
	else if (mac_algo == 512)
		hashhex = 128;
	else
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // key_length
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != (hashhex>>1))
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
	if ((p = strtokm(NULL, "$")) == NULL) // stored_hmac (not stored in salt)
		goto bail;
	if (hexlenl(p) != hashhex)
		goto bail;

	p2 = strrchr(ciphertext, '$');
	if (!p2)
		goto bail;
	++p2;
	if (strcmp(p, p2))
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

// we only grab first 20 bytes of the hash, but that is 'good enough'.
// it makes a lot of other coding more simple.
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
	int inc = 1;

#if defined(SIMD_COEF_32)
	if (cur_salt->mac_algo == 1)
		inc = SSE_GROUP_SZ_SHA1;
	else if (cur_salt->mac_algo == 256)
		inc = SSE_GROUP_SZ_SHA256;
#if defined(SIMD_COEF_64)
	else if (cur_salt->mac_algo == 512)
		inc = SSE_GROUP_SZ_SHA512;
#endif
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc)
	{
#if !defined(SIMD_COEF_32)

		if (cur_salt->mac_algo == 1) {
			unsigned char mackey[20];
			int mackeylen = cur_salt->key_length;

			pkcs12_pbe_derive_key(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			hmac_sha1(mackey, mackeylen, cur_salt->data,
					cur_salt->data_length,
					(unsigned char*)crypt_out[index],
					BINARY_SIZE);
		} else if (cur_salt->mac_algo == 256) {
			unsigned char mackey[32];
			int mackeylen = cur_salt->key_length;
			pkcs12_pbe_derive_key(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			hmac_sha256(mackey, mackeylen, cur_salt->data,
					cur_salt->data_length,
					(unsigned char*)crypt_out[index],
					BINARY_SIZE);
		} else if (cur_salt->mac_algo == 512) {
			unsigned char mackey[64];
			int mackeylen = cur_salt->key_length;
			pkcs12_pbe_derive_key(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			hmac_sha512(mackey, mackeylen, cur_salt->data,
					cur_salt->data_length,
					(unsigned char*)crypt_out[index],
					BINARY_SIZE);
		}

#else
		if (cur_salt->mac_algo == 1) {
			unsigned char *mackey[SSE_GROUP_SZ_SHA1], real_keys[SSE_GROUP_SZ_SHA1][20];
			const unsigned char *keys[SSE_GROUP_SZ_SHA1];
			int mackeylen = cur_salt->key_length, j;
			size_t lens[SSE_GROUP_SZ_SHA1];

			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
				mackey[j] = real_keys[j];
				lens[j] = saved_len[index+j];
				keys[j] = (const unsigned char*)(saved_key[index+j]);
			}
			pkcs12_pbe_derive_key_simd(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY, keys,
					lens, cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
				hmac_sha1(mackey[j], mackeylen, cur_salt->data,
						cur_salt->data_length,
						(unsigned char*)crypt_out[index+j],
						BINARY_SIZE);
			}
		} else if (cur_salt->mac_algo == 256) {
			unsigned char *mackey[SSE_GROUP_SZ_SHA256], real_keys[SSE_GROUP_SZ_SHA256][32];
			const unsigned char *keys[SSE_GROUP_SZ_SHA256];
			int mackeylen = cur_salt->key_length, j;
			size_t lens[SSE_GROUP_SZ_SHA256];

			for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
				mackey[j] = real_keys[j];
				lens[j] = saved_len[index+j];
				keys[j] = (const unsigned char*)(saved_key[index+j]);
			}
			pkcs12_pbe_derive_key_simd(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY, keys,
					lens, cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
				hmac_sha256(mackey[j], mackeylen, cur_salt->data,
						cur_salt->data_length,
						(unsigned char*)crypt_out[index+j],
						BINARY_SIZE);
			}
		} else if (cur_salt->mac_algo == 512) {
#if defined(SIMD_COEF_64)
			unsigned char *mackey[SSE_GROUP_SZ_SHA512], real_keys[SSE_GROUP_SZ_SHA512][64];
			const unsigned char *keys[SSE_GROUP_SZ_SHA512];
			int mackeylen = cur_salt->key_length, j;
			size_t lens[SSE_GROUP_SZ_SHA512];

			for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
				mackey[j] = real_keys[j];
				lens[j] = saved_len[index+j];
				keys[j] = (const unsigned char*)(saved_key[index+j]);
			}
			pkcs12_pbe_derive_key_simd(cur_salt->mac_algo, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY, keys,
					lens, cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
				hmac_sha512(mackey[j], mackeylen, cur_salt->data,
						cur_salt->data_length,
						(unsigned char*)crypt_out[index+j],
						BINARY_SIZE);
			}
#else
			int j;

			for (j = 0; j < inc; ++j) {
				unsigned char mackey[64];
				int mackeylen = cur_salt->key_length;
				pkcs12_pbe_derive_key(512, cur_salt->iteration_count,
						MBEDTLS_PKCS12_DERIVE_MAC_KEY,
						(unsigned char*)saved_key[index+j],
						saved_len[index+j], cur_salt->salt,
						cur_salt->saltlen, mackey, mackeylen);

				hmac_sha512(mackey, mackeylen, cur_salt->data,
						cur_salt->data_length,
						(unsigned char*)crypt_out[index+j],
						BINARY_SIZE);
			}
#endif
		}
#endif
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

/* report iteration count as tunable cost value */
static unsigned int get_mac_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->mac_algo;
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
		{
			"mac-type",
		},
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
		{
			get_mac_type,
		},
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
