/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth dot se> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_gpg_fmt_plug.c file.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pfx;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pfx);
#else

#include <stdint.h>
#include <string.h>

#include "misc.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "options.h"
#include "hmac_sha.h"
#include "pfx_common.h"

#define FORMAT_LABEL            "pfx-opencl"
#define FORMAT_NAME             "PKCS12 PBE (.pfx, .p12)"
#define ALGORITHM_NAME          "SHA1 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1001
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              sizeof(int)
#define PLAINTEXT_LENGTH        32
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests pfx_tests[] = {
	{"$pfxng$1$20$2048$8$e861d3357729c35f$308206513082032f06092a864886f70d010706a08203203082031c0201003082031506092a864886f70d010701301c060a2a864886f70d010c0103300e04086c933ea5111fd24602020800808202e83c56ad18c45e54aaca4d170750cfbfb3059d6cf161e49d379eab15e722216cb479eee8da7b6e6ffc89e01fbf30f4eb5e1b88ca146c166c700a68473d25a0979344cc60d1e58230a12d24b8be6e9174d3afecdf111cd7d96527831ac9c8f4bf3817cda021f34b61899f2a75fe511e8dedfb70367fa9902d2d3e500f853cc5a99ec8672a44713d24ae49382a20db6349bc48b23ad8d4be3aa31ba7e6d720590b5e4f6b0b5d84b7789ae9da7a80bfa3c27e507fc87e7bc943cff967db6b76f904ac52c1db5cfe9915fa3493cd42b8db6deae62bc01593e34bc8598f27a24cdfd242701ff72d997f959f3a933ab5a2762df33849c116715b78cb0d83267aff913619cbbdf003e13318e4b188a8a4f851b9f59ae2c71ab215c565f7872e5d54c06f92d6f59eaf19d95f9b4526d52d289cd17bc0c2079f9f13c20a70a566773d90ca6d888386d909b6362cb79e15cf547dceab1fe793c577b70f72463969f7b416fb5a6228053363558df18588b53406343ab320a1bbf1757b67ef8e3075f44dee4521f4a461d37ea894c940bc87f9bd33276f2843ff5922fd8e61d22a8619ad23154880fd7d957c0f151458fc4f686d96695a823b08c1795daaf79e41118a3c57ee065a693853a9c4b2004440662f51d63bb9973dc4bb8c541d424416c57d01a825be4d31dab7c7f4b2b738e4bbfdda1e3d3b95e026dadee4dfe155c0f4a24991693f679b452516bc19eab7cf7eb41b476358583d46630e8cda55974b8fcbe25b93e91e73f584a913149137c1c20d13f38826d8dba9bcf5504b8cee77e20a19d6fb050e9213b8aeb11c26a871c600701aea352ba2dcea15d8010d25034f64aa488b580b8282d226f8203bba6aa424b0a25bcceb9c7c718b6c276022d988ca063d2e88350d68903f95aa3265b44d909c07fa9477a5dfcfe3b5ed49b789d6e1c13aca012630343021dbc0c0f17dae6688eae495b76d21be49ced2c2e98e1068d8725d8a581958fb2530871dff1b3f910ae8beb3bc07bfb4b1d2d73fc5d440dc9bcd32ba656c32e357051bef3082031a06092a864886f70d010701a082030b0482030730820303308202ff060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408749558ace83617660202080004820280ef790b9cd427ec99a350a6e3afb1727cf3dd859d5377897805a7093e1ca42ab8cccc6c52d2b86d61ed55b5bd743fb2a4ec556b438933a9d97a55e5ad1fb3f9967e550be3d708feb5c7287e31afed165a4a91bd5a80292a1e061f97a8c11339963843348badf3fd898e89fd92bda5ad0195d8d4f75e7bce9f0518eeb85365860cd32ad5cea0958efef02bfb74aec0af0765729dae079f5eb08b099d3b06a9b9c6cd6f1e1e4170208ebec3c61ae3421e90cef0f2b5cd2187e43cc4ceecf4aec06340f886efb94f517e578d13659392246a69505de3914b719fba74709ef0f03f010429f899dbddab950f6e58462b2fe2663986a5e0c8ff235e89bca3bb6e41fcd602a0277a83822ac1a14101c83fd1cafdc45c1980ecf54ef092deb2fea736b428158e0847256fc1211f94ea8075145be5a5fb26206e125d55f45500844f1a83f063d0be19b60427dadbd89109bb9ee31a1ac79c863204e8e80c044b8b6bc45c756c26be514e4270a293faf4608065a27b4a51253cb9f831614d5c7f25ec1d4e36063e68e4e405c1f4deb98a786c57a376609441f2dcbe6393487b884624570f6cbb02b53f58ea4acb0faedd2931293dc87664a0c589322480686f6613ffb794c3b3b1872cd7a418712a35666b53bd8383f2e7aa6e8a9e20dd3d46cc3aaaaf17841732dde708ba5611ebcc8777fb3f7b65f2cf95992fdf4f5a17ddf01f3ebe5fb6c9cd58cb74553865cbec3c9d391dcc3e96e654faf7be7fdc8d5fb5dff98799e740147d2ca4b6df47560a4a20bd8f30cf5b495f4e919c9efad3aa59491a3e2ba4e53606e2016ce13e8271e70ccd5b57eec99a8604caf5997e648f3eb541769267f9cdf76aa84917ebd8a1f60a973ed22cca9fa0d3589bb77dafed82ea4f8cd19d3146301f06092a864886f70d01091431121e10006f00700065006e00770061006c006c302306092a864886f70d01091531160414a38a6be4b090be5e29259879b75e0e482f4a4dd8$a790274918578289d80aa9fd0d526923f7b8f4d4", "openwall"},
	{"$pfxng$1$20$1024$20$456a2344e138862de7ad2e0b274952ef566e2b63$308209cb3082057806092a864886f70d010701a082056904820565308205613082055d060b2a864886f70d010c0a0102a08204fa308204f63028060a2a864886f70d010c0103301a0414e9a49f4190a3084e02ceba2f049303750f6646da02020400048204c8cd40bb89c287b9fe70a88825e33a648c76aa1b35d93131d445e48943ee50ff8a0aee6a0483a289fbacf21290a8553e3414ea6bd6b305407d709bbaf915a99430c998d9ba68e71f4036d42feb386061d645433390658df91bd4e9750a39f9288f7cf8001e2adc8e4d7480f1a5e2d63799df20d9eb956f86b33330ec2c206b1ae47cf54d9cf2cdd970664c251e64cc725456e2c14506cfd7d9ff1d2894a50093fff4f29d5967a0f788ed707ade93cb3ad7e87d96dad844d2037f4d5e863ec5170c0f1d4514d752a266cd4db49b63c5d86646e54a68187ddc99b00499286f79e2e7c54e30d3a1b1f035d7113180d072c7218d399f8b5427dc2d6fcb42518bd6bb97f74c97ea2358ef39fb176397fe7729cd5c3a474423f0a0e74a91c77bb27b24f82463081fed53bdf216840b2c60482846010b654e2c74db4abfb07936e0cc9d0d133ac7a4baa03091de25f6eea70d85fe9376349731ecc03fe437175101fd6698929f43a94835c6453b68335f478cfa1fab1ddf0236570ca5a07cebf1aa3c36d7804654a5eac8328377abba3b81627fcac7f1dbdb56ba1f0f861af9967c5d245459a81891fb5dd833f0bca633eb616cf10397b295d857c63501e85fb9f11f1fd3dd80baac425ecf0efa012817ca9b23e06575a3942613fad67b4bda4fabfd29bd1897b0623d6d47ec000bd656f5b7c78b9a4808ac022524b17a8df676b86dc29b6d008d09cb1148110bd07464c071504d7dae5803602247da1e4cd5d490771322d7eb568d0ad0293f4d2626ac0f60f568a92eccd097f6d5247e043b7cdb52ddfef0516e7053fb42b7d1b16564f1c862c1bf45436290a5dab1f0e90b24bdd4433ce0cbcc7b0eafc445dcc6fe8a52e606d3977ce6d9e44f037ea8dbf36bce63a877aaafde13b1bb5005856d315f30fd4feaf26ef8eeef899802aa2442364c147b074c64878a696a1f2cadd9bacb187b62c239c16f163d6c44e157dd8daa4610142eb40dadbc3405c4ade7d127db20bc4384bd1d4c2a2a5dc907aa0468c2485654bceeee3d4011d74e6e85ed88811ccf1cd6b3d5540c5709b8e14fb9e610b552502343ec739e8c9c6d6459062f76275de1fa1b24ed8a9924ea9176dfb89520b7fbec9e9968bd0320afc513e560966b524a82ef5a206f1823742e820bbbe6dca6b0a33c8f04208376bfd01f049f666c735b1efe2550a8601b1839bf045c56a9772a3e25235d2fb61f9007713ff57ae47f6335a44e6730bdaaebe833996aaaa78138ddb7d8719570a429debb8183fbd07f71a037335ec5b1d40c62f7163b85dc71d8db536c9092f155429b65ea81f8ff3c7892ebf881c107ea2c167df47d044ae7ed3fb5328d673753450c82d7049dfeaf1dde821a0ee0d6676a1656584cdbd4532f8d2493ea4794d88acacb147f19ca15777a67fe5031991ebc45ea43e87574f9d2f52de0722d6cc7f5b7a378a461148f1f7c5ee8bc7c7ae4fe80b4eed13b35d16906a084120c645812db0bd70e419c004512f284ab7635f17ee2ecc728aef2cda256b86fb4cc9d3e21736249735962d6ccd307a67fdbdb0815184f116eb1747de19449c6fb9410cb669fa2a3f2ab5ca16c3cca918555b583f61f2126aa0895ccdac7a5604ca1e84a76c15c508d620bb9037e5e5acf97e94438a059bc771d84dc1f63fd3f4780274a2f0a03f9b09a0cf4638e0c317f6ebb24f9062fe8c7023d4c06f3c67c9ac2008e8da33150302b06092a864886f70d010914311e1e1c006d0079005f00630065007200740069006600690063006100740065302106092a864886f70d0109153114041254696d6520313334303937373036353139303082044b06092a864886f70d010706a082043c308204380201003082043106092a864886f70d0107013028060a2a864886f70d010c0106301a04147d79e2d2b2986ea4d929b3ba8b956739a393b00802020400808203f82c0ebc2a236e5ffc4dff9e02344449f642fdf3b16da9b2e56d5a5e35f323b23b8ff915fbaf2ff70705465170ccd259a70bb1cde9f76e593f9a7a0d4764806dad2fa5c3b1ee2711e9dbbcaa874f8985f1b6c2ca1d55c919cf9e88aababe7826107cdb937e7cca57809b20a6351504ab688327e4df957a3c167772cf66aed6a2007ead81896465d4931efe7c3291a49761f1428c766fd82e1736218e90d9f8592475d164d9a79f3424cb6a543f7040d3f0dba6996d496f4f603b7d59527e5c9c89b3f96c55fa73b72385629cbd606cf9f88833db66bb1519dee62a0cd4989d93457fa1162b594b86bc7134c9aa530fe10d62b914f1818395f82d5224c3bc793a04b0ab41dc98694535f5bfbf2aa943d6c794f407e02248be842c55789091d1cc28bbfdf86bc1346142b057558ce1e64e38f8b2d7d68d539150f3de23f43d59637ae678f3687e69b52fdf46f54c32b84a658a2a69fb16da7ebb45ea84c9e38d6cedfc1227b86a6ea3094d0908d588213834192849fa5c25b2460bb22fdd9d9e317efaca646ea582ecb50f6a466f55ae38573afe904eadf42b6c596c8740dbf92cbd38c347624f3399ac2d20d0727f897f38417901dfdaa798631af8992fcad5d708882576036531d2deb867fe46d63921dc50b8c73fbc59586a861d7ae47c2a5ff892e9dffc6d8e6e8161506819ebc020cfb7bc4c1708832d53f8cc864012ab8379a1323e23b0edb5ffe48a942411cef6197f5545ae6822a3096db972f96d4d200ba600a1e95595d4532e7a9861b233f71ff37ea3c19143c87dd6d4a3f3186a7693dc11067c7b4c967984d4bbbf9d88acacb1ff3ba4536ea265a0503865d86af408748fe8191119cd7b570b5352f190265d5d468e911ba0020b526d3892119fda21243568cfa638251c9044c91a88d2f8a05dd0d90088b0b79ac2a2ca263aa108160a7f6943ce709a02743afb6e4ec9a7f7535635f839c2baf938418accec3d5c1ad2bbcec69ab337155bd0bb1b45c7e16e32f251d4da7796f013d6d502581853da6ab9736382115141886c14512fb5ca22e3e9e20366257579eb4225a6a3716457b9b1c0df63cb71a34b888de021f3520d62e96675ea8767e23d55b50e9aa40babafe398f5482c83f8caa57d7ed3486ce7dedace7158067194892defe38af28c1695cd6f14a1ddae959541fab3b59e72c17d2a67d980c749ef00b1f61ece68d81c79b4ec4f4d9eeaad43895a0dc9d86f4d7fe114f01189b3db72ee92963d4403c3aca8bf6d60ef7ee7fcd8102b3247048b4d517cd0ab76a0f8d68d33733934cb35a8e40d7de70c4f166c453fda74553069c51dd33f6f513bb9ef0a983187fc7d896c668590577a4e269688cc7b9fbd1f3fe77d3f431cf002043c43e1cae82b22018931f1337ee276d49c19163a866ef10a64ac5b013db1cb1c$501f5cd8e454e44b6925715c4d2605a8d4ce70d0", "my_password"},
	{"$pfxng$1$20$2048$8$c70bc3c11be46232$308205f9308202cf06092a864886f70d010706a08202c0308202bc020100308202b506092a864886f70d010701301c060a2a864886f70d010c0103300e0408aeab408a953dae400202080080820288eac5f49ac4a3c50ec87cfd7592cd19e7deafbd62f58eb68ec542bf073778bf238533fc1363ff41e87dc72e75d97fbbd9707ca0fa171216f5c5d56906efc96f15883138b31a151b40ae2d72e7d4310095f03c85d75672d983566db3cae50c59613a26b64d54fcaa5cd8c328854359868eae40e66c7f527ce213d3a8645d012afa3fbb9ddab6c6dd1bc3863cc2c0014380e606da2f7f7ede8ef1c8a35d48b4f150651387461cf1327f12629411b3b3f7b0d8e3dce9e03b5ef52b1cb911b469685b491ceec0276a6c3a2e64beab805fa67cea73c0ed6bd498d563a89b874032fed141857f0a80342442d20af18a084877df28b3abd4c9d7218551bef523c17b4729d0689b0833e190e3e60995ca3fe5075629ea4ffde3e65f20777086d5cbcfe742cc22ef46d06e9ba35e4017eb35fec30cb7ddc37fa22daa9e77e202d864f6d34541d854f00f9e8c1445ac432bff67a5a00b6cd0da5eb796c7a44e92b5c67f55de92ebcef8f690d7b3892362d884f2d8c657db5dc308c95a43cc42bfc5449b45c05e9e60ca5d88d0c07b9cbe6b76da91f7c572e1c02ef71a18833e6779df711a4104e21d5939a982e19e22292df280adc3f0b10339f53fdbc44356a95c27eb23932302678b86094d5f4d60e028af61c01d7fcd83ab9f78c4499c3e7bd29507c397ca43d397b90cb267a6ec15f37b50cf4f2d82d4a4fe8f56355c27c20cfd93ed5f84f321244c7a7dc404619b3f9bb83affbf4d1d702b336ac3e504ccb86c18a979354faf0bf4e725fe1ef051dca8ce0209b7905f8f19c5ec51fbede48f57cbb90d14d666ca09fb4d0b92c6e2a54e8ad1b51cc20cbe17c86901f76d509bcbf0d6ecbf08685da20ec75c11d8c509cf2ab9842e2be34aa24920d4a035e1641cf3d5b1669d46ac9531514d3082032206092a864886f70d010701a08203130482030f3082030b30820307060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e040806de2bcadc588fa502020800048202800d03f420c35a4b8e1b3b0592306996feb16d41001d0aace08d4dadc51fb2498f504c4bf57a54eec39102d76665eed9c46006c9a181bca37c64e96f11b0c7c24bea8bdcdab174ec1aa2f85b6a0ae4ba082516e977a212ee8ecb5d79b7431f951749046ffad4fbb2106016cb024da53894b7f2c7e0b8d2af6a4823d57d30b884fba32bebb88c0bf53f370663f37a4276750ee22c2a76fb428f888dbc1bba10bc0976c7a5e73181dd84aaccfe98e2fee04212f1dea2284bbd0fb990646fb276610198eaf210d44c63d245234fd6c7486d2b899395d75ca569f4cc7f1c1b9583d2e5a3310ffd7826fcf206cca0fd2557b9317ef638e5d553ffff917e41c6a3f184ca72a1581725a954f5ed157dc9b04b1f2f044bc267f9de7e4d80aef84b91a94b66dacf86ab78928c873b2b8963ef1b2fac24a603011edb223aa8aa22bf3784e6938edf7811516ae4862a77693b1c254a4ed30dc85bf4b5a79942f841dc09db799eaa89051fc51eb917d9faa9781af961ec34e2df5ba531628d777437b282a2548d9f64eb72069f0325cbc65123c67606c0812920862480457d0df6ea547a9f778d48b24b6ca72d47bfd4cc6431e126a43c8d14ecae263da06bcb73413091d154c0e67fb6f629131c2d4a0d1b750941b0ab8a188ddb4cd427396d83f922bee0f3a85383d5bcb8ec89338b933d181aba79d7f2566e74b9a01ecd755ca4ab38963fcf36c985f5513ea678a822cf8acab673234bcc3d7b210da1b762814a0cf658e5d8ec9305b887d444131278f790fb8c77f3737c5f8f864ac7554bbf4ee8c3d78523462628faac312e2d37062c72d05ba2fed1a51c9017a75160cd267897802463e638a8e02c2a2230f518365470aca7e8c418bfe99227ad13f0bf2bf6d4124724af314e302306092a864886f70d0109153116041467a3f379b2dd87441f6abf68c9a9f8429a92c044302706092a864886f70d010914311a1e1800740065007300740069006e006700310032003300340035$585f5cfb43702b6d02b55418ce3925d04cdbcc63", "testing12345"},
	/* UTF-8 encoded password */
	{"$pfxng$1$20$2048$8$246876fb4549c3d6$308209b83082046f06092a864886f70d010706a08204603082045c0201003082045506092a864886f70d010701301c060a2a864886f70d010c0106300e040857a09c271e9771460202080080820428f439279cf3fb6175757342476240ed8a8b11112f17a6ff541e6f9c8cbd568bff2316be01ba429f4157c1a12f4a5c664c17f84e03d9e20e0ec37d912d9afd9929b1daa16f3ee94cda6a0d32f80bf345fb0064a8060e6736a8463b5bd634d5da02c474bca7fdf95fc6f0b00ae4130bc54a2b9b34b78cc6466e9c4258a58f00da88eab28d2735f3081d212b7da02bbdbf85620cb4f99966ccb41992b902b71bef26c08d2522594f6527a1023bb31ead7a4bb2bde3751163ab7809976b710c0e8be22e1b2a4b45cf64b0d045312c1d3c24381109450d3038c9fed392a4eedb3745720eac1d1c9b7e44712eab74866524a263938b6207bd48884d164da0aff58326288391f641b0bf916bb5a7c796d0907fc37a0c7fd8a8d0d0c146dea39207d7bf480f906409ffad67104c8b780b553f8913215d2088272a9f0d8de8f40ea2d20c37387e6277e0c5fef87f97d1f5460e648046a2c0d5972afe9622c6808223d1cd3169c5d6e88f26b8d682500908262c638f8afd79d392db6c8c64e4ec3b171261a122b32bb709b39eca0e08863f1f07a2e17778f901ef032b698260cdd525366e5782922ef76b6c471ba92226bb3fcbabc3cad2ebd2cbd14ee1e13b159f9ee39779cf01dea7b9b087b55c6f2025ec6418dc5d511b0211b10f470fc2ddc0bc685b2ef5ad39cd0013663f327b41a8ee129cca131279d314e54665f65cc263ccd040ada859f4f0b3f69a63130eece791d5cd08154d2f04edc71e646270aeb789cc260cd4d31905b23520ae3c39f6df9043b98b18212ecf53383c9cc89e3d1c6cd5aa618f0ed65be139e09e5e77748e8f2d5dd9b61e98505244abde0d2a9467b6d58c87b1a75a130d3296268060b3d75592bcdbc4e8c6cf7a539d642bd73e4d4d4b7b4aca7fceb4497d12e0a91d2a43ce4bb8e8fef1078ff70142a6a2948f4b20a5dfd0e33720f4ac871c9047e43d92db21d87f74fc8e20834aa2c7a436cbc21b70e4647a89a1a721ec67ede6e343c7b988ac2ccb01230b47344437590875fbdfca12d0c897109a26f02d8c5e33539ff16a58da388e726063c937bdf25f494e87c2ee813292a406eeafcc320645c79fdbdc328b317ab40e02b4a641fcf5b642ee1322b66e62e503013e8ecb7303f1b4b0eb44084026821e03d081de61732f0417ba818403ea995595db47cf5ac3251d3d6a7394f6f713123cbc613101b6a6a57fb43a90d70f3851b8070ec2f9a60b4f8b6f13062b2b45a0aeda68f3dffeddc535861e2555a067f3d55b3db787ae62b5b3f23663eff527745a5e3726c213e83ac77dde8c3ac289ea5ecba1fda1f2047541c1e96f0d57f0b375a9481bf739a4c7efb250cf704e9cd1c0a246dc56b5e47b47655b4a2eaa498dd80abda1ee6fd25e8899adfbc78a163971ca72abc3c8c70938794dbc168a1f02cb1121d22631db3c9dfa634a9934ae4b0e65558b61a8ec44af49048684d33a4ace8223771ff0bea76763b8d34b16164714c3b12a3082054106092a864886f70d010701a08205320482052e3082052a30820526060b2a864886f70d010c0a0102a08204ee308204ea301c060a2a864886f70d010c0103300e0408d0a3ed2c17f2d7f402020800048204c892638e8c066e3f00284c1a86e33c78384434f36df6b59cdb2b3783c325d5947d823035521a58cd72ebb4646417fa3fa1a98e4ca4b8f6b48cd695becec2e4aef88829dc8576d2237329bd1cfc83673138d7cd133beec63c26b4467ee55921eb2ed4855ff6dc1d95c992f1f482d691e26801dd9599171dde7ef5411e388b5f785ed55a9339331d70f1be70859ecb9c0c62445a6c58f6dd647e70b60885e29808693fbef982adb8a70208a3d1356e4d6279df444cc86dbadba362c22a9b4b9d61032aceca274bd83095a6113009afd03e746e2c79a78caf0e9e87241035d08eb0e528fe4ff1a04a96f289374e2d1c7fb27eed0be3f409e45c8f212e9ea68da884339768317deb39c20201d36b9533fe7c2513e0c5b25a40a2c88cb29edac2ba77badc3440aaf28dfc13fd16331b9495fcd9faf9f55836e6fac2f1d609526defe8ae00232b66e3548e0f9d37f620b6f97d731c33971e3cbe6fa3d3427576ad8ee36f16593dbc404912aecbc446bbf8aa99c58f152d3c72ef20920c45bd12933af7de2d54912c43e568c5d2589c933c2517b4dd726f997c5880eb89168c295a74134d8dffe3e07cdb3bdf1e8acf373c4735b86ca079b21079407dcbce9407353c69a6eaa7b9d9f17bf28a5bdd87e11295918ef4b0b26e3a5e8fa4d5cc26d3bb29ca8a9fd2cc1dff0f821bc71c8661b80de539fcb37fa216d113b0385eac7144e738518b5fb284ac6247ae7da98bf974aa7c7a67efce09a6537f94144f70c35e3eba039aa973e660ad8c649ff3b790677b0256da032a82e261375c7f703a185a5f8a4583aec4352e62af66d7f325d2bdd7777e64e0fb5cf5b6fca83c541b700de68fb0947579305ac89f3f44a0326ed4eb327d938b3ffa9e440da290019179540783d5e40deb701078afe37b185cac98bc9e7c4857846b86a91990cdbf26e69f6fb0584a4fd3943d789a1c0c2ac82af1ac52ef57818c3a1ab9622c12475ebb5895d38fdf28bd0b298ce43137b94caa02be252aa9378bbd13e84b5307c879decdad6a230ac2463f983c41748bbc7b11dda2c6facc7de06ec5e4b8e2b557612ac1b14c8881b342a047a231fb9d863632ae692ee070c56d190271b3ac30bd0e5cbb6b3d671a8030693c5094d6c6dc86a35b7d27f3a7ca7e18c77e4347628d0d145ee9104533f6a669a3adfdbe9a0ae3df00c0445a965a5460ccfd0c932426ffe63690a4f4972a66f9235bc44789f7cc031fa051e3b1328f21f81417e8e19a301388113bdd135438ae6072144d876455d4b0e34d60bf94b1188b9b9ef2c5995a97c86e6f7420b8319d97012a30bd7148625e7f746d344d202b236bb62ba9d793875efcf12091653749047656017d140e4e772c0a9d83a1cb8ba9aed082626b1005fc3320fafc87b1adbbf87e32e3756b18291744f87ac7657831f8ea33c8d81156149e443a763ac7762163b8a6263562a1497b7d7ed120b968e1bdc4c8d623c6583f06b96139ba6813b1f0199e905993b1df2a88cdc96eac9eb034fe47c98317e0128d4c3dd4307f40421be7ac958040e3c93df02cd884590baf1bc46c49e3fb05f1a32d06ed43a3f8f88365ed13f2a9717d3a262fdbe63b826557f5cfcaafd1ce3623f66868241a60d28b9780fc4573ae312334913a445a73efb532cf5c7a0263df2dc4b40a69a0efbbf5a1b61d5c410d3d77683517aef4b1afa03d141dd38bc84c5ecaef01df8b4b288073413125302306092a864886f70d010915311604146070685a72842f58b4151f4f85ef30fb0a18007e$3d99ff40ef8ab07022e5e2cf26a1f22acf6b5671", "möller"},
	{"$pfxng$1$20$2048$8$8a4a0ba026e93132$308204583082027706092a864886f70d010706a0820268308202640201003082025d06092a864886f70d010701301c060a2a864886f70d010c0106300e0408af17a2ebf12476a5020208008082023065ad0c71081c2d50e73692bfef56e0d6e06b48dbb0b9d4ed7fd9a49e13c38996d3885bc340d591f6ac6978cd01ac55df6d237996cc470c777019377cd123709dfd13b78b5801607e14dab2f52a4e94e58e8142217b153f11e9ddef4cd8344042007346a29c21495d674fa11b7a6ff79347cc90a0a5b4fbcce5a6c21d8b6d8be0a4c0f84041e1c846b023050009a31f7fdd63dfbe5c179b1cdc56b6c6df6b9bd215c71a1c318b619da29cdfd0bcaabff5a6835b051d2ff5a02f3d02b95115d867d77a6c692aeb9619938614598ca84e60949dc868c890b9daae50d55a1ed02ee01975b769ca8eb18b909136e1a32c096ab767b97fd60d3b182870ddabf0b5a65ef6e8c69e8918e966fb7475c6b5263dad23534c843ad87dad85f81671cafe6b52f832051314d859c196f0b5e4228dfa20085604ee4cfc99d5f2c35b76930007d0f5d4a7bad060081a93b70752f4575679320f2b8914930c19e0e59cf95276504617681d5ef745380981537846466ddd9cf8130f157c3b2688749cb071fa36ec12157b57349b932fe5d635b853b5ba399a7e4113c639b45dcb618228d1e8a2077963c2c8f670a0189432d59d7ef915f00aa7171d9653c413aea748033cc60c37e3af9b9cdea29fecaf0fcc0d960cbf2da468c7b52b61860c8cfcc841d5bc2fe5605a34686d31c9fff66cb9a7830415b8eb0d2981c757660297d7d9843309bc26f2eded4800b34027e661e22ac3f3da82749d4bac74e02c017fd0a339f0bb400627c8d31684f30fd0e81d0973154eff06c5308201d906092a864886f70d010701a08201ca048201c6308201c2308201be060b2a864886f70d010c0a0102a082018630820182301c060a2a864886f70d010c0103300e040873a3921c345b0bd702020800048201600b7098f289339c8d8756fdd00f63883126ea62ca6b7d8b27cc40075e6e3d952fbd3074084a70d54619f875ff4af0a8da823c1110a4914259cfe03ae35798d0ebbb6ac43e7272bee2365bc5beb8a80d0cb8cca06fd18e2f6db5a9410650b6f4075dae2c5bb0b373b398c18fb41bbf76a6abb921d3a92612e10275aaea600fbc3d2686c44231159e3a63206aa7188ebd0815468bdd943c3866ab34a3b4f87c848154d3dc7e006662474e41cf162738c081033668397729a3fc92919f6044b1241ff1d2f300a42e54963d3d19b5201d4ec4e6b199225e23aaaed056da321075585da9889242378f5027c4ee8d999eac2b2fb5493fa0de8f2291cf75cdb29edf4cd53ac5c702ab3c41598b0bb99453571c50ac4aa3fbf23a0070b05779886550a7fdc0f3ecae4c730d3d031ac0b91397385a10bcd98f34e132d326895a35b3132b1cdc59bb7eaa9312be82861325a5fd6b0f8208530644cc1b96277f9e7701b243f73125302306092a864886f70d0109153116041400e22764f0d0103973b2d4c26925cc9985eebf14$d9d1c9053ad4101943f883baffa11eab65f73e97", "abcdefghijklmnopqrstuvwxyz12345"}, // Length 31, see #2606
	{NULL},
};

extern volatile int bench_running;

// input
typedef struct {
	uint32_t length;
	uint32_t v[PLAINTEXT_LENGTH / 4];
} pfx_password;

// output
typedef struct {
	uint32_t v[20 / 4];
} pfx_hash;

// input
typedef struct {
	uint32_t iterations;
	uint32_t keylen;
	uint32_t saltlen;
	uint32_t salt[20 / 4];
	uint32_t datalen;
	uint32_t data[MAX_DATA_LENGTH / 4];
} pfx_salt;

static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static struct custom_salt *cur_salt;
static cl_int cl_error;
static pfx_password *inbuffer;
static pfx_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

size_t insize, outsize, settingsize, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(pfx_password) * gws;
	outsize = sizeof(pfx_hash) * gws;
	settingsize = sizeof(pfx_salt);

	inbuffer = mem_calloc(1, insize);
	crypt_out = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(crypt_out);
		crypt_out = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DMAX_DATA_LENGTH=%d",
		         PLAINTEXT_LENGTH, MAX_DATA_LENGTH);
		opencl_init("$JOHN/kernels/pfx_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "pfx", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(pfx_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 200);
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

static int pfx_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr, *p2;
	int mac_algo, saltlen, hashhex, extra;

	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // mac_algo
		goto bail;
	if (!isdec(p))
		goto bail;
	mac_algo = atoi(p);
	if (mac_algo == 1) // 1 -> SHA1, 256 -> SHA256
		hashhex = 40; // hashhex is length of hex string of hash.
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
	if (hexlenl(p, &extra) > saltlen * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // data
		goto bail;
	if (hexlenl(p, &extra) > MAX_DATA_LENGTH * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // stored_hmac (not stored in salt)
		goto bail;
	if (hexlenl(p, &extra) != hashhex || extra)
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;

	currentsalt.saltlen = cur_salt->saltlen;
	currentsalt.iterations = cur_salt->iteration_count;
	currentsalt.keylen= cur_salt->key_length;
	currentsalt.datalen= cur_salt->data_length;
	memcpy((char*)currentsalt.salt, cur_salt->salt, currentsalt.saltlen);
	memcpy((char*)currentsalt.data, cur_salt->data, currentsalt.datalen);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");
}

static void pfx_set_key(char *key, int index)
{
	uint32_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, crypt_out, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

struct fmt_main fmt_opencl_pfx = {
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
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{
			"mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]",
		},
		{ FORMAT_TAG },
		pfx_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		pfx_valid,
		fmt_default_split,
		pfx_common_get_binary,
		pfx_common_get_salt,
		{
			pfx_get_mac_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
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
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
