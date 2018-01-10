/*
 * Common code for the StarOffice format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "staroffice_common.h"
#include "johnswap.h"
#include "memdbg.h"

struct fmt_tests staroffice_tests[] = {
	{"$sxc$*0*0*1024*16*4448359828281a1e6842c31453473abfeae584fb*8*dc0248bea0c7508c*16*1d53770002fe9d8016064e5ef9423174*860*864*f00399ab17b9899cd517758ecf918d4da78099ccd3557aef5e22e137fd5b81f732fc7c167c4de0cf263b4f82b50e3d6abc65da613a36b0025d89e1a09adeb4106da28040d1019bb4b36630fc8bc94fe5b515504bf8a92ea630bb95ace074868e7c10743ec970c89895f44b975a30b6ca032354f3e73ec86b2cc7a4f7a185884026d971b37b1e0e650376a2552e27ba955c700f8903a82a6df11f6cc2ecf63290f02ffdd278f890d1db75f9e8bd0f437c4ec613d3c6dcb421bbd1067be633593ba9bd58f77ef08e0cca64c732f892567d20de8d4c444fa9c1c1adc5e4657ef9740cb69ce55c8f9e6b1cfed0739ef002f1e1c1e54a5df50a759d92354f78eb90a9d9378f36df7d1edd8002ea0d637604fcd2408494c2d42b1771e2a2a20b55044836f76db4ed71e8a53f55a04f9437946603e7246c2d2d70caf6be0de82e8977fab4de84ca3783baedac041195d8b51166b502ff80c17db78f63d3632df1d5ef5b14d8d5553fc40b072030f9e3374c93e929a490c6cfb170f04433fc46f43b9c7d27f3f8c4ed759d4a20c2e53a0701b7c3d9201390a9b5597ce8ba35bd765b662e2242b9821bbb63b6be502d2150fff37e4b7f2a6b592fd0e319a7349df320e7fe7da600a2a05628dc00e04d480c085417f676bd0518bc39d9a9be34fc0cb192d5fa5e0c657cdf7c1ad265a2e81b90ac8b28d326f98b8f33c123df83edc964d2c17a904d0df8bd9ecbf629929d6e48cadc97f49a8941ada3d219e8c0f04f37cecc9a50cc5307fd2a488c34829b05cd1615ae0d1ef0ce450529aa755f9ae38332187ffe4144990de3265afaacb9f0f0fb9c67f6210369f7a0cc5bb346412db08e0f4732f91aa8d4b32fe6eece4fba118f118f6df2fb6c53fa9bc164c9ab7a9d414d33281eb0c3cd02abe0a4dd1c170e41c1c960a8f12a48a7b5e1f748c08e1b150a4e389c110ea3368bc6c6ef2bee98dc92c6825cbf6aee20e690e116c0e6cf48d49b38035f6a9b0cd6053b9f5b9f8360024c9c608cbba3fe5e7966b656fa08dec3e3ce3178a0c0007b7d177c7c44e6a68f4c7325cb98264b1e0f391c75a6a8fd3691581fb68ef459458830f2138d0fd743631efd92b742dfeb62c5ea8502515eb65af414bf805992f9272a7b1b745970fd54e128751f8f6c0a4d5bc7872bc09c04037e1e91dc7192d68f780cdb0f7ef6b282ea883be462ffeffb7b396e30303030", "openwall"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*259cafe530bd09f8*16*8f53ea878d0795cfe05dcc65fb272c20*1024*1024*ffb0f736b69d8433f958e8f475f609948ad7c9dd052f2b92c14cb1b395ffcac043a3def76d58442e131701b3b53d56ea570633bb20c83068542420160f5db3cee5eece05b67b54d0d4cdf3fbfd928d94852924e391aa3f70cad598b48b946399b0cd1e9e7e7d081a888933f8a1973e83166799396e8290771463c623620b51fb5310b9b0e0de3e5597b66a091301ada3ba6a5d7515d1fcf0eff65e543b50f8fe2222619600054eaf69c7aa680c96bc403f115cab32d6d8e8bc0db3904a71ce3eb1283ca73fd6f75845d9b7d0275e4727a0f56bfbf962a9079f51849de2c9dee7f1dadbbae944f442169281004773309b0f8d68f2cf83076fd8b19afbccf5ab7dc58fb9554fee82e2c491d6434a4cef6f3209775343c840bc4bdfab6705000e67412ac74d00f5b6aba1fd21bca5213234a5a1100a9d93daa141a4936723ea77d008a35c9078167a3529706432b36b9ec012c060d093535c85ca6feb75165d620d7d663c3e76b9bf3af614556ed8560b446a8a73649cb935383a30b4fd8fd75522203e4575cf4bc2b7f01a9294310fe021c71acbf68f6f1e95f48c30c14151c51d4fb878a16272ee73753bc750cbd48007c842412ca1dcb6214215b082c00d619a5318e2ebe9149410f501170093784afc2bd71dd9f5a87b349b96661747b1627e8cba8a5c98559fb146fa7e30db4c6f648ce3c2209f84551a7a1cd46d9172ae1354b6d093f89f6f5f58d29c1d7af8830df62e67753caa8166322caa0f8adf4b61d2013d35baa7c002e1d4c83b1cba8aaa57cf4946627fa63ba7a6a5a5c803e8d5a4794845ab670ef950b918a360cd9f12e8f3424ecab1f505cb494ad35f28d12ff183471d0f47bd67e6abd3b8c8e206d11149474a19b5c13d165d8f6dc39cf579fe1000295328aeeb82e0ae8020d2f61e4c3d6e68c25a655ab72aad5e9e74af4cf27c74158fdb1a29a3d76cd658976fa0a30743247408df00a23b593f68861348a6c46af05d21a4b81fedbf5715462ec8ffc5f001a85c43058ac1fab488236588ef0bf08dd8dd7c7fce630a0a996395b503647d9a2f0dd63dd2f939eca8e1849ee4ed41a6d5672d947177e8f890692de879a20dd9e366ec494d270faf0d24fc076172a25998aac218586404687e7c77b55e77e0eff9b1c65c3f8da99deaa86411ab6aca2531d84b364349591bc73e7504163afd23c5208e321883ee611ea7e4e5885086e4fa7196e16b948cb54808b64b94106c74900e3190fd5f6068b490fd0c9c64481771527a0e2d00899fd5b7a9e7f508cc6770018fadf09d965d7a12ad3624d2161d9546d4a7937b5f961d7f7c4714786380c147e1ec6b0583503bd5a139b892831d1ea925993bb86f12e75d9010ceba230a1c286fa3d1d654a1672313cbf0763c05c622cee452f76957c42ba0e853ecda163d15e8600a702ccdc9e8f88a", "Ghe+t0Blaster"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*9bb755c8a4fe8c34*16*112b9d41098c8677615755361da473a6*1024*1024*b95f0f2e0e1c7b4ee61168b646804d4b70b615f3c978cec65c9a7ab515417c79625d104373fd5012c3da6b356f8408a3a75edcc8b2aad0aa38bb33edd8933bdadbffde35a350ade73ccb9df29c2996082f5e94e324496835f8dfebe15ca38950e0f435d711ef964aa09915d58287967b5e321ca195a7f90253157afe82329da9a496c97292419b9a94cdb92f919e6d54700466aff61c200c5a355905b5a37c12d77b0e4ffd23f0204cfa664f4c0545f233db8d35af5fe337b459135da398fd23101becb194db305496474ba4179a7355285a9ec935044e1831f290f5f87ed3e00925e7fb4fc6bc38d9f0cfe9abf72560400490d2fd398d2d49516b618f99168602f323dd1786bcca394830341dfbeb377f9b7ef161dc1470f5e92b6152fa7a4f428e8ae40100791491a9e1c9385298522320488f00535866ac6e08354a75b8b2fd293066da7eb6b4ad7f3e13c8dc98cd815b2393f147fdac6279f76fdac9abd0a94131fa84fe4e99634a362a56d60ce588f6e0b66d6f8b6d411511272ffe32181d20e7d2c3d4b680764607afb2c29dcb94a845b920e96f6c27575534f8b7f9ddd93bdcef0d717d0a899fa937e7d2eeeb6d5b0338757f6e69dac72524d4b6f74edce1f937008eb3653bcc31a88712af940cf47ec3f3efd83e4da89d1a6cb7da6cf8d7d41430bc81a4b5d7bb46cad687f2f505e3379143ae274eed6201c3b17c1e05e516a14cbf2351ccf9fdd46e1309afb170bd01eb8f6a1d8e12441525199455fb550e3fc689b1801332b2d985e336b158f846fcbca18fbe6ea21438cf1fb5fdbce8d6350e65d6468342880845675ec721af2fb9df917a3968b4a1a477fc4c74ee38a71a230d77c2a7cf66ae6b83804488cbd25213ebc470cd845a2691b16161a640ebb385aa2381dc91f692f6c4ca2709b5a7e94dfb4548000a29b56f1da08701945d6209fabbd1621b28849fc27810775f1a0e0204d3ae9040a8cfb1386499a39d87149cfc1579de7d059662ad25a67abd42b30bb3608f09142ca030351c3a1e921e4c7bbc11aab846ef42eb5d1418c15ada77539aca096e0678439cd1b60950d2aa0cc4d2004b1ac48dc6a454c5a8e9ea7e910047c7c83895fd614fd9dfd961631eb23757646143c2aeb03c1a6476e78fc4ccf0f02cc1f88ec1b0080a170ac6871dc183939f7a4376965b0dfa7922012582eec4846ee621edc5547a2b9c4893e7f67f76541a4bd4a91827a57b3db5cdea29a2a3cc20238d89c8145c14b037360ad27f54f87317ef70472d6b1fd9f1168bcf8aba6071257b3adebab8d4e115188ed4af3fc3574fdccb4bc7eeb00a6a442f1b96a989b735f5e6059ec72c1677b77f437dcb93066f8591a11071799c3a0ec3b48f6160976aff1928c375358837e1ef02e20397b2e9d8d9c4bff23172c9b4c0b941cb1b49b5bc070f72a14cd384", "M1racl33"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*ceb1edb1e3cb72fd*16*f7104c9b2789540f5fd4beef009c0139*1024*1024*709130b940a9663d0a5687133c6f78535d05a72936faed8c2f3c1b4e29423baaabcee4f0d7d57e3ad8d8c090486f974c4d0ce4be5b29ef8e1b02c01b4af1959ed0b277146a45aec35a48997b584b82697803193644eefd88a7eefcae8819839e13702f887278a597dd954babd82bf71bf8ca8559af0e5537be0264e358d36b4f5067960edf608de731e04d117de953386aadee71849edbc494fac3e6b14567a9e9c545a06d402acd3158441829f25478ed0f9086dabd2d3913b123b43c27176f8f08f30312d84e82d47654097a2bce95554357db3ce3d45a7441472067f55e4ea6244a3dedc23db4bea8f549109ffac382cf5b652c5b1ee431bcab1051567c263a9d668c5d6a15a6f8da754914746c1d3c7eb6347bdd8d6a3ac82e4c742fcf8721913c111dfd5398f2698db00f7220d2a3562e02f7f7a6505af3ba1ee10b46f2ab5b5d2f52d288fd12814c6edbcb8d50b6e8716fba0d5962747b971689fe75e94fa36ec39598ea30e15ab2b9c9f22ca04b890a13b18fb3c7a962050426bb2da08c8b993608b9c1ffd0a21e0c74e993242ead8eb30f86d7d2dcdbd4774d85c2e06adbe4b40050ff0ac1a8afe8fbc2175ec4da4676a691b1fce38421175734c20f07a604fea5287e1c33b420aa9db4de9bd97382c161b4ec0818add675e52ebf036aad779f24b824be4b2b013c470ff66cbf44f5800e128a3b328e80a5fd6295b9b3a94e915f9add6710cb9444432751a7a31c3a3422f48a5eabc26d9a52571b8447bdd0a5977ff7153d95337cef7ff2ec29774332fbeed6ee5eed5e12288cc13e14ba9d5ff3dd052e28ba96715f5b95d7ea214ebcd9e60b26308eb11370b824b5cff2644dd2117985b3c25ba8076d4025cf3a3a62da62d5e11d44422a142048e8cd00c7de6a0a55fd5dc09a3ed01dfe35b88268f351b6ff289fee8e52ac29fe32d9990e0d6d87f39727b6a762bac9d509c6ea235fc8bedc3bec2143eae9fd2cb831b798ef8261d72785002638b940947de0aad64f791f9a27e5b091e55adf4aee0649f6785bdd37e0248fedd1759d771aeacacb3ff6e7cf2d045f791428ab61710b54e869213393caf1b6bc99066678351deafc290cecc1f6b40b5532adbbab9a70408c61a437d4483b6a75cb61a55b20881efc0d849e0f60c1887f0fa091672179a145c4ab1b6487a0e939e0123d5aaffa3aec66ab593f9c25d27f22f4a73a999a4ab45e8bc7d71a85e2d40afadad1a1dc0b8389f96f91614293fa205583ef1c3440e3df50e8aa5f1a13e5929b72cd003461ff03d44d8c84bdada176b24459021d398b2b91b61a9c0b553a8714c703d32452c691a33f1581e98c2439514ca3e7deeef90850f8d6d89bf1d3a5762a56ef769ea588f5c1705bfb7b944cfbbb0632718ee3722f4e1929b35706d6413a315a11bc16349af109a7e675df2ab1eebe93", "excel123"},
	/* The following test vectors were created using StarOffice 7 (so-7-ga-bin-windows-en.exe) */
	// sample-1-openwall.sxd
	{"$sxc$*0*0*1024*16*93dc05fdf891ccb4d65148626cad37708b3c133d*8*d623654058a5d844*16*36975ec7f67f107817f64c8f29072166*417*418*9d958cae3d8f12d953e9618d00afd4a7eba06365566cba72fe5b721566dcd9f27ef1ec8e9bf2b3bbe5cc0d9368be799254acb5906c02e0ba1ad537c4c85ddbf6059fa67178b3941997c09531a35f5097929b5b2098571a80730119e2713da37ad7b9f8c9ef5b05d586ce1511483bf64540f2808ee442042b9bba1e0dcf4fff68f4831889869c9042a05a6d37f3ea0d15e50935776735ab52d930661d89f13310de0ff97075666b1a5ac38bc4f0304828c25b674d06c42e522c37f1a04f1febb38cd177b07c6a8c8921b05c30d1e00a3bee0d3c5b0c753bf8ac36757f4e84cdaa96abfb85141ac43baedada66bd3c5351e899526a71cbc3c34fc48b3fb2d8aa39da6108d8c6a1b2e1f5e12644abe0b66a561a4e8149224747c3ab6b5c04fb470d688321f2b06cfc10787b38baa03edf9c0660da486f2eb2dbbd9de574fb1726862bd15d803e997aa165de0b6bd2e72ca9a420f600419eb7412a98730d8d109b0828cacd3cdf58fc7c14cdb2a3a1e54f4df57e5aab99378479c9e0e442d38e7bb7115264f509a7dea2609eb300dbd66978f2a1e7c3d6dd3e5718bcc5ef7284ca2e7330", "openwall"},
	// sample-2-openwall.sxi
	{"$sxc$*0*0*1024*16*191da4e1f1a14597f530dc6f9c84d3981b8abeb5*8*ed8118de2daf083c*16*7e5a39f71e7628ffbc204cac871979da*866*868*74782a8afb13a2c91d661d48662acca5cd728fa0ecdd57a740acf38a6945a98f0247d67fa66e72a137422360d95b68078a8c6dd953c150d4d6b3831105a6dbc00ffc22ac0306ebd41981fa73dd136fcdaddd8eb31fda5f9056da985af33290220a67bff42377354f144172d6a98d2a4669c73abe9691569872b6358fc7dfbcdf0b55c99ad2de755925201affcb0140ca577e1c400a707b34e30f863d8b785602bb6173d3ade298ca60f08537e017326475e1761c3343c97658f647a6153f52477b2b4fde3eccb19b44c4e8e1c448a3474ea642a6ef76bd44ad039e44d93110eee128fb56048d7fa0f7b8ef028bd5d1cecf4b0713c6367234f21dd43be42639b01019e4d548ff1da6168839ff1bb521b610d67f9ecb1c2165a042fcfa17662c1c580b1300f31c1b5190ed156301a76764395d3ea2d0e0a5e23f958b172a7e68c095c1f144115a6d5b435991c696c0a029b33bc8ae16e993a272b01f183e7ab9c91bab945014568fa217aeba68e374ca9e81cbe5e75f3af6bf19e95f010ea1d4d4d2056d0b7a325cc8fd9107afdd89e66804a6ee7d8ba89f5256ee36b2e1704244d806a530c496e88b9be3150b4b0336b1de82b47cf2f65ea3ea731d8aabe62a42ccbad1bbeffac1f478c8f29fbdd74f10fa998d28d231dec4abf5c444036dc2d9480be710a76c2dffa136e6521c8c260f6c8f3b5a56147ec6ccb12f984bd754ba86ce067bfa798c4b206898c5a675bd4124d4a6534330bd1562589193ba16fece4cf51bc48aff0047554f8c10f7fa798e6c174eab62f1fee7270c00f230f10d2d8a601336044a8450e2ebba336aac9f2aca5a39dafa56f6d0bb43eaacfb7c39e82a872253570c013664ed1037aca28b7e88db6f7a3af2be4611d85f7bf4923e1b5b94da82d3d6ddc411c0cac410cc4815c139facee0e375ca17067919e3cc25da250a5d74d560b9a576951193a1ff716b99227a2c1acf289925dc98ca6624a23679b6cf451a072fbed73a3508be14f658e6abffc430ddf702b636aa5d990f8f8b9602d667a6cb017578d1731e8514eba93d9fa2c5e82a04df3851d951c43a2c591ab041a068db15bf54cae9cfd5bb7b6042d953100c24158f2e692988e96a5991dd3f08f3edc48cc56ab843fda262e0754b588befe7b532f1a120de5ba6af263dafb2aab06bcd7b9339e55379af06cd463e619ca3e94840bef040d8808f988cf3f1f33030", "openwall"},
	// sample-3-openwall.sxc
	{"$sxc$*0*0*1024*16*8c6e0964ce62cb0f6a7c829a68a62c5cda8ff16f*8*e70fb88992aa933b*16*58df832d56aea90b8229e8535b261ec5*664*664*f36e8b4dd0f4b076782ae4ded70f4f43f69bcc24ad6ba940369ee9adbc0b61582c5867dfe0bb33ae44b114e547e2b056018f9d25b8cc8e8e85cd3dba45da5b34ff476900736bc81586a5aa149b5c68e5a444ee4ad1b1225e56d8fe581c87a7049b03061740afb0bfb02c51ddc967331ee95f22f99277437a23b9b574663cff80be5f8ddb76a01d30bf4d5d053b5dcd68651fc07908c5e13e8bb4f7b8d138d87507ad67f9c83d07a0a6e7d341d273f68af71fefa8e6e0296430eb81a9f24d13bc001a04b579b3114b09f22bc9b713611b2e08d35cc2bfffd6501fc4a3c1044bcba60cd8fc608e237bd783b871543c42621d5b603ab0bb37749f6e8053e4b308d85d21204014cead4b8fc510e7b6b8d8a7887775acf30959313ba46a5912939b2fdfaa32bd21cc03e9661c0fc55dad31be375da57625e6b99b2342afafb7fae7eb7dfe1f1c1576138bbed6cab873820770ee92d797a7351994b0011332ce254bafd6f5c709769ac2480668befef49a21c74778bda91ff4fd1811fa62759112bcadab91d3580b9dea3d765f5bee14496214456f3251dae7e85fe869d2088c34d04cdf965804bf008da561ae8f3d6cbbfdf978a8ba003ccf72ef7978724414b1d6c2cbf45473786d416361177c029412115ede00eaa66f590635414294a2918e2dda7c497b6cc58165b639dac15a5e2cb63b5f324f1c07e29b70bee03e9c5782b5b344ba03e89ae5a6513f2591c58d93e1090476039c154c087b9fca00a402dd8cdeb2834f4988a152d91660acd3e4a22456b50d534ad16f2b99974b58403a7d6ffe683dd809ca98020a5cb6dea640f64e8924bccb1cdf08e8ebb1c3c4fa7adca3b4558c4f066cc5853e5b446998239244e5bbc8ef635442f5b9d0e25ec9177d670b8047a6795b6b075c263ecb540d01c1032ec2d27278fb5011", "openwall"},
	// sample-4-openwall123.sxw
	{"$sxc$*0*0*1024*16*107a051bef6079cb3b8312ef41883d9136558c51*8*9783fa7804330e7b*16*5b9920926b313df7f2f0849939e8df53*536*536*8b2a85c2faaf654986c8649597166986eb32b230bec96028a38f70535143c24f01bc88ff9a9c568e8b51ad0820a302bc6d77637686b8eaed09238eb24ea13aab13a7c4ebc53d9ee35546bc98706b8999263e30f97b0936ae7deb96333178107118bdb1e6ac26ecb623163853c42e1afc37614365bd8ff48882fe817c0ad675200f77791ccb7fa8961398f685befbc2d5e4a22ea3339aa8f434c99c3b6047b9c2852f7a1a70c2ed142ac5e7dd257f3c3adf22774ab6e741bb66818dfd33b0177e0d0e67efb74679d55e67a2649154a248e2490ee0acdffb3d391be184f1bebdb6e74b579400ab6c447e14ff4d79f8d20affe36722a77efb63a35c5feca920ebff2b39c26b9dfc3b3d7fdd670ffe6a3df19daed73c0327debfef25898391265264ca4133310898c1a166055c8b8fa150add0b5810cb5a62fdf8fdebb542f851d25b385eb75fc446ab5606dc5c723ce703844dabdde2f3727ca2feed6dfe9fe59a9993d1bf3c7c941e04e50d85207f1c72bd65eabf792f2eb7ca33e681dc5b92fe1825c1296f47e236bab503c9b40b182bc291275827d8801e343639089ac7627fea9ce4b8bf75eefeff8178f617143c0a044c074ba2971b1a24fd7e3f321ca3dd7180ee290b15bdc98944134ffd9b4784a3d1aa4d993ba00c5894cea41e18ac8d4d2f4bf8f15a2bc1f1e8c5c7692fa3ec43a93f56b1f2e601de57db1b622f11a58f5f3333514b659f16ab08f6b8c29680edb1be0774b9fd4f5", "openwall123"},
	{NULL}
};

int staroffice_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	res = atoi(p);
	if (res <= 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* key size */
		goto err;
	res = atoi(p);
	if (res != 16 && res != 32)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	if (hexlenl(p, &extra) != FULL_BINARY_SIZE * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv length */
		goto err;
	res = atoi(p);
	if (res <= 0 || res > 16)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	res = atoi(p);
	if (res <= 0 || res > 32)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* original length */
		goto err;
	res = atoi(p);
	if (res <= 0 || res > 1024)             /* 1024 because of "unsigned char output[1024];" in crypt_all */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length */
		goto err;
	res = atoi(p);
	if (res <= 0 || res > 1024)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* content */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if (strtokm(NULL, "*") != NULL)	        /* the end */
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *staroffice_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN; /* skip over "$sxc$*" */
	p = strtokm(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.key_size = atoi(p);
	strtokm(NULL, "*");
	/* skip checksum field */
	p = strtokm(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.original_length = atoi(p);
	p = strtokm(NULL, "*");
	cs.length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *staroffice_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[FULL_BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;

	ctcopy += FORMAT_TAG_LEN;
	strtokm(ctcopy, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);

	return out;
}

typedef struct
{
    uint32_t st[5];
    uint32_t cnt;
    unsigned char buf[64];
} SHA1_CTX_buggy;

#define rol(n, bits) (((n) << (bits)) | ((n) >> (32 - (bits))))
#define W2(i) (W[i&15] = rol(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+W[i]+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+W2(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+W2(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

static void SHA1Hash_buggy(uint32_t st[5], const unsigned char buf[64]) {
	uint32_t a, b, c, d, e, W[16];

#if ARCH_LITTLE_ENDIAN
	uint32_t *p32 = (uint32_t*)buf;
	for (a = 0; a < 16; ++a)
		W[a] = JOHNSWAP(p32[a]);
#else
	memcpy((char*)W, buf, 64);
#endif

	a = st[0];
	b = st[1];
	c = st[2];
	d = st[3];
	e = st[4];
	R0(a, b, c, d, e, 0);
	R0(e, a, b, c, d, 1);
	R0(d, e, a, b, c, 2);
	R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4);
	R0(a, b, c, d, e, 5);
	R0(e, a, b, c, d, 6);
	R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8);
	R0(b, c, d, e, a, 9);
	R0(a, b, c, d, e, 10);
	R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12);
	R0(c, d, e, a, b, 13);
	R0(b, c, d, e, a, 14);
	R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16);
	R1(d, e, a, b, c, 17);
	R1(c, d, e, a, b, 18);
	R1(b, c, d, e, a, 19);
	R2(a, b, c, d, e, 20);
	R2(e, a, b, c, d, 21);
	R2(d, e, a, b, c, 22);
	R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24);
	R2(a, b, c, d, e, 25);
	R2(e, a, b, c, d, 26);
	R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28);
	R2(b, c, d, e, a, 29);
	R2(a, b, c, d, e, 30);
	R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32);
	R2(c, d, e, a, b, 33);
	R2(b, c, d, e, a, 34);
	R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36);
	R2(d, e, a, b, c, 37);
	R2(c, d, e, a, b, 38);
	R2(b, c, d, e, a, 39);
	R3(a, b, c, d, e, 40);
	R3(e, a, b, c, d, 41);
	R3(d, e, a, b, c, 42);
	R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44);
	R3(a, b, c, d, e, 45);
	R3(e, a, b, c, d, 46);
	R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48);
	R3(b, c, d, e, a, 49);
	R3(a, b, c, d, e, 50);
	R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52);
	R3(c, d, e, a, b, 53);
	R3(b, c, d, e, a, 54);
	R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56);
	R3(d, e, a, b, c, 57);
	R3(c, d, e, a, b, 58);
	R3(b, c, d, e, a, 59);
	R4(a, b, c, d, e, 60);
	R4(e, a, b, c, d, 61);
	R4(d, e, a, b, c, 62);
	R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64);
	R4(a, b, c, d, e, 65);
	R4(e, a, b, c, d, 66);
	R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68);
	R4(b, c, d, e, a, 69);
	R4(a, b, c, d, e, 70);
	R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72);
	R4(c, d, e, a, b, 73);
	R4(b, c, d, e, a, 74);
	R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76);
	R4(d, e, a, b, c, 77);
	R4(c, d, e, a, b, 78);
	R4(b, c, d, e, a, 79);
	st[0] += a;
	st[1] += b;
	st[2] += c;
	st[3] += d;
	st[4] += e;
}

static void SHA1Init_buggy(SHA1_CTX_buggy *ctx) {
	ctx->st[0] = 0x67452301;
	ctx->st[1] = 0xEFCDAB89;
	ctx->st[2] = 0x98BADCFE;
	ctx->st[3] = 0x10325476;
	ctx->st[4] = 0xC3D2E1F0;
	ctx->cnt = 0;
}

static void SHA1Update_buggy(SHA1_CTX_buggy *ctx, const unsigned char *data, uint32_t len)
{
	uint32_t i;
	uint32_t j;

	j = (ctx->cnt&63);
	ctx->cnt += len;
	if ((j + len) > 63)
	{
		memcpy(&ctx->buf[j], data, (i = 64 - j));
		SHA1Hash_buggy(ctx->st, ctx->buf);
		for (; i + 63 < len; i += 64)
		{
			SHA1Hash_buggy(ctx->st, &data[i]);
		}
		j = 0;
	}
	else
		i = 0;
	memcpy(&ctx->buf[j], &data[i], len - i);
}

void SHA1Final_buggy(unsigned char digest[20], SHA1_CTX_buggy *ctx)
{
	unsigned i;
	int LibreOffice_bug = 0;
	const unsigned char *pad = (unsigned char*)"\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	uint32_t bits = ctx->cnt<<3;

	if ((ctx->cnt & 63) >= 52 && (ctx->cnt & 63) <= 55) {
		LibreOffice_bug = 1;
	}

	i = ctx->cnt&63;
	if (i < 56) {
		SHA1Update_buggy(ctx, pad, 60-i);
	} else {
		SHA1Update_buggy(ctx, pad, 64-i);
		SHA1Update_buggy(ctx, &pad[4], 60);
	}
	if (LibreOffice_bug)
		SHA1Update_buggy(ctx, &pad[4], 64);

#if ARCH_LITTLE_ENDIAN
	bits = JOHNSWAP(bits);
#endif
	SHA1Update_buggy(ctx, (unsigned char*)&bits, 4);
	for (i = 0; i < 20; i++)
	{
		digest[i] = (unsigned char)
			((ctx->st[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}

// mimic bug in Star/Libre office SHA1. Needed for any string of length 52 to 55 mod(64)
void SHA1_Libre_Buggy(unsigned char *data, int len, uint32_t results[5]) {
	SHA1_CTX_buggy ctx;
	SHA1Init_buggy(&ctx);
	SHA1Update_buggy(&ctx, data, len);
	SHA1Final_buggy((unsigned char*)results, &ctx);
}
