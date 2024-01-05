/*
 * Common code for the blockchain format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "aes.h"
#include "blockchain_common.h"

struct fmt_tests blockchain_tests[] = {
	/* here is a v2 hash.  NOTE, it uses 5000 pbkdf2 for the hash */
	{"$blockchain$v2$5000$544$9a4d5157d4969636b2fe0738f77a376feda2fb979738c5cf0e712f5d4a2f001608824a865d25041bc85e0ad35985999fcfae7d218eb109a703781f57e7b5a03c29ffdfb756ec8ee38ed8941b056922cdd174c8e89feb40e1a0e1766792845f57992ae9d7667eff41a5e5580f3f289b050d76cc0f049cbd30c675efc3a553c0f19f30cb9589c7c3773dd095de92a991963789408351f543c1dc307751e5f781c278da77270035e3743df01ab4e41155b6437d9c7e64388a28f8331aca4822e6b89cdd5f45061b99768218d853a3575bbd029564826bcb188d55444273cda588d4e593fc5d29696713d747cfc8302a3e9c9dbb1bb3754c2e00f28b69d8faeb2e45c04085359c6a9b6bfecfd0a6a8f27ad647b6bfd498f2224a8c0442f7fe730656263ac2869923b296ad9955dbad515b4f88ad33619bdacc33ae7f14c65fce029e0f9e4a9c414716d9a23e4361aa264493bb6fc9a7fda82599b0232174b9fc92a1c717ca2cc6deb8bd6aaf3706b95fdfdc582316cb3d271178dafe3a6704a918e07be057bef676bb144840c7f26676f183f2744fc2fe22c9c3feb7461b4383981c00b6fff403fef578f6e5464dc2d0bcb7b8d0dc2e7add502b34c8fe9f9b638eebe7ede25e351b17ea8b8c1f5213b69780c0ba7ef3d5734c0635e9d2ee49524914f047d45536180be25e7610db809db694ceeb16a3bfd8abd5ab0cda4415203408387698fe707568566f7f567164707091a806ac2d11b9b9dd0c3c991ff037f457", "Openwall1234#"},
	/* this is the 'raw' hash to the line above.  We do not handle this yet, but probably should.  It is also mime, and not base-16 */
	//{"{\"pbkdf2_iterations\":5000,\"version\":2,\"payload\":\"mk1RV9SWljay/gc493o3b+2i+5eXOMXPDnEvXUovABYIgkqGXSUEG8heCtNZhZmfz659IY6xCacDeB9X57WgPCn/37dW7I7jjtiUGwVpIs3RdMjon+tA4aDhdmeShF9XmSrp12Z+/0Gl5VgPPyibBQ12zA8EnL0wxnXvw6VTwPGfMMuVicfDdz3Qld6SqZGWN4lAg1H1Q8HcMHdR5feBwnjadycANeN0PfAatOQRVbZDfZx+ZDiKKPgzGspIIua4nN1fRQYbmXaCGNhTo1dbvQKVZIJryxiNVURCc82liNTlk/xdKWlnE9dHz8gwKj6cnbsbs3VMLgDyi2nY+usuRcBAhTWcaptr/s/QpqjyetZHtr/UmPIiSowEQvf+cwZWJjrChpkjspatmVXbrVFbT4itM2Gb2swzrn8Uxl/OAp4PnkqcQUcW2aI+Q2GqJkSTu2/Jp/2oJZmwIyF0ufySoccXyizG3ri9aq83Brlf39xYIxbLPScReNr+OmcEqRjge+BXvvZ2uxRIQMfyZnbxg/J0T8L+IsnD/rdGG0ODmBwAtv/0A/71ePblRk3C0Ly3uNDcLnrdUCs0yP6fm2OO6+ft4l41Gxfqi4wfUhO2l4DAun7z1XNMBjXp0u5JUkkU8EfUVTYYC+JedhDbgJ22lM7rFqO/2KvVqwzaRBUgNAg4dpj+cHVoVm9/VnFkcHCRqAasLRG5ud0MPJkf8Df0Vw==\"}", "Openwall1234#"},
	{"$blockchain$v2$5000$544$a48c0a5f37986945940bd374f2e473a8f7c04719c04f7e3843f9f58caef832a738f6e3eb48f78ee059495790b0db93d8e2a1bbe9b81cdf6ac278599a30be0a12fcfa341fc29705948b2d885b2e93627ab53f5b67c4294bf2ae59571c04fbedc5a0e65547d356fef8b8090ad8e5744d63224f160b00f898e2583b2abe818454d15878afc11d0aee31f12e0553a84dff23e8e1438a212ae9c51d2c203d6c3e4746cddc94182f83fb8b2f7de79d3493d991f3d8718a58b6af7c2d33d8ef77b76e20bb859b13fad787ea7ad9a057e3ac9697b051c6749e3d3dc9a7699e13b08c7254ad687cf09f005800ab190e13c7cf9b881582b52e6c154e562fe73a723b0b1c0b80be352873c1ab8456a4a0d57bb5185f5c4cb1e150359578344ea8321cc5a0a94807fe06a89742226b2c74e8b6f1653ea84bf79e525fc92ebb7aa9106774e1b9dc794f5280ab2a5df818aeae0e467aeac0083aaea0b1f9d4c754324938caa4e8594aa69f988a0c424ae1fe5e1b91c82bccf6f995ec28d3e300b2eb62daa6ba72b4df46a788d724ec0f1f102d262b6c129ee9cd0d5674d3bc71350091b23a6219ff900653cdb52143b549829330abd15eb1f2d8e742565ed5ede6285908b040b75ca0b1871bbfb8e3a8115afef2ff8c46f180765387fb55e896a9c3a3073f57509a4102dec52d77dbb88f97cf6d83f0834b1dc7c0343a1a6b2144f2d264a3f0c4d9eb014c07fde9f1c1b6cc02fdb2e87583277194332d90b3b491d1a441ed57ce", "johntheripper!"},
	/* v1 hashes, moved down the list because of their different length (400 vs. 384) */
	{"$blockchain$400$53741f25a90ef521c90bb2fd73673e64089ff2cca6ba3cbf6f34e0f80f960b2f60b9ac48df009dc30c288dcf1ade5f16c70a3536403fc11a68f242ba5ad3fcceae3ca5ecd23905997474260aa1357fc322b1434ffa026ba6ad33707c9ad5260e7230b87d8888a45ddc27513adb30af8755ec0737963ae6bb281318c48f224e9c748f6697f75f63f718bebb3401d6d5f02cf62b1701c205762c2f43119b68771ed10ddab79b5f74f56d611f61f77b8b65b5b5669756017429633118b8e5b8b638667e44154de4cc76468c4200eeebda2711a65333a7e3c423c8241e219cdca5ac47c0d4479444241fa27da20dba1a1d81e778a037d40d33ddea7c39e6d02461d97185f66a73deedff39bc53af0e9b04a3d7bf43648303c9f652d99630cd0789819376d68443c85f0eeb7af7c83eecddf25ea912f7721e3fb73ccaedf860f0f033ffc990ed73db441220d0cbe6e029676fef264dc2dc497f39bedf4041ba355d086134744d5a36e09515d230cd499eb20e0c574fb1bd9d994ce26f53f21d06dd58db4f8e0efbcaee7038df793bbb3daa96", "strongpassword"},
	{"$blockchain$384$ece598c58b22a3b245a02039ce36bdf589a86b6344e802b4a3ac9b727cc0b6977e9509bc1ac4d1b7b9cbf9089ecdc89706f0a469325f7ee218b2212b6cd3e32677be20eee91e267fe13ebded02946d4ae1163ef22b3dca327d7390091247ac770288a0c7be181b21a48a8f945d9913cdfdc4cfd739ee3a41ced11cacde22e3233250e36f8b8fb4d81de5298a84374af75b88afda3438eed232e52aa0eb29e0d475456c86ae9d1aaadca14bc25f273c93fd4d7fd8316ed5306733bca77e8214277edd3155342abe0710985dc20b4f80e6620e386aa7658f92df25c7c932f0eb1beca25253662bd558647a3ba741f89450bfdba59a0c016477450fbcecd62226626e06ed2e3f5a4180e32d534c7769bcd1160aad840cfd3b7b13a90d34fedb3408fe74379a9e8a840fe3bfee8e0ee01f77ee389613fa750c3d2771b83eeb4e16598f76c15c311c325bd5d54543571aa20934060e332f451e58d67ad0f4635c0c021fa76821a68d64f1a5fb6fd70365eef4442cedcc91eb8696d52d078807edd89d", "qwertyuiop1"},
	// v3 hash, generated using blockchain2john.py along with download-blockchain-wallet.py from btcrecover project
	{"$blockchain$v2$5000$1424$627b8b1e85bfb0d3afec77d5493209024b0033c6a6cb33c4bcc5c0095fae5fb722a4e7059708e52e36b019f526057cc3494be1897837cd213864c6470298ad62e71b458e252a48581da3b0e145c723bdbe3e06e09c2ac297eef53d4476b785f5cb71ae0845893c6e6d353d1caf935afaf7e2c7212d9ccfb62c2cc7e9e2f763ef3ea8ac8aa32897e6cf3369ec197763f88561d7ab9adbf07be5b5a242f4a214b2a26ac7f9ef167e2319318b7386abc8a994d339166ac19645ece24a0045e235eed2d31326ca2d5259e61b5c7fe25b19ab0f7bc9263963a05696c964a5878dbe449c2b5140f72d753f0a8fdaad9758b5c9ea85785989504848c3a2637295fbc2506806d5b0dc2e4f593c173ec7272d5ea5462dc04c125b67be0d3bf5f82daa88772e2ca2471606f012e1664d178d031424cebdf5d586b0e5062cd91f3359108c3beb6b7b1c7fd203099e3f2cbd1cedcac629efcc0b716b7ee34eb3bd857d1964f2e5640d3b0599527b513b57a2d0704750d38c7120244ca80036ee4ed70357580f65c370474e7e4603a80a2e094b37267efc8d2b6229e2ddc2ad98a1f4ad41c5a6a38b75d117f6add26c686078af930cbe26234f02920c3fe6027ed0a9456fc4718d3222d24b108cc0eaa3798ea6acca84afee79550b1e5952ef388fd6a60188ead282720f0f3cabd165190837417dc5298ff9736f030148e57c17a7a698a4a4d2543654072f02f1d631bc76f59bef25181927272cb58931a126273c3818126de5b95247c5bfde807c79f29286cc5134b76e23dbbeee9a5928ed5497f423936b1f202f177d639f372d1cc9d2ae959044b5f9c4d9e63137c2b45b1349eb642d7d5e33389a727ad776f9e40778b19e6d562e41c5a81f8d1abe4e4893c388cdacf5cbd8a5e347b0c584cd1cec010593441a4dccbfcb0614e159a65120d15beb85f1318d809f5e1c63d5c5607da44b03b39acb356e8038eb13f0eba3dc39e824200925856a8f4aaccb0dac8a7e1519001f239dcf6db3d76b62761deb5a1014c0be617dc35ff02e15e9881758f5d556ab8f5ec54ea06693ae53294033582925cc401002acd3a8a6176e0574dfe05ff0a4045ad348924bbd4933005357b624f69b8a6183f2f2dd4d73ff6bb984909b696793bab507406e38178bb4ad8d9b98d4987e41fd168780d753da284deec1859de9a70ced8ea2cda37c302c27c83ee0a5325616b522110876c0119c7f184c311a3f893316a943d917bf8e7db882aa9ebaaaaecfa35fdb2e85145b187b34a445247a5c20ec7c4ff52eeeaca8da2a12b8075626cec76057fa7613a2107e0f2c0c5b5a69d86a0d442d40b24da908118b655fed1aef2390f534d9a0c5ab9388cf50f9ff87e0e81c1739cbd4e65bb712d924fde2fc5382b47a6c004cb63174efa4563fdb13f3c74c02933233cbc909ee0e8e456ca2b322c12a8a5c764a6f84c451623a44778c678e492cd15b38fc0b02e11ad7cbd64a87a21aa7b450f525cbd9d86c5880e64f080c0a5abfd17c23f687c6efa3fbea1eb00af8e0d118445f3ef75860023306f2dd1a262a4a9469c5cc6f51d30ca62cfeb5c25009dd49d7fbbb05f27a318f4fa078c275cefbbfebdbb670499e3549ee4e9a295f4dd808e60c8d8043caee8571599b47f104827e4e40026f9a819f9f3eba1f18b4c67592a0c2b4bf3c50f28b3ca5a931d75c8d0eb7b0a80a5e17f7a05d2ade6f4dca649a4d5f39bf24a17f83a17cb4dd5eb01edd7fe24b3dcdaf70636fbf87082f0711bba74748a5089d6e447dcafbc46fe1956c03082b3abcf76144a591182169f2a2c07aba497d656f5e383ffc7a67c60d4c04899644c76e44437d2b8288f7933c5cb8f12c2234f13f65d73305f0de20744c620498203d6968bb08dc531404348a4dd68b98546492c57cef0839ad4a9d8cc6e9c6e02e2fa2b3fbf61af70dcccdc1a02ce9f903926f2febea2836d8d682a05b413798ad78c65e2f5b91038c932256e467906d93ead157216dd21e16", "openwall123"},
	// Android-Wallet-2-App, generated using blockchain2john.py --base64
	{"$blockchain$352$6a3677566f2151892605506a740425da22114857bb93cac2504bedadc55638f69aa7da274b22d41b78f8c402dbb9259dac8d27b22d2106e942da8b5a3ba226f40b61d7bd3ccf60bb5805ef8ea86d9ab7519b98a7f9c6e78b78218314ffb681b65771ddd9df902eb81411a3cdc5ce2ffcbc0c97f51d5d68b69417456399343c7d56a4e7408f9c9adc70ef36efd3b5efbba614ec9a2c42c3500c34c3863105092339c9e7c77b3c38d5f152c81f90b1fca55cdbbe6508dd203394d7e975973aa345bf7e972c630922b90355ee3e31a2a195f025ad8cfd181bcfa380095107676d5d0a11aed50765f88c452a93bda9a3c1c4e7216b2b05742c299c51f9cc02ce8b7b8abfec1d83eb05aa861d63000c468fc90060b88c6c73bfc42b54456c94c3d7e721f9c1e0b75ce2dc46d6e7762bade21c9701b54acdda9c04d3bade33ac893b824419561e12822061412c35c1018cba946881ce0bc2231fbeb78ea9f9dc23fda0", "testblockchain"},
	{NULL}
};

int blockchain_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (!strcmp(p, "v2")) {
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
	}
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > BIG_ENOUGH || !len)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (hexlenl(p, &extra) != len * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *blockchain_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	static union {
		struct custom_salt _cs;
		uint32_t dummy;
	} un;
	struct custom_salt *cs = &(un._cs);

	memset(&un, 0, sizeof(un));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	if (!strcmp(p, "v2")) {
		p = strtokm(NULL, "$");
		cs->iter = atoi(p);
		p = strtokm(NULL, "$");
	} else
		cs->iter = 10;
	cs->length = MIN(SAFETY_FACTOR, atoi(p));
	p = strtokm(NULL, "$");
	for (i = 0; i < cs->length; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}

int blockchain_decrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[SAFETY_FACTOR];
	AES_KEY akey;
	unsigned char iv[16];
	memcpy(iv, data, 16);

	AES_set_decrypt_key(derived_key, 256, &akey);
	AES_cbc_encrypt(data + 16, out, 16, &akey, iv, AES_DECRYPT);
	/* various tests */
	if (out[0] != '{') // fast test
		return -1;

	// check for android format. See https://github.com/gurnec/btcrecover/issues/203
	if (memmem(out, 16, "\"address_book", 13)) {
		return 0;
	}

	// v4, see https://github.com/openwall/john/issues/5078
	if (memmem(out, 16, "\"tx_notes\"", 10)) {
		return 0;
	}

	// "guid" will be found in the first block
	if (memmem(out, 16, "\"guid\"", 6)) {
		AES_cbc_encrypt(data + 32, out + 16, SAFETY_FACTOR - 32, &akey, iv,
		                AES_DECRYPT);
		if (memmem(out, SAFETY_FACTOR - 16, "\"sharedKey\"", 11))
			// Do not check for "options" string. It is too further
			// down in the byte stream for v3 wallets.  Note, we
			// 'could' check that the guid and sharedKey values are
			// 'valid' GUID's, but there really is no point. We already have
			// 2^144 confidence in the simple text strings being found.
			return 0;
	}
	return -1;
}
