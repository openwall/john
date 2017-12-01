/*
 * Common code for the PEM format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include <openssl/des.h>

#include "arch.h"
#include "pem_common.h"
#include "jumbo.h"
#include "asn1.h"
#include "memdbg.h"

// $PEM$type$cipher$$salt$iterations$iv$blob_length$blob  // type, and cipher should be enough for all possible combinations
struct fmt_tests pem_tests[] = {
	/* https://github.com/bwall/pemcracker/blob/master/test.pem */
	{FORMAT_TAG "1$1$0c71e1c801194282$2048$87120f8c098437d0$640$c4bc6bc5447bed58e6f945cd1fde56d52aa794bd64b3c509fead910b1e7c1be9b6a89666c572c8ba5e469c5732ff105ecb97875efc2490ea9659082bdf0f3a2fd263ceb86bde4807bb85b01ca25efe25655fcdb9d54db94f7f48bb9b04af2bad5c2aaed87dc289da8b3fb891a9797f73adacb05b21717fe11d4ebdf8f1d39ecfcb8791447263572f487b087484c02e40a13a89c0613ebc4958a0853781eb1382c1f9ac1f1f97dd06e1a26d98088c5f262680a33dbf2e7742a436847cead5af15c538a5eb21b99e0c4ca30d08f5e805678bdbae6a3ee53623b7cebaeac6c7dd54834f6806112909d2d74da35ea907d35cfbd9cfcca4c302e9dc19b3017957747b4525e7832067d462f15451ca47be771add080da835dc177c26df3dd3fbf4b44d0ac7aea30a44469fe542abaf9bb2787b5694c7fdc1b9765167bf9ea5bf695e927bb98217491d7f1843a1e39e2a1a6a178b03e391031a80943f08b6dd7fa5104e38c4a4bad773775a71f5d076641a52a1100e701c14e5a15ac3dbaefad5f2ceb3ccded6689aef2bc9060c36599580f34324ecfa8cf2628da6475934bb53a8f7ef4a07fc1d0a4d41bfc9bac91859ce98f3f8876bbfba01bbe4491fa2d511b2f6eb5ae7ad4213a24c21fef676c8713de9c674d7a88d8844765732dbab43ee9faa5245ddb6fd6d66ab301b82dca829aeacaa5f178cd12aa0565c8a2d6c00b8c7f611ceedeee8ea68d99582fe9ba701c46d1ea78c88bb942ee3e30e83d9843cbda720bd2dcc07f2b4497e781cd54156e5e1022c4fb5827ab4e0469bb40500a6978eed0f27e0258e7304b0745e90eb36bb8d8e1c15c458313c547c3bfe54d75ac26405c40cfa0fecbf2a95e312870c08b13e6b36494c09c8a8ef12057e090a24e05fd3", "komodia"},
	// openssl pkcs8 -in test-rsa.pem -topk8 -v2 des3 -iter 2049 -out new.pem
	{"$PEM$1$1$671f19f01d9d0275$2049$50524fb9fd8b147d$1224$cae9d4d53583f50d4c468eca9061458ff1316732d6f28a70f0a1740021f594c8738ca58bfa0e4eb97a826776c3dce6ab89dd71ad30bf7630ec2f1fb18d895954f42a61ce2529e26b7d868267c44b21c03fac11387ce1d5e5b88a75f2038737820ccc768c72e0cdd3d78ba912fa6255eb4e3738cdae60109be2450d053aa91fb62a312263f484eae6f1fb757cf7d92e63f066498e4ed809e5318143f48afde4398a695bbe6804148b319c4f54633f91a08fdcc373a4a66b6f14a2b659e149a25053ff5bc0035b58aa462c8558ab3aefdc2770bad36b5fde810d6fbf07c29ea8e3a72fbfaa1b977663f8b61129b50658866d4a39bb4e9da24b4ef226170a3d9ded7f99a4e6265ca65ba94078da5f2ade1567bc93812205e8ff085cb07479af22e261d1255e29b02aca3278ac29232a49d2656b217f4822d72c7dcd24d2fde44aab525f2bcf970627597b26cc540c9cf8112002fdb35c2fbf97d7532648fa2c3b0508d974b35713a1ff81ff44f8414867e4d8f6b4027ecfd47fd4992b3a3e6e29b43c6ae76c2d503bb5bb260655960b659e55af66254bbfb248a247df3294518fab8295640c4f317ab25adf345f8693dd89514472938da1801d405c3b75419d39d6fe9a554d798da2b26566eef4f7e360dfb2802f68f33d6d4fb756d2e2140f5fef476048fdd923371d6dd494b3aed07fd7733d03783921296ec39ab392ff13bfed5e2c52c1642d999c57635230a4fb7673c5a003bd6b407179a49b2967dd39b1668c35ed75f4517c08d8ee21186a15076fe289733eb4a9a6b90bc61c4ace009ffa40e7319e54006214297f2f219b9fc3c6931fac9568d2d5e457954a6a4999959cbee476e6142b5cc6a373fe7504fe41ac09b5d4f6af9e02357076556f787dc47c6ab9783fea53d1c87c65718a554c5fff242c15118c90f6f6a61e8a0427b98f5244b0f43138493393834f8991da9411b53e394615ebb3303018a905b41baa4be084b0c9008d257018add9278a676d53d812b6c494ebaff36509c9e82626a1c81ecba85ccd569fbebd7d6d546b45439315dc2a37fdffcb356e79122211ad295a2819b9ac30aa7344bc26b2bd618c15d6bd52c90741ef8c3baba7e54daee004c3ecadcda4fc2e63c769a98a540e12b1c37bb47935a5bbd82762e3be995244a766755c3007477b22392998694de7be8f695048870d78d4e57cc222cfae9251bc21ad4f6b3303473b0da554464862a24da4334701389730eae91b70c5ecdad201e7174ef7ec09928a84f4f64d5b8e7398bad1d25a4a9b17e0f58da58377ec796273f5bc48cdda81e9cf02434ee06f10f8330b54e0f102fd79105c2a4d85e4c5d275fe47107bd76d66b88b59489d7ca36c2e8a104426c6f34c48425ea33d610655178b13af409ff807cc196e48d4036e3d01e485ee0420f6ffbadfb142fd08459b0ff1c1c2d424aaa553bb73a90c19fa454b6f4ee9732f13d666b8fb8a86fe08b394ce94a0d68d091dfd124e386d19882782afaa9b97ce626123962e784c41398499ec1b8848be2b2c62597dfaf91d7e4cfef0a5b8bd4d9afa5824c3bb595029deb8b67c55d9eb976215a10e1846b1b82f0e1ad6968fbe2b98b3f50e0ec641dcbee8ed4c078ba09b2fea93800172fc0ae64f9ad510d59925f50a214168b431f1e88a26e77c4d507503f483bb1955b4cbc4571111dbbf1c78a1e4915ffba4be4fafcb22410032d86df1aa7e", "password"},
	// openssl pkcs8 -in test-rsa.pem -topk8 -v2 des3 -iter 2047 -out new.pem
	{"$PEM$1$1$029375ebb44d8c3f$2047$3c7dbbee4df5863e$1224$b97ff356c7687abcd4ea17527b45eaf84d69ac127ddc4b05383331a56e9a0c26661735f9fc5298fcef7fe4280ccafed909ef8494e8dcdc75ebf23daeb3eb28ce5e1e6181c050e6c9416b41176eb87a12ec6898b90a75b0deece18eb7d4c13372eedf1060ceac9230d77843a21dbfa24edd1e41d6aada961f205295198bec11e2d87ae5d2d07daf1b5f5a21455d68003ba40291c20b91114d9339b69a4564c749b64668b209f8a7cef029c8d7f6369c17ddc6bee527576c3da794aeb6125ce9f7d41fc8d5690fc2447a594721390d7803bc600e2c67801636072047f51ca1a9fff2d629e987aa18aa4b08d0f7dce547132d8073718ab2b1fb9ce7ce46551e82749f72ef228b6e8e4420395efb3e90ebe9cc15719f3a0afd71f387a2d432783804efdccf2b554fa4d60c1a5ff385ed784f1cb4b8fe013a08c08e1f9457897457f7e342a5071e471ad261708fd0cb9c75040a85ed27ac1079379557c4dcb74384701f6e30514e80788a543adb036135d94cbdf1feef5c0d287cc081fe75eddb29e37b462c4077bf07da74bb16ee96df3d7f1bcf616198e11d4c489eb33712b29e26c0d32df878074d7e145684cfec9d4f26e53d1cb10d45b13b55195ae9f6afa5c93b67e423558aa73cc4c6d83bb6ff80559076201b352e60f3bc0f018f79e6282fa6ce322f51703860f2da59606d8ab3433ced6359f3dee0d5b046929f1068903460cb84c5c2b2e2c478cc8547d88227aec9b2cf099d3a897778410a0e43138dc30f30768d3e90b675265f725e6b9cd7ca4a7db912c3e67ab2d680e8bf7e3f1ef9b9815b15873ee6a739972117dc4736cfe256be12b70ca1661cb9d32d69a396de5a0ceb81de37c1c395146f479b6e2b24017ee487b68e0b77bb4890533a50275caa68ffdc54cff2652fe94956d0b2c0463104a1b8e04f01f0c125e1125ce598a75d61152eabf97a58e6e789f60e240958b7e75ac208e48465150f389b9a5ff7ae5636cc29e72a573e8faf0ee80bd1a2a2e846a897019d75cad79b16a59be3da46a823baf9a04104d2d009e2780d21c3439c7e791f3ec63a296fbf4dc15e955e00e1be652cc70e930a08db2797694aeec3c20722b65e0cbaa8e3b753b3a51f3b16f32fbe55876f48615937e4ce9da7d985c8772923fce3cd6c463b422ce61fdfff8ba28df7a3cdc7253ad4ce0a35218962a45edc5dd3e24a2248e407d6106dab81cea41b453ac509c4f0ec03d220ff84c842755f4f8673c0975cac13f84f7176cc9c4cd27eb74b42065ea9a4853ef0d2940596f112f3c766db0b6c7e5d5d91bb0aad5e44e34abbc871dbfdb7824e014fa7d2ae62bd253f422482538c4c35dcb7f4a20c915b698262737df04bf7e6806d5bbfff7c54d6ba4c5892dcd122bc0fe80c7399228029cc4c29f388d9787c46d609abb2554a010984db73e8605272a1bd7570aca1ccc04edee3d704b7387bd9866423a015a88e4efced478c00210e213c3d2b2bebdf1584d9a8fb2a31397a12a2d07ecf6247c70d2950f0db3f64aad13647e7db47ca51d7c95f50fc016d9731c992f2463f794ea915b7b5307db6de25fbd3ba7a7b4b15f7a011ab399a2b8c73cd5a7a1b00743928499effb5ab1a402e8600c52f8d1204d8923c2d8e41cdd941d591b554f79dfee3c3eb33a427ab360f90a8820c2957e2b5afd06ea3f02df3563eec9a06f64a6e019e33ed0a112d53382d071cbf835907094158", "alonglongpassword"},
	{"$PEM$1$1$74ae53fd1cf3e5e8$2048$33c1919f1cd1e8b8$336$6e59f6d3fbb084e224da89d23bfe0aec18f1491f58e334119ad83edd10d81b636622736e8a712a34959d78da79af603ec33d1a57bfaef2081e0ff8eccab31a0ad9cc18a60c20c1a2e15790c89972c5abb642a76ddeadf6fe8423c1b1737286a177b931352c5c78d105f828e9dc30fba659147f920aeaabb006988a020845faa985b948de42cc46b23406fffd2f05756c9e13e2fbc049c4be4736f9ec770c8da288a908e8abbbe1fe5c75cc65b7721d4eb338e67fe1bba937830cb9e857f3236a2894059bead0266e6ff78c7a52cab687b5e256bf1393674cdd857062d860434c530647d21edaa7f79b0e134de5cd536117ee5cbc49065c6142b30c1d3e5b0de8c55dd2748ba8bb5915498d5ed3c4abaedba13f4b10a8ff10d3383bce98dd3d52a6393ff1e791d9410bc90b34e115ed7ce10cdc75e6df29c31714983af39f1513395ef89cf2d57f68fc134996ef1afa0b", "dsa"},
	{"$PEM$1$1$cbb6cdcfc1b27cc8$2048$9b9e633ba83d48c2$144$54f2ab743656618ae51062fd6f2ff07a5078dcf3a1fa52075f50f4508e0c342b1f3e29703f4932c689e29f385f7ad73bf96ec7bb536ea8dafd40b9e5aee6f3e27dc21ee538d9e146a9361fc34ae5dd818b23c106688a451a5e180362954698a35111cef9315ffcd6cb4d440a6899177ff0384a9533923c05f97a5bbd3f94415688ca5c3af97f9edab771dc84807a6bcc", "ecdsa"},
	{NULL}
};

int pem_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // cipher
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != 16 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	if (hexlenl(p, &extra) != 16 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // ciphertext length
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	if (hexlenl(p, &extra) != len*2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *pem_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // type
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");   // salt

	for (i = 0; i < SALTLEN; i++)
		cur_salt->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cur_salt->iterations = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < IVLEN; i++)
		cur_salt->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cur_salt->ciphertext_length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cur_salt->ciphertext_length; i++)
		cur_salt->ciphertext[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)cur_salt;
}

/* The decrypted data should have a structure which is similar to,
 *
 * SEQUENCE(3 elem)
 *    INTEGER0
 *    SEQUENCE(2 elem)
 *      OBJECT IDENTIFIER1.2.840.113549.1.1.1
 *      NULL
 *    OCTET STRING(1 elem)
 *      SEQUENCE(9 elem)
 *      INTEGER0
 *      INTEGER(1024 bit) 163583298361518096026606050608205849417059808304583036000248988384009…
 *      INTEGER65537
 *      INTEGER(1024 bit) 117735944587247616941254265546766890629007951201899342739151083099399…
 *      INTEGER(512 bit) 1326824977515584662273167545044211564211924552512566340747744113458170…
 *      INTEGER(512 bit) 1232892816562888937701591901363879998543675433056414341240275826895052…
 *      INTEGER(512 bit) 1232481257247299197174170630936058522583110776863565636597653514732029…
 *      INTEGER(511 bit) 6306589984658176106246573218383922527912198486012975018041565347945398…
 *      INTEGER(512 bit) 1228874097888952320
 */
int pem_decrypt(unsigned char *key, unsigned char *iv, unsigned char *data, struct custom_salt *cur_salt)
{
	unsigned char out[CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;
	int length = cur_salt->ciphertext_length;

	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, cur_salt->ciphertext_length, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

	// padding byte can be 4 / 6 or so on!
	if (check_pkcs_pad(out, cur_salt->ciphertext_length, 8) < 0)
		return -1;

	/* check message structure, http://lapo.it/asn1js/ is the best tool for learning this stuff */

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	if (*(pos + 2) != 0) // *(pos + 1) == header length
		goto bad;
	if (hdr.length != 1)
		goto bad;
	pos = hdr.payload + hdr.length;
	if (hdr.payload[0] != 0)
		goto bad;

	// SEQUENCE
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload; /* go inside this sequence */

	// OBJECT IDENTIFIER (with value 1.2.840.113549.1.1.1, 1.2.840.10040.4.1 for DSA)
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OID) {
		goto bad;
	}
	if ((memcmp(hdr.payload, "\x2a\x86\x48\x86", 4) != 0) && (memcmp(hdr.payload, "\x2a\x86\x48\xce", 4) != 0))
		goto bad;

	return 0;
bad:
	return -1;
}
