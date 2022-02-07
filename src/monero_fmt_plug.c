/*
 * Format for cracking Monero wallet hashes.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if !AC_BUILT
#if __GNUC__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ARCH_LITTLE_ENDIAN 1
#endif
#endif
#include "arch.h"
#if ARCH_LITTLE_ENDIAN
#if FMT_EXTERNS_H
extern struct fmt_main fmt_monero;
#elif FMT_REGISTERS_H
john_register_one(&fmt_monero);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // MKPC and OMP_SCALE tuned on i5-6500 CPU

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "chacha.h"
#include "slow_hash.h"

#define FORMAT_LABEL            "monero"
#define FORMAT_NAME             "monero Wallet"
#define FORMAT_TAG              "$monero$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "Pseudo-AES / ChaCha / Various 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define MAX_CIPHERTEXT_LENGTH   4096
#define IVLEN                   8

static struct fmt_tests tests[] = {
	// 4 hashes from monero-gui-v0.11.1.0
	{"$monero$0*e0b3e6cadcb68205dd0608b79576034e7a29000806fffb766a655714a4a822bcd1d93c5524b6ef91fd8ae94f0d3ffe1e55a78305c39e52892a7e34d4dfe6983d8492967fe3cd4ea611829c37fc5f65107e8c54b72a96fe63c20b71dda388e08114b88b15055953f182186c19fe9c1816819dc89d162ffffab552634515a8a5aec13300541e6e83d0227af34557b3cc2f64951af8890674a632d48385fe8fc6aca8ec286729793ebd7a85248aaa6c00cb8b530094d6316f9c92a50bea7eb201fbda5a62bcba0413fc3cedf07cf74c3b49a27dd0ed555b7a79d18ab58c89bfaf5c53eb25f01fa950b8afe18c3d4098ce794c2920cc834c915204f3003c37f0aab9f98810b0e3ecd7202a375e0f7e5d845b68abaf45df587756e7c058f6bde6a4cee8a7544efe1d2d71d272b22817dcca7f0969668c5b5bb28d472fc0c429ed25d8987c9537bc1fe309ff39a1dd652c9d618dc433cc4de93906565c44d5eade81b2afbd6fb835f6bea472c1bf949cff305e33252e7921875df833bc6cac040399f0f4445716de0c0fb61518589c570ee76483537b091fad80cfb34b3014740f3456eb2ff9a429004d1ca156ea904290d6edf76e0953ea0bfa6075e88f8bdb63350f317909beccdf7e764b64201d6005b00f33b40e9c1acc2f3e7b7f986340ad7ede0b9a246d9fac416b58937c0e788fdb0f92cdd50cad0a8cb6e926cc0bcfc066d5c5acf70732d58825e1ff2f77eba4697aab68deeb00ffe7b5dffd65436ccf4d6d7148901067628733fc5997b368076bff26424d46d5ba0966d730c6dbdabb2bd9882aed8055e58980ce1000ae6853763187368741a2a3da21efc95583f5705859ffb3c45e8cbef59cafbb76cac69f86e8fb1eea7768ff51ddc66065bac297ea82afbdf8bcfdd03fa4a89dbfc7055e73ab384d6b9fae3d142e9a8768f0f94f26030559da03bcc5df8734c4e3202921faa39aa0bd78ce7d4302143fadf7ac5c97f41dc87d006e241dc10aa22eec9e075d8557a93a6bc7725de06a7c213c47e6b24142131b3d9cb45516b8ef5c8d77103502ac77e53b402ea0d92d01663c7148d99d889d35f76d2177a38bc4caee131fa941aa56a0fe1007e0470306cfe4f8a3e9fc0c63eb983cc625e5716aad730d07bd2bd148516bd4667b2f56b4b3dec528367968db74347be4052a9dd2045d5660bb835d38ca909665048f8a89573729339598c6221b1d12c2f2", "openwall"},
	{"$monero$0*fde0b4cf059549acfe070c232edab30965481dba434b85d0c0066bf27a9de86d84c28a030f0719a9e1f088892885412adfa2cc573127d19bef9ee75a490c3f5637d6b798c4ccf123de87e3d499a20855ebb256cb2af6279e0df905bcfffb4b327c493d5039c85b582017b6e148bd0732f14c4db9d8420578781f7f27c9a808dc9b04e3c53ad0097caee7592a5c503fcba93dce49d60327b30048dcc3a08c97a3df6f0c182ef3e46911576d2946da7d4f7b4715317b40d333a8852aaa2b1758ff4c49569998998af4aad924c5069e344f87f2f443ac0c0f9ff7ddb78dea63720ef3f78b4c083469152a5fb4c4104bbe1ead04b23664024962cd516d2b2b8fb28cad59ab554e77b3f140629218c329456b96ed07bf177011c29dcad6869f3d043c5c3f0b1c3e6760af36d1a35a5c1cb841f040285ede38ef74531693f593b6ef65c3be60853988a95af00bd38b4f25ef5c8484001ebadb259f97009ac1c922c19bdd01bff48e2e199afc2e961dbab40bacb8b9c61c239e981b31bb1af3082ccd0d9834c174560f24bb45e6ca65f025863b1a282c9488999a32392f3ce61054b11004e8c98e69a2f8ef489de95de25ead5cfff64d57aab87e054f9e87f5868dca644086b8b0539f3b9ff8f322468321a12ab27d03bf390cd3ace0a7ca313620e18fa65e6cb93fcdb62922fc13cf64f6f756ac7807346aaa58261ce1dc972b20c87f4e17d19ba2107636a715ee672885c167430a7b00453b41183e80e72dd258235af06f17a94d65fcf42da14403084b95dfef7a6f3aed03a6cba2f19a441b4aba72d169e07d5e9fde41df05e73eb434735682afe7a3dc0e4d7089b76559306dbaeb69cb0c44319eceb90e0351b6f2dc8f1154daf1ae7e258067e2e4ee58be2fd42529e54a6e1b857dba54f2a227891d3bb86baad765a754431f6f0c64b60296064419604bce322a30048fbe6d668920e3c19155c771d8f01d7b76090a590e8e1177e34228edb1034568f93e916aed042de361716e8f7f66fedd4bd406bfaca794e40aabe0313901d63e9299399093cd400876a1f895eb02838f9fdd68753e086c62b6a3c4379c85831ea952c377114107f4632aa641e5165be1dab0b8f6259f29d8e487195850277b80f867b118327d1b9e5a9f6dc22cfcacb33eac42cef45941439bc9044e0a86bb8b7eecdefa252861d01116581a40723d998c6c8b63aab5d015b894c1f4082e4fab7c559e346d2f8c3e93def682fb42294c52c30ee99268701de1bcf70830da97d28313ed5684acfc3b1f2c6b380f3d4487547e0eb1732768f927d0218be7fb4a4d17c0ea7cb841d2d87c59661c34ceedcf635f9b87c9262d46b7c41ce5d64e17e7be6ff07278ddeb4f79a39466f7e8e556a1a745192440fc44a57f760afee705f9ec3bb31fd903ecf04e9e6ce0d00589100d36c0a9acea981f96d973bcc248afe0", "12345678"},
	{"$monero$0*d644b8d292a5d956d7071274bf149d4cede0e8051140229b025c319a37a6ecbc1b270264653a54dcc53fef6b0536fa0b48d3480de1017e233c58fbeed28e3d9ec8814272d74e24854038d4c461ce9115eb2c8892e69fd8d3dda9f940605cf075658efc9ef29bc164ccb812635f314c80cf1a6425bdc201e6421e9c2aec643ef2f9f3892cd0f3460c5a5cdfc5f4b4fbd27a9fcf58d9271283680ebc9782c1df0efd56e0943464f81a7b42aefe2912c81ad729dabb05bf104a2841c7ac5ef6bb8f101e336d4020cd7ec0b9e1be46fdc9a580b59b73e25d768331828af19a3297e8d81b309088a4c891618ca3a24f4484fd13816fd03b11fc635c34c7c4e881648b6a4fd56693c57d9c772f4ab5f48dea2e9143ba3f27a37321a6fd888e95c99b1f5bad8508820158cbae44b752f18752705013d92a969f66b32b6ad7eebf047d4a35f1c7308743fd9611be1dd1a8e23800f2d4be3a2e9a672faa665674056d13d31b1813b0b3903f346ef939215cfaa769a4a11ca49ce249a6ef25f97f6dd1b1d05d6eeda9d20f07f105ecdc3a58195afc603b77b482f3090d7a8a2b18dd920fb194ce297218f3de4adf9c58ae8d3f223b3aba19ce738664453b44310a7cf1c5aad1c421e79f88273360ab265715ac55e7fc0e683fdccbea4e85b4ce5f6694193977278f86c2343c43a269e479bda937541f171aa1b0447b78f050c409ac1b5a548fff4d597f0b3369d617a536af1fa606a63fefa68ef677a8d22e87faf09d8a1c814e6a7fc03aa783a033ba15db74f850dcba85eb9a147cbdc533fb914b91dfb8582b6414af2caef34f094b3a3fb0ca799dbf3e19fc2aeb0c72f9f3cfd6e5b54dda7c11acb9bd193d34344ce27beed96be7d240b9518d503735f870844faec2119fa4852b127a13b7955e21996213fe9a47e89305b94f89a2df45460a0fa9783713291edc2a20e0bf9981da696e37fe9e403a7612bf32bcfa6675dd22069c4f266ca14d55e0dbdddf421977584531898a627bac0d9c9b1b46221d2bd6be6424cba85c255d1262344b33e4537980956e057ced23513760bf9194e6e33378ae856bf9fd673432d585ddd6c8f52d891cc5b8644f8de91abc1e52322b0fa354ada16becbaa46da89bbaf101f206a8338fdd73664d88e585f3ce285208e34ce1b21b30e69dcc8173b814430441aefadbed95f6535b68a5d72de09e5d6b70d55bb9fcc962406e951a0da945818bf4d26745854aa231d7df909838783bbbddab7ddd6fe6ab976ebafd157a7575de28c62550835bf71e604e3e75721870e84b6aa9804c7927fc8bf57bd369350273ffa6719fddb57c0ac842b71e9a4c92edd39233e88c3bec33901e343707e7662018a2e099d89c6081453d47f3ed6752820984d6fc4097eb", "åbc"},
	{"$monero$0*136deb150e5c3e5add07f07536335ac68bc36eba5ee21725630f822c3d9b6ce3a63a74e586b8ae7b578e6fa8fad7124abb52012283365eb1525f09542c5cd385ac8b2b3db3ac689c93498672ec21c0b6e9cf795aee92e958363283fb7c58c79da4549211d4b9152441de8a6f92568813e4976780dfeabde5548dff18088c5f355f0dbb4922d8976a14ea944280cb5bcd3e45ec461fb4052e4cc9bd4de25650fdffc3497b65a47092a7239db649a9728257a794a9f8046d0be842488dc3677295b216ed44ac082ee2234158c1e245c56e62c13fa53a8243d17fcb52df7ad7fdae956f251dfa12cc6e6f7a5f0d501d46d8f7d5bf2a7e8ce2116e23f89a174235be5316e54a55efc582b52687a5d50dc48ff8955a9e98db252782bbdd5fd178fc0346355a47d67637d3238727a582f4b6ce659bc6e20cac6c9dfbcf66f63c2758e14dd193486c454203e4abd96593417955158320006f3286606af7555c4b399235fbccc9c56f55f5598ec75fba32e225acec3c7a727c6328ce984ad77005704b9ae2c4e705abfa2c30b8c6d7c8e1f3ca4e61ade9b5a7bbfbbdabf02df71bd846567b0a21e61a45e21298794e7458e02167e8bd89979e9ec89ff6e29ea6f39529de62a68168b07917e2396e8f01b9c433aac14f2149e2098a9eab67fd5b4164afe6eccdcbaf4fd5169cd806c98a0b69a0d6f27da5434891887c033a79e23e07e8ea1c3d9681e5824f66ac44befe98353d52ac3b1cfba0b9cebb2aebfe34f3675d3e4e236225a1aca4b52ee293847592b514002892be68db73d169f12eaaa7ec1f72411ad007a25da29b2ea7a3b9ab83ebb44f7f297c6a359871b9bab1e8192cbca973568b6790d196177b86e0a5a95593d32a7fc62a91f4ffb3cb6b6113357f37927c36b8540b6ca777dd8aedb7a79a0e522c8ce033b27d5d123ed40ea07ca9f5cfddd827ebb81a88c72d27120a2e7f08200567e512d608f915aad797d3c81ea620dd53b725292c716e413922d954ff3ab858c613eafafd44668a762bd718b72b7d02a6c9abd8dcf9baff43425bcc1cce4b9e777c25489086e7101755fab05edf86dbc565f5bc42df8f8b149dfeeb66ab0a30b40d5bf825a2fe8e1eb8796279b2d0b629defccb580117d0b6b87f270e241614c85aa38ae3e7fbfc88828dbcb73d2a316db75bf2392fa1f5f5e3f9f00e4f447d0183ef15cdb16f14444cf77cad68a9e3b58a436ab018a2032eea596d8b9624713c47664ba3bec9542245b2dcfb97dcbdf9822d0760c4950a0a2710e5571ba666081fd5485d1cdb19f96d67b43155aea6361c1686c22f571ab9ec6ccb74f0ae363f4f77d13601862e0ae4c158e8c7294c09ed0a70308587b09292097686ef449b7f01448a284f3db57585b17a6ac2b438c412ec5e06fb", "abcd"},
	// monero.linux.x64.v0-9-0-0.tar.bz2 (Jan, 2016)
	{"$monero$0*82f9813599dbe2cbf30485af32e33b83edaa71570d0d75ca534290b0f66573fb41611002f9b3a4010a8bb3bd7e5c13548a4e9860a7708f49cc35eddd6fc8a42a2fb747afe5c354a03197346e701fdd5007c9c67ac1d795f33f2fdbc1b3b0f416ffbfd7718b7b4ac91ee045057bd52c0b0a4ec367051bf337b620f7768693b219709b8dd56143c53c1c347513a57591e15eab2a5108ecea704fea78417b7a0d48f9eb97ddd7c17e5cc3a757fa95e84b6fe9ff5eb388d04b7675add008a9216bf238cedba2e3280fab66116f44876594651a63ec747b629d67994a7568a51f41133addf6c7c64ebf31e84871d83d7cf96fc3112cafeba1ac39ff6fb476dc2bea9504ff1df85e55cb8a3afab6fddb79428b8b491b118a936735ea199e856e11d4f03e2e39910a565ee780ccefe021e0e19addde151477035971d716c70085981a745445fffeccb1c9ccc27721ae1e4ee7c52e0d16ae5287265e61a9a5c8434be0b35554658d707a1aecfc54e195ebd61053703b854ec5740f50522fa8ca7ef4fd21db994cd9fe106fe6f49823c90359ea35c82b9b983a494b517b53d7bb6e509ca949ceb16d2f980a24e0ea0f2fc1b61db6bc61f3323633d90efaafdec6ecb6fad850a8caf9ab20d645c2a21ace7e65bc794fb6fcd73111711c48397e0ad04e764fd51636852b83a328b3828039a7667919af99613b91aaea82f0e58da43ae6b62ba6fd2450f1ee907a9de55215fda58b7d7d046d6f3c2d2f9cf6caaa97ac11a8927ec02ee1ceb7e3344646550c44ed2e522ca2687e536cf6e007f532bc50e26fdbe560826116efa018c6f3da9b7c6abbb02c525ca4312fd79d2aeddec0115be4f7dab2e4dc47846c45dda0c014ff31983938cb4db2d9ba9454c4f6f90a61", "openwall"},
	// bitmonero wallet v0.8.6.295(0.1-g5ceffa8) (June, 2014)
	{"$monero$0*982cc13dd90ed2e2970294b2a67480826acaf8eeedec74acccc5929c33d6b7cf01609f0ddb72817579c4375bd1d8f4d47c36c67d83bd3a817d1242211c6824720e430757c24238189875fbb7fe5e643b4273ac3912c7f4f6998ed1086634cebcce035a4af0122c2a6e601ff160bcfa0cfce06d8b3dd38915aa4f6067a732f954da2029ccca5664bbf5df2b2ce046918eec9b71224ec75418686eb437678ebfba50ed3e07ce0bba39f45610775b9958f44b3a53bf3294d7c55f2c455e2ada17f4426969fbc57cc659793892e558b163dd4826889c865b685ea49c54744ecbfcce9d9d39d16e8874a35ec767ab5b69e498f0989f7dd22becb2d50797e7c2867536bc6a1e9b0ecc0d864204c5114fef9ed86d962fced5cac90dbb33a72d16753075bf", "test"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t ctlen;
	int type;
	unsigned char ct[MAX_CIPHERTEXT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int type;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version / type
		goto err;
	if (!isdec(p))
		goto err;
	type = atoi(p);
	if (type != 0 && type != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	value = hexlenl(p, &extra);
	if (value > MAX_CIPHERTEXT_LENGTH * 2 || value < 32 * 2 || extra)
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
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	cs.ctlen = strlen(p) / 2;
	for (i = 0; i < cs.ctlen; i++)
		cs.ct[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

// Based on https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.cpp
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char km[64];
		unsigned char out[32];
		unsigned char iv[IVLEN];
		struct chacha_ctx ckey;

		// 1
		memcpy(iv, cur_salt->ct, IVLEN);
		cn_slow_hash(saved_key[index], saved_len[index], (char *)km);
		chacha_keysetup(&ckey, km, 256);
		chacha_ivsetup(&ckey, iv, NULL, IVLEN);
		chacha_decrypt_bytes(&ckey, cur_salt->ct + IVLEN + 2, out, 32, 20);
		if (memmem(out, 32, (void*)"key_data", 8) || memmem(out, 32, (void*)"m_creation_timestamp", 20)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
			continue;
		}

		// 2
		memcpy(iv, cur_salt->ct, IVLEN);
		chacha_keysetup(&ckey, km, 256);
		chacha_ivsetup(&ckey, iv, NULL, IVLEN);
		chacha_decrypt_bytes(&ckey, cur_salt->ct + IVLEN + 2, out, 32, 8);
		if (memmem(out, 32, (void*)"key_data", 8) || memmem(out, 32, (void*)"m_creation_timestamp", 20)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
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
	return 1;
}

struct fmt_main fmt_monero = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
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

#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning ": monero format requires little-endian, format disabled."
#elif _MSC_VER
#pragma message(": monero format requires little-endian, format disabled.")
#endif
#endif

#endif	/* ARCH_LITTLE_ENDIAN */
