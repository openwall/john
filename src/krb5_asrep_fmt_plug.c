/*
 * This software is
 * Copyright (c) 2015 Michael Kramer <michael.kramer@uni-konstanz.de>,
 * Copyright (c) 2015-2018 magnum,
 * Copyright (c) 2016 Fist0urs <eddy.maaalou@gmail.com>,
 * Copyright (c) 2017 @harmj0y,
 * Copyright (c) 2017 Dhiru Kholia <dhiru [at] openwall.com>
 *
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Changes,
 *
 * Slight modifications to krb5tgs format to support AS-REP responses by
 * @harmj0y (2017)
 *
 * Added support for AES etypes by Dhiru Kholia in October, 2017. Special
 * thanks goes to Kevin Devine for his work in this area.
 *
 * Documentation,
 *
 * http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/ says,
 *
 * If you can enumerate any accounts in a Windows domain that don't require
 * Kerberos preauthentication, you can now easily request a piece of encrypted
 * information for said accounts and efficiently crack the material offline
 * (using the format), revealing the user’s password. The reason for Kerberos
 * preauthentication is to prevent offline password guessing. While the AS-REP
 * ticket itself is encrypted with the service key (in this case the krbtgt
 * hash) the AS-REP "encrypted part" is signed with the client key, i.e. the
 * key of the user we send an AS-REQ for. If preauthentication isn't enabled,
 * an attacker can send an AS-REQ for any user that doesn't have preauth
 * required and receive a bit of encrypted material back that can be cracked
 * offline to reveal the target user’s password.
 *
 * While the AS-REP ticket uses type 2 like a TGS-REP ticket (i.e.
 * kerberoasting) this component of the response is encrypted with the service
 * key, which in this case is the krbtgt hash and therefore not crackable.
 * However, the AS-REP encrypted part, which is the section we can essentially
 * 'downgrade; to RC4-HMAC, is the same algorithm but of message type 8. This
 * difference caused this format to be born.
 *
 * Our krb5tgs format cracks "TGS-REP" messages and this format cracks "AS-REP"
 * messages.
 *
 * Use this format with https://github.com/HarmJ0y/ASREPRoast.
 *
 * See http://www.zytrax.com/tech/survival/kerberos.html for the basics on
 * Kerberos.
 *
 * Note: This format works even when Kerberos preauthentication is enabled,
 * given that the sniffed Kerberos traffic (.pcap) with AS-REP message is
 * available.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5asrep;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5asrep);
#else

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "common.h"
#include "md4.h"
#include "hmacmd5.h"
#include "hmac_sha.h"
#include "pbkdf2_hmac_sha1.h"
#include "unicode.h"
#include "krb5_common.h"
#include "krb5_asrep_common.h"
#include "rc4.h"

#define FORMAT_LABEL            "krb5asrep"
#define FORMAT_NAME             "Kerberos 5 AS-REP etype 17/18/23"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define MIN_PLAINTEXT_LENGTH    0
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 2)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               16 // Tuned w/ MKPC for core i7
#endif

/*
  assuming checksum == edata1, for etype 23

  formats are:
	 checksum$edata2
	 $krb5asrep$23$checksum$edata2
	 $krb5asrep$18$salt$edata2$checksum // etype 18
*/

static struct fmt_tests tests[] = {
	// hero-17-abcd.pcap
	{"$krb5asrep$17$EXAMPLE.COMhero$4e7c79214fd330b2e505a4c75e257e4686029136d54f92ce91bb69d5ffc064e64e925b3ae8bc1df431c74ccaf2075cb4a1a32151b0848964e147bf6f8e4a50caa7931faad50433991e016e312c70ad9007e38166f8df39eda3edd2445cce757e062d0919e663a67eb9fdb472b2a840cf521f18bd794947bcc0c0c6394cc5a60b860c963640867e623732206e7bf904d3b066a17b6f4ea3fd6d74f110ee80052e5297f7a19aaec22e22d582d183d43d6ca1792da187a3a182d1f479c5b4692841ccd701a63735d64584c4f8d199d67876dae5181f4eadfe75e454d0587d0953d7e16cb1b63265da6188b10c1746a2e83c41707bd03fcb2d460d1c6802826a0347b5ee7cdbe5384acad139b4395928bd$7ed0277ba9b853008cc62abe", "abcd"},
	{"63B386C8C75ECD10F9DF354F42427FBF$BB46B57E89D878455743D1E4C2CD871B5A526A130595463CC021510BA476247B8F9431505155CBC3D7E6120E93623E083A6A508111937607B73F8F524C23E482B648A9C1BE74D7B72B230711BF405ACE9CAF01D5FAC0304509F0DE2A43E0A0834D5F4D5683CA1B8164359B28AC91B35025158A6C9AAD2585D54BAA0A7D886AC154A0B00BE77E86F25439B2298E9EDA7D4BCBE84F505C6C4E6477BB2C9FF860D80E69E99F83A8D1205743CCDD7EC3C3B8FEC481FCC688EC3BD4BA60D93EB30A3259B2E9542CC281B25061D298F672009DCCE9DCAF47BB296480F941AFCDA533F13EA99739F97B92C971A7B4FB970F", "Password123!"},
	// http://www.exumbraops.com/layerone2016/party (sample.krb.pcap, packet number 1114, AS-REP)
	{"$krb5asrep$23$771adbc2397abddef676742924414f2b$2df6eb2d9c71820dc3fa2c098e071d920f0e412f5f12411632c5ee70e004da1be6f003b78661f8e4507e173552a52da751c45887c19bc1661ed334e0ccb4ef33975d4bd68b3d24746f281b4ca4fdf98fca0e50a8e845ad7d834e020c05b1495bc473b0295c6e9b94963cb912d3ff0f2f48c9075b0f52d9a31e5f4cc67c7af1d816b6ccfda0da5ccf35820a4d7d79073fa404726407ac840910357ef210fcf19ed81660106dfc3f4d9166a89d59d274f31619ddd9a1e2712c879a4e9c471965098842b44fae7ca6dd389d5d98b7fd7aca566ca399d072025e81cf0ef5075447687f80100307145fade7a8", "P@$$w0rd123"},
	// https://github.com/openwall/john/issues/2721, AS-REP-eTYPE-RC4-HMAC-openwall.pcap
	{"$krb5asrep$23$c447eddaebf22ebf006a8fc6f986488c$eb3a17eb56287b474cecad5d4e0490d949977ba3f5015220bcd3080444d5601d67b76c5453b678e8527624e40c273bea4cfe4a7303e136b9bc3b9e63b6fb492ee4b4d2f830c5fa5a55466b57a678f708438f6712354a2deb851792b09270f4941966b82a2fd5ad8fa1fbd95a60b0f9bcd57774b3e55467a02ffcb3f1379104c24e468342f83df20b571e6f34f9a9842b43735d58d94514dcefa76719c0f5c7c3a3bfa770380924625aa0a3472d7c02d10dbb278fd946f7efcfe59a4d4cb7bdb9c5dbddc027611fe333d3ac940ec5b4ed43b55ab54b03cd2df0a9a2a7b5d235c226b259bd5ff8e0e49680351d4f0c4d13e258bc8d383cad6fc2711be0", "openwall"},
	// AS-REP-with-PA-unsupported-openwall.pcap
	{"$krb5asrep$18$EXAMPLE.COMlulu$b49aa3de9314e2d8daafe323f2e84b9a4ddc361d99bf3bf3a99102f8bff5368bdefc9d7ae090532fdad2a508ac1271bfbd17363b3a1da23bf9db324a24c238634e3ab28d7f4eca009b4c3953c882f5a4206458a0b4238f3e538308d7339382f38412bbfe7b71e269274526edf7b802ea1ecdf7b8c17f9502b7a6750313329a68b8f8a2d039c8dfe74b9ead98684cfc86e5d0f77c18ba05718b01c33831db17191a0e77f9cef998bbb66a794915b03c94725aceabe9e2b5e25b665a37b5dd3a59a5552bd779dd5f0ae7295d232194eec1ca1ba0324bdc836ba623117e59fcfedab45a86d76d2c768341d327c035a1f5c756cfc06d76b6f7ea31c7a8e782eb48de0aab2fb373ffc2352c4192838323f8$a5245c7f39480a840da0e4c6", "openwall"},
	// luser-18-12345678.pcap
	{"$krb5asrep$18$EXAMPLE.COMluser$42e34732112be6cec1532177a6c93af5ec3b2fc7da106c004d6d89ddcb4131092aecbead3e9f30d07b593f4c7adc6478ab50b80fee07db3531471f5f1986c8882c45fef784258f9d43195108b83a74f6dcae1beed179c356c0da4e2d69f122efc579fd207d2b2b241a6c275997f2ec6fec95573a7518cb8b8528d932cc14186e4c5d46cef1eed4f2924ea316d80a62b0bcd98592a11eb69c04ef43b63aeae35e9f8bd8f842d0c9c33d768cd33c55914c2a1fb2f7c640b7270cf2274993c0ce4f413aac8e9d7a231c70dd0c6f8b9c16b47a90fae8d68982a66aa58e2eb8dde93d3504e87b5d4e33827c2aa501ed63544c0578032f395205c63b030cccc699aafb9132692c79a154d645fe83927b0eda$420973360c2e907b9053f1db", "12345678"},
	// ADSecurityOrg-MS14068-Exploit-KRBPackets.pcapng, https://adsecurity.org/?p=676
	{"$krb5asrep$23$8cf8eb5287e28a4006c064892150c4fb$3e05ecc13548bec8e1eeb900dea5429cc6931bae9b8524490eb3a8801560871fe44355ed556202afbb39872e1bbb5c3c4f1b37dcd68fda89a23ebad917d4bbb0933edd94331598939e5d0c0c98c7e219a2e9dd6b877280d1bd7c51131413be577a167208bcc21e9fe7ae8f393278d740e72ca5c44c42d5cb0bf6bab0a36f1b88b7ddc4abbc6f152e652f6ba35c2955fb4132e11b7e566f3b422c3740f79847b77783d245a4e570b8a621b4ff6ff4815566446af70313ee78133707a76a4e4424783bd7c04920aa822a1a36b29f7e25cef186e6439fc46e42e23d6bd918969ef49b8388aef158e443b3a57dbde7ada631fbef7326f9046a9b", "TheEmperor99!"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_K1)[16];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

static struct custom_salt *cur_salt;

static unsigned char constant[16];
static unsigned char ke_input[16];
static unsigned char ki_input[16];

static int valid(char *ciphertext, struct fmt_main *self)
{
	return krb5_asrep_valid(ciphertext, self, 1);
}

static void init(struct fmt_main *self)
{
	unsigned char usage[5];

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
			sizeof(*saved_key),
			MEM_ALIGN_CACHE);
	saved_K1 = mem_alloc_align(sizeof(*saved_K1) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);

	// generate 128 bits from 40 bits of "kerberos" string
	nfold(8 * 8, (unsigned char*)"kerberos", 128, constant);

	/* The "well-known constant" used for the DK function is the key usage number,
	 * expressed as four octets in big-endian order, followed by one octet indicated below.
	 * Kc = DK(base-key, usage | 0x99);
	 * Ke = DK(base-key, usage | 0xAA);
	 * Ki = DK(base-key, usage | 0x55); */

	memset(usage, 0, sizeof(usage));
	usage[3] = 0x03;        // key number in big-endian format
	usage[4] = 0xAA;        // used to derive Ke
	nfold(sizeof(usage) * 8, usage, sizeof(ke_input) * 8, ke_input);

	memset(usage, 0, sizeof(usage));
	usage[3] = 0x03;        // key number in big-endian format
	usage[4] = 0x55;        // used to derive Ki
	nfold(sizeof(usage) * 8, usage, sizeof(ki_input) * 8, ki_input);
}

static void done(void)
{
	MEM_FREE(saved_K1);
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt**)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	const unsigned char data[4] = {8, 0, 0, 0};
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT)
	{
		unsigned char tkey[MIN_KEYS_PER_CRYPT][32];
		int len[MIN_KEYS_PER_CRYPT];
		int i;
		unsigned char K3[16];
#ifdef _MSC_VER
		unsigned char ddata[65536];
#else
		unsigned char ddata[cur_salt->edata2len];
#endif
		unsigned char checksum[16];
		RC4_KEY rckey;

		if (cur_salt->etype == 23) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				if (new_keys) {
					MD4_CTX ctx;
					unsigned char key[16];
					UTF16 wkey[PLAINTEXT_LENGTH + 1];
					int len;

					len = enc_to_utf16(wkey, PLAINTEXT_LENGTH,
							(UTF8*)saved_key[index+i],
							strlen(saved_key[index+i]));
					if (len <= 0) {
						saved_key[index+i][-len] = 0;
						len = strlen16(wkey);
					}

					MD4_Init(&ctx);
					MD4_Update(&ctx, (char*)wkey, 2 * len);
					MD4_Final(key, &ctx);

					hmac_md5(key, data, 4, saved_K1[index+i]);
				}

				hmac_md5(saved_K1[index+i], cur_salt->edata1, 16, K3);

				RC4_set_key(&rckey, 16, K3);
				RC4(&rckey, 32, cur_salt->edata2, ddata);

				/* check the checksum */
				RC4(&rckey, cur_salt->edata2len - 32, cur_salt->edata2 + 32, ddata + 32);
				hmac_md5(saved_K1[index+i], ddata, cur_salt->edata2len, checksum);

				if (!memcmp(checksum, cur_salt->edata1, 16)) {
					cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
		}  else if (cur_salt->etype == 17 || cur_salt->etype == 18) {
			// See "krb5int_decode_tgs_rep", "krb5int_enctypes_list", "krb5int_dk_decrypt" (key function),
			// "krb5_k_decrypt", and "krb5_kdc_rep_decrypt_proc"
			// from krb5 software package.
			// https://www.ietf.org/rfc/rfc3962.txt document, https://www.ietf.org/rfc/rfc3961.txt, and
			// http://www.zeroshell.org/kerberos/Kerberos-operation/
			const int key_size = (cur_salt->etype == 17) ? 16 : 32;

#ifdef SIMD_COEF_32
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				len[i] = strlen(saved_key[i+index]);
				pin[i] = (unsigned char*)saved_key[i+index];
				pout[i] = tkey[i];
			}
			pbkdf2_sha1_sse((const unsigned char **)pin, len, (unsigned char*)cur_salt->salt, strlen(cur_salt->salt), 4096, pout, key_size, 0);
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				len[i] = strlen(saved_key[index+i]);
				pbkdf2_sha1((const unsigned char*)saved_key[index], len[i],
						(unsigned char*)cur_salt->salt, strlen(cur_salt->salt),
						4096, tkey[i], key_size, 0);
			}
#endif
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				unsigned char Ki[32];
#ifdef _MSC_VER
				unsigned char plaintext[65536];
#else
				unsigned char plaintext[cur_salt->edata2len];
#endif
				unsigned char checksum[20];
				unsigned char base_key[32];
				unsigned char Ke[32];

				dk(base_key, tkey[i], key_size, constant, 16);
				dk(Ke, base_key, key_size, ke_input, 16);
				krb_decrypt(cur_salt->edata2, cur_salt->edata2len, plaintext, Ke, key_size);
				// derive checksum of plaintext
				dk(Ki, base_key, key_size, ki_input, 16);
				hmac_sha1(Ki, key_size, plaintext, cur_salt->edata2len, checksum, 20);
				if (!memcmp(checksum, cur_salt->edata1, 12)) {
					cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}

			}
		}
	}
	if (cur_salt->etype == 23)
		new_keys = 0;

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

struct fmt_main fmt_krb5asrep = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		MIN_PLAINTEXT_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"etype"
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		krb5_asrep_split,
		fmt_default_binary,
		krb5_asrep_get_salt,
		{
			krb5_asrep_etype
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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

#endif
#endif /* HAVE_LIBCRYPTO */
