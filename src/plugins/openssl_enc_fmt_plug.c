/*
 * OpenSSL "enc" cracker for JtR.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall.com>
 *
 * $ openssl enc -aes-256-cbc -p -e -a -salt -in hello.txt -out hello.txt.enc
 * enter aes-256-cbc encryption password:
 * Verifying - enter aes-256-cbc encryption password:
 * salt=305CEDC2A0521011
 * key=E08A1E6E1493BD3D3DAA25E112259D1688F7A0302AC8C16208DBDCEF179765F0
 * iv =582FDDF9603B9B03A54FC0BB34370DDE
 *
 * $ cat hello.txt
 * 123456789012
 *
 * Input Format:
 *
 * $openssl$cipher$md$salt-size$salt$last-chunks$inlined$known-plaintext$plaintext
 * $openssl$cipher$md$salt-size$salt$last-chunks$0$datalen$data$known-plaintext$plaintext
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_openssl;
#elif FMT_REGISTERS_H
john_register_one(&fmt_openssl);
#else

#if AC_BUILT
#include "autoconfig.h"
#endif

#ifdef __CYGWIN__
// cygwin has HORRIBLE performance GOMP for this format it runs at 1/#cpu's the speed of OMP_NUM_THREADS=1 or non-GMP build
#undef _OPENMP
#undef FMT_OMP
#undef FMT_OMP_BAD
#define FMT_OMP 0
#define FMT_OMP_BAD 0
#endif

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "aes.h"
#include "md5.h"
#include "sha.h"
#include "openssl_code.h"
#include "arch.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "jumbo.h"

#define FORMAT_LABEL        "openssl-enc"
#define FORMAT_NAME         "OpenSSL \"enc\" encryption"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   " (AES-128, MD5)"
#define BENCHMARK_LENGTH    7
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define PLAINTEXT_LENGTH    125
#define FORMAT_TAG          "$openssl$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  64

#ifndef OMP_SCALE
#define OMP_SCALE           2
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[16];
	int cipher;
	int md;
	int inlined;
	int kpa;
	int datalen;
	unsigned char kpt[256];
	int asciipct;
	unsigned char data[1024];
	unsigned char last_chunks[32];
} *cur_salt;

static struct fmt_tests tests[] = {
	// same test vector twice for consistent multi-salt benchmark
	{"$openssl$1$0$8$a1a5e529c8d92da5$8de763bf61377d365243993137ad9729$1$0", "password"},
	{"$openssl$1$0$8$a1a5e529c8d92da5$8de763bf61377d365243993137ad9729$1$0", "password"},
	{"$openssl$1$1$8$844527fb2f5d7ad5$ebccb1fcd2b1b30c5c3624d4016978ea$1$0", "password"},
	{"$openssl$0$0$8$305cedc2a0521011$bf11609a01e78ec3f50f0cc483e636f9$1$0", "password"},
	{"$openssl$0$0$8$305cedc2a0521011$bf11609a01e78ec3f50f0cc483e636f9$1$1$123456", "password"},
	{"$openssl$0$0$8$3993671be477e8f0$95384ad4fb11d737dc7ba884ccece94698b46d68d28c5cc4297ce37aea91064e$0$256$9bbbc2af64ba27444370e3b3db6f4077a5b83c099a9b0a13d0c03dbc89185aad078266470bb15c44e7b35aef66f456ba7f44fb0f60824331f5b598347cd471c6745374c7dbecf49a1dd0378e938bb9d3d68703e3038805fb3c7bf0623222bcc8e9375b10853aa7c991ddd086b8e2a97dd9ddd351ee0facde9bc3529742f0ffab990db046f5a64765d7a4b1c83b0290acae3eaa09278933cddcf1fed0ab14d408cd43fb73d830237dcd681425cd878bf4b542c108694b90e82f912c4aa4de02bd002dce975c2bb308aad933bfcfd8375d91837048d110f007ba3852dbb498a54595384ad4fb11d737dc7ba884ccece94698b46d68d28c5cc4297ce37aea91064e$0", "password"},
	{"$openssl$0$0$8$3993671be477e8f0$95384ad4fb11d737dc7ba884ccece94698b46d68d28c5cc4297ce37aea91064e$0$256$9bbbc2af64ba27444370e3b3db6f4077a5b83c099a9b0a13d0c03dbc89185aad078266470bb15c44e7b35aef66f456ba7f44fb0f60824331f5b598347cd471c6745374c7dbecf49a1dd0378e938bb9d3d68703e3038805fb3c7bf0623222bcc8e9375b10853aa7c991ddd086b8e2a97dd9ddd351ee0facde9bc3529742f0ffab990db046f5a64765d7a4b1c83b0290acae3eaa09278933cddcf1fed0ab14d408cd43fb73d830237dcd681425cd878bf4b542c108694b90e82f912c4aa4de02bd002dce975c2bb308aad933bfcfd8375d91837048d110f007ba3852dbb498a54595384ad4fb11d737dc7ba884ccece94698b46d68d28c5cc4297ce37aea91064e$1$00000000", "password"},
	// natalya.aes-256-cbc
	{"$openssl$0$2$8$8aabc4a37e4b6247$0135d41c5a82a620e3adac2a3d4f1358d1aa6c747811f98bdfb29157d2b39a55$0$240$65fdecc46300f543bdf4607ccc4e9117da5ab3b6978e98226c1283cb48701dbc2e1ac7593718f363dc381f244e7a404c8a7ff581aa93b702bebf55ed1c8a82fb629830d792053a132cbaeb51292b258d38fb349385af592a94acded393dfb75bc21874e65498360d93d031725028a9e9b0f8edcfcd89c2a4e88784a24712895fca4f463e2089ef7db580d7841301c1d63c640fd79e9d6c0ad3b4fc94fe610eb5f29400e883027e0469537e79c3ee1ae2cd3250b825288c4373c45f5ea6f6f1236681c55bcc4f1eb137c221bb3f42a0480135d41c5a82a620e3adac2a3d4f1358d1aa6c747811f98bdfb29157d2b39a55$1$privkey", "knockers"},
	// ASCII string < 16 bytes: "The quick"
	{"$openssl$0$2$8$6e3955dd5790111c$687853f2594b2f4e4f49951077625be1$1$2$90", "password"},
	{"$openssl$0$2$8$6e3955dd5790111c$687853f2594b2f4e4f49951077625be1$1$2$100", "password"},
	{"$openssl$0$2$8$6e3955dd5790111c$687853f2594b2f4e4f49951077625be1$1$1$The quick", "password"},
	// ASCII string between 16 and 256 bytes: "The quick brown fox jumps over the lazy dog."
	{"$openssl$0$2$8$da5c09fca9a4894d$229516b6295f39ee36e6724d6e9b168f66fc551f8172bc1851b9ede39cdb90f7$0$48$973af09515cc7d0dbd563a25294c375b229516b6295f39ee36e6724d6e9b168f66fc551f8172bc1851b9ede39cdb90f7$2$100", "password"},
	{"$openssl$0$2$8$da5c09fca9a4894d$229516b6295f39ee36e6724d6e9b168f66fc551f8172bc1851b9ede39cdb90f7$0$48$973af09515cc7d0dbd563a25294c375b229516b6295f39ee36e6724d6e9b168f66fc551f8172bc1851b9ede39cdb90f7$1$The quick brown fox", "password"},
	// 224-byte ASCII string (14 blocks, 15 with padding): Data contains last block
	{"$openssl$0$2$8$cb3d94ee46bf32ac$c3fdb0c15f39c87010daa177298d839aba0a35551dd74d3e84363f99d00289b7$0$240$a16da957bfdbbbb62833a79a114c18a8b70d44c46b9198cedbeb33a3c5d6fe3348c2ce78f0cdddeff11f1829f218b876f01c1f5d40f45deaf01e7c2397a34ff0c3ed7f5543bd1bd815c2cf23b50cb6067f6b18ddc55693160dbe8719c43cae38541c9c6d4194db425bc7f13ebc1f8614194eff022b9564ea3d8cc09994a9ae3376d4f3071cf7044d965323826ec828c65b090ddaffd9fa47d211acab2a1549f404b764455e233570111ea9adad06e0aa97c6835d9a981447a0514595bfc0243427ac35c43506e2c3662dea5f38975002c3fdb0c15f39c87010daa177298d839aba0a35551dd74d3e84363f99d00289b7$2$100", "password"},
	// 225-byte ASCII string (>14 blocks, 15 with padding): Data contains last block
	{"$openssl$0$2$8$017748af48a56915$3b1e37c5a1bb55ae9af3818b1b92ad218fa05ef754e3b8e29b0e8620e5fa0165$0$240$2897f0d64317add24f216fa19173acec587613cb17b5debed782cd763b8d4dcc8a5d6fc16b36be0c4521a1038c1f805d4c8f1c3316b985c9f484370ea2facd89c47036533dc22c3b2e81e12342e18dd0b85c694396c3e9f531577f4012d8de3d4543b8b92ad279e805f4e71c4fca5f3957e895eaf8b4ff551e0e33992ac8fe3be2b79f41087b11ee010c167d77fb8374a6e4f60bd04ea6f94b86bc8008db7faf5beda3e0662bd88c448cce289bc65d0d3cc8fcf21c670ead86d1897fea0f43bc88fb6b992d1f2ccdeb14f0ce7cd266a43b1e37c5a1bb55ae9af3818b1b92ad218fa05ef754e3b8e29b0e8620e5fa0165$2$100", "password"},
	// 240-byte ASCII string (15 blocks, 16 with padding): Data contains last block
	{"$openssl$0$2$8$2fca87f8f64b78ab$41a3a83776ee2400dddc1259cea4ed5207777c7d47f96ad19400c8e15dc518c1$0$256$aa5d05043ade8aeb59dd3f7ddffe61aed83b81d0bbaae9e179b31dd57fc9734bfb8b402670a95153a1d0840e36451ba7be37132d63b0b60cf53b756d41c80548189f985a430f2631318205904d8bc43c2c3a05a2dc51b00da69cf74d6b062ca85c3b4a9fe721910ba7e52d60b9e178e618d6a34dcd8eebde6f84dafd9bea1dee4159be23756aaa3dc238bcb92405fbcef7a68a606c2d8a56ddf8d271d6d172d2d821b18d89d634caa96ee5feaa712f7f731351dcfbc42d0a97d1f482693b2aca460249af480a69a24cdf715dcf5ef8e4be093a59a48f15f0a65c619ca61eff8541a3a83776ee2400dddc1259cea4ed5207777c7d47f96ad19400c8e15dc518c1$2$100", "password"},
	// 255-byte ASCII string (>15 blocks, 16 with padding): Data contains last block
	{"$openssl$0$2$8$bb33e7cf3146f12d$b16f004972d6b1ee659f0776d25d34961eecfc5bf9a91ff989d16859916b89dd$0$256$2df15da5ad5415635af6513c7e28f8e57985aee6835087bd6cd18212b6f6c45e4d6e07d97358f7b536ce5040afe64c711ba1848ecf1da057857bbc4190b438987b75377e46972a168f6d3273548a04e3bee6c4851133d98f920de5a97c076dbfbd7672c28564b6e74cb95513f6715d2e678abf25b4ebdd1b4c1829c5ba452b50d37ab224898a92b83af787b1be58caf2f8259a4b258d0c250ab656499fb73a18832dca1e0ced1072d9baf7689b1a377214f357a4bfaf67539a72e0e48d189c53fb5aeeedb09b0e1d13dcefb12c00694c2cdde9f3cbfb78f6529acb9d9676b4deb16f004972d6b1ee659f0776d25d34961eecfc5bf9a91ff989d16859916b89dd$2$100", "password"},
	// 256-byte ASCII string (16 blocks, 17 with padding): Data does not contain last block
	{"$openssl$0$2$8$669aa44bbf9e8833$a9fd0cf099004adb0c3512e4fc6203bf457180e09e01de8b16929d9e52c81b8d$0$256$fb5dfe6bb1e82747510cdc2338db37384fc0b678237b90389f7e310021506589670c3795eaeab3c2633fab72a27e88e1354cc883261a7170dfffe9d1f5c8c7cfda055288f5964c6ef288eb22a5dff039a5f0499e795b0a531bb9d0bad35e765108e2ae2190d747fe77732f2b130f091e75f531c4811095f2ccac132d1fc5403f4b38847d3ba170824b522e5269a0cd410bb2cfa05037d4dd136a373e73d3ea0c150006a938b3c9da312919b1990ea1fc31c5a1e58bf9b0130d01309ecde21e1494310a9e55082960bbc56265170fd4ce9a7fdc8ba25de14e1f390f84b451e2dfc8fcc25ffc9156c622b67d74a297a2c9a9fd0cf099004adb0c3512e4fc6203bf$2$100", "password"},
	// 270-byte ASCII string
	{"$openssl$0$2$8$c7d03fc12da26737$e30642894416d6c947d819eb85d7052fc8be90e6a05bf9973560553dc86a53e5$0$256$7135342851dc7b631ec47295fc3fb06ec05eea723071672699a125b6b03f10866ea6a500ca15c809110c5495ffac101b0b6b0ac396959a16a570e1ab765f772dfff291f97784373014df25c4d4effa22c009b471f0558163b2242646e89d873ec8048151f130800d09bcb40ca85d0632db6b29734c42cf14d04c7b590ae8350206474e01649a916fb62006ae3fa3e02f6f28a6ae6c9761d1a2a1bc8ef5a7611404ca22f1cbcf5e76049e29c51344a65a09a5f33770a62fa7469698a3a0869c736df3cdc06ca3ed734c5ceec13ade34ca9247ba1ae19698e4d533cfe3dcb9ff3e03683f99a085e6ab153d485dde21bc64e30642894416d6c947d819eb85d7052f$2$100", "password"},
	{"$openssl$0$2$8$c7d03fc12da26737$e30642894416d6c947d819eb85d7052fc8be90e6a05bf9973560553dc86a53e5$0$256$7135342851dc7b631ec47295fc3fb06ec05eea723071672699a125b6b03f10866ea6a500ca15c809110c5495ffac101b0b6b0ac396959a16a570e1ab765f772dfff291f97784373014df25c4d4effa22c009b471f0558163b2242646e89d873ec8048151f130800d09bcb40ca85d0632db6b29734c42cf14d04c7b590ae8350206474e01649a916fb62006ae3fa3e02f6f28a6ae6c9761d1a2a1bc8ef5a7611404ca22f1cbcf5e76049e29c51344a65a09a5f33770a62fa7469698a3a0869c736df3cdc06ca3ed734c5ceec13ade34ca9247ba1ae19698e4d533cfe3dcb9ff3e03683f99a085e6ab153d485dde21bc64e30642894416d6c947d819eb85d7052f$1$The quick brown fox", "password"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

//#define DEBUG_VALID
#ifdef DEBUG_VALID
// Awesome debug macro for valid()
#define return if (printf("\noriginal: %s\n",ciphertext)+printf("fail line %u: '%s' p=%p q=%p q-p-1=%u\n",__LINE__,p,p,q,(unsigned int)(q-p-1)))return
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *q = NULL;
	int len;

	if (strncmp(ciphertext, FORMAT_TAG,  TAG_LENGTH) != 0)
		return 0;
	p += TAG_LENGTH;		// cipher

	q = strchr(p, '$');
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) != 1)
		return 0;
	if (*p != '0' && *p != '1')
		return 0;
	p = q; q = strchr(p, '$');	// md
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) != 1)
		return 0;
	if (*p != '0' && *p != '1' && *p !='2')
		return 0;
	p = q; q = strchr(p, '$');	// salt-size
	if (!q)
		return 0;
	q = q + 1;
	len = strspn(p, DIGITCHARS);
	if (len < 1 || len > 2 || len != q - p - 1)
		return 0;
	len = atoi(p);
	if (len < 1 || len > sizeof(cur_salt->salt))
		return 0;
	p = q; q = strchr(p, '$');	// salt
	if (!q)
		return 0;
	q = q + 1;
	if (2 * len != q - p - 1 || 2 * len != strspn(p, HEXCHARS_lc))
		return 0;
	p = q; q = strchr(p, '$');	// last-chunks
	if (!q)
		return 0;
	q = q + 1;
	len = strspn(p, HEXCHARS_lc);
	if (len != q - p - 1 || len < 2 || (len & 1) || len/2 > sizeof(cur_salt->last_chunks))
		return 0;
	p = q; q = strchr(p, '$');	// inlined
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) != 1)
		return 0;
	if (*p != '0' && *p != '1')
		return 0;
	if (*p == '0') {
		p = q; q = strchr(p, '$');	// datalen
		if (!q)
			return 0;
		q = q + 1;
		len = strspn(p, DIGITCHARS);
		if (len < 1 || len > 3 || len != q - p - 1)
			return 0;
		len = atoi(p);
		if (len < 1 || len > sizeof(cur_salt->data))
			return 0;
		p = q; q = strchr(p, '$');	// data
		if (!q)
			return 0;
		q = q + 1;
		if (2 * len != q - p - 1 || 2 * len != strspn(p, HEXCHARS_all))
			return 0;
	}
	p = q; q = strchr(p, '$');	// known-plaintext
	if (!q)
		return !strcmp(p, "0");
	if (strlen(q) == 1)
		return 0;
	q = q + 1;
	if ((q - p - 1) != 1)
		return 0;
	if (*p != '0' && *p != '1' && *p != '2')
		return 0;
	if (strlen(q) > sizeof(cur_salt->kpt) - 1)
		return 0;

#ifdef DEBUG_VALID
#undef return
#endif
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i, res;
	char *p;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.cipher = atoi(p);
	p = strtokm(NULL, "$");
	cs.md = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	res = strlen(p) / 2;
	for (i = 0; i < res; i++)
		cs.last_chunks[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.inlined = atoi(p);
	if (cs.inlined) {
		p = strtokm(NULL, "$");
		cs.kpa = atoi(p);
		if (cs.kpa) {
			p = strtokm(NULL, "$");
			strncpy((char*)cs.kpt, p, 255);
			if (cs.kpa == 2) {
				cs.asciipct = atoi(p);
				if (!cs.asciipct) {
					cs.asciipct = 90;
				}
			}
		}
	}
	else {
		p = strtokm(NULL, "$");
		cs.datalen = atoi(p);
		p = strtokm(NULL, "$");
		for (i = 0; i < cs.datalen; i++)
		cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "$");
		cs.kpa = atoi(p);
		if (cs.kpa) {
			p = strtokm(NULL, "$");
			strncpy((char*)cs.kpt, p, 255);
			if (cs.kpa == 2) {
				cs.asciipct = atoi(p);
				if (!cs.asciipct) {
					cs.asciipct = 90;
				}
			}
		}
	}

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static int count_ascii(unsigned char *data, int len) {
	int nascii = 0;
	int c;
	for (c = 0 ; c < len ; c++) {
		if (data[c] == 0x0a || data[c] == 0x0d || (data[c] >= 32 && data[c] < 127))
			nascii++;
	}
	return nascii;
}

static int kpa(unsigned char *key, unsigned char *iv, int inlined)
{
	AES_KEY akey;
	unsigned char out[1024];
	AES_set_decrypt_key(key, 256, &akey);
	if (inlined) {
		AES_cbc_encrypt(cur_salt->last_chunks, out, 16, &akey, iv, AES_DECRYPT);
		if (cur_salt->kpa == 1) {
			if (memmem(out, 16, cur_salt->kpt, strlen((char*)cur_salt->kpt)))
				return 0;
		} else if (cur_salt->kpa == 2) {
			int len = check_pkcs_pad(out, 16, 16);
			int nascii = count_ascii(out, len);
			if ( (nascii * 100) / len >= cur_salt->asciipct )
				return 0;
		}
	}
	else {
		AES_cbc_encrypt(cur_salt->data, out, cur_salt->datalen, &akey, iv, AES_DECRYPT);
		if (cur_salt->kpa == 1) {
			if (memmem(out, cur_salt->datalen, cur_salt->kpt, strlen((char*)cur_salt->kpt)))
				return 0;
		} else if (cur_salt->kpa == 2) {
			int len = check_pkcs_pad(out, cur_salt->datalen, 16);
			if (len == -1 && cur_salt->datalen >= 256)
				len = cur_salt->datalen;
			int nascii = count_ascii(out, len);
			if ( (nascii * 100) / len >= cur_salt->asciipct )
				return 0;
		}
	}
	return -1;
}

static int decrypt(char *password)
{
	unsigned char out[16];
	AES_KEY akey;
	unsigned char iv[16];
	unsigned char biv[16];
	unsigned char key[32];
	int nrounds = 1;  // Seems to be fixed as of OpenSSL 1.1.0e (July, 2017)

	// FIXME handle more stuff
	switch(cur_salt->cipher) {
		case 0:
			switch(cur_salt->md) {
				case 0:
					BytesToKey(256, md5, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 256, &akey);
					break;
				case 1:
					BytesToKey(256, sha1, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 256, &akey);
					break;
				case 2:
					BytesToKey(256, sha256, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 256, &akey);
					break;
			}
			break;
		case 1:
			switch(cur_salt->md) {
				case 0:
					BytesToKey(128, md5, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 128, &akey);
					break;
				case 1:
					BytesToKey(128, sha1, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 128, &akey);
					break;
				case 2:
					BytesToKey(128, sha256, cur_salt->salt,
					           (unsigned char*)password, strlen(password),
					           nrounds, key, iv);
					AES_set_decrypt_key(key, 128, &akey);
					break;
			}
			break;
	}
	memcpy(biv, iv, 16);

	if (cur_salt->inlined)
		AES_cbc_encrypt(cur_salt->last_chunks, out, 16, &akey, iv, AES_DECRYPT);
	else {
		memcpy(iv, cur_salt->last_chunks, 16);
		AES_cbc_encrypt(cur_salt->last_chunks + 16, out, 16, &akey, iv, AES_DECRYPT);
	}

	// now check padding
	if (check_pkcs_pad(out, 16, 16) < 0)
			return -1;

	if (cur_salt->kpa)
		return kpa(key, biv, cur_salt->inlined);
	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		if (decrypt(saved_key[index]) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_openssl = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD | FMT_NOT_EXACT | FMT_HUGE_INPUT,
/*
 * FIXME: if there wouldn't be so many false positives,
 *        it would be useful to report some tunable costs
 *
 * FIXME: explain what false positives have to do with not
 *        reporting of tunable costs
 */
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
