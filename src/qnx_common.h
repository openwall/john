/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2015 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_QNX_H
#define _COMMON_QNX_H

#include "base64_convert.h"

/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT          1000

#define FORMAT_NAME		"qnx hash"
#define BENCHMARK_COMMENT	" (rounds=1000)"
#define BENCHMARK_LENGTH	-1
#define CIPHERTEXT_LENGTH	43

// binary size is 'max' which is for sha512
#define BINARY_SIZE		64
#define BINARY_SIZE_MD5		16
#define BINARY_SIZE_SHA256	16
#define BINARY_ALIGN		4
#define SALT_LENGTH		32
#define SALT_ALIGN		4

/* ------- Check if the ciphertext if a valid QNX crypt ------- */
static int valid(char *ciphertext, struct fmt_main *self) {
	char *origptr = strdup(ciphertext), *ct = origptr;
	int len;
	if (*ct != '@')
		return 0;
	ct = strtokm(&ct[1], "@");
	// Only allow @m @s or @S signatures.
	if (*ct == 'm') len = 32;
	else if (*ct == 's') len = 64;
	else if (*ct == 'S') len = 128;
	else return 0;

	// If ANYTHING follows the signtuare, it must be ",decimal" However
	// having nothing following is valid, and specifies default of ,1000
	if (ct[1]) {
		if (ct[1] != ',' || !isdec(&ct[2]))
			return 0;
	}
	ct = strtokm(NULL, "@");
	if (!ishexlc(ct) || strlen(ct) != len)
		return 0;
	ct = strtokm(NULL, "@");
	if (!ishexlc(ct) || strlen(ct) > SALT_LENGTH)
		return 0;
	MEM_FREE(origptr);
	return 1;
}

static void *get_binary(char *ciphertext) {
	static ARCH_WORD_32 outbuf[BINARY_SIZE/4];
	unsigned char *out = (unsigned char*)outbuf;
	memset(outbuf, 0, sizeof(outbuf));
	ciphertext = strchr(&ciphertext[1], '@') + 1;
	base64_convert(ciphertext, e_b64_hex, strchr(ciphertext, '@')-ciphertext, out, e_b64_raw, BINARY_SIZE, 0);
	return (void *)outbuf;
}

/* here is our 'unified' tests array. */
#ifdef __QNX_CREATE_PROPER_TESTS_ARRAY__
static struct fmt_tests tests[] = {
	{"@m@bde10f1a1119328c64594c52df3165cf@6e1f9a390d50a85c", "password"},
	{"@s@1de2b7922fa592a0100a1b2b43ea206427cc044917bf9ad219f17c5db0af0452@36bdb8080d25f44f", "password"},
	{"@S@386d4be6fe9625c014b2486d8617ccfc521566be190d8a982b93698b99e0e3e3a18464281a514d5dda3ec5581389086f42b5dde023e934221bbe2e0106674cf7@129b6761", "password"},
	{"@S@60653c9f515eb8480486450c82eaad67f894e2f4828b6340fa28f47b7c84cc2b8bc451e37396150a1ab282179c6fe4ca777a7c1a17511b5d83f0ce23ca28da5d@caa3cc118d2deb23", "password"},
	{"@S@1030f372de34b8caac99b481d81ad9b57b923b385edcd3ed84f6721192f5238f34aba739e1d124919bd85c8efe13948593a6b691d8b41c1be5bc9b3906577f5d@abcd1234abcd1234", "password"},
	{"@S,98@4e1c05c14b3b590326219db534615139de00ebe8f66a571467bfaac324c975e97c85702a40aa48f660eaac0095d4c1aa0607092b0af3f2935ba4b23ce01e47b1@abcd1234abcd1234", "3"},
	{"@S,99@c6977abd2a945f9b45c0afff9f4f679524b9348f12bcf20a36b5b286f41d9f801cb9c883ad31073830b0d627abbe5925d0893e1daeac62d48799f0dc8efdd8eb@abcd1234abcd1234", "3"},
	{"@S,100@a305c157dbb3ec42558799b2b02fa2036cd7fac5fe6f3ef932eb6504590f09abb90b97581a08e07e1b56d41c0956317f56d9c19e77e625447cdd1071500440b1@abcd1234abcd1234", "3"},
	{"@S,101@3ee6b8d87dcc36a9ecafae28937c7330d721babc1a9ebf45e093e88fd17d66045cf2694a3e802c86bdc4332912188f9c4c9f0518274db087a5f94bc91707e3fe@abcd1234abcd1234", "3"},
	{"@S,102@5872742aaee2dd8590701ef2de5c1cd44c50bc66dac824ad49f10efb2819653f73f515dd904671638862faf3cf325062c57ce59c0ce0b479dbfed0d9ce605059@abcd1234abcd1234", "3"},
	{"@S,103@fda36b95dadf5d653bdb33a73a4a7ad9ad4cbe1119c5ecf8222455fdde4ccf18d914326c3a69b90376127c09ade980f389a67d8084a6c182d3aff5b94d99a8b7@abcd1234abcd1234", "3"},
	{"@S,104@accfddb4f51ce2e3c48e11716e09a5c7abd961d4d5cf61e821df865898ff3578a5529c322f83865aa2d33706288797e428472f1ae3841f7b093fec382e462a09@abcd1234abcd1234", "3"},
	{"@S,105@7608e7216b8bf4d150b8485ffaee5b23e41671fbc2ed3b6b9951966e7b223650e31c3f10f5b14b61fe40c16afc8a6422876dc62063881ccaf2a9e389778455af@abcd1234abcd1234", "3"},
	{"@S,106@09f28e72ff50f5f85be8a463fc00bcbd71fc1f56942cbe965e25a16bcd5a28b35e65d1355460006444f9d6498fdc7e72828bdc40ef0d65f36fd4e54107155d39@abcd1234abcd1234", "3"},
	{"@S,107@3183440bd9d73989f299b197abf442a43d18d7247322ec4bb5c382f13c9e66081090c02840821a808a1cfbc2fc44ffa8d9be7564f3d94f2fe3201255ff03f216@abcd1234abcd1234", "3"},
	{"@S,108@f3789c10c1d31b4f21be09fa0e582ed3ddf3a2b012d9ffedfc3e910053da0e26cc35d9839120d90ddd142de5ecdac806f3b3b72ee14f4f04eee2dd0dbd8dc827@abcd1234abcd1234", "3"},
	{"@S,109@7dec05c14db6ab295623c94e47a91b5e55957daf7cfb71269e3e4f37c5ca32c747fc9e9298e0aecdacdf96bc4832a40753d6bc57fb0c55925b94be92de8453ee@abcd1234abcd1234", "3"},
	{"@S,110@0b33dc7b80d90088e18adc411dd3f29fa051a00860be4cdd3ded72590c4894ff4dfe72f69c1c4e89f62fb5efa96c8ed300aa25bdd57d22d1e1ea854fd1f8a62b@abcd1234abcd1234", "3"},
	{"@S,111@57e31e7a28fa390a4b016ea6ef97d3827db4d24395a1e36dbcb029ab503d3658c450bca4244a2be1f0fa4ead24899dfd74decfa3f01d08e465b360f3917c7e18@abcd1234abcd1234", "3"},
	{"@S,112@87355ea88eabfba54933b43a0e32f6757ab0a0b20394e39a0828a175f381d7f06b0769573ca5eff7b3ce4f9d4cb334c43a61b51291b7f155507edf56e3948666@abcd1234abcd1234", "3"},
	{"@S,113@4f2ef54c01ee8ebf4bcea03dbf94d143ecd4f822523efa0c1479b7bcd6208ee71f286817e41398965014504fdbcc08fa40acb7833594be80209a56647806fcc0@abcd1234abcd1234", "3"},
	{"@S,114@5347a566d374d0535cb452a19859639033d4cfe0d2529bf1980263f0e143319c6b27ab2c8e8ab8d8d741a0eb58ef6a0948c253f10caa2c5a34233d3373150931@abcd1234abcd1234", "3"},
	{"@S,115@40ca3ea8f8f17445691cee5a3cc0f302b0774e4e142110dc48081b912feb2f8a8e1fa673e2e9946fecf87343e7cacf0bd7b610c056531c5d3506f71f54f60be0@abcd1234abcd1234", "3"},
	{"@S,116@7cb4b2479ad8259356d8a9c26cf30086d059b075d77c14927d78e002de9dbd75ec1dbca35ec30e1efc1035b2e9bfcdee5869ea05b73f9fefdda90d75f9c411b6@abcd1234abcd1234", "3"},
	{"@S,117@d3cee9351113142df12ea2c8311285056eb7542f5d4d4bc40e599185ae11eb907d8f1964725e4b77fee93a4b2480193d557dbe688b83bd9a40f0590e2d3a794c@abcd1234abcd1234", "3"},
	{"@S,118@43c22dc188df3dc10c8798a5b0a4a46591b6a02a2b9266e87468cfde1ba0b3ed6cc3a381b9c1fff503b235bc4ca1c8d6c9f1a26a96f74ae1d2d0bf09d2baee21@abcd1234abcd1234", "3"},
	{"@S,119@3cd8bdcf039419dafd6a838aead31d5a2b2326f3d0a09f15fb3775686e8a440217f634f67e36d84971443f6049116a67a46cdc9937c2227baa92832c3af5e924@abcd1234abcd1234", "3"},
	{"@S,120@8c644495efb8b774537914f216881f7b8c5613682ab466d7dc49974657b0d508dd1742619fc0def22b9a9fe8b4b90a03ce20d4686da526b9190f226b0792b677@abcd1234abcd1234", "3"},

	{NULL}
};
#endif

#endif
