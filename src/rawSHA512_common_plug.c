/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "formats.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "rawSHA512_common.h"

struct fmt_tests sha512_common_tests_rawsha512_111[] = {
	{"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{FORMAT_TAG "f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
	{"82244918c2e45fbaa00c7c7d52eb61f309a37e2f33ea1fba78e61b4140efa95731eec849de02ee16aa31c82848b51fb7b7fbae62f50df6e150a8a85e70fa740c", "TestTESTt3st"},
	{"fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
	{"c96f1c1260074832bd3068ddd29e733090285dfc65939555dbbcafb27834957d15d9c509481cc7df0e2a7e21429783ba573036b78f5284f9928b5fef02a791ef", "mot\xf6rhead"},
	{"aa3b7bdd98ec44af1f395bbd5f7f27a5cd9569d794d032747323bf4b1521fbe7725875a68b440abdf0559de5015baf873bb9c01cae63ecea93ad547a7397416e", "12345678901234567890"},
	{"db9981645857e59805132f7699e78bbcf39f69380a41aac8e6fa158a0593f2017ffe48764687aa855dae3023fcceefd51a1551d57730423df18503e80ba381ba", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
// password too long for this implementation
	{"7aba4411846c61b08b0f2282a8a4600232ace4dd96593c755ba9c9a4e7b780b8bdc437b5c55574b3e8409c7b511032f98ef120e25467678f0458643578eb60ff", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"},
	// this one DOES NOT work for a 1 limb. Only 111 bytes max can be used, unless we do 2 sha512 limbs.
//	{"a5fa73a3c9ca13df56c2cb3ae6f2e57671239a6b461ef5021a65d08f40336bfb458ec52a3003e1004f1a40d0706c27a9f4268fa4e1479382e2053c2b5b47b9b2", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"},
#ifdef DEBUG //Special test cases.
	{"12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9", "1234567890"},
	{"eba392e2f2094d7ffe55a23dffc29c412abd47057a0823c6c149c9c759423afde56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02", "123456789012345678901234567890"},
	{"3a8529d8f0c7b1ad2fa54c944952829b718d5beb4ff9ba8f4a849e02fe9a272daf59ae3bd06dde6f01df863d87c8ba4ab016ac576b59a19078c26d8dbe63f79e", "1234567890123456789012345678901234567890"},
	{"49c1faba580a55d6473f427174b62d8aa68f49958d70268eb8c7f258ba5bb089b7515891079451819aa4f8bf75b784dc156e7400ab0a04dfd2b75e46ef0a943e", "12345678901234567890123456789012345678901234567890"},
	{"8c5b51368ec88e1b1c4a67aa9de0aa0919447e142a9c245d75db07bbd4d00962b19112adb9f2b52c0a7b29fe2de661a872f095b6a1670098e5c7fde4a3503896", "123456789012345678901234567890123456789012345678901"},
	{"35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f", "1234567890123456789012345678901234567890123456789012345"},
#endif
	{NULL}
};

struct fmt_tests sha512_common_tests_rawsha512_20[] = {
	{"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{FORMAT_TAG "f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
	{"82244918c2e45fbaa00c7c7d52eb61f309a37e2f33ea1fba78e61b4140efa95731eec849de02ee16aa31c82848b51fb7b7fbae62f50df6e150a8a85e70fa740c", "TestTESTt3st"},
	{"fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
	{"c96f1c1260074832bd3068ddd29e733090285dfc65939555dbbcafb27834957d15d9c509481cc7df0e2a7e21429783ba573036b78f5284f9928b5fef02a791ef", "mot\xf6rhead"},
	{"aa3b7bdd98ec44af1f395bbd5f7f27a5cd9569d794d032747323bf4b1521fbe7725875a68b440abdf0559de5015baf873bb9c01cae63ecea93ad547a7397416e", "12345678901234567890"},
	{NULL}
};

struct fmt_tests sha512_common_tests_xsha512_20[] = {
	{"bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
	{"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
	{"$LION$5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
	{"6e447043e0ffd398d8cadeb2b693dd3306dbe164824a31912fb38579b9c94284da8dddfde04b94f8dc03acaa88ed7acabf4d179d4a5a1ae67f9d18edd600292b3b3aa3b7", "1"},
	{"$LION$4f665a61556fc2f8eb85805fb59aff5b285f61bd3304ea88521f6a9576aa1ba0a83387206cb23db5f59b908ffdcc15dfa74a8665bdcc04afc5a4932cb1b70c328b927821", "12"},
	{"6b354a4d64903461d26cb623d077d26263a70b9b9e9bd238a7212df03e78653c0a82c2cb9eebc8abde8af5a6868f96e67d75653590b4e4c3e50c2c2dc3087fd0999a2398", "123"},
	{"$LION$4f7a5742171fa68108e0a14e9e2e5dde63cb91edf1ebf97373776eb89ad1416a9daa52128d66adb550a0efe22772738af90a63d86336995ecbb78072f8b01272bdc5a4af", "1234"},
	{"3553414d79fe726061ed53f6733fbd114e50bb7b671405db7a438ce2278b03631ea892bc66e80f8e81c0848cfef66d0d90d8d81ccd2a794258cf8c156630fd6b1e34cb54", "12345"},
	{"$LION$7130783388b31fabc563ba8054106afd4cfa7d479d3747e6d6db454987015625c8ab912813e3d6e8ac35a7e00fa05cfbbaf64e7629e4d03f87a3ec61073daef2f8ade82b", "123456"},
	{"45736e346f878c0017207c3398f8abd6b3a01550518f8f9d3b9250077d5a519c2bacf8d69f8d17ca479f3ada7759fa5005a387256ae9dcccf78ae7630ec344458ed5f123", "1234567"},
	{"$LION$4b43646117eb0c976059469175e7c020b5668deee5a3fb50afd9b06f5e4a6e01935a38fa0d77990f5ddb663df3a4c9e1d73cec03af1e6f8c8896b7ec01863298219c2655", "12345678"},
	{"5656764a7760e50b1057b3afdb98c02bd2e7919c244ec2fa791768d4fd6a5ecffb5d16241f34705156a49ec2a33b2e0ed3a1aa2ff744af4c086adbdcbe112720ed388474", "123456789"},
	{"$LION$52396836b22e1966f14f090fc611ed99916992d6e03bffa86fe77a4993bd0952e706c13acc34edefa97a1dee885c149b34c27b8b4f5b3b611d9e739833b21c5cf772e9e7", "1234567890"},
	{"66726849de71b8757c15933a6c1dda60e8253e649bef07b93199ccafe1897186ed0ad448ddbfdbe86681e70c0d1a427eaf3b269a7b78dcc4fa67c89e6273b062b29b0410", "12345678901"},
	{"$LION$51334c32935aaa987ca03d0085c566e57b50cd5277834cd54995b4bc7255b798303b7e000c8b0d59d1ab15ce895c331c0c9a3fe021f5485dbf5955835ecd02de169f39cd", "123456789012"},
	{"4d7677548a5ab1517073cd317db2639c6f7f9de5b4e5246ef7805fc0619c474ed82e3fa88c99bf3dc7f9f670ff70d9a23af429181cc2c79ff38f5cad1937e4fc02db1e5a", "1234567890123"},
	{"bb0489dfbaaec946f441d4ea0d6acb50ee556103d9bdcc3f950d5a1112f1dd660ba1bca6a1954d0164cdc3b6a116b9bf8240cd1abec4abc73a6693799740de83544dd49e", "1952"},
	{"$LION$bb0489df4db05dbdc7be8afeef531f141ce28a00d7d5994693f7a9cf1fbbf98b45bb73ed10e00975b3bafd795fff667e3b3319517cc2f618ce92ff0e5c72032098fe1e75", "passwordandpassword"},
	{NULL}
};

struct fmt_tests sha512_common_tests_xsha512[] = {
	{"bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
	{"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
	{"$LION$5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
	{"6e447043e0ffd398d8cadeb2b693dd3306dbe164824a31912fb38579b9c94284da8dddfde04b94f8dc03acaa88ed7acabf4d179d4a5a1ae67f9d18edd600292b3b3aa3b7", "1"},
	{"$LION$4f665a61556fc2f8eb85805fb59aff5b285f61bd3304ea88521f6a9576aa1ba0a83387206cb23db5f59b908ffdcc15dfa74a8665bdcc04afc5a4932cb1b70c328b927821", "12"},
	{"6b354a4d64903461d26cb623d077d26263a70b9b9e9bd238a7212df03e78653c0a82c2cb9eebc8abde8af5a6868f96e67d75653590b4e4c3e50c2c2dc3087fd0999a2398", "123"},
	{"$LION$4f7a5742171fa68108e0a14e9e2e5dde63cb91edf1ebf97373776eb89ad1416a9daa52128d66adb550a0efe22772738af90a63d86336995ecbb78072f8b01272bdc5a4af", "1234"},
	{"3553414d79fe726061ed53f6733fbd114e50bb7b671405db7a438ce2278b03631ea892bc66e80f8e81c0848cfef66d0d90d8d81ccd2a794258cf8c156630fd6b1e34cb54", "12345"},
	{"$LION$7130783388b31fabc563ba8054106afd4cfa7d479d3747e6d6db454987015625c8ab912813e3d6e8ac35a7e00fa05cfbbaf64e7629e4d03f87a3ec61073daef2f8ade82b", "123456"},
	{"45736e346f878c0017207c3398f8abd6b3a01550518f8f9d3b9250077d5a519c2bacf8d69f8d17ca479f3ada7759fa5005a387256ae9dcccf78ae7630ec344458ed5f123", "1234567"},
	{"$LION$4b43646117eb0c976059469175e7c020b5668deee5a3fb50afd9b06f5e4a6e01935a38fa0d77990f5ddb663df3a4c9e1d73cec03af1e6f8c8896b7ec01863298219c2655", "12345678"},
	{"5656764a7760e50b1057b3afdb98c02bd2e7919c244ec2fa791768d4fd6a5ecffb5d16241f34705156a49ec2a33b2e0ed3a1aa2ff744af4c086adbdcbe112720ed388474", "123456789"},
	{"$LION$52396836b22e1966f14f090fc611ed99916992d6e03bffa86fe77a4993bd0952e706c13acc34edefa97a1dee885c149b34c27b8b4f5b3b611d9e739833b21c5cf772e9e7", "1234567890"},
	{"66726849de71b8757c15933a6c1dda60e8253e649bef07b93199ccafe1897186ed0ad448ddbfdbe86681e70c0d1a427eaf3b269a7b78dcc4fa67c89e6273b062b29b0410", "12345678901"},
	{"$LION$51334c32935aaa987ca03d0085c566e57b50cd5277834cd54995b4bc7255b798303b7e000c8b0d59d1ab15ce895c331c0c9a3fe021f5485dbf5955835ecd02de169f39cd", "123456789012"},
	{"4d7677548a5ab1517073cd317db2639c6f7f9de5b4e5246ef7805fc0619c474ed82e3fa88c99bf3dc7f9f670ff70d9a23af429181cc2c79ff38f5cad1937e4fc02db1e5a", "1234567890123"},
	{"bb0489dfbaaec946f441d4ea0d6acb50ee556103d9bdcc3f950d5a1112f1dd660ba1bca6a1954d0164cdc3b6a116b9bf8240cd1abec4abc73a6693799740de83544dd49e", "1952"},
	{"$LION$bb0489df4db05dbdc7be8afeef531f141ce28a00d7d5994693f7a9cf1fbbf98b45bb73ed10e00975b3bafd795fff667e3b3319517cc2f618ce92ff0e5c72032098fe1e75", "passwordandpassword"},
	{"$LION$74646d77d2d52596eb45e290e32329960fa295e475bc014638ef44c7727c24b5171fb47bbd27fbb6f1a3ad458793ae6edf60ed558f098406d56ac34adf0281e2ded9749e", "Skipping and& Dipping"},
	{NULL}
};

struct fmt_tests sha512_common_tests_ssha512[] = {
	{"{SSHA512}SCMmLlStPIxVtJc8Y6REiGTMsgSEFF7xVQFoYZYg39H0nEeDuK/fWxxNZCdSYlRgJK3U3q0lYTka3Nre2CjXzeNUjbvHabYP", "password"},
	{"{SSHA512}WucBQuH6NyeRYMz6gHQddkJLwzTUXaf8Ag0n9YM0drMFHG9XCO+FllvvwjXmo5/yFPvs+n1JVvJmdsvX5XHYvSUn9Xw=", "test123"},
	{"{SSHA512}uURShqzuCx/8BKVrc4HkTpYnv2eVfwEzg+Zi2AbsTQaIV7Xo6pDhRAZnp70h5P8MC6XyotrB2f27aLhhRj4GYrkJSFmbKmuF", "testpass"},
	{NULL}
};

static uint64_t H[8] = {
	0x6a09e667f3bcc908LL,
	0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL,
	0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL,
	0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL,
	0x5be0cd19137e2179LL
};

/* ------- Check if the ciphertext if a valid SHA2 hash ------- */
int sha512_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

int sha512_common_valid_xsha512(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	if (strncmp(pos, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return 0;
	pos += XSHA512_TAG_LENGTH;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == XSHA512_CIPHERTEXT_LENGTH+6;
}

int sha512_common_valid_nsldap(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (strncasecmp(ciphertext, NSLDAP_FORMAT_TAG, NSLDAP_TAG_LENGTH))
		return 0;
	ciphertext += NSLDAP_TAG_LENGTH;

	len = strspn(ciphertext, NSLDAP_BASE64_ALPHABET);
	if (len < (DIGEST_SIZE+1+2)/3*4-2)
		return 0;
	if (len < strlen(ciphertext) - 2)
		return 0;
	/* Max length needs at least 1 =; assumes (DIGEST_SIZE + NSLDAP_SALT_LEN) % 2 == 2. */
	if (len > NSLDAP_CIPHERTEXT_LENGTH - 1)
		return 0;

	len = strspn(ciphertext, NSLDAP_BASE64_ALPHABET "=");
	if (len != strlen(ciphertext))
		return 0;
	if (len & 3 || len > NSLDAP_CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

/* ------- Binary ------- */
void * sha512_common_binary(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, BINARY_ALIGN);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#if defined(SIMD_COEF_64) && ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
	return out;
}

void *sha512_common_binary_BE(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, BINARY_ALIGN);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
	return out;
}

void *sha512_common_binary_rev(char *ciphertext)
{
	static union {
		unsigned char out[DIGEST_SIZE];
		uint64_t x;
	} x;
	unsigned char *out = x.out;
	char *p;
	int i;
	uint64_t *b;

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = JOHNSWAP64(b[i])-H[i];
		b[i] = JOHNSWAP64(t);
	}
	return out;

}

void * sha512_common_binary_xsha512(char *ciphertext)
{
	static union {
		unsigned char out[DIGEST_SIZE];
		uint64_t x;
	} x;
	unsigned char *out = x.out;
	char *p;
	int i;

	ciphertext += XSHA512_TAG_LENGTH;
	p = ciphertext + 8;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#if defined(SIMD_COEF_64) && ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
	return out;
}

void *sha512_common_binary_xsha512_BE(char *ciphertext)
{
	static union {
		unsigned char out[DIGEST_SIZE];
		uint64_t x;
	} x;
	unsigned char *out = x.out;
	char *p;
	int i;

	ciphertext += XSHA512_TAG_LENGTH;
	p = ciphertext + 8;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
	return out;
}

void * sha512_common_binary_xsha512_rev(char *ciphertext)
{
	static union {
		unsigned char out[DIGEST_SIZE];
		uint64_t x;
	} x;
	unsigned char *out = x.out;
	char *p;
	int i;
	uint64_t *b;

	ciphertext += XSHA512_TAG_LENGTH;
	p = ciphertext + 8;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = JOHNSWAP64(b[i])-H[i];
		b[i] = JOHNSWAP64(t);
	}
	return out;
}

void *sha512_common_binary_nsldap(char *ciphertext) {
	static union {
		char out[DIGEST_SIZE+8];
		uint64_t x;
	} x;
	char *realcipher = x.out;

	ciphertext += NSLDAP_TAG_LENGTH;
	base64_convert(ciphertext, e_b64_mime, strlen(ciphertext), realcipher, e_b64_raw, sizeof(x.out), flg_Base64_DONOT_NULL_TERMINATE, 0);

#if defined(SIMD_COEF_64) && ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64 (realcipher, DIGEST_SIZE/8);
#endif
	return (void*)realcipher;
}

/* ------- Prepare ------- */
/* Convert Cisco hashes to hex ones, so .pot entries are compatible */
char * sha512_common_prepare_xsha512(char *split_fields[10], struct fmt_main *self)
{
	static char Buf[XSHA512_TAG_LENGTH + XSHA512_CIPHERTEXT_LENGTH + 1];

	if (strnlen(split_fields[1], XSHA512_CIPHERTEXT_LENGTH + 1) ==
	    XSHA512_CIPHERTEXT_LENGTH && ishex(split_fields[1])) {
		sprintf(Buf, "%s%s", XSHA512_FORMAT_TAG, split_fields[1]);
		return Buf;
	}
	return split_fields[1];
}

/* ------- Split ------- */
char * sha512_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

char * sha512_common_split_xsha512(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[XSHA512_TAG_LENGTH + XSHA512_CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return ciphertext;

	memcpy(out, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH);
	memcpylwr(out + XSHA512_TAG_LENGTH, ciphertext, XSHA512_CIPHERTEXT_LENGTH + 1);
	return out;
}
