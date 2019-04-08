/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_RAWSHA256_H
#define _COMMON_RAWSHA256_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */
/* Note: Cisco hashes are truncated at length 25. We currently ignore this. */
#define HEX_CIPHERTEXT_LENGTH   64
#define CISCO_CIPHERTEXT_LENGTH 43

#define HEX_TAG                 "$SHA256$"
#define CISCO_TAG               "$cisco4$"

#define HEX_TAG_LEN             (sizeof(HEX_TAG) - 1)
#define CISCO_TAG_LEN           (sizeof(CISCO_TAG) - 1)

#define DIGEST_SIZE             32
#define BINARY_ALIGN            MEM_ALIGN_WORD

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107

int sha256_common_valid(char *ciphertext, struct fmt_main *self);
void * sha256_common_binary(char *ciphertext);
void * sha256_common_binary_BE(char *ciphertext);
char * sha256_common_prepare(char *split_fields[10], struct fmt_main *self);
char * sha256_common_split(char *ciphertext, int index, struct fmt_main *self);

#ifdef _RAWSHA256_H
static struct fmt_tests sha256_common_tests[] = {
	{"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{HEX_TAG "71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
	{"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
	{HEX_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{HEX_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
	{HEX_TAG "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ""},
	{"LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{CISCO_TAG "LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc", "openwall"},
	{"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
	{"1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014", "test1"},
	{"fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13", "test3"},
	{"d150eb0383c8ef7478248d7e6cf18db333e8753d05e15a8a83714b7cf63922b3", "thatsworking"},
	{"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", "1234567890"},
	{CISCO_TAG "OsOmQzwozC4ROs/CzpczJoShdCeW9lp7k/tGrPS5Kog", "1"},
	{CISCO_TAG "d7kgbEk.P6mpKdduC66fUy1BF0MImo3eyJ9uI/JbMRk", "openwall"},
	{CISCO_TAG "p5BSCWNS3ivUDpZlWthR.k4Q/xWqlFyEqXdaPikHenI", "2"},
	{CISCO_TAG "HwUf7ev9Fx84X2vvspULAeDbmwlg9jgm/Wk63kc3vfU", "11"},
	{CISCO_TAG "bsPEUMVATKKO9yeUlJfE3OCzHlgf0s6goJpg3P1k0UU", "test"},
	{CISCO_TAG "Xq81UiuCj7bz9B..EX2BZumsU/d8pF5gs2NlRMW6sTk", "applesucks"},
	{CISCO_TAG "O/D/cn1nawcByQoJfBxrNnUx6jjfWV.FNFx5TzmzihU", "AppleSucks"},
#if PLAINTEXT_LENGTH > 19 //Has to be inside a header, it check againt a #define.
	{"6ed645ef0e1abea1bf1e4e935ff04f9e18d39812387f63cda3415b46240f0405", "12345678901234567890"},
	{"f54e5c8f810648e7638d25eb7ed6d24b7e5999d588e88826f2aa837d2ee52ecd", "123456789012345678901234567890"},
	{"a4ebdd541454b84cc670c9f1f5508baf67ffd3fe59b883267808781f992a0b1d", "1234567890123456789012345678901234567890"},
	{"f58fffba129aa67ec63bf12571a42977c0b785d3b2a93cc0538557c91da2115d", "12345678901234567890123456789012345678901234567890"},
	{"3874d5c9cc5ab726e6bbebadee22c680ce530004d4f0bb32f765d42a0a6c6dc1", "123456789012345678901234567890123456789012345678901"},
	{"03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9", "1234567890123456789012345678901234567890123456789012345"},
	{"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
	{"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
	{"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
	{CISCO_TAG "hUsuWZSE8dZERUBYNwRK8Aa8VxEGIHsuZFUCjNj2.Ac", "verylongbutweakpassword"},
	{CISCO_TAG "fLUL1VG98zYDf9Q.M40nZ5blVT3M6UBex74Blw.UDCc", "thismaximumpasswordlength"},
#endif
	{NULL}
};
#endif
#endif
