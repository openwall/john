/*
 * rawsha1 cracker patch for JtR, common code. 2015 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "johnswap.h"
#include "rawSHA1_common.h"

struct fmt_tests rawsha1_common_tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{FORMAT_TAG "A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	// repeat hash in exactly the same form that is used in john.pot (lower case)
	{FORMAT_TAG "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{"{SHA}MtEMe4z5ZXDKBM438qGdhCQNOok=", "abcdefghijklmnopqrstuvwxyz"},
	{"{SHA}cMiB1KJphN3OeV9vcYF8nPRIDnk=", "aaaa"},
	{"{SHA}iu0TIuVFC62weOH7YKgXod8loso=", "bbbb"},
	{"{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=", "ccccccccc"},
	{"{SHA}vNR9eUfJfcKmdkLDqNoKagho+qU=", "dddddddddd"},
	{"{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=", "12345"},
	{"{SHA}IOq+XWSw4hZ5boNPUtYf0LcDMvw=", "1234567"},
	{"{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs=", "123456"},
	{"{SHA}d1u5YbgdocpJIXpI5TPIMsM3FUo=", "princess"},
	{"{SHA}Y2fEjdGT1W6nsLqtJbGUVeUp9e4=", "abc123"},
	{"{SHA}fCIvspJ9goryL1khNOiTJIBjfA0=", "12345678"},
	{"{SHA}7o2HKPQ1/VUPg4Uqq6tSNM4dpSg=", "iloveyou"},
	{"{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "password"},
	{"{SHA}98O8HYCOBHMq32eZZczDTKeuNEE=", "123456789"},
	{"{SHA}X+4AI5lA+IPUwoVOQcf5iedSeKM=", "nicole"},
	{"{SHA}8c9lHOGiGRp2DAsvFhI095WOJuQ=", "rockyou"},
	{"{SHA}PQ87ndys7DDEAIxeAw5sE6R4y08=", "daniel"},
	{NULL}
};

struct fmt_tests axcrypt_common_tests[] = {
	{"e5b1b15baef2fc90a5673262440a959200000000", "oHemeheme"},
	{"2fbf0eba37de1d1d633bc1ed943b907f00000000", "azertyuiop1"},
	{"ebb7d1eff90b09efb3b3dd996e33b967", "Fist0urs"},
	{"c336d15500be1804021533cb9cc0ac2f", "enerveAPZ"},
	{"2a53e6ef507fabede6032a934c21aafc", "gArich1g0"},
	{"145595ef8b1d96d7bd9c5ea1c6d2876600000000", "BasicSHA1"},
	{"{SHA}VaiuD3vBn9alvHyZcuPY0wAAAAA=", "base64test"},
	{"{SHA}COqO1HN3nVE2Fh45LQs05wAAAAA=", "base64test0truncated"},
	{NULL}
};

char *rawsha1_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	char *ciphertext = split_fields[1];

	if (strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD))
		return ciphertext;

	ciphertext += TAG_LENGTH_OLD;

	if (base64_valid_length(ciphertext, e_b64_mime,
	                        flg_Base64_MIME_TRAIL_EQ_CNT, 0) != HASH_LENGTH_OLD)
		return ciphertext;

	strncpy(out, FORMAT_TAG, sizeof(out));
	base64_convert(ciphertext, e_b64_mime, HASH_LENGTH_OLD,
	               &out[TAG_LENGTH], e_b64_hex, sizeof(out) - TAG_LENGTH,
	               flg_Base64_MIME_TRAIL_EQ, 0);

	return out;
}

int rawsha1_common_valid(char *ciphertext, struct fmt_main *self)
{
	int extra;

	if (!strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD)) {
		ciphertext += TAG_LENGTH_OLD;
		if (base64_valid_length(ciphertext, e_b64_mime,
		                        flg_Base64_MIME_TRAIL_EQ_CNT, 0) ==
		    HASH_LENGTH_OLD)
			return 1;
		return 0;
	}
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	if (hexlen(ciphertext, &extra) == DIGEST_SIZE * 2 && !extra)
		return 1;
	return 0;
}

int rawsha1_axcrypt_valid(char *ciphertext, struct fmt_main *self)
{
	char out[41];
	int extra;

	if (hexlen(ciphertext, &extra) != 32 || extra)
		return rawsha1_common_valid(ciphertext, self);
	sprintf(out, "%s00000000", ciphertext);
	return rawsha1_common_valid(out, self);
}

char *rawsha1_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	extern int ldr_in_pot;

	if (ldr_in_pot && !strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD)) {
		static char *fields[10];

		fields[1] = ciphertext;
		return rawsha1_common_prepare(fields, self);
	}

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strncpy(out, FORMAT_TAG, sizeof(out));
	strnzcpylwr(&out[TAG_LENGTH], ciphertext, HASH_LENGTH + 1);

	return out;
}

char *rawsha1_axcrypt_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[41];
	int extra;

	if (hexlen(ciphertext, &extra) != 32 || extra)
		return rawsha1_common_split(ciphertext, index, self);
	sprintf(out, "%s00000000", ciphertext);
	return rawsha1_common_split(out, index, self);
}

void *rawsha1_common_get_binary(char *ciphertext)
{
	static uint32_t out[DIGEST_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)out;

	ciphertext += TAG_LENGTH;
	base64_convert(ciphertext, e_b64_hex, HASH_LENGTH,
	               realcipher, e_b64_raw, DIGEST_SIZE,
	               flg_Base64_NO_FLAGS, 0);
	return (void*)realcipher;
}
