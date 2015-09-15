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
#include "memdbg.h"

struct fmt_tests rawsha1_common_tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{FORMAT_TAG_OLD "A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	// repeat hash in exactly the same form that is used in john.pot (lower case)
	{FORMAT_TAG_OLD "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	//{"{SHA}MtEMe4z5ZXDKBM438qGdhCQNOok=", "abcdefghijklmnopqrstuvwxyz"},
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

extern int ldr_in_pot;

char *rawsha1_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 8];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD))
		ciphertext += TAG_LENGTH_OLD;
	memset(out, 0, sizeof(out));
	strncpy(out, FORMAT_TAG, sizeof(out));
	base64_convert(ciphertext, e_b64_hex, DIGEST_SIZE*2, &out[TAG_LENGTH], e_b64_mime, HASH_LENGTH, flg_Base64_MIME_TRAIL_EQ);

	return out;
}
int rawsha1_common_valid(char *ciphertext, struct fmt_main *self)
{
	if (ldr_in_pot && (!strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD) || strlen(ciphertext) == 40))
		ciphertext=rawsha1_common_split(ciphertext,1,self);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH)) {
		ciphertext += TAG_LENGTH;
		if (base64_valid_length(ciphertext, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT) == HASH_LENGTH)
			return 1;
	}
	return 0;
}

char *rawsha1_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 6];
	char *ciphertext;

	if (!strncmp(split_fields[1], FORMAT_TAG, TAG_LENGTH))
		return split_fields[1];
	ciphertext = split_fields[1];
	if (!strncmp(ciphertext, FORMAT_TAG_OLD, TAG_LENGTH_OLD))
		ciphertext += TAG_LENGTH_OLD;

	if (strlen(ciphertext) != DIGEST_SIZE*2)
		return split_fields[1];
	memset(out, 0, sizeof(out));
	strncpy(out, FORMAT_TAG, sizeof(out));
	base64_convert(ciphertext, e_b64_hex, DIGEST_SIZE*2, &out[TAG_LENGTH], e_b64_mime, HASH_LENGTH, flg_Base64_MIME_TRAIL_EQ);

	return out;
}

void *rawsha1_common_get_binary(char *ciphertext)
{
	static ARCH_WORD_32 out[DIGEST_SIZE / 4 + 1];
	unsigned char *realcipher = (unsigned char*)out;

	ciphertext += TAG_LENGTH;
	base64_convert(ciphertext, e_b64_mime, 28, realcipher, e_b64_raw, DIGEST_SIZE, flg_Base64_MIME_TRAIL_EQ);
	return (void*)realcipher;
}
