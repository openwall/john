/*
 * NT-long (can handle up to 110 Unicode characters of password), this
 * is a thin dynamic alias format for dynamic='md4(utf16($p))'.
 *
 * This software is Copyright (c) 2022 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NT_long;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NT_long);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"

#define FORMAT_LABEL        "NT-long"
#define FORMAT_NAME         ""

#define ALGORITHM_NAME      "?" /* filled in by dynamic */
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107

#define BINARY_SIZE         16
#define BINARY_ALIGN        MEM_ALIGN_WORD

#define SALT_SIZE           0
#define DYNA_SALT_SIZE      (sizeof(char*))
#define SALT_ALIGN          MEM_ALIGN_NONE

#define FORMAT_TAG          "$NT$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)
#define FORMAT_TAG2         "@dynamic=md4(utf16($p))@"
#define TAG_LENGTH2         (sizeof(FORMAT_TAG2) - 1)

#define PLAINTEXT_LENGTH    0 /* Dynamic will set this from the script */
#define CIPHERTEXT_LENGTH   (TAG_LENGTH + 32)

static char *dyna_script =
	"Expression=md4(utf16($p))\n"
	"Flag=MGF_FLAT_BUFFERS\n"
	"Flag=MGF_UTF8\n"
	"MaxInputLenX86=110\n"
	"MaxInputLen=110\n"
	"Func=DynamicFunc__clean_input_kwik\n"
	"Func=DynamicFunc__setmode_unicode\n"
	"Func=DynamicFunc__append_keys\n"
	"Func=DynamicFunc__MD4_crypt_input1_to_output1_FINAL\n"
	"Test=@dynamic=md4(utf16($p))@e0fba38268d0ec66ef1cb452d5885e53:abc\n"
	"Test=@dynamic=md4(utf16($p))@69bf94898385467264708f3cc51cf0a4:john\n"
	"Test=@dynamic=md4(utf16($p))@d45dacc099500056235d8728be238f12:passweird\n";

static struct fmt_tests tests[] = {
	{"e0fba38268d0ec66ef1cb452d5885e53", "abc"},
	{"@dynamic=md4(utf16($p))@e0fba38268d0ec66ef1cb452d5885e53", "abc"},
	{"$NT$69bf94898385467264708f3cc51cf0a4", "john"},
	{"$NT$d45dacc099500056235d8728be238f12", "passweird"},
	{"$NT$fbefc2766ab7defcc894800387a32b35", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEF"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{NULL}
};

static char Conv_Buf[80];
static int dyna_type;
static char dyna_hash_type[24];
static int dyna_hash_type_len;
static struct fmt_main *pDynamic;
static void init(struct fmt_main *self);
static void get_ptr();

/* this function converts the NT signature string into the dynamic syntax */
static char *Convert(char *Buf, char *ciphertext, int in_load)
{
	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	else if (!strncmp(ciphertext, FORMAT_TAG2, TAG_LENGTH2))
		ciphertext += TAG_LENGTH2;

	if (in_load)
		snprintf(Buf, sizeof(Conv_Buf), "$dynamic_6xxx$%s", ciphertext);
	else
		snprintf(Buf, sizeof(Conv_Buf), "%s%s", dyna_hash_type, ciphertext);
	return Buf;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	get_ptr();

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	else if (!strncmp(ciphertext, FORMAT_TAG2, TAG_LENGTH2))
		ciphertext += TAG_LENGTH2;

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

	if (!*pos && pos - ciphertext == 32)
		return pDynamic->methods.valid(Convert(Conv_Buf, ciphertext, 0), pDynamic);
	else
		return 0;
}

/*
 * Handle pwdump files:  user:uid:lmhash:ntlmhash:::
 * Note, we address the user id inside loader.
 */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!valid(split_fields[1], self) && split_fields[1][0] != '$') {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "%s%s", FORMAT_TAG, split_fields[3]);
			if (valid(out, self))
				return out;
		}
	}
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, dyna_hash_type, dyna_hash_type_len))
		ciphertext += dyna_hash_type_len;
	else if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	else if (!strncmp(ciphertext, FORMAT_TAG2, TAG_LENGTH2))
		ciphertext += TAG_LENGTH2;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);

	memcpylwr(&out[TAG_LENGTH], ciphertext, 32);
	out[CIPHERTEXT_LENGTH] = 0;

	return out;
}

static void *binary(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.binary(Convert(Conv_Buf, ciphertext, 0));
}

struct fmt_main fmt_NT_long =
{
	{
		/*
		 * Setup the labeling and stuff. The max and min crypts are set to 1
		 * here, but will be reset within our init() function.
		 */
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_DYNAMIC | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		tests
	},
	{
		/*
		 *  All we need here, is the pointer to valid, and the pointer to init
		 *  When init is called, we will properly set the rest
		 */
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
	}
};

static void link_funcs() {
	fmt_NT_long.methods.split   = split;
	fmt_NT_long.methods.binary  = binary;
	fmt_NT_long.methods.salt    = fmt_default_salt;
	fmt_NT_long.methods.prepare = prepare;
}

static void init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic->methods.init(pDynamic);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic) {
		dynamic_LOCAL_FMT_FROM_PARSER_FUNCTIONS(dyna_script, &dyna_type, &fmt_NT_long, Convert);
		sprintf(dyna_hash_type, "$dynamic_%d$", dyna_type);
		dyna_hash_type_len = strlen(dyna_hash_type);
		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_NT_long, Convert(Conv_Buf, tests[0].ciphertext, 0), "NT", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */
