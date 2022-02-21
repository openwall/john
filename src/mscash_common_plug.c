/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) Feb 29, 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the mscash and mscash2 crackers
 *  (CPU, OpenCL)
 */

#include <stdio.h>
#include "formats.h"
#include "memory.h"
#include "common.h"
#include "base64_convert.h"
#include "unicode.h"
#include "johnswap.h"
#include "mscash_common.h"


/**************************************
 * Common stuff for mscash(1) hashes
 **************************************/

/* Note: some tests will be replaced in init() if running UTF-8 */
struct fmt_tests mscash1_common_tests[] = {
	{"176a4c2bd45ac73687676c2f09045353", "", {"root"} }, // nullstring password
	{"M$test2#ab60bdb4493822b175486810ac2abe63", "test2" },
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3" },
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4" },
	{"M$#january#72488d8077e33d138b9cff94092716e4", "issue#2575"}, // salt contains '#'
	{"64cd29e36a8431a2b111378564a10631", "test1", {"TEST1"} },    // salt is lowercased before hashing
	{"290efa10307e36a79b3eebf2a6b29455", "okolada", {"nineteen_characters"} }, // max salt length
	{"ab60bdb4493822b175486810ac2abe63", "test2", {"test2"} },
	{"b945d24866af4b01a6d89b9d932a153c", "test4", {"test4"} },
	{NULL}
};

void mscash1_adjust_tests(struct fmt_main *self, unsigned target_encoding,
                          unsigned plain_len,
                          void (*set_key_utf8)(char*,int),
                          void (*set_key_encoding)(char*,int))
{
	if (target_encoding == UTF_8) {
		self->methods.set_key = set_key_utf8;
		self->params.plaintext_length = (plain_len * 3);
		mscash1_common_tests[1].ciphertext = "M$\xC3\xBC#48f84e6f73d6d5305f6558a33fa2c9bb";
		mscash1_common_tests[1].plaintext = "\xC3\xBC";         // German u-umlaut in UTF-8
		mscash1_common_tests[2].ciphertext = "M$user#9121790702dda0fa5d353014c334c2ce";
		mscash1_common_tests[2].plaintext = "\xe2\x82\xac\xe2\x82\xac"; // 2 x Euro signs
	} else if (target_encoding == ENC_RAW || target_encoding == ISO_8859_1) {
		mscash1_common_tests[1].ciphertext = "M$\xFC#48f84e6f73d6d5305f6558a33fa2c9bb";
		mscash1_common_tests[1].plaintext = "\xFC";         // German u-umlaut in ISO_8859_1
		mscash1_common_tests[2].ciphertext = "M$\xFC\xFC#593246a8335cf0261799bda2a2a9c623";
		mscash1_common_tests[2].plaintext = "\xFC\xFC"; // 2 x Euro signs
	} else {
		self->methods.set_key = set_key_encoding;
	}
}

int mscash1_common_valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*MSCASH1_MAX_SALT_LENGTH+1];
	UTF16 realsalt[MSCASH1_MAX_SALT_LENGTH+2];
	int saltlen;
	/* Extra +4 over similar code in split() to catch truncation (#5027). */
	/* Extra +1 until #5029 is fixed. */
	char lc_buf[MSCASH1_MAX_CIPHERTEXT_LENGTH + 1 + 4 + 1];

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	l = strlen(ciphertext);
	if (l <= 32 || l > MSCASH1_MAX_CIPHERTEXT_LENGTH)
		return 0;

	/* lowercase can transform string in unexpected ways (#5026). */
	memcpy(lc_buf, ciphertext, FORMAT_TAG_LEN);
	l = enc_lc((UTF8*)&lc_buf[FORMAT_TAG_LEN], sizeof(lc_buf) - 1 - FORMAT_TAG_LEN,
	           (UTF8*)&ciphertext[FORMAT_TAG_LEN], l - FORMAT_TAG_LEN);
	l += FORMAT_TAG_LEN;
	ciphertext = lc_buf;

	if (l <= 32 || l > MSCASH1_MAX_CIPHERTEXT_LENGTH)
		return 0;

	l -= 32;
	if (ciphertext[l-1]!='#')
		return 0;

	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	// This is tricky: Max supported salt length is 19 characters of Unicode
	saltlen = enc_to_utf16(realsalt, MSCASH1_MAX_SALT_LENGTH+1, (UTF8*)strnzcpy(insalt, &ciphertext[FORMAT_TAG_LEN], l - FORMAT_TAG_LEN), l - 3);
	if (saltlen < 0) {
		static int error_shown = 0;
#ifdef HAVE_FUZZ
		if (options.flags & (FLG_FUZZ_CHK | FLG_FUZZ_DUMP_CHK))
			return 0;
#endif
		if (!error_shown)
			fprintf(stderr, "%s: Input file is not UTF-8. Please use --input-enc to specify a codepage.\n", self->params.label);
		error_shown = 1;
		return 0;
	}
	if (saltlen > MSCASH1_MAX_SALT_LENGTH) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due to salt length limitation\n", self->params.label);
		return 0;
	}
	return 1;
}

char *mscash1_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	/* Extra +1 until #5029 is fixed. */
	static char out[MSCASH1_MAX_CIPHERTEXT_LENGTH + 1 + 1];

	memcpy(out, ciphertext, FORMAT_TAG_LEN);
	// lowercase salt as well as hash, encoding-aware
	enc_lc((UTF8*)&out[FORMAT_TAG_LEN], sizeof(out) - 1 - FORMAT_TAG_LEN,
	       (UTF8*)&ciphertext[FORMAT_TAG_LEN], strlen(ciphertext) - FORMAT_TAG_LEN);

	return out;
}

char *mscash1_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	int i;

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];

	if (!split_fields[0])
		return split_fields[1];

	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];

	if (split_fields[1][i])
			return split_fields[1];

	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
	sprintf(cp, "%s%s#%s", FORMAT_TAG, split_fields[0], split_fields[1]);
	if (mscash1_common_valid(cp, self))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

void *mscash_common_binary(char *ciphertext)
{
	static uint32_t binary[BINARY_SIZE/sizeof(uint32_t)];
	char *hash = strrchr(ciphertext, '#') + 1;
	uint32_t i, v;

	for (i = 0; i < BINARY_SIZE/sizeof(uint32_t); i++) {
		v  = ((unsigned int)(atoi16[ARCH_INDEX(hash[0])]))<<4;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[1])]));

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[2])]))<<12;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[3])]))<<8;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[4])]))<<20;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[5])]))<<16;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[6])]))<<28;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[7])]))<<24;
		hash += 8;

		binary[i] = v;
	}
	return binary;
}



/**************************************
 * Common stuff for mscash2 hashes
 **************************************/

/* this is the longest of all hashes */
#define MSCASH2_MAX_MAX_SALT_LEN     128
// x3 because salt may be UTF-8 in input  // changed to $DCC2$num#salt#hash  WARNING, only handles num of 5 digits!!
#define MSCASH2_MAX_CIPHERTEXT_LENGTH (6 + 5 + MSCASH2_MAX_MAX_SALT_LEN*3 + 2 + BINARY_SIZE*2)

/* Note: some tests will be replaced in init() if running UTF-8 */
struct fmt_tests mscash2_common_tests[] = {
	{"c0cbe0313a861062e29f92ede58f9b36", "", {"bin"} },           // nullstring password
	{"$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1" },
	{"$DCC2$10240#Joe#e09b38f84ab0be586b730baf61781e30", "qerwt" },
	{"$DCC2$10240#Joe#6432f517a900b3fc34ffe57f0f346e16", "12345" },
	{"87136ae0a18b2dafe4a41d555425b2ed", "w00t", {"nineteen_characters"} }, // max common salt length
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	// the next five may get replaced with long salt and long password hashes, depending upon the format
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
#if 0
	{"cfc6a1e33eb36c3d4f84e4c2606623d2", "longpassword", {"twentyXXX_characters"} },
	{"99ff74cea552799da8769d30b2684bee", "longpassword", {"twentyoneX_characters"} },
	{"0a721bdc92f27d7fb23b87a445ec562f", "longpassword", {"twentytwoXX_characters"} },
	// max length user name 128 bytes, and max length password, 125 bytes
	{"$DCC2$10240#12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678#5ba26de44bd3a369f43a1c72fba76d45", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
#endif
	{"$DCC2$10240#TEST2#c6758e5be7fc943d00b97972a8a97620", "test2" },    // salt is lowercased before hashing
	{"$DCC2$10240#test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"$DCC2$10240#test4#6f79ee93518306f071c47185998566ae", "test4" },
	// salt contains #
	{"$DCC2$10240##january#cceed966f6689269b758893bb6bbb985", "issue#2575"},

	// Non-standard iterations count
	{"$DCC2$10000#Twelve_chars#54236c670e185043c8016006c001e982", "magnum"},
	{"$DCC2$20480##january#474b0082a3a812a1c517fbd7a4e23811", "issue#2575"},

	{"$DCC2$january#26b5495b21f9ad58255d99b5e117abe2", "verylongpassword" },
	{"$DCC2$february#469375e08b5770b989aa2f0d371195ff", "(##)(&#*%%" },
	{"$DCC2$john-the-ripper#495c800a038d11e55fafc001eb689d1d", "batman#$@#1991" },
	{"$DCC2$#59137848828d14b1fca295a5032b52a1", "a" }, //Empty Salt
	{NULL}
};

void mscash2_adjust_tests(unsigned encoding, unsigned plain_len, unsigned salt_len) {
	int i;
	if (encoding == UTF_8) {
		// UTF8 may be up to three bytes per character
		// but core max. is 125 anyway
		//self->params.plaintext_length = MIN(125, 3*PLAINTEXT_LENGTH);
		mscash2_common_tests[1].plaintext = "\xc3\xbc";         // German u-umlaut in UTF-8
		mscash2_common_tests[1].ciphertext = "$DCC2$10240#joe#bdb80f2c4656a8b8591bd27d39064a54";
		mscash2_common_tests[2].plaintext = "\xe2\x82\xac\xe2\x82\xac"; // 2 x Euro signs
		mscash2_common_tests[2].ciphertext = "$DCC2$10240#joe#1e1e20f482ff748038e47d801d0d1bda";
	}
	else if (options.target_enc == ISO_8859_1) {
		mscash2_common_tests[1].plaintext = "\xfc";
		mscash2_common_tests[1].ciphertext = "$DCC2$10240#joe#bdb80f2c4656a8b8591bd27d39064a54";
		mscash2_common_tests[2].plaintext = "\xfc\xfc";
		mscash2_common_tests[2].ciphertext = "$DCC2$10240#admin#0839e4a07c00f18a8c65cf5b985b9e73";
	}
	// reset, just in case we are proessing multiple formats (like a blind -test=0 run)
	for (i = 6; i <= 9; ++i) {
		mscash2_common_tests[i].plaintext = mscash2_common_tests[5].plaintext;
		mscash2_common_tests[i].ciphertext = mscash2_common_tests[5].ciphertext;
	}
	// now adjust some values based upon size of passwords.
	if (salt_len >= 22) {
		mscash2_common_tests[6].plaintext = "longpassword";
		mscash2_common_tests[6].ciphertext = "$DCC2$10240#twentyXXX_characters#cfc6a1e33eb36c3d4f84e4c2606623d2";
		mscash2_common_tests[7].plaintext = "longpassword";
		mscash2_common_tests[7].ciphertext = "$DCC2$10240#twentyoneX_characters#99ff74cea552799da8769d30b2684bee";
		mscash2_common_tests[8].plaintext = "longpassword";
		mscash2_common_tests[8].ciphertext = "$DCC2$10240#twentytwoXX_characters#0a721bdc92f27d7fb23b87a445ec562f";
	}
	if (plain_len >= 125) {
		if (salt_len >= 128) {
			// max length user name 128 bytes, and max length password, 125 bytes
			mscash2_common_tests[9].plaintext = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
			mscash2_common_tests[9].ciphertext = "$DCC2$10240#12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678#5ba26de44bd3a369f43a1c72fba76d45";
		} else {
			// max length user name 19 bytes, and max length password, 125 bytes
			mscash2_common_tests[9].plaintext = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
			mscash2_common_tests[9].ciphertext = "$DCC2$10240#nineteen_characters#cda4cef92db4398ce648a8fed8dc6853";
		}
	}
}

int mscash2_common_valid(char *ciphertext, int max_salt_length, struct fmt_main *self)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*MSCASH2_MAX_MAX_SALT_LEN+1];
	UTF16 realsalt[129];
	int saltlen;
	/* Extra +4 over similar code in split() to catch truncation (#5027). */
	/* Extra +1 until #5029 is fixed. */
	char lc_buf[MSCASH2_MAX_CIPHERTEXT_LENGTH + 1 + 4 + 1];

	if (strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG2_LEN))
		return 0;

	l = strlen(ciphertext);
	if (l <= 32 || l > MSCASH2_MAX_CIPHERTEXT_LENGTH)
		return 0;

	/* lowercase can transform string in unexpected ways (#5026). */
	memcpy(lc_buf, ciphertext, FORMAT_TAG2_LEN);
	l = enc_lc((UTF8*)&lc_buf[FORMAT_TAG2_LEN], sizeof(lc_buf) - 1 - FORMAT_TAG2_LEN,
	           (UTF8*)&ciphertext[FORMAT_TAG2_LEN], l - FORMAT_TAG2_LEN);
	l += FORMAT_TAG2_LEN;
	ciphertext = lc_buf;

	if (l <= 32 || l > MSCASH2_MAX_CIPHERTEXT_LENGTH)
		return 0;

	l -= 32;
	if (ciphertext[l-1]!='#')
		return 0;

	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	/* We demand an iteration count (after prepare()) */
	if (strchr(ciphertext, '#') == strrchr(ciphertext, '#'))
		return 0;

	// This is tricky: Max supported salt length is 128 characters of Unicode
	i = FORMAT_TAG2_LEN;
	while (ciphertext[i] && ciphertext[i] != '#') ++i;
	++i;
	saltlen = enc_to_utf16(realsalt, max_salt_length, (UTF8*)strnzcpy(insalt, &ciphertext[i], l-i), l-(i+1));
	if (saltlen < 0) {
		static int error_shown = 0;
#ifdef HAVE_FUZZ
		if (options.flags & (FLG_FUZZ_CHK | FLG_FUZZ_DUMP_CHK))
			return 0;
#endif
		if (!error_shown)
			fprintf(stderr, "%s: Input file is not UTF-8. Please use --input-enc to specify a codepage.\n", self->params.label);
		error_shown = 1;
		return 0;
	}
	if (saltlen > max_salt_length) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due to salt length limitation\n", self->params.label);

		return 0;
	}

	// iteration count must currently be less than 2^16. It must fit in a UTF16 (salt[1]);
	sscanf(&ciphertext[6], "%d", &i);
	if (i >= 1<<16)
		return 0;

	return 1;
}

char *mscash2_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	/* Extra +1 until #5029 is fixed. */
	static char out[MSCASH2_MAX_CIPHERTEXT_LENGTH + 1 + 1];

	memcpy(out, ciphertext, FORMAT_TAG2_LEN);
	// lowercase salt as well as hash, encoding-aware
	enc_lc((UTF8*)&out[FORMAT_TAG2_LEN], sizeof(out) - 1 - FORMAT_TAG2_LEN,
	       (UTF8*)&ciphertext[FORMAT_TAG2_LEN], strlen(ciphertext) - FORMAT_TAG2_LEN);

	return out;
}

char *mscash2_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	int i;

	if (!strncmp(split_fields[1], FORMAT_TAG2, FORMAT_TAG2_LEN) &&
	    strchr(split_fields[1], '#') == strrchr(split_fields[1], '#')) {
		if (mscash2_common_valid(split_fields[1], 128, self))
			return split_fields[1];
		// see if this is a form $DCC2$salt#hash.  If so, make it $DCC2$10240#salt#hash and retest (insert 10240# into the line).
		cp = mem_alloc(strlen(split_fields[1]) + 7);
		sprintf(cp, "%s10240#%s", FORMAT_TAG2, &(split_fields[1][6]));
		if (mscash2_common_valid(cp, 128, self)) {
			char *cipher = str_alloc_copy(cp);
			MEM_FREE(cp);
			return cipher;
		}
		MEM_FREE(cp);
		return split_fields[1];
	}
	if (!split_fields[0])
		return split_fields[1];

	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];
	if (split_fields[1][i])
			return split_fields[1];

	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	sprintf(cp, "%s10240#%s#%s", FORMAT_TAG2, split_fields[0], split_fields[1]);
	if (mscash2_common_valid(cp, 128, self))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}
