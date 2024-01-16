/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum / JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_CRYPTSHA256_H
#define _COMMON_CRYPTSHA256_H


/* ------ Contains (at least) prepare(), valid() and split() ------ */
/* Prefix for optional rounds specification.  */
#define ROUNDS_PREFIX           "rounds="
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT          5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN              1	/* Drepper has it as 1000 */
/* Maximum number of rounds.  */
#define ROUNDS_MAX              999999999

#define FORMAT_NAME		"crypt(3) $5$"
#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	0x107
#define CIPHERTEXT_LENGTH		43

#define BINARY_SIZE				32
#define BINARY_ALIGN			4
#define SALT_LENGTH				16
#define SALT_ALIGN				4
#define FORMAT_TAG			"$5$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

/* ------- Check if the ciphertext if a valid SHA-256 crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
			return 0;

	ciphertext += FORMAT_TAG_LEN;

	if (!strncmp(ciphertext, ROUNDS_PREFIX,
			sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		if (!strtoul(num, &endp, 10))
					return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
			}
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;
	return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3) \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void * get_binary(char * ciphertext) {
	static uint32_t outbuf[BINARY_SIZE/4];
	uint32_t value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i=0;

	do {
		TO_BINARY(i, (i+10)%30, (i+20)%30);
		i = (i+21)%30;
	} while (i != 0);
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12);
	out[31] = value >> 8;
	out[30] = value;
	return (void *)out;
}

// here are the 'current' lengths supported by the different cryptsha256
// implementations:
//    opencl:  #define PLAINTEXT_LENGTH        35
//    CPU:     #define PLAINTEXT_LENGTH        24

/* here is our 'unified' tests array. */
#ifdef __CRYPTSHA256_CREATE_PROPER_TESTS_ARRAY__
static struct fmt_tests tests[] = {
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
	{"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
	{"$5$kc7lRD1fpYg0g.IP.ThisShouldBeTruncated.$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
	{"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"},
	{"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},

#if PLAINTEXT_LENGTH > 35
	{"$5$aewWTiO8RzEz5FBF$CZ3I.vdWF4omQXMQOv1g3XarjhH0wwR29Jwzt6/gvV/", "012345678901234567890123456789012345"},
#endif
#if PLAINTEXT_LENGTH >= 35
	{"$5$mTfUlwguIR0Gp2ed$nX5lzmEGAZQ.1.CcncGnSq/lxSF7t1P.YkVlljQfOC2", "01234567890123456789012345678901234"},
#endif
#if PLAINTEXT_LENGTH >= 24
	{"$5$fnJDgbSMK0ZQbj2j$xuV9QTbDdySL1tZxYKCL2OZRvR9G4acRXe1md0UbPmA", "123456789012345678901234"},
#endif

	// Here is a test case for rounds=50000. Works, but slows down self test a lot
	{"$5$rounds=50000$LKO/Ute40T3FNF95$S51z7fjx29wblQAQbkqY7G8ExS18kQva39ur8FG5VS0", "U*U*U*U*"},

	//Special test cases. (from GPU implementations)
	{"$5$UOUBPEMKQRHHRFML$zicoLpMLhBsNGtEplY/ehM0NtiAqxijiBCrolt7WBW0", "jjti"},

	// all formats should handle this 15 byte password.
	{"$5$XSLWLBSQUCNOWXOB$i7Ho5wUAIjsH2e2zA.WarqYLWir5nmZbUEcjK//Or7.", "hgnirgayjnhvi"},
	{"$5$VDCTRFOIDQXRQVHR$uolqT0wEwU.pvI9jq5xU457JQpiwTTKX3PB/9RS4/h4", "o"},
	{"$5$WTYWNCYHNPMXPG$UwZyrq0irhWs4OcLKcqSbFdktZaNAD2by1CiNNw7oID", "tcepf"},
	{"$5$DQUHKJNMVOEBGBG$91u2d/jMN5QuW3/kBEPG0xC2G8y1TuDU7SGAUYTX.y0", "wbfhoc"},
	{"$5$saltstring$0Az3qME7zTXm78kfHrR2OtT8WOu2gd8bcVn/9Y.3l/7", "john"},

	{"$5$saltstring$7cz4bTeQ7MnNssphNhFVrITtuJYY/1tdvLL2uzLvOk8", "a"},
	{"$5$saltstring$4Wjlxdm/Hbpo8ZQzKFazuvfUZPVVUQn6v1oPTX3nwX/", "ab"},
	{"$5$saltstring$tDHA0KPsYQ8V.LDB1/fgW7cvROod5ZajSrx1tZU2JG9", "abc"},
	{"$5$saltstring$LfhGTHVGfbAkxy/xKLgvSfXyeE7hZheoMRKhjfvNF6.", "abcd"},
	{"$5$saltstring$Qg0Xm9f2VY.ePLAwNXnOPU/s8btLptK/tEU/gFnn8BD", "abcde"},
	{"$5$saltstring$2Snf.yaHnLnLI3Qhsk2S119X4vKbwQyiTMOHp3Oy7F5", "abcdef"},
	{"$5$saltstring$4Y5UR.6zwplRx6y93NJVyNkxqdlyT64EV68F2mCrZ16", "abcdefg"},
	{"$5$saltstring$bEM3iuUR.CTgy8Wygh4zu.CAgmlwx3uxm3dGA34.Ij4", "abcdefgh"},
	{"$5$saltstring$1/OrKXZSFlaEE2DKMhKKE8qCld5X0Ez0vtz5TvO3U3D", "abcdefghi"},
	{"$5$saltstring$1IbZU70/Wo9m1b40ha6Ao8d.v6Ja0.bAFg5/QFVzoX/", "abcdefghij"},
	{"$5$saltstring$S4gCgloAzqAXE5sRz9DShPvaXrwt4vjDJ4fYgIMbLo1", "abcdefghijk"},
	{"$5$saltstring$AFNSzsWaoMDvt7lk2bx0rPapzCz2zGahXDdFeoXrNE9", "abcdefghijkl"},
	{"$5$saltstring$QfHc8JBd2DfyloVL0YLDa23Dc67N9mbdYqyRJQlFqZ5", "abcdefghijklm"},
	{"$5$saltstring$XKHiS.SSJ545PvJJr2t.HyUpmPZDAIT8fVvzr/HGhd0", "abcdefghijklmn"},
	// all formats should handle this 15 byte password.
	{"$5$saltstring$VxW44bFDcvixlQoTE4E.k5c8v1w0fGMyZ4tn8nGcWn0", "abcdefghijklmno"},

	{"$5$QSTVVEKDIDYRNK$4j8TST.29P07GHASD.BUHd0UTaFz7h.Mz//zcHokoZ5", "cgyihfkqk"},

	// These were found in a bug #1077 https://github.com/openwall/john/issues/1077
	// and created by pass_gen to test all lengths of salts. NOTE, I could
	// not get pass_gen.pl to do a null salt. Not sure it could be made anyway
	{"$5$1$EjlWWGGbmWXm00wmWG2EutReY7G/TA9awDah5IvTSy2", "short_salt"},
	{"$5$12$lhPEqohC1/lflYSl2juFZgDasZIiVdryUeIP/.XKRDA", "short_salt"},
	{"$5$123$KOc9ndqmAVjarsk6RvQu2bEca5o7qly.lG2gNTAvzYA", "short_salt"},
	{"$5$1234$LqOTc55Fc4K0O6h53GqAVINUCmtYuAW/8zNDoXE9zjA", "short_salt"},
	{"$5$12345$9fAbLJJamYElIPFc5Pb9S6XfteLYOEHjdBMwdy1oWp.", "short_salt"},
	{"$5$123456$qKfIMUCUvbINEaqXwe6LAvog3Ofj6YKXPpTXGWc5VPB", "short_salt"},
	{"$5$1234567$367DyB16D3vHEhYfZAPQPqynsKNgkClsdQiB/I3EfQ6", "short_salt"},
	{"$5$12345678$5Xt3LE6ogpAZvCXdQ/vPCwpzNYpABPINvsLiM5iJ9Z4", "short_salt"},
	{"$5$123456789$csTeZZS4O/WMMHBn9mgI9mrQC8xuffJvd/jdrvYRHV5", "short_salt"},
	{"$5$1234567890$ZS3MJOM5Rin821TVyDKq0QNTRnU6di94XhLwJc.BTj5", "short_salt"},
	{"$5$12345678901$QdspXWcGfNr9E/Y85tslyPjFt5yQzZLsnUTlFH5AXq4", "short_salt"},
	{"$5$123456789012$g4ldCaiyPo9fwJLJZV/oA1qux/hHElXYdgo//9UOqB6", "short_salt"},
	{"$5$1234567890123$rejKhy.g7TXlffFRqEgPxI1gTDbqt/LDuvfRPinDHs3", "short_salt"},
	{"$5$12345678901234$aKCh3GXmEudusN/fbNpSprqtwetjEGrEzNJdkAm9HF/", "short_salt"},
	{"$5$123456789012345$F0HVo5HW7oxYD6cYALYrLXPq.oILAyWpdjn9pdGw6M/", "short_salt"},

	// from a comment in the OpenCL implementation:
	//{"$5$EKt.VLXiPjwyv.xe$52wdOp9ixFXMsHDI1JcCw8KJ83IakDP6J7MIEV2OUk0", "1234567"},
	// from a comment in the CUDA implementaton:
	//{"$5$rounds=5000$abcdefghijklmnop$BAYQep7SsuSczAeXlks3F54SpxMUUludHi1C4JVOqpD","abcdefghijklmno"},
	{NULL}
};
#endif

#endif
