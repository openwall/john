/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_CRYPTSHA512_H
#define _COMMON_CRYPTSHA512_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */
/* Prefix for optional rounds specification.  */
#define ROUNDS_PREFIX           "rounds="
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT          5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN              1	/* Drepper has it as 1000 */
/* Maximum number of rounds.  */
#define ROUNDS_MAX              999999999

#define FORMAT_NAME		"crypt(3) $6$"
#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	0x107
#define FORMAT_TAG			"$6$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

/* ------- Check if the ciphertext if a valid SHA-512 crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ciphertext += FORMAT_TAG_LEN;

	if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;

		if (!strtoul(num, &endp, 10))
			return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
	}
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH)
		return 0;
	return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3)	  \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void * get_binary(char * ciphertext) {
	static uint32_t outbuf[64/4];
	uint32_t value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i = 0;

	do {
		TO_BINARY(i, (i+21)%63, (i+42)%63);
		i = (i+22)%63;
	} while (i != 21);
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6);
	out[63] = value;
	return (void *)out;
}

#ifdef __CRYPTSHA512_CREATE_PROPER_TESTS_ARRAY__
static struct fmt_tests tests[] = {
	{"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
	{"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
	{"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
	{"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
	{"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
	{"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
	// Special test cases, the first two exceed the plain text length of the GPU implementations
	//{"$6$va2Z2zTYTtF$1CzJmk3A2FO6aH.UrF2BU99oZOYcFlJu5ewPz7ZFvq0w3yCC2G9y4EsymHZxXe5e6Q7bPbyk4BQ5bekdVbmZ20", "123456789012345678901234"},
	//{"$6$1234567890123456$938IMfPJvgxpgwvaqbFcmpz9i/yfYSClzgfwcdDcAdjlj6ZH1fVA9BUe4GDGYN/68UiaR2.pLq4gXFfLZxpMr.", "123456789012345678901234"},

#if PLAINTEXT_LENGTH >= 79
	{"$6$z5rY05O8xEsEkPIo$e.KPoL.0xBWZHeyY8VQloVEKw2QuDGA9UT7lxO9qduym0ne9sSvl9PZowelKvyji41CYy9Yq0CgJzR6LrmW9m/", "1234567890123456789012345678901234567890123456789012345678901234567890123456789"},
	{"$6$6IVHO6ILuFRibuMu$SSTNvTegZ5r3jjAish2m1hqfJeX64.btBb8hDQZNvAPx/K.kBfPaFvcXYkC3YxHEBLaOed3UAVDz7NAm.otik0", "1234567890123456789012345678901"},
	{"$6$ApJWFvgJKcXwSN73$c1wipqpEWqOvcxKg0KcBpMQsNEdbxqIK9M1shyQsGKxIRxCSwcVjAXqGfTTiAJdCVlO2UcBVFNn8m0EjDrujB/", "12345678901234567890123456789012"},
	{"$6$7B9On3osTM18AJuu$g5gBc05cHNGyskbnLg87OU.BvblHZl0h4JFF7lx6n4qgCRJ6PUVfsruRQadl.eR4jEblHbEPRWK5vfDWWMCaQ.", "12345678901234567890123456789012345678901234567"},
	{"$6$mpsXsAli1bsaprT2$SBvVIA7N.Tk6Zb.PIHhdlzlUNYXt45XiI9BsOIzjdmo.63YGLoAUQ6TVmeOlMaFKALyQN7.f5xuloVBj2MTkb.", "123456789012345678901234567890123456789012345678"},
#endif
#if PLAINTEXT_LENGTH >= 24
	{"$6$qWotV46KKiE7Ys69$mk9slOOUDXIJ6ElSdzPJDVWFTkxynoUIHtOujyC7mwHe7ZuZp/UzhmHpBgvjahMrrxN55eowki.bTBT6AvRiL.", "123456789012345678901234"},
#endif
#if PLAINTEXT_LENGTH >= 15
	{"$6$DsS6VmHwcMRA5mAo$vWl2YYUsgN3PTtwDLKhfOIEixnA0USAWN2IswislKP7p8pISFLG6PfBJZU8Smekyl0NiReg552lOmEPaOjhKp/", "123456789012345"},
#endif
	{"$6$mwt2GD73BqSk4$ol0oMY1zzm59tnAFnH0OM9R/7SL4gi3VJ42AIVQNcGrYx5S1rlZggq5TBqvOGNiNQ0AmjmUMPc.70kL8Lqost.", "password"},
#ifdef DEBUG
	{"$6$rounds=391939$saltstring$P5HDSEq.sTdSBNmknrLQpg6UHp.9.vuEv6QibJNP8ecoNGo9Wa.3XuR7LKu8FprtxGDpGv17Y27RfTHvER4kI0", "amy"},
	{"$6$rounds=391939$saltstring$JAjUHgEFBJB1lSM25mYGFdH42OOBZ8eytTvKCleaR4jI5cSs0KbATSYyhLj3tkMhmU.fUKfsZkT5y0EYbTLcr1", "amy99"},
#endif
	{"$6$TtrrO3IN$D7Qz38n3JOn4Cc6y0340giveWD8uUvBAdPeCI0iC1cGYCmYHDrVXUEoSf3Qp5TRgo7x0BXN4lKNEj7KOvFTZV1", ">7fSy+N\\W=o@Wd&"}, // Password: >7fSy+N\W=o@Wd&
	{"$6$yRihAbCh$V5Gr/BhMSMkl6.fBt4TV5lWYY6MhjqApHxDL04HeTgeAX.mZT/0pDDYvArvmCfmMVa/XxzzOBXf1s7TGa2FDL0", "0H@<:IS:BfM\"V"},   // Password: 0H@<:IS:BfM"V
	{"$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/", "Hello world!"},
	{"$6$saltstring$fgNTR89zXnDUV97U5dkWayBBRaB0WIBnu6s4T7T8Tz1SbUyewwiHjho25yWVkph2p18CmUkqXh4aIyjPnxdgl0", "john"},
	{"$6$saltstring$MO53nAXQUKXVLlsbiXyPgMsR6q10N7eF7sPvanwdXnEeCj5kE3eYaRvFv0wVW1UZ4SnNTzc1v4OCOq1ASDQZY0", "a"},
	{"$6$saltstring$q.eQ9PCFPe/tOHJPT7lQwnVQ9znjTT89hsg1NWHCRCAMsbtpBLbg1FLq7xo1BaCM0y/z46pXv4CGESVWQlOk30", "ab"},
	{"$6$saltstring$pClZZISU0lxEwKr1z81EuJdiMLwWncjShXap25hiDGVMnCvlF5zS3ysvBdVRZqPDCdSTj06rwjrLX3bOS1Cak/", "abc"},
	{"$6$saltstring$FJJAXr3hydAPJXM311wrzFhzheQ6LJHrufrYl2kBMnRD2pUi6jdS.fSBJ2J1Qfhcz9tPnlJOzeL7aIYi/dytg.", "abcd"},
	{"$6$saltstring$XDecvJ/rq8tgbE1Pfuu1cTiZlhnbF5OA/vyP6HRPpDengVqhB38vbZTK/BDfPP6XBgvMzE.q9rj6Ck5blj/FK.", "abcde"},
	{"$6$saltstring$hYPEYaHik6xSMGV1lDWhF0EerSUyCsC150POu9ksaftUWKWwV8TuqSeSLZUkUhjGy7cn.max5qd5IPSICeklL1", "abcdef"},
	{"$6$saltstring$YBQ5J5EMRuC6k7B2GTsNaXx8u/957XMB.slQmY/lOjKd1zTIQF.ulLmy8O0VnJJ3cV.1pjP.KCgEjjMpz4pnS1", "abcdefg"},
	{"$6$saltstring$AQapizZGhnIjtXF8OCvbSxQJBuOKvpzf1solf9b76wXFX0VRkqids5AC4YSibbhMSX0z4463sq1uAd9LvKNuO/", "abcdefgh"},
	{"$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1", "abcdefghi"},
	{"$6$saltstring$Xet3A8EEzzSuL9hZZ31SfDVPT87qz3a.xxcH7eU50aqARlmXywdlfJ.6Cp/TFG1RcguqwrfUbZBbFn1BQ93Kv.", "abcdefghij"},
	{"$6$saltstring$MeML1shJ8psyh5R9YJUZNYNqKzYeBvIsITqc/VqJfUDs8xO5YoUhCn4Db7CXuarMDVkBzIUfYq1d8Tj/T1WBU0", "abcdefghijk"},
	{"$6$saltstring$i/3NHph8ZV2klLuOc5yX5kOnJWj9zuWbKiaa/NNEkYpNyamdQS1c7n2XQS3.B2Cs/eVyKwHf62PnOayqLLTOZ.", "abcdefghijkl"},
	{"$6$saltstring$l2IxCS4o2S/vud70F1S5Z7H1WE67QFIXCYqskySdLFjjorEJdAnAp1ZqdgfNuZj2orjmeVDTsTXHpZ1IoxSKd.", "abcdefghijklm"},
	{"$6$saltstring$PFzjspQs/CDXWALauDTav3u5bHB3n21xWrfwjnjpFO5eM5vuP0qKwDCXmlyZ5svEgsIH1oiZiGlRqkcBP5PiB.", "abcdefghijklmn"},
	{"$6$saltstring$rdREv5Pd9C9YGtg.zXEQMb6m0sPeq4b6zFW9oWY9w4ZltmjH3yzMLgl9iBuez9DFFUvF5nJH3Y2xidiq1dH9M.", "abcdefghijklmno"},
	{NULL}
};
#endif

#endif
