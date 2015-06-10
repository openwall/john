/* Cracker for "lineage" (aka invulnerable) hashes.
 *
 * This hash format was seen in the PHDays Hash Runner 2015 content, and it
 * apparently exists in the wild too. Based on cryptsha512* files in JtR.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2015 , Aleksey Cherepanov <lyosha [at] openwall.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */


#include "arch.h"

#if (AC_BUILT && HAVE_CRYPT)

#define FMT_STRUCT_NAME fmt_lineage

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT_NAME;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT_NAME);
#else

#include <assert.h>
#include <unistd.h>
#include "formats.h"
#include "common.h"
#include "johnswap.h"
#include "base64.h"

/* remove to enable debug printing */
#define printf(...)

#define ROUNDS_PREFIX           "rounds="
#define ROUNDS_DEFAULT          5000
#define ROUNDS_MIN              1 /* Drepper has it as 1000 */
#define ROUNDS_MAX              999999999
#define SALT_LENGTH             16


#define FORMAT_LABEL            "lineage"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "lineage"

#define FORMAT_TAG              "$lineage$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

/* up to 16 chars are used for quick check */
#define PLAINTEXT_LENGTH        125

/* 16 base64 chars */
#define BINARY_SIZE             12
#define BINARY_ALIGN            MEM_ALIGN_WORD

#define SALT_SIZE               0
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define CIPHERTEXT_LENGTH       86

static struct fmt_tests tests[] = {
	{"$lineage$$6$rounds=5000$gTLyhjtf/ExB4234$z4mzW4JbhldIqR7te8HGdMsC/6DlwtN2zI/GjFyGSMOlvhcmuctOFUyeaCBgIgOHz6yY3Ul0IY/QQr6.HnaIh.", "ZxcvbnZxcvbn"},
	{"$6$rounds=5000$oYJjwEHmRYuC6WY8$QzHVQLZuEZHxAVOGKeFiRbCAVefmcEJTlU1yviFPkT5YMmcs1nO6OVV3lnimS4n5Ughwdhf5AWvGG06x5RRpa1", "juliajulia"},
	{"$6$rounds=5000$sZaJohuoStht3EO4$h5GR0B5gZa3zPOsdsAzmw9cptSdeOychlKjeL6cWqrp28myUY5Dp5sDVEM5eYWaGB0zTPmlaE4p0Ci92J64j5/", "bulletbullet"},
	{"$6$rounds=5000$tTndIJEuzR/ysaH2$X30oa7pdS7eif4rPeaKBlmZ6TPFralg8cB4TtwzC2qP.aiLLt.yYGejLWn.p1c3/ejs/Ljg7.ma1utz1gmy3d0", "pepsipepsi"},
	{"$6$rounds=5000$tQvOdMV6dUJHRVYB$GLvXXUCMqhX93zFakkEYHRo./jJRmfioBHotzSVk4I5dICjNu57pOyFWR2vxqB1dD7epst4UC1s8mL.00yht6/", "TestiTesti"},
	{"$6$rounds=5000$RQ7UqxYvG6YTovUT$8k4UEjT1qMjVBqjv7H5i6cTfli5qxO1Xdc2QWM2h2Hd7lJmHDDl7riT51ji5pt2VZxptXQp1naNbYZ2Nf72lG.", "yellowyellow"},
	{"$6$rounds=5000$IeOBvw72rV1YqHop$.LXIB6qJ0MEFuQtFgMVOaOgAupKJ52DCaPj4CHWIKUg7aQXtzTm85nBbo5GpgQMJgpJZALPHGW1Pm0pmRD8GB.", "keithkeith"},
	{"$6$rounds=5000$MUl7WOEdKTdGcMtx$P8oiOmLBkNFmw6ZmJdC9nGwM37r45yjXhNu.PWUle0xuy6pSH9V2v/qSjXm5bSx/flTQw07zJcKrl42q14J1n1", "Charlotte9"},
	{"$6$rounds=5000$MXmjmCUU3bEYzB3P$AMPTnBbbhNNxgkfPGDrxIbfGrVLWxqkBSZMB7GwQVyP58g9B/IngSlN9VrDaYL6ECCu8qclZpvH4apCjGc6dh0", "chancechance"},
	{"$6$rounds=5000$tTqi3ucHYTbfyA4S$OyuHgxW8oypfz9QvgQ113UK/TM9GXelKJjQB1HIcdCD2.RaV42lxmWsNFy8yHGt.ld9mZUrPEfAGqgmFyjANo1", "1234567892013"},
	{"$6$rounds=5000$tTolUGmB47VcS42R$c5Bh5CtUL.ALboWlEq4DtEkznwbzpt9fEdhpIoERiBOp/.S/uaAP1LSG8w9G6NDfMQI/Mfa1AkcVBWgsMoeKp0", "1478523692013"},
	{"$6$rounds=5000$MbeHx3p+cA/aWllZ$PxXLcCUDhKVJekJGOYPY45S7hQ/m4o5Gi.s20OOdU0I8EizpUblNqjEbmCR.2oMNc4UKFAGOsQVAjSYHWppEY/", "cAlenDar"},
	{"$6$rounds=5000$Ieshd851y+OShsrL$a1.3IiIvtSTBQFuhKwNoNqT8GVTcE8MRYvjy4AdmjNsq4F1qX3v/IGYtxsfGkY0o3WB98fe9BhcTUxk.TZMC5.", "kaTHeRine"},
	{"$6$rounds=5000$qRy0WeDkTLpv7+zs$GGiq1UTaF1h54y2L5pc8xxj8E.CojzfaXXB2kUxvdUMbpfJvbO2sm8Jd728TKNkFFxrp0m0lyUGvcjYv29cbg/", "FREeDoM"},
	{"$6$rounds=5000$KdG42WjXT9oPj4yM$M1BzWOx64FGrGKyOKEDmCtL2272njzfq72r0d83d0nXZGmamklpCPAWxM2tZd4Az8z8eKrAvyCaoyFgQahZbu.", "GAbrieL"},

	{"$6$rounds=5000$tRP0pRz01PQhoaKi$WwzQG6SPoV883KLbRz3uBStsrLGgBfyRnttVYWiw3XpJJEeDjM5YHwn/QowaSz5cIxruRmEFa9AmzDqsXgn0I0", "DIgITAL"},
	{"$6$rounds=5000$tTqi3ucHYTbfDGdt$UekRxnFJpNDsiS11f.fa.Y9a03F2Jvmng0z4A53xhgdWiT9SRK6xQ.3oP7ACT5GxelVeaSj8V5jXCtW0t16fv0", "123456789987654321"},
	{"$6$rounds=5000$wWIKf8KmLf6rkcvD$RfgN07zfWBgzBGpRQ50kmwDsEEr5IsytAlRkADKawlUW4VGHa.yqSxpyazLyHlB2J8kS9mplxaPDwZsK/sNYY1", "zxcvbnm2011"},
	{"$6$rounds=5000$sbYhkCnhZddin4gv$ThNVO8UQMDp3oqxwvNti5I2qh5H3gbj67rem8u90aSB6/DyVaruFSyjYmoDM1pFgE7y.5ppMLODr1cNZCWyCl/", "beautifulbeautiful"},
	{"$6$rounds=5000$tTlFadSudQylb91Q$DOq9XuASlIznbfHOGX59lvJIOYLG60rntjOv1Vpi6dPKvyhtF96Mkm4683.K5H1BXuOqOP3RSPmD4sCS05k.4.", "pacificpacific"},
	{"$6$rounds=5000$ydgedcjt4jZjWdvQ$1ynkfIpgFwZ7Q9FIRglo4Ez4xZhsGLo4e68Qxwg31xFMRz1ZZDIPcbr1VdzRFCu4mgxFkFLwmMfx56TrHMEnd/", "vanessa2015"},
	{"$6$rounds=5000$CcngijOIL6AJcYEc$9eEtl4Z9ETxC45/Qt9aamCTJKK05AWzF.bzeNAqn95jITjQ6GmXwfWBsajnnJ.BDNyBDWRoaX1s6UANa1gCeD.", "WalleyeWalleye"},
	{"$6$rounds=5000$SYHaYdhj/+K3jdff$egjGbf4wL3QolD7uH5Ffdv27ffCM8dxAGYoYCG5Ykfq9LZcLgjjrOk9pRjirBwLaOzbz/QrnSyoxx7WUCyk.h0", "western2011"},
	{"$6$rounds=5000$tZmPlyoD8amspAQu$M6UCxnKbypa0IiHzY3ID.g/xGrfxJxejZlttCGYS034Zubol5U1bYnh6YOipYSVdvEzO76j2WBLsIP47FxbYh.", "transporttransport"},
	{"$6$rounds=5000$MXkha9b3OZqLHEa7$AIzBCDz.t/Gulq6osIHnTWPEbe6kPoHylYBeCIDK7HBoP/WeAO4bTzYiCaQw9AntsCpNzONNdVqZhQ4Z.NhHw/", "christianchristian"},
	{"$6$rounds=5000$pREenCXR30d6BKHt$sOuF60hq7nKp61xQDnrdAxnhrGvZoSPpazybCb1zb3YIiXFEA5dwh3Y6VzPvlbcwnE.Wlds9YI2hLGMVf1Q1s/", "houstonhouston"},
	{"$6$rounds=5000$CXuSlhegK/0gCJby$OPt9ogKnCx9TlolVVr8ciXwu4TZKscPl5sc9dk1RdDryVoiqccQxJAgRQLLi3LodlaUw42ZBNWvClnasPlwfx.", "WhocaresWhocares"},
	{"$6$rounds=5000$NXrgVHXSIIzZ0bbS$rFjBakFOJ.q4RekRfjWqX5915JQy/1Jv4u2eZhD6g7dVTD2CHsIBYnLvguWeomee/76Dihodzo8CXDK1VJPQV.", "000000000000000000000000"},
	{"$6$rounds=5000$JWibYN3kFUMy1paD$Txbaeuk80cFdPUSd1pjqm6Xj2Q40eqHJEA6YCFTQckxIxyaSJfYPH5flZJB/9NFEO5WgTyewElio4YKUyj4ds/", "medicalmedicalmedicalmedical"},
	{"$6$rounds=5000$McdPKpMotnYHf8rV$KIVLHZNX4hPqv7kB.hgyZty03EJRYEu/eqM/hv8xcru1OynmFz0XZvqGhnZXINNXUInzn7aGsTqKhqjnBHiH3/", "Catherine2012"},
	{"$6$rounds=5000$tTOvVejRrMsenp2d$/RMSSA85cpygejcWDPineQqV5Gl3JI5gYiGbu16TH6Kbr26MDNf5KW2UekE5QPsdpnP2CXSMxRSFKhLl2xUra.", "dctIon"},
	{"$6$rounds=5000$NfK+DzIXLaqnY7LT$3ySozgdI2H6n21B44nThYLs5HMO60sq.r//3K1p1LY/7J5gVDdHeAfovDBYNUlOAOb0aFxSz.PvyHr3328oA01", "abc123abc1232015"},
	{"$6$rounds=5000$qZjjxn/8nJ2USXxh$I88UhJzQ40j.h6yrbH.Z2/DKD/W9n.qWcVnd25UH9R0/XfyaO37ukoKypS8Yob333KFlDg6iUcri0HItSuhuD/", "november19992015"},
	{NULL}
};

#define make_full_static_buf(type, var, len) static type (var)[(len)]
#define make_dynamic_static_buf(type, var, len)         \
    static type *var;                                   \
    if (!var)                                           \
        var = mem_alloc_tiny((len), MEM_ALIGN_WORD)


#if 1
#define make_static_buf make_dynamic_static_buf
#else
#define make_static_buf make_full_static_buf
#endif
/* "make_static_buf" to make dabbrev pick this. */

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 2];

static unsigned char crypt_out[MAX_KEYS_PER_CRYPT][BINARY_SIZE + 1];

static void init(struct fmt_main *self)
{
	/* make_static_buf(ARCH_WORD_64, buf, 20); */
	/* char *t = "ASNFZ4mrze8="; */
	/* base64_decode(t, strlen(t), buf); */
	/* printf(">> %016llx\n", buf[0]); */
}

/* ------- Check if the ciphertext if a valid SHA-512 crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	if (strncmp(ciphertext, "$6$", 3))
		return 0;

#define const_salt "$6$rounds=5000$"

	if (strncmp(ciphertext, const_salt, sizeof(const_salt) - 1))
		return 0;
	else
		ciphertext += sizeof(const_salt) - 1;

	for (pos = ciphertext; *pos && *pos != '$'; pos++)
		;

	if (!*pos || pos != &ciphertext[SALT_LENGTH] || *pos != '$')
		return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F)
		pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	make_static_buf(char, out, TAG_LENGTH + CIPHERTEXT_LENGTH + SALT_LENGTH + sizeof(const_salt) + 1);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + SALT_LENGTH + sizeof(const_salt) + 1);
	return out;
}

/* We store only "salt" */
static void *binary(char *ciphertext)
{
	make_static_buf(unsigned char, buf, BINARY_SIZE);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	assert(strncmp(ciphertext, const_salt, sizeof(const_salt) - 1) == 0);

	ciphertext += sizeof(const_salt) - 1;

	assert(ciphertext[BINARY_SIZE/3*4] == '$');
	/* given hashes had length of salt == 16 always. we don't check it */

	base64_decode(ciphertext, BINARY_SIZE/3*4, (char*)buf);
	/* memcpy(buf, ciphertext, BINARY_SIZE); */
	return buf;
}

#define make_get_hash(num, mask) \
	static int get_hash_ ## num (int index) { return ((unsigned long long *)crypt_out[index])[0] & mask; }

make_get_hash(0, 0xf)
make_get_hash(1, 0xff)
make_get_hash(2, 0xfff)
make_get_hash(3, 0xffff)
make_get_hash(4, 0xfffff)
make_get_hash(5, 0xffffff)
make_get_hash(6, 0x7ffffff)

static void set_key(char *key, int index)
{
	strcpy(saved_key[index], key);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
#define T unsigned long long
	T rslt, one, two, three, four;
	T nBytes;
	int index = 0;
	T key[20];
	T dst[20];
	size_t i;

	T p1_1 = 213119;    T p1_2 = 2529077;
	T p2_1 = 213247;    T p2_2 = 2529089;
	T p3_1 = 213203;    T p3_2 = 229589;
	T p4_1 = 213821;    T p4_2 = 2529997;

	for (i = 0; i < 20; i++) {
		key[i] = 0;
		dst[i] = 0;
	}

	i = 0;

#define str (saved_key[index])

	nBytes = strlen((char*)str);
	while (i < nBytes && i < 19) {
		i++;
		key[i] = str[i - 1];
		dst[i] = key[i];
	}


#define intval

	rslt = key[1] + key[2]*256 + key[3]*65536 + key[4]*16777216;
	one = rslt * p1_1 + p1_2;
	/* one = one - intval(one/ 4294967296) * 4294967296; */
	one = one % 4294967296;

	rslt = key[5] + key[6]*256 + key[7]*65536 + key[8]*16777216;
	two = rslt * p2_1 + p2_2;
	/* two = two - intval(two/ 4294967296) * 4294967296; */
	two = two % 4294967296;

	rslt = key[9] + key[10]*256 + key[11]*65536 + key[12]*16777216;
	three = rslt * p3_1 + p3_2;
	/* three = three - intval(three/ 4294967296) * 4294967296; */
	three = three % 4294967296;

	rslt = key[13] + key[14]*256 + key[15]*65536 + key[16]*16777216;
	four = rslt * p4_1 + p4_2;
	/* four = four - intval(four/ 4294967296) * 4294967296; */
	four = four % 4294967296;

	key[4] = intval(one/16777216);
	key[3] = intval((one - key[4] * 16777216) / 65535);
	key[2] = intval((one - key[4] * 16777216 - key[3] * 65536) / 256);
	key[1] = intval((one - key[4] * 16777216 - key[3] * 65536 - key[2] * 256));

	key[8] = intval(two/16777216);
	key[7] = intval((two - key[8] * 16777216) / 65535);
	key[6] = intval((two - key[8] * 16777216 - key[7] * 65536) / 256);
	key[5] = intval((two - key[8] * 16777216 - key[7] * 65536 - key[6] * 256));

	key[12] = intval(three/16777216);
	key[11] = intval((three - key[12] * 16777216) / 65535);
	key[10] = intval((three - key[12] * 16777216 - key[11] * 65536) / 256);
	key[9] = intval((three - key[12] * 16777216 - key[11] * 65536 - key[10] * 256));

	key[16] = intval(four/16777216);
	key[15] = intval((four - key[16] * 16777216) / 65535);
	key[14] = intval((four - key[16] * 16777216 - key[15] * 65536) / 256);
	key[13] = intval((four - key[16] * 16777216 - key[15] * 65536 - key[14] * 256));

	dst[1] = dst[1] ^ key[1];

	i=1;
	while (i<16){
		i++;
		dst[i] = dst[i] ^ dst[i-1] ^ key[i];
	}

	i=0;
	while (i<16){
		i++;
		if (dst[i] == 0) {
			dst[i] = 102;
		}
	}

	/* We take only BINARY_SIZE out */
	for (i = 0; i < BINARY_SIZE; i++)
		crypt_out[index][i] = dst[i + 1];

	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	size_t i;
	unsigned long long b = ((unsigned long long *)binary)[0];
	for (i = 0; i < count; i++) {
		unsigned long long v = ((unsigned long long *)crypt_out[i])[0];
		if (v == b)
			return 1;
		if (memcmp(crypt_out[i], binary, BINARY_SIZE))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	/* quick check */
	unsigned long long b = ((unsigned long long *)binary)[0];
	unsigned long long v = ((unsigned long long *)crypt_out[index])[0];
	if (v != b)
		return 0;
	if (memcmp(crypt_out[index], binary, BINARY_SIZE))
		return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	char *out;
	if (!strncmp(source, FORMAT_TAG, TAG_LENGTH))
		source += TAG_LENGTH;
	/* crypt_r() here? */
	out = crypt(saved_key[index], source);
	if (strcmp(out, source))
		return 0;
	return 1;
}


struct fmt_main FMT_STRUCT_NAME = {
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
		/* SALT_SIZE, */
		0,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif
