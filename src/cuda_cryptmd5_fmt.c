/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_common.h"
#include "cuda_cryptmd5.h"

#define FORMAT_LABEL		"cryptmd5-cuda"
#define FORMAT_NAME		FORMAT_LABEL

#define CRYPT_TYPE		"MD5-based CRYPT"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define BINARY_SIZE		16
#define SALT_SIZE		(8+1)
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

void md5_crypt_gpu(crypt_md5_password *,uint32_t *, crypt_md5_salt *);

static crypt_md5_password *inbuffer;//[MAX_KEYS_PER_CRYPT];			/** plaintext ciphertexts **/
static uint32_t *outbuffer;//[MAX_KEYS_PER_CRYPT*4];			/** calculated hashes **/
static crypt_md5_salt host_salt;					/** salt **/


//tests are unified for 8+8 length
static struct fmt_tests tests[] = {
/*	   {"$1$Btiy90iG$bGn4vzF3g1rIVGZ5odGIp/","qwerty"},
	   {"$1$salt$c813W/s478KCzR0NnHx7j0","qwerty"},
	   {"$1$salt$8LO.EVfsTf.HATV1Bd0ZP/","john"},
	   {"$1$salt$TelRRxWBCxlpXmgAeB82R/","openwall"},
	   {"$1$salt$l9PzDiECW83MOIMFTRL4Y1","summerofcode"},
	   {"$1$salt$wZ2yVsplRoPoD7IfTvRsa0","IamMD5"},
	   {"$1$saltstri$9S4.PyBpUZBRZw6ZsmFQE/","john"},
	   {"$1$saltstring$YmP55hH3qcHg2cCffyxrq/","ala"},
*/
//         {"$1$salt1234$mdji1uBBCWZ5m2mIWKvLW.","a"},
//         {"$1$salt1234$/JUvhIWHD.csWSCPvr7po0","ab"},
//         {"$1$salt1234$GrxHg1bgkN2HB5CRCdrmF.","abc"},
//         {"$1$salt1234$iZuyvTkrucWx8kVn5BN4M/","abcd"},
//         {"$1$salt1234$wn0RbuDtbJlD1Q.X7.9wG/","abcde"},

//         {"$1$salt1234$lzB83HS4FjzbcD4yMcjl01","abcdef"},
//          {"$1$salt1234$bklJHN73KS04Kh6j6qPnr.","abcdefg"}, 
	{"$1$salt1234$u4RMKGXG2b/Ud2rFmhqi70", "abcdefgh"},	//saltlen=8,passlen=8
//         {"$1$salt1234$QjP48HUerU7aUYc/aJnre1","abcdefghi"},
//         {"$1$salt1234$9jmu9ldi9vNw.XDO3TahR.","abcdefghij"},

//         {"$1$salt1234$d3.LnlDWfkTIej5Ef1sCU/","abcdefghijk"},
//         {"$1$salt1234$pDV0xEgZR14EpQMmhZ6Hg0","abcdefghijkl"},
//         {"$1$salt1234$WumpbolX2y45Dlv0.A1Mj1","abcdefghijklm"},
//         {"$1$salt1234$FXBreA27b7N7diemBGn5I1","abcdefghijklmn"},
//         {"$1$salt1234$8d5IPIbTd7J/WNEG4b4cl.","abcdefghijklmno"},

	//tests from korelogic2010 contest
/*	   {"$1$bn6UVs3/$S6CQRLhmenR8OmVp3Jm5p0","sparky"},
	   {"$1$qRiPuG5Z$pLLczmBnwEOD75Vb7YZLg1","walter"},
	   {"$1$E.qsK.Hy$.eX0H6arTHaGOIFkf6o.a.","heaven"},
	   {"$1$Hul2mrWs$.NGCgz3fBGDyG7RMGJAdM0","bananas"},
	   {"$1$1l88Y.UV$swt2d0SPMrBPkdAD8RwSj0","horses"},
	   {"$1$DiHrL6V7$fCVDD1GEAKB.BjAgJL1ZX0","maddie"},
	   {"$1$7fpfV7kr$7LgF64DGPtHPktVKdLM490","bitch1"},
	   {"$1$VKjk2PJc$5wbrtc9oa8kdEO/ocyi06/","crystal"},
	   {"$1$S66DxkFm$kG.QfeHNLifEDTDmf4pzJ/","claudia"},
	   {"$1$T2JMeEYj$Y.wDzFvyb9nlH1EiSCI3M/","august"}, 
	 
	   //tests from MD5_fmt.c
	   {"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	   {"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
	   {"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	   {"$1$$qRPK7m23GJusamGpoGLby/", ""},
	   {"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	   {"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	   {"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	   {"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	   {"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	   {"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	   {"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	   {"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
*/
	{NULL}
};

static void cleanup()
{
 free(inbuffer);
 free(outbuffer);
}

static void init(struct fmt_main *pFmt)
{  
  //Alocate memory for hashes and passwords
  inbuffer=(crypt_md5_password*)malloc(sizeof(crypt_md5_password)*MAX_KEYS_PER_CRYPT);
  outbuffer=(uint32_t*)malloc(sizeof(uint32_t)*MAX_KEYS_PER_CRYPT*4);
  check_mem_allocation(inbuffer,outbuffer);
  atexit(cleanup);
  //Initialize CUDA
  cuda_init(gpu_id);
}

static int valid(char *ciphertext,struct fmt_main *pFmt)
{
	uint8_t i, len = strlen(ciphertext), prefix = 0;

	if (strncmp(ciphertext, md5_salt_prefix, strlen(md5_salt_prefix)) == 0)
		prefix |= 1;
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0)
		prefix |= 2;
	if (prefix == 0)
		return 0;

	char *p = strrchr(ciphertext, '$');
	if (p == NULL)
		return 0;
	for (i = p - ciphertext + 1; i < len; i++) {
		uint8_t z = ARCH_INDEX(ciphertext[i]);
		if (ARCH_INDEX(atoi64[z]) == 0x7f)
			return 0;
	}
	if (len - (p - ciphertext + 1) != 22)
		return 0;
	return 1;
};

static int findb64(char c)
{
	int ret = ARCH_INDEX(atoi64[(uint8_t) c]);
	return ret != 0x7f ? ret : 0;
}

static void to_binary(char *crypt, char *alt)
{

#define _24bit_from_b64(I,B2,B1,B0) \
  {\
      unsigned char c1=findb64(crypt[I+0]);\
      unsigned char c2=findb64(crypt[I+1]);\
      unsigned char c3=findb64(crypt[I+2]);\
      unsigned char c4=findb64(crypt[I+3]);\
      unsigned int w=c4<<18|c3<<12|c2<<6|c1;\
      unsigned char b2=w&0xff;w>>=8;\
      unsigned char b1=w&0xff;w>>=8;\
      unsigned char b0=w&0xff;w>>=8;\
      alt[B2]=b0;\
      alt[B1]=b1;\
      alt[B0]=b2;\
  }

	_24bit_from_b64(0, 0, 6, 12);
	_24bit_from_b64(4, 1, 7, 13);
	_24bit_from_b64(8, 2, 8, 14);
	_24bit_from_b64(12, 3, 9, 15);
	_24bit_from_b64(16, 4, 10, 5);
	uint32_t w = findb64(crypt[21]) << 6 | findb64(crypt[20]) << 0;
	alt[11] = (w & 0xff);
}

static void *binary(char *ciphertext)
{
	static char b[BINARY_SIZE];
	memset(b, 0, BINARY_SIZE);
	char *p = strrchr(ciphertext, '$') + 1;
	to_binary(p, b);
	return (void *) b;
}


static void *salt(char *ciphertext)
{
	static uint8_t ret[SALT_SIZE];
	memset(ret, 0, SALT_SIZE);
	uint8_t i, *pos = (uint8_t *) ciphertext, *dest = ret, *end;

	if (strncmp(ciphertext, md5_salt_prefix, strlen(md5_salt_prefix)) == 0) {
		pos += strlen(md5_salt_prefix);
		ret[8] = '1';
	}
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0) {
		pos += strlen(apr1_salt_prefix);
		ret[8] = 'a';
	}
	end = pos;
	for (i = 0; i < 8 && *end != '$'; i++, end++);
	while (pos != end)
		*dest++ = *pos++;
	return (void *) ret;
}

static int binary_hash_0(void *binary)
{
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}
static void set_salt(void *salt)
{
	uint8_t *s = salt;
	uint8_t len;
	for (len = 0; len < 8 && s[len]; len++);
	host_salt.saltlen = len;
	memcpy(host_salt.salt, s, host_salt.saltlen);
	host_salt.prefix = s[8];
}

static void set_key(char *key, int index)
{
	uint32_t len = strlen(key);
	inbuffer[index].length = len;
	memcpy((char *) inbuffer[index].v, key, len);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static void crypt_all(int count)
{
	md5_crypt_gpu(inbuffer, outbuffer, &host_salt);
}

static int get_hash_0(int index)
{
	return outbuffer[address(0, index)] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[address(0, index)] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[address(0, index)] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[address(0, index)] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[address(0, index)] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[address(0, index)] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[address(0, index)] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if(b==outbuffer[address(0,i)])
		return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint32_t i, *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if(t[i]!=outbuffer[address(i, index)])
		  return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_cuda_cryptmd5 = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    CRYPT_TYPE,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT,
	    tests},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
		    {
				binary_hash_0,
				binary_hash_1,
				binary_hash_2,
				binary_hash_3,
				binary_hash_4,
				binary_hash_5,
				binary_hash_6
		    },
		    fmt_default_salt_hash,
		    set_salt,
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
	    cmp_exact,
		fmt_default_get_source
	}
};
