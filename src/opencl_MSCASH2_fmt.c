/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/
#include "formats.h"
#include"common.h"
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
#include"common-opencl.h"

#define INIT_MD4_A                  0x67452301
#define INIT_MD4_B                  0xefcdab89
#define INIT_MD4_C                  0x98badcfe
#define INIT_MD4_D                  0x10325476

#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1


#define FORMAT_LABEL	        "mscash2-opencl"
#define FORMAT_NAME		"MSCASH2-OPENCL"
#define KERNEL_NAME		"PBKDF2"

#define ALGORITHM_NAME		"PBKDF2_HMAC_SHA1"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define MSCASH2_PREFIX "$DCC2$"

#define MAX_KEYS_PER_CRYPT 800*80
#define MIN_KEYS_PER_CRYPT 800*80

#define MAX_SALT_LENGTH 15 //LENGTH OF SALT IN ASCII BEFORE CONVERTING TO TO UNICODE
#define MAX_PLAINTEXT_LENGTH 20
#define MAX_CIPHERTEXT_LENGTH 54 //7 + MAX_SALT_LENGTH + 32

#define BINARY_SIZE 16

# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

typedef struct 
 { unsigned char username[MAX_SALT_LENGTH+1];
   unsigned int length;
 } ms_cash2_salt;

//CUDA MSCASH2 IMPLEMENTATION
static struct fmt_tests tests[] = {
	//{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	  {"$DCC2$administrator#a150f71752b5d605ef0b2a1e98945611","a"},
	//{"$DCC2$administrator#c14eb8279e4233ec14e9d393637b65e2","ab"},
	//{"$DCC2$administrator#8ce9c0279b4e6f226f52d559f9c2c5f3","abc"},
	//{"$DCC2$administrator#2fc788d09fad7e26a92d12356fa44bdf","abcd"},
	//{"$DCC2$administrator#6aa19842ffea11f0f0c89f8ca8d245bd","abcde"},
	{NULL}
};

 cl_uint *dcc_hash_host;
 cl_uint *dcc2_hash_host;
 unsigned char key_host[MAX_KEYS_PER_CRYPT][MAX_PLAINTEXT_LENGTH+1]; 
 unsigned char ciphertext_host[MAX_KEYS_PER_CRYPT][MAX_CIPHERTEXT_LENGTH+1];
 ms_cash2_salt currentsalt;
 cl_platform_id pltfrmid;
 cl_device_id devid[1];
 cl_context cntxt;
 cl_command_queue cmdq;
 cl_program prg;
 cl_kernel krnl0;
 cl_int err;




void md4_crypt(unsigned int *buffer, unsigned int *hash)
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
 
    // round 1
    a = 0xFFFFFFFF  +  buffer[0]; a = (a << 3 ) | (a >> 29);
    d = INIT_MD4_D + (INIT_MD4_C ^ (a & 0x77777777)) + buffer[1]; d = (d << 7 ) | (d >> 25);
    c = INIT_MD4_C + (INIT_MD4_B ^ (d & (a ^ INIT_MD4_B))) + buffer[2]; c = (c << 11) | (c >> 21);
    b = INIT_MD4_B + (a ^ (c & (d ^ a))) + buffer[3]; b = (b << 19) | (b >> 13); 
 
    a += (d ^ (b & (c ^ d)))  +  buffer[4];  a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  +  buffer[5];  d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  +  buffer[6];  c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  +  buffer[7];  b = (b << 19) | (b >> 13);
 
    a += (d ^ (b & (c ^ d)))  + buffer[8] ;  a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  + buffer[9] ;  d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  + buffer[10];  c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  + buffer[11];  b = (b << 19) | (b >> 13);
 
    a += (d ^ (b & (c ^ d)))  + buffer[12]; a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  + buffer[13]; d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  + buffer[14]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  + buffer[15]; b = (b << 19) | (b >> 13);
 
    // round 2
    a += ((b & (c | d)) | (c & d)) + buffer[0]  + SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + buffer[4]  + SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + buffer[8]  + SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + buffer[12] + SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + buffer[1]  + SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + buffer[5]  + SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + buffer[9]  + SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + buffer[13] + SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + buffer[2]  + SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + buffer[6]  + SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + buffer[10] + SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + buffer[14] + SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + buffer[3]  + SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + buffer[7]  + SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + buffer[11] + SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + buffer[15] + SQRT_2; b = (b<<13) | (b>>19);         
 
    // round 3
    a += (d ^ c ^ b) + buffer[0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + buffer[8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + buffer[4]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[12] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + buffer[2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + buffer[10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + buffer[6]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[14] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + buffer[1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + buffer[9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + buffer[5]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[13] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + buffer[3]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
 
    d += (c ^ b ^ a) + buffer[11] +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + buffer[7]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[15] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    hash[0] = a + INIT_MD4_A;
    hash[1] = b + INIT_MD4_B;
    hash[2] = c + INIT_MD4_C;
    hash[3] = d + INIT_MD4_D;
}


unsigned char *byte2hexstring(unsigned char * byte, unsigned int len) {
    unsigned int i;
    unsigned char *hexstring;
 
    hexstring =(unsigned char*) malloc(len * 2 + 1);
    memset(hexstring,0, 2 * len + 1);
 
    for (i = 0; i < len; i++)
        sprintf((char*)&hexstring[2 * i], "%02x", byte[i]);
 
    return hexstring;
}



void PBKDF2_api(cl_uint *pass_api,cl_uint *salt_api,cl_uint saltlen_api,cl_uint *hash_out_api,int num)
{ 
  cl_mem pass,salt,hash_out;
  cl_event evnt;
  
  size_t N;
    
  pass=clCreateBuffer(cntxt,CL_MEM_READ_WRITE|CL_MEM_COPY_HOST_PTR,4*num*sizeof(cl_uint),pass_api,&err);
  if((pass==(cl_mem)0))  {printf("Create Buffer FAILED\n"); return;}
  
  salt=clCreateBuffer(cntxt,CL_MEM_READ_WRITE|CL_MEM_COPY_HOST_PTR,MAX_SALT_LENGTH*sizeof(cl_uint)/2 +1,salt_api,&err);
  if((salt==(cl_mem)0)) {printf("Create Buffer FAILED\n"); return;}
  
  hash_out=clCreateBuffer(cntxt,CL_MEM_READ_WRITE|CL_MEM_COPY_HOST_PTR,4*num*sizeof(cl_uint),hash_out_api,&err);
  if((hash_out==(cl_mem)0)) {printf("Create Buffer FAILED\n"); return;}
    
  
  
  if(clSetKernelArg(krnl0,0,sizeof(cl_mem),&pass)) {printf("Set Kernel FAILED.krnl0 arg0\n"); return;}
  if(clSetKernelArg(krnl0,1,sizeof(cl_mem),&salt)) {printf("Set Kernel FAILED.krnl0 arg1\n"); return;}
  if(clSetKernelArg(krnl0,2,sizeof(cl_uint),&saltlen_api)) {printf("Set Kernel FAILED.krnl0 arg2\n"); return;}
  if(clSetKernelArg(krnl0,3,sizeof(cl_mem),&hash_out))     {printf("Set Kernel FAILED.krnl0 arg3\n"); return;}

  N=num;
  if(clEnqueueNDRangeKernel(cmdq,krnl0,1,NULL,&N,NULL,0,NULL,&evnt)) {printf("Enqueue Kernel FAILED.krnl0\n"); return;}
  if(CL_SUCCESS!=clWaitForEvents(1,&evnt)) printf("SYNC FAILED\n");
  if(clEnqueueReadBuffer(cmdq,hash_out,CL_TRUE,0,4*num*sizeof(cl_uint),hash_out_api, 0, NULL, NULL)) {printf("Write Read FAILED\n"); return;} 
     
}

void DCC(unsigned char *salt,unsigned char *username,unsigned int username_len,unsigned char *password,unsigned int *dcc_hash,unsigned int id)
{
    unsigned int i;
    unsigned int buffer[16];
    unsigned int nt_hash[16];
    unsigned int password_len = strlen((const char*)password);
   
	memset(nt_hash, 0, 64);
    memset(buffer, 0, 64);
   
    // convert ASCII password to Unicode
     for(i = 0; i < password_len  >> 1; i++)  
        buffer[i] = password[2 * i] | (password[2 * i + 1] << 16);
    
    // MD4 padding
    if(password_len % 2 == 1)
        buffer[i] = password[password_len - 1] | 0x800000;
    else
        buffer[i]=0x80;
     
    // put password length at end of buffer
    buffer[14] = password_len << 4;
    
    // generate MD4 hash of the password (NT hash)
    md4_crypt(buffer, nt_hash);
 
    // concatenate NT hash and the username (salt)
    memcpy((unsigned char *)nt_hash + 16, salt, username_len << 1); 
   
    i = username_len + 8;
 
    // MD4 padding
    if(username_len % 2 == 1)
        nt_hash[i >> 1] = username[username_len - 1] | 0x800000;
    else
        nt_hash[i >> 1] = 0x80;
 
    // put length at end of buffer
    nt_hash[14] = i << 4; 
     
    md4_crypt(nt_hash, (dcc_hash+4*id));
	
}

static void init(struct fmt_main *pFmt)
{
  //Alocate memory for hashes and passwords
  dcc_hash_host=(cl_uint*)malloc(4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  dcc2_hash_host=(cl_uint*)malloc(4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  memset(dcc_hash_host,0,4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  memset(dcc2_hash_host,0,4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  opencl_init("$JOHN/pbkdf2_kernel.cl", gpu_id, platform_id);
  pltfrmid=platform[platform_id];
  devid[0]=devices[gpu_id];
  cntxt=context[gpu_id];
  cmdq=queue[gpu_id];
  prg=program[gpu_id];
  krnl0=clCreateKernel(prg,"PBKDF2",&err) ;
  if(err) {printf("Create Kernel PBKDF2 FAILED\n"); return ;}
  
}

static int valid(char *ciphertext,struct fmt_main *pFmt)
{   char *hash;
    int hashlength = 0;
	if(strncmp(ciphertext, MSCASH2_PREFIX, strlen(MSCASH2_PREFIX)) != 0) 		return 0;
	hash = strrchr(ciphertext, '#') + 1;
	if (hash == NULL)
	return 0;

	while (hash < ciphertext + strlen(ciphertext)) {
		if (atoi16[ARCH_INDEX(*hash++)] == 0x7f)
			return 0;
		hashlength++;
	   }
	if (hashlength != 32)
		return 0;
	
	return 1;
}

static void *binary(char *ciphertext)
{
	static unsigned int binary[4];
	int i;
	char *hash ;
	 hash= strrchr(ciphertext, '#') + 1;
	if (hash == NULL)
		return binary;
	
	for (i = 0; i < 4; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]);
		binary[i] = SWAP(binary[i]);
	}
	return binary;

}

static void *salt(char *ciphertext)
{   static ms_cash2_salt salt;
    unsigned int length;
	char *pos ; 
	length=0;
	pos=ciphertext + strlen(MSCASH2_PREFIX);
	while (*pos != '#')
	{   if(length==MAX_SALT_LENGTH){return NULL;} 
			salt.username[length++] = *pos++;
	} 
	salt.username[length] = 0;
	salt.length=length;
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(ms_cash2_salt));
}

static void set_key(char *key, int index)
{   int strlength,i;
    strlength=strlen(key);
	for(i=0;i<=strlength;++i)
		key_host[index][i]=key[i];

}

static  char *get_key(int index )
{ return (char *)key_host[index];
}

static void crypt_all(int count)
{    unsigned int i;
     unsigned char salt_unicode[MAX_SALT_LENGTH*2+1];
	 cl_uint salt_host[MAX_SALT_LENGTH/2 +1];
	 memset(salt_unicode,0,MAX_SALT_LENGTH*2+1);
     memset(salt_host,0,(MAX_SALT_LENGTH/2 +1)*sizeof(cl_uint));
     if(currentsalt.length%2==1)
     for(i = 0; i < (currentsalt.length >> 1) + 1; i++)
        ((unsigned int *)salt_unicode)[i] = currentsalt.username[2 * i] | (currentsalt.username[2 * i + 1] << 16);
     else
	   for(i = 0; i < (currentsalt.length >> 1) ; i++)
        ((unsigned int *)salt_unicode)[i] = currentsalt.username[2 * i] | (currentsalt.username[2 * i + 1] << 16);
	 
	for(i=0;i<count;i++) {
                                              DCC(salt_unicode,currentsalt.username,currentsalt.length,key_host[i],dcc_hash_host,i);
                                                   ciphertext_host[i][0]='\0';
						   strcat((char*)ciphertext_host[i],"$DCC2$");
						   strcat((char*)ciphertext_host[i],(const char*)currentsalt.username);
						   strcat((char*)ciphertext_host[i],"#");
	                     }
	memcpy(salt_host,salt_unicode,MAX_SALT_LENGTH*2+1);
	
	PBKDF2_api(dcc_hash_host,salt_host,currentsalt.length,dcc2_hash_host,count);
	
        for(i=0;i<count;i++)
	{  
		strcat((char*)ciphertext_host[i],(const char*)byte2hexstring((unsigned char*)(dcc2_hash_host+4*i),16));

	}
	
}

static int binary_hash_0(void *binary)
{
#ifdef _MSCASH2_DEBUG
	puts("binary");
	unsigned int i, *b = binary;
	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((unsigned int *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((unsigned int *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((unsigned int *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((unsigned int *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((unsigned int *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((unsigned int *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((unsigned int *) binary)[0] & 0x7ffffff;
}

static int get_hash_0(int index)
{
#ifdef _MSCASH2_DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 4; i++)
		printf("%08x ", dcc2_hash_host[index*4]);
	puts("");
#endif
	return dcc2_hash_host[index*4]& 0xf;
}

static int get_hash_1(int index)
{
	return dcc2_hash_host[index*4] & 0xff;
}

static int get_hash_2(int index)
{
	return dcc2_hash_host[index*4] & 0xfff;
}

static int get_hash_3(int index)
{
	return dcc2_hash_host[index*4] & 0xffff;
}

static int get_hash_4(int index)
{
	return dcc2_hash_host[index*4] & 0xfffff;
}

static int get_hash_5(int index)
{
	return dcc2_hash_host[index*4] & 0xffffff;
}

static int get_hash_6(int index)
{
	return dcc2_hash_host[index*4] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i, b = ((unsigned int *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == dcc2_hash_host[4*i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int i, *b = (unsigned int *) binary;
	for (i = 0; i < 4; i++)
		if (b[i] != dcc2_hash_host[index*4+i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{   unsigned int length;
    length=strlen((const char*)source);
	if(length!=strlen((const char*)ciphertext_host[count])) return 0;
	if(strncmp(source,(const char*)ciphertext_host[count],length)) return 0;
	return 1;
}

struct fmt_main fmt_opencl_mscash2 = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    ALGORITHM_NAME,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    MAX_PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    MAX_SALT_LENGTH*2,
		    MAX_KEYS_PER_CRYPT,
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
		    binary_hash_6},
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
		    get_hash_6},
		    cmp_all,
		    cmp_one,
	    cmp_exact}
};

