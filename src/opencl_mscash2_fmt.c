/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
* This format supports salts upto 19 characters.
* Minor bugs in original S3nf implementation limits salts upto 8 characters.
*/

#include "formats.h"
#include "common.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include "common_opencl_pbkdf2.h"
#include <omp.h>

#define INIT_MD4_A                  0x67452301

#define INIT_MD4_B                  0xefcdab89

#define INIT_MD4_C                  0x98badcfe

#define INIT_MD4_D                  0x10325476

#define SQRT_2                      0x5a827999

#define SQRT_3                      0x6ed9eba1


#define FORMAT_LABEL	           "mscash2-opencl"

#define FORMAT_NAME		   "MSCASH2-OPENCL"

#define KERNEL_NAME		   "PBKDF2"

#define ALGORITHM_NAME		   "PBKDF2_HMAC_SHA1"


#define BENCHMARK_COMMENT	   ""

#define BENCHMARK_LENGTH	  -1


#define MSCASH2_PREFIX            "$DCC2$"


#define MAX_KEYS_PER_CRYPT        65536*4

#define MIN_KEYS_PER_CRYPT        65536*4

#define MAX_PLAINTEXT_LENGTH      40

#define MAX_CIPHERTEXT_LENGTH     7 + MAX_SALT_LENGTH + 32


#define BINARY_SIZE               4


# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))


typedef struct 
{ 
	unsigned char username[MAX_SALT_LENGTH+1];
   
	unsigned int length;
	
} 	ms_cash2_salt;



static struct fmt_tests tests[] = {
	{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	{"$DCC2$test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"$DCC2$test4#6f79ee93518306f071c47185998566ae", "test4" },
	{"$DCC2$january#26b5495b21f9ad58255d99b5e117abe2", "verylongpassword" },
	{"$DCC2$february#469375e08b5770b989aa2f0d371195ff", "(##)(&#*%%" },
	{"$DCC2$nineteen_characters#c4201b8267d74a2db1d5d19f5c9f7b57", "verylongpassword" }, //max salt_length
	{"$DCC2$nineteen_characters#87136ae0a18b2dafe4a41d555425b2ed", "w00t"},
	{"$DCC2$administrator#56f8c24c5a914299db41f70e9b43f36d", "w00t" },
	{"$DCC2$eighteencharacters#fc5df74eca97afd7cd5abb0032496223", "w00t" },
	{"$DCC2$john-the-ripper#495c800a038d11e55fafc001eb689d1d", "batman#$@#1991" },
	
	
	{NULL}
};


	static cl_uint *dcc_hash_host;

	static cl_uint *dcc2_hash_host;

	static unsigned char key_host[MAX_KEYS_PER_CRYPT][MAX_PLAINTEXT_LENGTH+1]; 

	static ms_cash2_salt currentsalt;


static void md4_crypt(unsigned int *buffer, unsigned int *hash)
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

static void set_key(char*, int);
static void cleanup(void);
static  void crypt_all(int);


static void init(struct fmt_main *pFmt)
{
	///Alocate memory  
	dcc_hash_host=(cl_uint*)malloc(4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  
	dcc2_hash_host=(cl_uint*)malloc(4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  
	memset(dcc_hash_host,0,4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
  
	memset(dcc2_hash_host,0,4*sizeof(cl_uint)*MAX_KEYS_PER_CRYPT);
	
	///Select devices select_device(int platform_no, int device_no)
	//select_device(1,0);
	//select_device(1,1);
	///select default platform=0 and default device=0
	select_default_device();
	
	atexit(cleanup);
  
}


static void DCC(unsigned char *salt,unsigned char *username,unsigned int username_len,unsigned char *password,unsigned int *dcc_hash,unsigned int id)
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


static void cleanup()
{
	free(dcc_hash_host);
	
	free(dcc2_hash_host);
	
			
}


static int valid(char *ciphertext,struct fmt_main *pFmt)
{   
	char *hash;
    
	int hashlength = 0;
	
	if(strncmp(ciphertext, MSCASH2_PREFIX, strlen(MSCASH2_PREFIX)) != 0) 		return 0;
	
	hash = strrchr(ciphertext, '#') + 1;
	
	if (hash == NULL)
	    return 0;

	
	while (hash < ciphertext + strlen(ciphertext))
	      {
		  if (atoi16[ARCH_INDEX(*hash++)] == 0x7f)
			  return 0;
		
		  hashlength++;
	      }
	
	if (hashlength != 32)  return 0;
	
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
{   
	static ms_cash2_salt salt;
  
	unsigned int length;
  
	char *pos ; 
  
	length=0;
  
	pos=ciphertext + strlen(MSCASH2_PREFIX);
  
	while (*pos != '#')
	      {   
		if(length==MAX_SALT_LENGTH)
		return NULL; 
	  
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
{   
	int strlength,i;
   
	strlength=strlen(key);

	for(i=0;i<=strlength;++i)
	    key_host[index][i]=key[i];

}



static  char *get_key(int index )
{
	return (char *)key_host[index];
}

static void crypt_all(int count)
{    
	unsigned int i;
#ifdef _DEBUG     	
	struct timeval startc,endc,startg,endg;
	gettimeofday(&startc,NULL);
#endif          
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
	
	memcpy(salt_host,salt_unicode,MAX_SALT_LENGTH*2+1);
	
#ifdef _OPENMP	
#pragma omp parallel for private(i) firstprivate(count) shared(salt_unicode,currentsalt,key_host,dcc_hash_host)
#endif	   
	for(i=0;i<count;i++)    DCC(salt_unicode,currentsalt.username,currentsalt.length,key_host[i],dcc_hash_host,i);
	
#ifdef _DEBUG
	gettimeofday(&startg,NULL);
#endif	
	
	///defined in common_opencl_pbkdf2.c. Details provided in common_opencl_pbkdf2.h
	pbkdf2_divide_work(dcc_hash_host,salt_host,currentsalt.length,dcc2_hash_host,count);
	
	
#ifdef _DEBUG	
	gettimeofday(&endg,NULL);
	gettimeofday(&endc, NULL);
	printf("\nGPU:%f  ",(endg.tv_sec-startg.tv_sec)+(double)(endg.tv_usec-startg.tv_usec)/1000000.000);
	printf("CPU:%f  ",(endc.tv_sec-startc.tv_sec)+(double)(endc.tv_usec-startc.tv_usec)/1000000.000 - ((endg.tv_sec-startg.tv_sec)+(double)(endg.tv_usec-startg.tv_usec)/1000000.000));
#endif	
}



static int binary_hash_0(void *binary)
{
#ifdef _DEBUG
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
#ifdef _DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 4; i++)
		printf("%08x ", dcc2_hash_host[index]);
	puts("");
#endif
	return dcc2_hash_host[4*index]& 0xf;
}

static int get_hash_1(int index)
{
	return dcc2_hash_host[4*index] & 0xff;
}

static int get_hash_2(int index)
{
	return dcc2_hash_host[4*index] & 0xfff;
}

static int get_hash_3(int index)
{
	return dcc2_hash_host[4*index] & 0xffff;
}

static int get_hash_4(int index)
{
	return dcc2_hash_host[4*index] & 0xfffff;
}

static int get_hash_5(int index)
{
	return dcc2_hash_host[4*index] & 0xffffff;
}

static int get_hash_6(int index)
{
	return dcc2_hash_host[4*index] & 0x7ffffff;
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
	return 1;
}



static int cmp_exact(char *source, int count)
{   
      unsigned int *bin,i;
      
      bin=(unsigned int*)binary(source);
      
      i=4*count+1;
      
      if(bin[1]!=dcc2_hash_host[i++])   return 0;
      
      if(bin[2]!=dcc2_hash_host[i++]) return 0;
      
      if(bin[3]!=dcc2_hash_host[i]) return 0;
      
      return 1;
    
      
}



static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{	
	char *cp;
	
	if (!strncmp(split_fields[1], "$DCC2$", 6) && valid(split_fields[1], pFmt))
	   return split_fields[1];
	
	if (!split_fields[0])
	   return split_fields[1];
	
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	
	sprintf (cp, "$DCC2$%s#%s", split_fields[0], split_fields[1]);
	
	if (valid(cp, pFmt))
	{
		char *cipher = str_alloc_copy(cp);
		
		MEM_FREE(cp);
		
		return cipher;
	}
	
	MEM_FREE(cp);
	
	return split_fields[1];
}

void clear_keys()
{ 
	int i;
	
	memset(dcc2_hash_host,0,MAX_KEYS_PER_CRYPT);
	
	for(i=0;i<MAX_KEYS_PER_CRYPT;i++)
		memset(key_host[i],0,MAX_PLAINTEXT_LENGTH );
  
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
		    MAX_SALT_LENGTH*2+1,
		    MAX_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT|FMT_OMP ,
	            tests
	},{
		    init,
		    prepare,
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
		    clear_keys,
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

