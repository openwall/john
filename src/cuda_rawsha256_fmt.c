/*
* This software is Copyright (c) 2011 Lukas Odzioba
* <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* This file is shared by cuda-rawsha224 and cuda-rawsha256 formats, 
* SHA256 definition is used to distinguish between them. 
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_common.h"
#include "cuda_rawsha256.h"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1 /// Raw benchmark
#define PLAINTEXT_LENGTH	54
#define SALT_SIZE		0

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT	
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#ifdef SHA256
  #define FORMAT_NAME		"raw-sha256-cuda"
  #define SHA_TYPE		"SHA256" 
  #define CIPHERTEXT_LENGTH	64 ///256bit
  #define BINARY_SIZE		32
  #define SHA_HASH		sha256_hash
  #define TESTS			sha256_tests
  #define FMT_MAIN		fmt_cuda_rawsha256
  static struct fmt_tests sha256_tests[]={
  {"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc","openwall"},
  {NULL}  
  };
#endif
#ifdef SHA224
  #define FORMAT_NAME		"raw-sha224-cuda"
  #define SHA_TYPE		"SHA224" 
  #define CIPHERTEXT_LENGTH	56 ///224bit
  #define BINARY_SIZE		32 
  #define SHA_HASH 		sha224_hash
  #define TESTS			sha224_tests
  #define FMT_MAIN		fmt_cuda_rawsha224
  static struct fmt_tests sha224_tests[]={
  {"d6d8ff02342ea04cf65f8ab446b22c4064984c29fe86f858360d0319","openwall"},
  {NULL}  
  };
#endif
extern void gpu_rawsha256(sha256_password *,SHA_HASH*);
extern void gpu_rawsha224(sha256_password *,SHA_HASH*);
static char saved_keys[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH+1];		/** plaintext ciphertexts **/
static sha256_password 	*inbuffer;			/** binary ciphertexts **/
static SHA_HASH	*outbuffer;				/** calculated hashes **/

static void preproc(char *key, int index){ /// todo - move to gpu
  uint32_t dl=strlen(key),j;
  uint32_t *blocks = inbuffer[index].v;
  memset(inbuffer[index].v,0,sizeof(sha256_password));
  for(j=0;j<dl;j++){
      uint32_t tmp=0;
      tmp |= (((uint32_t) key[j]) << ((3-(j & 0x3)) << 3));
      blocks[j/4]|=tmp;
    }
    blocks[j / 4] |= (((uint32_t) 0x80) << ((3-(j & 0x3)) << 3));
    blocks[15]=0x00000000|(dl*8);
}

static void cleanup()
{
 free(inbuffer);
 free(outbuffer);
}

static void init(struct fmt_main *pFmt){
   //Alocate memory for hashes and passwords
  inbuffer=(sha256_password*)malloc(sizeof(sha256_password)*MAX_KEYS_PER_CRYPT);
  outbuffer=(SHA_HASH*)malloc(sizeof(SHA_HASH)*MAX_KEYS_PER_CRYPT);
  check_mem_allocation(inbuffer,outbuffer);
  atexit(cleanup);
  //Initialize CUDA
  cuda_init(gpu_id);
}

static int valid(char * ciphertext,struct fmt_main *pFmt){
  int i;
  if(strlen(ciphertext)!=CIPHERTEXT_LENGTH) return 0;
  for(i=0;i<CIPHERTEXT_LENGTH;i++){
    if(!(
      (ciphertext[i]>='0' && ciphertext[i]<='9')||
      (ciphertext[i]>='a' && ciphertext[i]<='f')||
      (ciphertext[i]>='A' && ciphertext[i]<='Z')))
	return 0;
  }
  return 1;
};


static void *binary(char *ciphertext){
  static char realcipher[BINARY_SIZE];
  memset(realcipher,0,BINARY_SIZE);
  int i;
  for(i=0;i<BINARY_SIZE;i+=4){
      realcipher[i]=atoi16[ARCH_INDEX(ciphertext[(i+3)*2])]*16+atoi16[ARCH_INDEX(ciphertext[(i+3)*2+1])];
      realcipher[i+1]=atoi16[ARCH_INDEX(ciphertext[(i+2)*2])]*16+atoi16[ARCH_INDEX(ciphertext[(i+2)*2+1])];
      realcipher[i+2]=atoi16[ARCH_INDEX(ciphertext[(i+1)*2])]*16+atoi16[ARCH_INDEX(ciphertext[(i+1)*2+1])];
      realcipher[i+3]=atoi16[ARCH_INDEX(ciphertext[(i)*2])]*16+atoi16[ARCH_INDEX(ciphertext[(i)*2+1])];
  }
  return (void*)realcipher;
}

static int binary_hash_0(void *binary){
   return (((ARCH_WORD_32*)binary)[0] & 0xf);
}

static int binary_hash_1(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0xff;
}

static int binary_hash_2(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary){
  return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff;
}

static void set_salt(void *salt){}
static void set_key(char *key, int index){
    memset(saved_keys[index],0,PLAINTEXT_LENGTH+1);	
    strnzcpy(saved_keys[index],key,PLAINTEXT_LENGTH);
    preproc(key,index);
}
static char *get_key(int index){
  return saved_keys[index];
}

static void crypt_all(int count){
  #ifdef SHA256
  gpu_rawsha256(inbuffer,outbuffer);
  #else
  gpu_rawsha224(inbuffer,outbuffer);
  #endif
}

static int get_hash_0(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xf;
}

static int get_hash_1(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xff;
}

static int get_hash_2(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xfff;
}

static int get_hash_3(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xffff;
}

static int get_hash_4(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xfffff;
}

static int get_hash_5(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0xffffff;
}

static int get_hash_6(int index){
  return ((ARCH_WORD_32*)outbuffer[index].v)[0] & 0x7ffffff;
}

static int cmp_all(void *binary,int count){
  uint32_t i;
  uint32_t b=((uint32_t *)binary)[0];
  for(i=0;i<count;i++)
    if(b==outbuffer[i].v[0])
      return 1;
  return 0;
}

static int cmp_one(void *binary,int index){
  int i;
  uint32_t *t=(uint32_t *)binary;
  for(i=0;i<CIPHERTEXT_LENGTH/8;i++)
    if(t[i]!=outbuffer[index].v[i])
      return 0;
  return 1;
}
static int cmp_exact(char *source,int count){
  return 1;
}

struct fmt_main FMT_MAIN={
  {
    FORMAT_NAME,
    FORMAT_NAME,
    SHA_TYPE,
    BENCHMARK_COMMENT,
    BENCHMARK_LENGTH,
    PLAINTEXT_LENGTH,
    BINARY_SIZE,
    SALT_SIZE,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_CASE | FMT_8_BIT ,
    TESTS
  },
  {
    init,
    fmt_default_prepare,
    valid,
    fmt_default_split,
    binary,
    fmt_default_salt,
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
    cmp_exact	
  }
};