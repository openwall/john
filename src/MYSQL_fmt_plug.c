////////////////////////////////////////////////////////////////
// MySQL password cracker - v1.0 - 16.1.2003
//
//    by Andrew Hintz <http://guh.nu> drew at overt.org
//
//    This production has been brought to you by
//    4tphi <http://4tphi.net> and violating <http://violating.us>
//
// This file is an add-on to John the Ripper <http://www.openwall.com/john/>
//
// Part of this code is based on the MySQL brute password cracker
//   mysqlpassword.c by Chris Given
// This program executes about 75% faster than mysqlpassword.c
// John the ripper also performs sophisticated password guessing.
//
// John the Ripper will expect the MySQL password file to be
// in the following format (without the leading // ):
// dumb_user:5d2e19393cc5ef67
// another_luser:28ff8d49159ffbaf

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// johntr includes
#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "common.h"

//johntr defines
#define FORMAT_LABEL "mysql"
#define FORMAT_NAME "MYSQL"
#define ALGORITHM_NAME "mysql"

#define BENCHMARK_COMMENT ""
#define BENCHMARK_LENGTH -1

// Increase the PLAINTEXT_LENGTH value for longer passwords.
// You can also set it to 8 when using MySQL systems that truncate
//  the password to only 8 characters.
#define PLAINTEXT_LENGTH 32

#define CIPHERTEXT_LENGTH 16

#define BINARY_SIZE 16
#define SALT_SIZE 0

#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 1


//used for mysql scramble function
struct rand_struct {
  unsigned long seed1,seed2,max_value;
  double max_value_dbl;
};


void make_scrambled_password(char *,const char *);
char *scramble(char *,const char *,const char *, int);

//test cases
static struct fmt_tests mysql_tests[] = {
  {"30f098972cc8924d", "http://guh.nu"},
  {"3fc56f6037218993", "Andrew Hintz"},
  {"697a7de87c5390b2", "drew"},
  {"1eb71cf460712b3e", "http://4tphi.net"},
  {"28ff8d49159ffbaf", "http://violating.us"},
  {"5d2e19393cc5ef67", "password"},
  {NULL}
};


//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

//used by set_key
static char saved_key[PLAINTEXT_LENGTH + 1];

static int mysql_valid(char *ciphertext, struct fmt_main *pFmt) { //returns 0 for invalid ciphertexts

  int i; //used as counter in loop

  //ciphertext is 16 characters
  if (strlen(ciphertext) != 16) return 0;

  //ciphertext is ASCII representation of hex digits
  for (i = 0; i < 16; i++){
    if (!(  ((48 <= ciphertext[i])&&(ciphertext[i] <= 57)) ||
	    ((97 <= ciphertext[i])&&(ciphertext[i] <= 102))  ))
      return 0;
  }

  return 1;
}

static void mysql_set_key(char *key, int index) {
  strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *mysql_get_key(int index) {
    return saved_key;
}

static int mysql_cmp_all(void *binary, int index) { //also is mysql_cmp_one
  return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int mysql_cmp_exact(char *source, int count){
  return (1); //  mysql_cmp_all fallthrough?
}

static void mysql_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
  make_scrambled_password(crypt_key,saved_key);
}

////////////////////////////////////////////////////////////////
//begin mysql code
// This code was copied from mysqlpassword.c by Chris Given
// He probably copied it from password.c in the MySQL source
// The code is GPLed

void randominit(struct rand_struct *rand_st,unsigned long seed1, unsigned long seed2) {
  rand_st->max_value= 0x3FFFFFFFL;
  rand_st->max_value_dbl=(double) rand_st->max_value;
  rand_st->seed1=seed1%rand_st->max_value ;
  rand_st->seed2=seed2%rand_st->max_value;
}
static void old_randominit(struct rand_struct *rand_st,unsigned long seed1) {
  rand_st->max_value= 0x01FFFFFFL;
  rand_st->max_value_dbl=(double) rand_st->max_value;
  seed1%=rand_st->max_value;
  rand_st->seed1=seed1 ; rand_st->seed2=seed1/2;
}
double rnd(struct rand_struct *rand_st) {
  rand_st->seed1=(rand_st->seed1*3+rand_st->seed2) %
    rand_st->max_value;
  rand_st->seed2=(rand_st->seed1+rand_st->seed2+33) %
    rand_st->max_value;
  return(((double) rand_st->seed1)/rand_st->max_value_dbl);
}
void hash_password(unsigned long *result, const char *password) {
  register unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
  unsigned long tmp;
  for (; *password ; password++) {
    if (*password == ' ' || *password == '\t')
      continue;
    tmp= (unsigned long) (unsigned char) *password;
    nr^= (((nr & 63)+add)*tmp)+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=tmp;
  }
  result[0]=nr & (((unsigned long) 1L << 31) -1L); /* Don't use sign bit
					      (str2int) */;
  result[1]=nr2 & (((unsigned long) 1L << 31) -1L);
  return;
}
void make_scrambled_password(char *to,const char *password) {
  unsigned long hash_res[2];
  hash_password(hash_res,password);
  sprintf(to,"%08lx%08lx",hash_res[0],hash_res[1]);
}
static inline unsigned int char_val(char X) {
  return (unsigned int) (X >= '0' && X <= '9' ? X-'0' : X >= 'A' && X <= 'Z' ?
		 X-'A'+10 : X-'a'+10);
}
char *scramble(char *to,const char *message,const char *password, int
	       old_ver) {
  struct rand_struct rand_st;
  unsigned long hash_pass[2],hash_message[2];
  if(password && password[0]) {
    char *to_start=to;
    hash_password(hash_pass,password);
    hash_password(hash_message,message);
    if (old_ver)
      old_randominit(&rand_st,hash_pass[0] ^
		     hash_message[0]);
    else
      randominit(&rand_st,hash_pass[0] ^ hash_message[0],
		 hash_pass[1] ^ hash_message[1]);
    while (*message++)
      *to++= (char) (floor(rnd(&rand_st)*31)+64);
    if (!old_ver) {
      char extra=(char) (floor(rnd(&rand_st)*31));
      while(to_start != to)
        *(to_start++)^=extra;
    }
  }
  *to=0;
  return to;
}

//end mysql code
////////////////////////////////////////////////////////////////

struct fmt_main fmt_MYSQL = {
  {
    FORMAT_LABEL,
    FORMAT_NAME,
    ALGORITHM_NAME,
    BENCHMARK_COMMENT,
    BENCHMARK_LENGTH,
    PLAINTEXT_LENGTH,
    BINARY_SIZE,
    SALT_SIZE,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_CASE | FMT_8_BIT,
    mysql_tests
    }, {
      fmt_default_init,
	  fmt_default_prepare,
      mysql_valid,
      fmt_default_split,
      fmt_default_binary,
      fmt_default_salt,
      {
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash
      },
      fmt_default_salt_hash,
      fmt_default_set_salt,
      mysql_set_key,
      mysql_get_key,
      fmt_default_clear_keys,
      mysql_crypt_all,
      {
	fmt_default_get_hash,
	fmt_default_get_hash,
	fmt_default_get_hash,
	fmt_default_get_hash,
	fmt_default_get_hash
      },
      mysql_cmp_all,
      mysql_cmp_all, //should it be the same as cmp_all or same as cmp_exact?
      mysql_cmp_exact //fallthrough
    }
};
