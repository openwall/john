/*
 * EPiServer module for john 1.7.2 (and possibly later)
 * Uses hashes/salts found in the tblSID of an EPiServer database installation
 *
 * Created by Johannes Gumbel (johannes [at] iforge.cc)
 *
 * If you have any questions as to how a function incorporates with john, please refer to formats.h of john
 *
 * version 0.1 released on 10 jan 2007
 *
 * See doc/EPi.patch.README or http://iforge.cc/files/EPi.patch.README
 * for information on the input file format.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#include "sha.h"

#define PLAINTEXT_LENGTH   0x80-4
#define BINARY_LENGTH      20
#define SALT_LENGTH        30

static ARCH_WORD global_crypt[BINARY_LENGTH / ARCH_SIZE + 1];
static char global_key[PLAINTEXT_LENGTH]; // set by set_key and used by get_get
static char global_salt[SALT_LENGTH + PLAINTEXT_LENGTH]; // set by set_salt and used by crypt_all
                                                         // the extra plaintext_length is needed because the
                                                         // current key is copied there before hashing

int valid(char *ciphertext, struct fmt_main *pFmt);
void* binary(char *ciphertext);
void* salt(char *ciphertext);
void set_salt(void *salt);
void set_key(char *key, int index);
char* get_key(int index);
void crypt_all(int count);
int cmp_all(void *binary, int count);
int cmp_one(void *binary, int index);
int cmp_exact(char *source, int index);

struct fmt_tests global_tests[] =
{
  {"0x5F1D84A6DE97E2BEFB637A3CB5318AFEF0750B856CF1836BD1D4470175BE 0x4D5EFDFA143EDF74193076F174AC47CEBF2F417F", "Abc.!23"},
  {NULL}
};

// Define john integration
struct fmt_main fmt_EPI =
{
  { // fmt_params
    "epi",
    "EPiServer SID Hashes",
    "SHA-1",
    "", // benchmark comment
    0, // benchmark length
    PLAINTEXT_LENGTH,
    BINARY_LENGTH,
    SALT_LENGTH,
    1,
    1,
    FMT_CASE | FMT_8_BIT, // flags XXX, these are just guesses
    global_tests
  },
  { // fmt_methods
    fmt_default_init,
	fmt_default_prepare,
    valid,
    fmt_default_split,
    binary,
    salt,
    { // binary_hash[3]
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    set_salt,
    set_key,
    get_key,
    fmt_default_clear_keys,
    crypt_all,
    { // get_hash[3]
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    cmp_all,
    cmp_one,
    cmp_exact,
	fmt_default_get_source
  }
};

/*
 * Expects ciphertext of format: 0xHEX*60 0xHEX*40
 */
int valid(char *ciphertext, struct fmt_main *pFmt)
{
  unsigned int len, n;

  if(!ciphertext) return 0;
  len = strlen(ciphertext);

  if(len != 105)
    return 0;

  // check fixed positions
  if(ciphertext[0]  != '0' || ciphertext[1]  != 'x' ||
     ciphertext[62] != ' ' ||
     ciphertext[63] != '0' || ciphertext[64] != 'x')
    return 0;

  for(n = 2; n < 62 && atoi16[ARCH_INDEX(ciphertext[n])] != 0x7F; ++n);
  for(n = 65; n < 105 && atoi16[ARCH_INDEX(ciphertext[n])] != 0x7F; ++n);

  return n == len;
}

void _tobin(char* dst, char *src, unsigned int len)
{
  unsigned int n;

  if(src[0] == '0' && src[1] == 'x')
    src += sizeof(char)*2;

  for(n = 0; n < len; ++n)
    dst[n] = atoi16[ARCH_INDEX(src[n*2])]<<4 |
             atoi16[ARCH_INDEX(src[n*2+1])];
}

void* binary(char *ciphertext)
{
  static char bin[BINARY_LENGTH];

  _tobin(bin, (char*)(ciphertext+65), sizeof(bin));

  return bin;
}

void* salt(char *ciphertext)
{
  static char salt[SALT_LENGTH];

  _tobin(salt, (char*)(ciphertext+2), sizeof(salt));

  return salt;
}

void set_salt(void *salt)
{
  memcpy(global_salt, salt, SALT_LENGTH);
}

void set_key(char *key, int index)
{
  if(!key) return;
  strnzcpy(global_key, key, PLAINTEXT_LENGTH);
}

char* get_key(int index)
{
  return global_key;
}

void crypt_all(int count)
{
  static SHA_CTX ctx;

  // Yes, I'm overwriting the last byte of the salt, perhaps the coder at ElektoPost whom wrote the EPiServer password checking function used to be a C coder (their code is written in .NET)
  strnzcpy(global_salt+SALT_LENGTH-1, global_key, PLAINTEXT_LENGTH);

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, (unsigned char*)global_salt, SALT_LENGTH+strlen(global_key));
  SHA1_Final((unsigned char*)global_crypt, &ctx);
}

int cmp_all(void *binary, int count)
{
  if (((ARCH_WORD *)binary)[0] != global_crypt[0])
    return 0;

  return !memcmp(&((ARCH_WORD *)binary)[1], &global_crypt[1],
    BINARY_LENGTH - ARCH_SIZE);
}

int cmp_one(void *binary, int index)
{
  return cmp_all(binary, 0);
}

// This functions job is done in cmp_all instead
int cmp_exact(char *source, int index)
{
  return 1;
}

