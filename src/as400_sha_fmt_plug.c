// AS/400 SHA plugin for JtR
// This software is Copyright (c) 2016 Bart Kulach (@bartholozz) and Rob Schoemaker (@5up3rUs3r)
// and it is hereby released to the general public under the following terms:
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//
// This plugin is loosely based on the lotus85 plugin by Sebastien Kaczmarek <skaczmarek@quarkslab.com>
//
// AS/400 SHA1 hash is calculated as follows:
// - userid is padded with spaces to be 10 characters long, 
//   converted to uppercase and UTF-16BE
// - password is converted to UTF-16BE
// - Hash is calculated from SHA1(userid+password)
// 
// See http://www.hackthelegacy.org for details and tooling to retrieve hashes from AS/400 systems


// ==================================================================================================
// Registration of the plugin and includes

#if FMT_EXTERNS_H
extern struct fmt_main fmt_as400;
#elif FMT_REGISTERS_H
john_register_one(&fmt_as400);
#else

#include <stdio.h>
#include <string.h>
#include "stdint.h"

#include "sha.h"

#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64 
static int omp_t = 1;
#endif

#include "formats.h"
#include "common.h"
#include "memdbg.h"


// ==================================================================================================
// Plugin definition

#define FORMAT_LABEL          "as400-sha"
#define FORMAT_NAME           "IBM i (aka AS/400)"
#define ALGORITHM_NAME        "SHA1"
#define BENCHMARK_COMMENT     ""
#define BENCHMARK_LENGTH      -1
#define PLAINTEXT_LENGTH      32
#define CIPHERTEXT_LENGTH     40                                 // Length of ciphertext in hexadecimal text notation (like in inputfile)
#define BINARY_SIZE           0
#define BINARY_LENGTH         20                                 // Binary length of hashes
#define BINARY_ALIGN          1
#define SALT_SIZE             sizeof(struct custom_salt)
#define SALT_ALIGN            1
#define MIN_KEYS_PER_CRYPT    1
#define MAX_KEYS_PER_CRYPT    1

#define AS400_USERID_LENGTH   10                                 // Fixed length of AS/400 userid for calculations


// ==================================================================================================
// Structures and global variables

// Charset used for testing if ciphertext string is hexadecimal. 
// AS/400 hashes are stored in uppercase and also we get an error in the JtR CI if we allow mixed case hexadecimal, 
// so therefore we only allow uppercase characters for hash
static const char AS400_BASE16_CHARSET[] = "0123456789ABCDEF";

// Definition of structure to hold data to pass between functions (we abuse the salt functions for this)
static struct custom_salt {
	char username_utf16be[(AS400_USERID_LENGTH*2)+1];   // holds the userid of this user converted to UTF-16BE
	uint8_t storedbinaryhash[BINARY_LENGTH];			// holds the binary representation of the hash for this user
} *cur_salt;

// Definition of variables to hold retrieved hashes and calculated hashes in binary format
static uint8_t (*as400_computed_binary_hash)[BINARY_LENGTH];
static uint8_t (*as400_retrieved_binary_hash)[BINARY_LENGTH];

// Plaintext candidate passwords delivered by JtR engine
static char (*as400_saved_passwords)[PLAINTEXT_LENGTH+1];


// ==================================================================================================
// Plugin initialization (called only once when plugin is initialized)

static void as400_init(struct fmt_main *self)
{
	
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif

	// Allocate menory to store candidate passwords that are provided by main program of JtR
	as400_saved_passwords = mem_calloc_tiny(
		(PLAINTEXT_LENGTH + 1) * self->params.max_keys_per_crypt,
		MEM_ALIGN_CACHE);
		
	// Allocate memory to store binary hashes computed from password candidates	
	as400_computed_binary_hash = mem_calloc_tiny(
		BINARY_LENGTH * self->params.max_keys_per_crypt,
		MEM_ALIGN_CACHE);
		
	// Allocate memory to store binary hashes fetched from the inputfile
	as400_retrieved_binary_hash = mem_calloc_tiny(
		BINARY_LENGTH * self->params.max_keys_per_crypt,
		MEM_ALIGN_CACHE);
}


// ==================================================================================================
// Check if given ciphertext (hash) format is valid 

static int as400_valid(char *ciphertext,struct fmt_main *self)
{
	int i,len;

	// Check if length of ciphertext is correct 
	//(note: userid is added to ciphertext in prepare function --> take in consideration for check!)
	len = strlen(ciphertext);
	if(len!=CIPHERTEXT_LENGTH+AS400_USERID_LENGTH)
		return 0;
	
	// Check if ciphertext only contains hexadecimal characters
	// (note: discard first 10 characters that contain username!!!)
	for (i=AS400_USERID_LENGTH;i<len;i++)
		if(!strchr(AS400_BASE16_CHARSET,ciphertext[i]))
			return 0;

	return 1;
}


// ==================================================================================================
// Prepare the input from the inputfile for further processing
// Inputfile is in the format userid:hash
// We need the userid that is associated with a hash for the calculation of the hash, therefore
// userid is added to ciphertext, so that we can access the username later in the process in get_salt()
// All preparation needed for userid is done in this function, so that later on in the process, userid is ready to use.
// This is for performance reasons, because prepare() is only called once per retrieved userid:hash. If we would do comutations
// later, e.g. in the crypt_all() function, this would degrade performance

static char *as400_prepare(char *fields[10], struct fmt_main *self)
{
	int i;
	
	// temporary variable to hold username
	char username[AS400_USERID_LENGTH+1] = "";
	
	// temporary variable to hold username + hash
	static char retval[AS400_USERID_LENGTH+CIPHERTEXT_LENGTH+1] = "";

	// fix suggested by jfoug: if hash (fields[1]) in inputfile is incorrect length, just return without adding password
	if (strlen(fields[1]) != CIPHERTEXT_LENGTH)
		return fields[1];
	
	// Truncate field[0] to AS400_USERID_LENGTH characters and store as username (just in case a longer id was provided)
	strncat(username, fields[0], AS400_USERID_LENGTH);

	// In further processing, userid needs to be in uppercase. We do this already here for efficiency reasons
	for(i=0;i<AS400_USERID_LENGTH;i++)
	{
		if (username[i] >= 'a' && username[i] <= 'z') 
		{
			username[i] = username[i] - 32;
		}
	}
	
	// In further processing, the AS400 userid needs to be exactly AS400_USERID_LENGTH characters long. Pad userid with spaces to get correct length
	// We do this here for efficiency, so that we do not need to pad the userid in other places. Also, makes splitting of internal representation easier
	while(strlen(username)<AS400_USERID_LENGTH)
	{
		strcat(username," ");
	}		
	
	// Store username in first 10 characters of return value so that we can access username in get_salt
	strcpy(retval,username);
	// Concatenate hash from inputfile to return value
	strcat(retval,fields[1]);

	return(retval);
}


// ==================================================================================================
// get_salt fills the salt structure with data for later use

static void *get_salt(char *ciphertext)
{
	int i,len;
	static struct custom_salt cs;
	
	// Temporary variables to hold username and hash
	char username[AS400_USERID_LENGTH+1];
	char hash[CIPHERTEXT_LENGTH+1];

	// Fix suggested by jfoug: initialize cs structure
	memset (&cs, 0, sizeof(cs));
	
	// Split ciphertext into username and hash (because these were concatenated in prepare())
	for(i = 0; i < AS400_USERID_LENGTH; i++)
		username[i] = ciphertext[i];
	username[AS400_USERID_LENGTH] = '\0';
	
	for(i = 0; i < CIPHERTEXT_LENGTH; i++)
		hash[i] = ciphertext[i+AS400_USERID_LENGTH];
	hash[CIPHERTEXT_LENGTH] = '\0';
	
	// convert ciphertext to binary and store for later use 
	len = strlen(hash) >> 1;
	for (i = 0; i < len; i++)
		cs.storedbinaryhash[i] = (atoi16[ARCH_INDEX(hash[i << 1])] << 4) + atoi16[ARCH_INDEX(hash[(i << 1) + 1])];

	// Store userid as utf-16be for later use (we do this here for performance reasons)
	for(i=0;i<AS400_USERID_LENGTH;i++)
	{
		cs.username_utf16be[(i*2)]=0x00;
		cs.username_utf16be[(i*2)+1]=username[i];
	}
	
	return (void*)&cs;
}


// ==================================================================================================
// Retrieve the current salt from memory for use in crypt_all() function

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}


// ==================================================================================================
// Store the password candidates that are passed from the JtR engine
// in our own variables for later use. 

static void as400_set_key(char *key,int index)
{
	strnzcpy(as400_saved_passwords[index],key,strlen(key)+1);
}


// ==================================================================================================
// Return the passwords candidate that is stored at 'index'
// This function is used by JtR engine to retrieve the plaintext password associated with a cracked hash 

static char *as400_get_key(int index)
{
	return as400_saved_passwords[index];
}


// ==================================================================================================
// function to compute AS/400 hash

static void as400_password_hash(const char *userid_utf16be, const char *password, uint8_t *hash)
{ 
	int i;
	char password_utf16be[(PLAINTEXT_LENGTH*2)+1];
	
	SHA_CTX s_ctx;
	uint8_t digest[SHA_DIGEST_LENGTH];

	// convert password to utf-16be
	for(i=0;i<(strlen(password));i++)
	{
		password_utf16be[(i*2)]=0x00;
		password_utf16be[(i*2)+1]=password[i];
	}
	
	// Calculate SHA1 hash from userid+password
	SHA1_Init(&s_ctx);

	SHA1_Update(&s_ctx, userid_utf16be, (AS400_USERID_LENGTH*2));
	SHA1_Update(&s_ctx, password_utf16be, (strlen(password)*2));

	SHA1_Final(digest, &s_ctx);

	memcpy(hash, digest, sizeof(digest));
}


// ==================================================================================================
// Main callback to compute as/400 hash. This function is called by JtR engine to
// calculate a number of AS/400 hashes

static int as400_crypt_all(int *pcount, struct db_salt *salt)
{	
	int count = *pcount;
	int index = 0;
	
	// Compute digest for all given plaintext passwords
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		
		memset(as400_computed_binary_hash[index], 0, BINARY_LENGTH);
		memset(as400_retrieved_binary_hash[index], 0, BINARY_LENGTH);
		
		as400_password_hash(cur_salt->username_utf16be, as400_saved_passwords[index], as400_computed_binary_hash[index]);
		
		// Store the binary hash as retrieved from the file (to be used by compare functions)
		memcpy(as400_retrieved_binary_hash[index], cur_salt->storedbinaryhash, BINARY_LENGTH);
		
	}
	return count;
}


// ==================================================================================================
// Check if at least one of the computed hashes matches with its associated retrieved hash
// If this is the case, JtR engine will call cmp_one() to find the matching hashes

static int as400_cmp_all(void *binary,int count)
{
	int i;
	
	for(i = 0; i < count; i++)
	{
		if(!memcmp(as400_computed_binary_hash[i],as400_retrieved_binary_hash[i],BINARY_LENGTH))
			return 1;
	}

	return 0;
}


// ==================================================================================================
// Check which of the calculated hashes matched

static int as400_cmp_one(void *binary,int index)
{
	return !memcmp(as400_computed_binary_hash[index],as400_retrieved_binary_hash[index],BINARY_LENGTH);
}


// ==================================================================================================
// No ASCII ciphertext, thus returns true

static int as400_cmp_exact(char *source,int index)
{
	return 1;
}


// ==================================================================================================
// Structure holding data for internal self tests

static struct fmt_tests as400_tests[] =
{
	// Format of each line: {"hash like in internal representation", "valid password for hash", {"userid as in file","hash as in file"}}
	{"ROB       4C106E52CA196986E1C52C7FCD02AF046B76C73C", "banaan", {"ROB","4C106E52CA196986E1C52C7FCD02AF046B76C73C"}},
	{"BART      CED8050C275A5005D101051FF5BCCADF693E8AB7", "Kulach007", {"BART","CED8050C275A5005D101051FF5BCCADF693E8AB7"}},
	{"SYSOPR    1BA6C7D54E9696ED33F4DF201E348CA8CA815F75", "T0Psecret!", {"SYSOPR","1BA6C7D54E9696ED33F4DF201E348CA8CA815F75"}},
	{"SYSTEM    A1284B4F1BDD7ED598D4B5060D861D6D614620D3", "P@ssword01", {"SYSTEM","A1284B4F1BDD7ED598D4B5060D861D6D614620D3"}},
	{"QSYSDBA   94C55BC7EDF1996AC62E8145CDBFA285CA79ED2E", "qsysdba", {"QSYSDBA","94C55BC7EDF1996AC62E8145CDBFA285CA79ED2E"}},
	{"QSECOFR   CDF4063E283B51EDB7B9A8E6E542042000BD9AE9", "qsecofr!", {"QSECOFR","CDF4063E283B51EDB7B9A8E6E542042000BD9AE9"}},	
	{"TEST1     44D43148CFE5CC3372AFD2610BEE3D226B2B50C5", "password1", {"test1","44D43148CFE5CC3372AFD2610BEE3D226B2B50C5"}},
	{"TEST2     349B12D6588843A1632649A501ABC353EBF409E4", "secret", {"TEST2","349B12D6588843A1632649A501ABC353EBF409E4"}},
	{"TEST3     A97F2F9ED9977A8A628F8727E2851415B06DC540", "test3", {"TeSt3","A97F2F9ED9977A8A628F8727E2851415B06DC540"}},
	{NULL}
};


// ==================================================================================================
// JtR as400 structure registration

struct fmt_main fmt_as400 =
{
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
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NULL },
		as400_tests
	}, {
		as400_init,
		fmt_default_done,
		fmt_default_reset,
		as400_prepare,
		as400_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL, 
		set_salt,
		as400_set_key,          
		as400_get_key,          
		fmt_default_clear_keys,
		as400_crypt_all,        
		{
			fmt_default_get_hash
		},
		as400_cmp_all,          
		as400_cmp_one,          
		as400_cmp_exact
	}
};

#endif /* plugin stanza */
