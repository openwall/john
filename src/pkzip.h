#ifndef PKZIP_H
#define PKZIP_H

#include "dyna_salt.h"

typedef unsigned short u16;
typedef unsigned char u8;
typedef          char c8;
typedef ARCH_WORD_32 u32;

#include "crc32.h"

u32 fget32LE(FILE * fp);
u16 fget16LE(FILE * fp);

#define MAX_PKZ_FILES 3

// These came from the gladman headers
#define KEY_LENGTH(mode)    (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)   (4 * ((mode) & 3) + 4)
#define KEYING_ITERATIONS   1000
#define PASSWORD_VERIFIER
#ifdef  PASSWORD_VERIFIER
#define PWD_VER_LENGTH      2
#else
#define PWD_VER_LENGTH      0
#endif


#if USE_PKZIP_MAGIC
typedef struct zip_magic_signatures_t {
	u8 *magic_signature[8];
	u8  magic_sig_len[8];
	u8  magic_count;
	u8  max_len;
} ZIP_SIGS;
#endif
typedef struct zip_hash_type_t {
	u8 *h;						// at getsalt time, we leave these null.  Later in setsalt, we 'fix' them
	u16 c;
	u16 c2;
	u32 datlen;
	u8 magic;					// This is used as 'magic' signature type. Also, 255 is 'generic text'
	u8 full_zip;
	u32 compType;				// the type of compression  0 or 8
#if USE_PKZIP_MAGIC
	ZIP_SIGS *pSig;
#endif
} ZIP_HASH;

typedef struct zip_salt_t {
	dyna_salt dsalt;
	char fname[1024];			// if the zip is too large, we open the file in cmp_exact read the
								// data a small buffer at a time.  If the zip blob is small enough
								// (under 16k), then it simply read into H[x].h at init() time.
								// and cmp_exact does not need fname to be used.
	u32 offset;					// this is the offset to zip data (if we have to read from the file).
	u32 full_zip_idx;			// the index (0, 1, 2) which contains the 'full zip' data.
	// start of the dyna zip 'compared' data.
	u32 cnt;					// number of hashes
	u32 chk_bytes;				// number of bytes valid in checksum (1 or 2)
	ZIP_HASH H[MAX_PKZ_FILES];
	u32 crc32;					// if a 'full' file of encr data, then this is the CRC
	u32 compLen;				// length of compressed data (whether part or full)
	u32 deCompLen;				// length of decompressed data (if full).
	u32 compType;				// the type of compression  0 or 8

	u8  zip_data[1];			// we 'move' the H[x].h data to here.  Then we 'fix' it up when later setting the salt.
} PKZ_SALT;

typedef union MY_WORD {
	u32 u;
	u8  c[4];
} MY_WORD;

#endif
