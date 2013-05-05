/*
 * New flags added for sha2 by JimF 2013. This change, and
 * all other modifications to this file by Jim are released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#ifndef __SSE_INTRINS_LOAD_FLAGS__
#define __SSE_INTRINS_LOAD_FLAGS__

/***************************************************************
 * WARNING!!!! any changes to these numbers will likely require
 * a new build of sse-intrinsics-32.S and sse-intrinsics-64.S
 ***************************************************************/

typedef enum {
	SHA256_MIXED_IN=0x0,	// input is an array of 16 __m128i ints that are properly SSE interleaved.  This is for 4 passwords. The data will be copied into a on the stack workspace
	SHA256_FLAT_IN=0x1,		// input is an array of 4 64 byte 'flat' values, instead of a properly SSE 'mixed' 64 uint32's.
	/****  NOTE, only 1 of the above 2 can be used, AND the buffer must properly match.  ****/

	SHA256_CRYPT_SHA224=0x4,// use SHA224 IV.
	SHA256_RELOAD=0x8,		// crypt key will be results of last crypt
	SHA256_RELOAD_INP_FMT=0x10,	// crypt key will be results of last crypt, however, it is in 'INPUT' format. Will not matter, unless PARA > 1
	SHA256_OUTPUT_AS_INP_FMT=0x20,	// Write final output, using 'INPUT' format. Will not matter, unless PARA > 1
	SHA256_SWAP_FINAL=0x40,	// swap results into LE.  Normally, results are left in BE
} SHA256_FLAGS;

typedef enum {
	SHA512_MIXED_IN=0x0,	// input is an array of 16 __m128i ints that are properly SSE interleaved.  This is for 2 passwords. The data will be copied into a on the stack workspace
	SHA512_FLAT_IN=0x1,		// input is an array of 2 64 byte 'flat' values, instead of a properly SSE 'mixed' 64 uint32's.
	/****  NOTE, only 1 of the above 2 can be used, AND the buffer must properly match.  ****/

	SHA512_CRYPT_SHA384=0x4,// use SHA384 IV.
	SHA512_RELOAD=0x8,		// crypt key will be results of last crypt
	SHA512_RELOAD_INP_FMT=0x10,	// crypt key will be results of last crypt, however, it is in 'INPUT' format. Will not matter, unless PARA > 1
	SHA512_OUTPUT_AS_INP_FMT=0x20,	// Write final output, using 'INPUT' format. Will not matter, unless PARA > 1
	SHA512_SWAP_FINAL=0x40,	// swap results into LE.  Normally, results are left in BE
} SHA512_FLAGS;

#endif /* __SSE_INTRINS_LOAD_FLAGS__  */
