/* NTLM kernel (OpenCL 1.0 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified
 * by Samuele Giovanni Tonon in 2011 and Sayantan Datta in 2013. No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * Copyright (c) 2013 Sayantan Datta
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#include "opencl_nt_fmt.h"

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define BITMAP_HASH_0 	    (BITMAP_SIZE_0 - 1)
#define BITMAP_HASH_1	    (BITMAP_SIZE_1 - 1)

#define GET_CHAR(x,elem) (((x)>>elem) & 0xFF)

#ifdef __ENDIAN_LITTLE__
	//little-endian
	#define ELEM_0 0
	#define ELEM_1 8
	#define ELEM_2 16
	#define ELEM_3 24
#else
	//big-endian
	#define ELEM_0 24
	#define ELEM_1 16
	#define ELEM_2 8
	#define ELEM_3 0
#endif

inline void coalasced_load(__private uint *nt_buffer, const __global uint *keys, uint *md4_size, uint gid, uint num_keys) {

	uint key_chars;
	uint nt_index = 0;
	uint temp, a,b,c,d;
	(*md4_size) = 0;

	// Extrct 4 chars every cycle
	do {      //Coalescing access to global memory
		  key_chars = keys[((*md4_size)>>2)*num_keys+gid];
		  (*md4_size) += 4;
		  a = GET_CHAR(key_chars, ELEM_0);
		  b = GET_CHAR(key_chars, ELEM_1);
		  c = GET_CHAR(key_chars, ELEM_2);
		  d = GET_CHAR(key_chars, ELEM_3);
		  nt_buffer[nt_index++] = (b << 16) | a ;
		  nt_buffer[nt_index++] = (d << 16) | c ;
		  temp = a * b * c * d ;

	} while(temp);

	a = a ? 0 : 4;
	b = b ? 0 : 3;
	c = c ? 0 : 2;
	d = d ? 0 : 1;

	(*md4_size) -= (a | b | c | d);

	temp = (*md4_size) >> 1;

	nt_buffer[temp] =  ((b&1) << 23) | (a << 5) | (d << 23) | (c << 6) | (nt_buffer[temp] & 0xFF);
	nt_buffer[temp + 1] = 0;

	(*md4_size) = (*md4_size) << 4;
}

inline void nt_crypt(__private uint *hash, __private uint *nt_buffer, uint md4_size) {
	uint tmp;

	/* Round 1 */
	hash[0] = 0xFFFFFFFF	+ nt_buffer[0]; hash[0]=rotate(hash[0], 3u);
	hash[3] = INIT_D+(INIT_C ^ (hash[0] & 0x77777777))   + nt_buffer[1]; hash[3]=rotate(hash[3], 7u);
	hash[2] = INIT_C+(INIT_B ^ (hash[3] & (hash[0] ^ INIT_B))) + nt_buffer[2]; hash[2]=rotate(hash[2], 11u);
	hash[1] = INIT_B + (hash[0] ^ (hash[2] & (hash[3] ^ hash[0])))		 + nt_buffer[3]; hash[1]=rotate(hash[1], 19u);

	hash[0] += (hash[3] ^ (hash[1] & (hash[2] ^ hash[3])))  +  nt_buffer[4] ; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ (hash[0] & (hash[1] ^ hash[2])))  +  nt_buffer[5] ; hash[3] = rotate(hash[3] , 7u );
	hash[2] += (hash[1] ^ (hash[3] & (hash[0] ^ hash[1])))  +  nt_buffer[6] ; hash[2] = rotate(hash[2] , 11u);
	hash[1] += (hash[0] ^ (hash[2] & (hash[3] ^ hash[0])))  +  nt_buffer[7] ; hash[1] = rotate(hash[1] , 19u);

	hash[0] += (hash[3] ^ (hash[1] & (hash[2] ^ hash[3])))  +  nt_buffer[8] ; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ (hash[0] & (hash[1] ^ hash[2])))  +  nt_buffer[9] ; hash[3] = rotate(hash[3] , 7u );
	hash[2] += (hash[1] ^ (hash[3] & (hash[0] ^ hash[1])))  +  nt_buffer[10]; hash[2] = rotate(hash[2] , 11u);
	hash[1] += (hash[0] ^ (hash[2] & (hash[3] ^ hash[0])))  +  nt_buffer[11]; hash[1] = rotate(hash[1] , 19u);

	hash[0] += (hash[3] ^ (hash[1] & (hash[2] ^ hash[3])))                  ; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ (hash[0] & (hash[1] ^ hash[2])))                  ; hash[3] = rotate(hash[3] , 7u );
	hash[2] += (hash[1] ^ (hash[3] & (hash[0] ^ hash[1])))  +    md4_size   ; hash[2] = rotate(hash[2] , 11u);
	hash[1] += (hash[0] ^ (hash[2] & (hash[3] ^ hash[0])))                  ; hash[1] = rotate(hash[1] , 19u);

	/* Round 2 */
	hash[0] += ((hash[1] & (hash[2] | hash[3])) | (hash[2] & hash[3])) + nt_buffer[0] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += ((hash[0] & (hash[1] | hash[2])) | (hash[1] & hash[2])) + nt_buffer[4] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += ((hash[3] & (hash[0] | hash[1])) | (hash[0] & hash[1])) + nt_buffer[8] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += ((hash[2] & (hash[3] | hash[0])) | (hash[3] & hash[0]))                + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += ((hash[1] & (hash[2] | hash[3])) | (hash[2] & hash[3])) + nt_buffer[1] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += ((hash[0] & (hash[1] | hash[2])) | (hash[1] & hash[2])) + nt_buffer[5] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += ((hash[3] & (hash[0] | hash[1])) | (hash[0] & hash[1])) + nt_buffer[9] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += ((hash[2] & (hash[3] | hash[0])) | (hash[3] & hash[0]))                + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += ((hash[1] & (hash[2] | hash[3])) | (hash[2] & hash[3])) + nt_buffer[2] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += ((hash[0] & (hash[1] | hash[2])) | (hash[1] & hash[2])) + nt_buffer[6] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += ((hash[3] & (hash[0] | hash[1])) | (hash[0] & hash[1])) + nt_buffer[10]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += ((hash[2] & (hash[3] | hash[0])) | (hash[3] & hash[0])) +   md4_size   + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += ((hash[1] & (hash[2] | hash[3])) | (hash[2] & hash[3])) + nt_buffer[3] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += ((hash[0] & (hash[1] | hash[2])) | (hash[1] & hash[2])) + nt_buffer[7] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += ((hash[3] & (hash[0] | hash[1])) | (hash[0] & hash[1])) + nt_buffer[11]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += ((hash[2] & (hash[3] | hash[0])) | (hash[3] & hash[0]))                + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	/* Round 3 */
	hash[0] += (hash[3] ^ hash[2] ^ hash[1]) + nt_buffer[0]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ hash[1] ^ hash[0]) + nt_buffer[8]  + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += (hash[1] ^ hash[0] ^ hash[3]) + nt_buffer[4]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	hash[1] += (hash[0] ^ hash[3] ^ hash[2])                 + SQRT_3; hash[1] = rotate(hash[1] , 15u);

	hash[0] += (hash[3] ^ hash[2] ^ hash[1]) + nt_buffer[2]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ hash[1] ^ hash[0]) + nt_buffer[10] + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += (hash[1] ^ hash[0] ^ hash[3]) + nt_buffer[6]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	hash[1] += (hash[0] ^ hash[3] ^ hash[2]) +   md4_size    + SQRT_3; hash[1] = rotate(hash[1] , 15u);

	hash[0] += (hash[3] ^ hash[2] ^ hash[1]) + nt_buffer[1]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[2] ^ hash[1] ^ hash[0]) + nt_buffer[9]  + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += (hash[1] ^ hash[0] ^ hash[3]) + nt_buffer[5]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	//It is better to calculate this remining steps that access global memory
	hash[1] += (hash[0] ^ hash[3] ^ hash[2]) ;
	tmp = hash[1];
	tmp += SQRT_3; tmp = rotate(tmp , 15u);

	hash[0] += (tmp ^ hash[2] ^ hash[3]) + nt_buffer[3]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += (hash[0] ^ tmp ^ hash[2]) + nt_buffer[11] + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += (hash[3] ^ hash[0] ^ tmp) + nt_buffer[7]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);

}

inline void cmp(__global uint *hashes,
	  __global const uint *loaded_hashes,
	  __local uint *bitmap0,
	  __local uint *bitmap1,
	  __private uint *hash,
	  __global uint *cmp_out,
	  __global uint *outKeyIdx,
	  uint gid) {

	uint num_loaded_hashes = loaded_hashes[0];
	uint loaded_hash, i, tmp;

	for(i = 0; i < num_loaded_hashes; i++) {

		loaded_hash = hash[0] & BITMAP_HASH_1;
		tmp = (bitmap0[loaded_hash >> 5] >> (loaded_hash & 31)) & 1U ;
		if(tmp) {

			loaded_hash = hash[1] & BITMAP_HASH_1;
			tmp &= (bitmap1[loaded_hash >> 5] >> (loaded_hash & 31)) & 1U;
			if(tmp) {

				loaded_hash = loaded_hashes[i * 4 + 3];
				if(hash[2] == loaded_hash) {

					loaded_hash = loaded_hashes[i * 4 + 4];
					if(hash[3] == loaded_hash) {

						hashes[i] = hash[1];
						hashes[1 * num_loaded_hashes + i] = hash[0];
						hashes[2 * num_loaded_hashes + i] = hash[2];
						hashes[3 * num_loaded_hashes + i] = hash[3];
						cmp_out[i] = 0xffffffff;
						outKeyIdx[2 * i] = gid ;
					}
				}
			}
		}
	}
 }

__kernel void nt_self_test(const __global uint *keys , __global uint *output)
{
	uint gid = get_global_id(0);
	uint nt_buffer[12] = { 0 };
	uint md4_size = 0;
	uint num_keys = get_global_size(0);

	// hash[0] and hash[1] values are sawpped
	uint hash[4];

	coalasced_load(nt_buffer, keys, &md4_size, gid, num_keys);
	nt_crypt(hash, nt_buffer, md4_size);

	//Coalescing writes
	output[gid] = hash[1];
	output[1*num_keys+gid] = hash[0];
	output[2*num_keys+gid] = hash[2];
	output[3*num_keys+gid] = hash[3];
}

__kernel void nt(const __global uint *keys ,
		       __global uint *output,
		 const __global uint *loaded_hashes,
		       __global uint *cmp_out,
		       __global uint *outKeyIdx,
		       __global struct bitmap_ctx *bitmap)
{
	uint gid = get_global_id(0);
	uint lid = get_local_id(0);
	uint nt_buffer[12] = { 0 };
	uint md4_size = 0;
	uint num_keys = get_global_size(0);
	uint i;

	// hash[0] and hash[1] values are sawpped
	uint hash[4];

	__local uint sbitmap0[BITMAP_SIZE_1 >> 5];
	__local uint sbitmap1[BITMAP_SIZE_1 >> 5];

	if(!gid)
		for (i = 0; i < loaded_hashes[0]; i++) {
			cmp_out[i] = 0;
			outKeyIdx[2 * i] = outKeyIdx[2 * i + 1] = 0;
		}

	for(i = 0; i < ((BITMAP_SIZE_1 >> 5) / LWS); i++)
		sbitmap0[i*LWS + lid] = bitmap[0].bitmap0[i*LWS + lid];

	for(i = 0; i < ((BITMAP_SIZE_1 >> 5)/ LWS); i++)
		sbitmap1[i*LWS + lid] = bitmap[0].bitmap1[i*LWS + lid];


	barrier(CLK_LOCAL_MEM_FENCE);

	coalasced_load(nt_buffer, keys, &md4_size, gid, num_keys);
	nt_crypt(hash, nt_buffer, md4_size);
	cmp(output, loaded_hashes, sbitmap0, sbitmap1, hash, cmp_out, outKeyIdx, gid);

}
