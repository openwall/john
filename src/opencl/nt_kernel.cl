/* NTLM kernel (OpenCL 1.0 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified
 * by Samuele Giovanni Tonon in 2011.  No copyright is claimed, and
 * the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

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

inline void nt_crypt(__private uint *hash, __private uint *nt_buffer, uint md4_size) {
	uint tmp;

	/* Round 1 */
	hash[0] = 0xFFFFFFFF	+ nt_buffer[0]; hash[0]=rotate(hash[0], 3u);
	hash[3] = INIT_D+(INIT_C ^ (hash[0] & 0x77777777))   + nt_buffer[1]; hash[3]=rotate(hash[3], 7u);
	hash[2] = INIT_C+(INIT_B ^ (hash[3] & (hash[0] ^ INIT_B))) + nt_buffer[2]; hash[2]=rotate(hash[2], 11u);
	hash[1] = INIT_B + (hash[0] ^ (hash[2] & (hash[3] ^ hash[0])))		 + nt_buffer[3]; hash[1]=rotate(hash[1], 19u);

#ifdef USE_BITSELECT

	hash[0] += bitselect(hash[3], hash[2], hash[1]) + nt_buffer[4] ; hash[0] = rotate(hash[0], 3u);
	hash[3] += bitselect(hash[2], hash[1], hash[0]) + nt_buffer[5] ; hash[3] = rotate(hash[3], 7u);
	hash[2] += bitselect(hash[1], hash[0], hash[3]) + nt_buffer[6] ; hash[2] = rotate(hash[2], 11u);
	hash[1] += bitselect(hash[0], hash[3], hash[2]) + nt_buffer[7] ; hash[1] = rotate(hash[1], 19u);

	hash[0] += bitselect(hash[3], hash[2], hash[1]) + nt_buffer[8] ; hash[0] = rotate(hash[0], 3u);
	hash[3] += bitselect(hash[2], hash[1], hash[0]) + nt_buffer[9] ; hash[3] = rotate(hash[3], 7u);
	hash[2] += bitselect(hash[1], hash[0], hash[3]) + nt_buffer[10]; hash[2] = rotate(hash[2], 11u);
	hash[1] += bitselect(hash[0], hash[3], hash[2]) + nt_buffer[11]; hash[1] = rotate(hash[1], 19u);

	hash[0] += bitselect(hash[3], hash[2], hash[1])                ; hash[0] = rotate(hash[0], 3u);
	hash[3] += bitselect(hash[2], hash[1], hash[0])                ; hash[3] = rotate(hash[3], 7u);
	hash[2] += bitselect(hash[1], hash[0], hash[3]) + md4_size     ; hash[2] = rotate(hash[2], 11u);
	hash[1] += bitselect(hash[0], hash[3], hash[2])                ; hash[1] = rotate(hash[1], 19u);

#else

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

#endif

	/* Round 2 */

#ifdef USE_BITSELECT

	hash[0] += bitselect(bitselect(hash[1], hash[2], hash[3]), bitselect(hash[3], hash[1], hash[2]), hash[1]) + nt_buffer[0] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += bitselect(bitselect(hash[0], hash[1], hash[2]), bitselect(hash[2], hash[0], hash[1]), hash[0]) + nt_buffer[4] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += bitselect(bitselect(hash[3], hash[0], hash[1]), bitselect(hash[1], hash[3], hash[0]), hash[3]) + nt_buffer[8] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += bitselect(bitselect(hash[2], hash[3], hash[0]), bitselect(hash[0], hash[2], hash[3]), hash[2]) +                SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += bitselect(bitselect(hash[1], hash[2], hash[3]), bitselect(hash[3], hash[1], hash[2]), hash[1]) + nt_buffer[1] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += bitselect(bitselect(hash[0], hash[1], hash[2]), bitselect(hash[2], hash[0], hash[1]), hash[0]) + nt_buffer[5] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += bitselect(bitselect(hash[3], hash[0], hash[1]), bitselect(hash[1], hash[3], hash[0]), hash[3]) + nt_buffer[9] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += bitselect(bitselect(hash[2], hash[3], hash[0]), bitselect(hash[0], hash[2], hash[3]), hash[2]) +                SQRT_2; hash[1] = rotate(hash[1] , 13u );

	hash[0] += bitselect(bitselect(hash[1], hash[2], hash[3]), bitselect(hash[3], hash[1], hash[2]), hash[1]) + nt_buffer[2] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += bitselect(bitselect(hash[0], hash[1], hash[2]), bitselect(hash[2], hash[0], hash[1]), hash[0]) + nt_buffer[6] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += bitselect(bitselect(hash[3], hash[0], hash[1]), bitselect(hash[1], hash[3], hash[0]), hash[3]) + nt_buffer[10]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += bitselect(bitselect(hash[2], hash[3], hash[0]), bitselect(hash[0], hash[2], hash[3]), hash[2]) + md4_size     + SQRT_2; hash[1] = rotate(hash[1] , 13u );

	hash[0] += bitselect(bitselect(hash[1], hash[2], hash[3]), bitselect(hash[3], hash[1], hash[2]), hash[1]) + nt_buffer[3] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += bitselect(bitselect(hash[0], hash[1], hash[2]), bitselect(hash[2], hash[0], hash[1]), hash[0]) + nt_buffer[7] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += bitselect(bitselect(hash[3], hash[0], hash[1]), bitselect(hash[1], hash[3], hash[0]), hash[3]) + nt_buffer[11]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += bitselect(bitselect(hash[2], hash[3], hash[0]), bitselect(hash[0], hash[2], hash[3]), hash[2]) +                SQRT_2; hash[1] = rotate(hash[1] , 13u );

#else

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

#endif

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

__kernel void nt(const __global uint *keys , __global uint *output)
{
	uint i = get_global_id(0);
	//Max Size 27-4 = 23 for a better use of registers
	uint nt_buffer[12];
	uint hash[4];

	//set key-------------------------------------------------------------------------
	uint nt_index = 0;
	uint md4_size = 0;

	uint num_keys = get_global_size(0);
	uint key_chars = keys[i];//Coalescing access to global memory
	uint cache_key = GET_CHAR(key_chars,ELEM_0);
	//Extract 4 chars by cycle
	int jump = 0;
	while(cache_key)
	{
		md4_size++;
		uint temp = GET_CHAR(key_chars,ELEM_1);
		nt_buffer[nt_index] = ((temp ? temp : 0x80) << 16) | cache_key;

		if(!temp) {
			jump = 1;
			break;
		}

		md4_size++;
		nt_index++;
		cache_key = GET_CHAR(key_chars,ELEM_2);

		//Repeat for a 4 bytes read
		if(!cache_key)
			break;

		md4_size++;
		temp = GET_CHAR(key_chars,ELEM_3);
		nt_buffer[nt_index] = ((temp ? temp : 0x80) << 16) | cache_key;

		if(!temp) {
			jump = 1;
			break;
		}

		md4_size++;
		nt_index++;

		key_chars = keys[(md4_size>>2)*num_keys+i];//Coalescing access to global memory
		cache_key = GET_CHAR(key_chars,ELEM_0);
	}

	if(!jump)
		nt_buffer[nt_index] = 0x80;

//key_cleaning:
	nt_index++;
	for(;nt_index < 12; nt_index++)
		nt_buffer[nt_index] = 0;

	md4_size = md4_size << 4;
	//end set key--------------------------------------------------------------------------

	nt_crypt(hash, nt_buffer, md4_size);

	//Coalescing writes
	output[i] = hash[1];
	output[1*num_keys+i] = hash[0];
	output[2*num_keys+i] = hash[2];
	output[3*num_keys+i] = hash[3];
}
