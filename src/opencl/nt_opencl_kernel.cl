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

#define NT_NUM_KEYS 1024*512

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

__kernel void nt_crypt(__global uint *data_info, const __global uint *keys , __global uint *output)
{
	uint i = get_global_id(0);
	//Max Size 27-4 = 23 for a better use of registers
	uint nt_buffer[12];

	
	//set key-------------------------------------------------------------------------
	uint nt_index = 0;
	uint md4_size = 0;
	
    	uint num_keys = data_info[1];
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
	
	uint a;
	uint b;
	uint c;
	uint d;
	
	/* Round 1 */
	a = 		0xFFFFFFFF					 + nt_buffer[0]; a=rotate(a, 3u);
	d = INIT_D+(INIT_C ^ (a & 0x77777777))   + nt_buffer[1]; d=rotate(d, 7u);
	c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2]; c=rotate(c, 11u);
	b = INIT_B + (a ^ (c & (d ^ a)))		 + nt_buffer[3]; b=rotate(b, 19u);
	
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[4] ; a = rotate(a , 3u );
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[5] ; d = rotate(d , 7u );
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[6] ; c = rotate(c , 11u);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[7] ; b = rotate(b , 19u);
	
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[8] ; a = rotate(a , 3u );
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[9] ; d = rotate(d , 7u );
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[10]; c = rotate(c , 11u);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[11]; b = rotate(b , 19u);
	
	a += (d ^ (b & (c ^ d)))                  ; a = rotate(a , 3u );
	d += (c ^ (a & (b ^ c)))                  ; d = rotate(d , 7u );
	c += (b ^ (d & (a ^ b)))  +    md4_size   ; c = rotate(c , 11u);
	b += (a ^ (c & (d ^ a)))                  ; b = rotate(b , 19u);
	
	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = rotate(a , 3u );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = rotate(d , 5u );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = rotate(c , 9u );
	b += ((c & (d | a)) | (d & a))                + SQRT_2; b = rotate(b , 13u);
	
	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = rotate(a , 3u );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = rotate(d , 5u );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = rotate(c , 9u );
	b += ((c & (d | a)) | (d & a))                + SQRT_2; b = rotate(b , 13u);
	
	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = rotate(a , 3u );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = rotate(d , 5u );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10]+ SQRT_2; c = rotate(c , 9u );
	b += ((c & (d | a)) | (d & a)) +   md4_size   + SQRT_2; b = rotate(b , 13u);
	
	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = rotate(a , 3u );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = rotate(d , 5u );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11]+ SQRT_2; c = rotate(c , 9u );
	b += ((c & (d | a)) | (d & a))                + SQRT_2; b = rotate(b , 13u);
	
	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0]  + SQRT_3; a = rotate(a , 3u );
	d += (c ^ b ^ a) + nt_buffer[8]  + SQRT_3; d = rotate(d , 9u );
	c += (b ^ a ^ d) + nt_buffer[4]  + SQRT_3; c = rotate(c , 11u);
	b += (a ^ d ^ c)                 + SQRT_3; b = rotate(b , 15u);
	
	a += (d ^ c ^ b) + nt_buffer[2]  + SQRT_3; a = rotate(a , 3u );
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = rotate(d , 9u );
	c += (b ^ a ^ d) + nt_buffer[6]  + SQRT_3; c = rotate(c , 11u);
	b += (a ^ d ^ c) +   md4_size    + SQRT_3; b = rotate(b , 15u);
	
	a += (d ^ c ^ b) + nt_buffer[1]  + SQRT_3; a = rotate(a , 3u );
	d += (c ^ b ^ a) + nt_buffer[9]  + SQRT_3; d = rotate(d , 9u );
	c += (b ^ a ^ d) + nt_buffer[5]  + SQRT_3; c = rotate(c , 11u);
	//It is better to calculate this remining steps that access global memory
	b += (a ^ d ^ c) ;
	output[i] = b;//Coalescing write
	b+= SQRT_3; b = rotate(b , 15u);
	
	a += (b ^ c ^ d) + nt_buffer[3]  + SQRT_3; a = rotate(a , 3u );
	d += (a ^ b ^ c) + nt_buffer[11] + SQRT_3; d = rotate(d , 9u );
	c += (d ^ a ^ b) + nt_buffer[7]  + SQRT_3; c = rotate(c , 11u);
	
	//Coalescing writes
	output[1*num_keys+i] = a;
	output[2*num_keys+i] = c;
	output[3*num_keys+i] = d;
}
