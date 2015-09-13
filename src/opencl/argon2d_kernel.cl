/*****Argon2d optimized implementation*
*  Code written by Daniel Dinu and Dmitry Khovratovich
* khovratovich@gmail.com
* modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
**/

#define USE_COALESCING 1

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_string.h"
#include "opencl_blake2.h"
#include "opencl_argon2d.h"
#include "opencl_blake2-round-no-msg.h"

#if USE_COALESCING == 1
#define MAP(X) ((X)*get_global_size(0))
#else
#define MAP(X) ((X))
#endif

// BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH is paVd with -D during build

struct argon2d_salt {
	unsigned int t_cost, m_cost;
	uchar lanes;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

static void scheme_info_t_init(scheme_info_t *scheme, __global ulong2* s, uint m, uint p, uchar l)
{
	scheme->state = s;
	scheme->mem_size = m;
	scheme->passes = p;
	scheme->lanes = l;
}

static void position_info_t_init(position_info_t *position, uint p, uchar s, uchar l, uint i)
{
	position->pass = p;
	position->slice = s;
	position->lane = l;
	position->index = i;
}

static int blake2b_long(uchar *out, const void *in, const uint outlen, const ulong inlen)
{
	uint toproduce;
	blake2b_state blake_state;
	if (outlen <= BLAKE2B_OUTBYTES)
	{
		blake2b_init(&blake_state, outlen);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final(&blake_state, out, outlen);
	}
	else
	{
		uchar out_buffer[BLAKE2B_OUTBYTES];
		uchar in_buffer[BLAKE2B_OUTBYTES];
		blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
		memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
		out += BLAKE2B_OUTBYTES / 2;
		toproduce = outlen - BLAKE2B_OUTBYTES / 2;
		while (toproduce > BLAKE2B_OUTBYTES)
		{
			memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
			blake2b(out_buffer, in_buffer, 0, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
			memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			toproduce -= BLAKE2B_OUTBYTES / 2;
		}
		memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
		blake2b(out_buffer, in_buffer, 0, toproduce, BLAKE2B_OUTBYTES, 0);
		memcpy(out, out_buffer, toproduce);

	}
	return 0;
}


static void ComputeBlock_pgg(ulong2 *state, __global ulong2 *ref_block_ptr, __global ulong2 *next_block_ptr)
{
	ulong2 ref_block[64];
	uchar i;

	ulong2 t0,t1;
	uchar16 r16 = (uchar16) (2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	uchar16 r24 = (uchar16) (3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

	for (i = 0; i < 64; i++)
	{
		ref_block[i] = ref_block_ptr[MAP(i)];
	}

	for (i = 0; i < 64; i++)
	{
		ref_block[i] = state[i] = state[i] ^ ref_block[i]; //XORing the reference block to the state and storing the copy of the result
	}


	// BLAKE2 - begin

	BLAKE2_ROUND_NO_MSG_V(state[0], state[1], state[2], state[3],
		state[4], state[5], state[6], state[7]);

	BLAKE2_ROUND_NO_MSG_V(state[8], state[9], state[10], state[11],
		state[12], state[13], state[14], state[15]);

	BLAKE2_ROUND_NO_MSG_V(state[16], state[17], state[18], state[19],
		state[20], state[21], state[22], state[23]);

	BLAKE2_ROUND_NO_MSG_V(state[24], state[25], state[26], state[27],
		state[28], state[29], state[30], state[31]);

	BLAKE2_ROUND_NO_MSG_V(state[32], state[33], state[34], state[35],
		state[36], state[37], state[38], state[39]);

	BLAKE2_ROUND_NO_MSG_V(state[40], state[41], state[42], state[43],
		state[44], state[45], state[46], state[47]);

	BLAKE2_ROUND_NO_MSG_V(state[48], state[49], state[50], state[51],
		state[52], state[53], state[54], state[55]);

	BLAKE2_ROUND_NO_MSG_V(state[56], state[57], state[58], state[59],
		state[60], state[61], state[62], state[63]);


	BLAKE2_ROUND_NO_MSG_V(state[0], state[8], state[16], state[24],
		state[32], state[40], state[48], state[56]);

	BLAKE2_ROUND_NO_MSG_V(state[1], state[9], state[17], state[25],
		state[33], state[41], state[49], state[57]);

	BLAKE2_ROUND_NO_MSG_V(state[2], state[10], state[18], state[26],
		state[34], state[42], state[50], state[58]);

	BLAKE2_ROUND_NO_MSG_V(state[3], state[11], state[19], state[27],
		state[35], state[43], state[51], state[59]);

	BLAKE2_ROUND_NO_MSG_V(state[4], state[12], state[20], state[28],
		state[36], state[44], state[52], state[60]);

	BLAKE2_ROUND_NO_MSG_V(state[5], state[13], state[21], state[29],
		state[37], state[45], state[53], state[61]);

	BLAKE2_ROUND_NO_MSG_V(state[6], state[14], state[22], state[30],
		state[38], state[46], state[54], state[62]);

	BLAKE2_ROUND_NO_MSG_V(state[7], state[15], state[23], state[31],
		state[39], state[47], state[55], state[63]);

	// BLAKE2 - end

	for (i = 0; i< 64; i++)
	{
		state[i] = state[i] ^ ref_block[i]; //Feedback
	}

	for (i = 0; i< 64; i++)
	{
		next_block_ptr[MAP(i)]=state[i];
	}
}

static void Initialize(scheme_info_t* info,uchar* input_hash)
{
	uchar l;
	uint i;
	__global ulong2 *memory=info->state;
	uchar block_input[BLAKE_INPUT_HASH_SIZE + 8];
	ulong2 out_tmp[BLOCK_SIZE/16];
	uint segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, BLAKE_INPUT_HASH_SIZE);
	memset(block_input + BLAKE_INPUT_HASH_SIZE, 0, 8);
	for (l = 0; l < info->lanes; ++l)
	{
		block_input[BLAKE_INPUT_HASH_SIZE + 4] = l;
		block_input[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long((uchar*)out_tmp, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		for(i=0;i<BLOCK_SIZE/16;i++)
			memory[MAP(l * segment_length*BLOCK_SIZE/16+i)]=out_tmp[i];
		block_input[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uchar*)out_tmp, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		for(i=0;i<BLOCK_SIZE/16;i++)
			memory[MAP((l * segment_length + 1)*BLOCK_SIZE/16+i)]=out_tmp[i];
	}
	memset(block_input, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

static void Finalize_g(__global ulong2 *state, uchar* out, uint outlen, uchar lanes, uint m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	uchar l;
	uint j;
	ulong2 blockhash[BLOCK_SIZE/sizeof(ulong2)];
	for(j=0;j<BLOCK_SIZE/sizeof(ulong2);j++)
	{
		blockhash[j]=0;
	}
	for (l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint segment_length = m_cost / (SYNC_POINTS*lanes);
		__global ulong2* block_ptr = state + MAP((((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE/16); //points to the last block of the first lane

		for (j = 0; j < BLOCK_SIZE / sizeof(ulong2); ++j)
		{
			blockhash[j] = blockhash[j]^block_ptr[MAP(j)];

		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);
}

static void FillSegment(scheme_info_t *info, position_info_t pos)
{
	uint i;

	ulong2 prev_block[64];

	uint next_block_offset;
	uchar lanes = info->lanes;
	__global ulong2* memory = info->state;
	uint phi;

	uint segment_length = (info->mem_size) / (lanes*SYNC_POINTS);
	//uint stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint start=0;

	uint prev_block_recalc=0; //number of the first block in the reference area in the previous slice

	if(0 == pos.pass && 0 == pos.slice) // First pass; first slice
	{
		uint bi;
		uint reference_block_offset;

		start += 3;
		if (segment_length <= 2)
			return;

		bi = (pos.lane * segment_length + 1) * BLOCK_SIZE / 16;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 64; i++)
		{
			prev_block[i] = memory[MAP(bi+i)];
		}

		next_block_offset = (pos.lane * segment_length + 2) * BLOCK_SIZE;

		reference_block_offset = (pos.lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock_pgg(prev_block, memory+ MAP(reference_block_offset/16), memory+MAP(next_block_offset/16));//Computing third block in the segment

		phi = ((ulong *)prev_block)[0];
	}
	else
	{
		uint prev_slice = (pos.slice>0)?(pos.slice-1):(SYNC_POINTS-1);
		uint bi;

		prev_block_recalc = (pos.slice > 0) ? ((pos.slice - 1)*lanes*segment_length) : (SYNC_POINTS - 2)*lanes*segment_length;
		bi = ((prev_slice * lanes + pos.lane + 1) * segment_length - 1) * BLOCK_SIZE / 16;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 64; i++)
		{
			prev_block[i] = memory[MAP(bi+i)];
		}

		phi = ((ulong *)prev_block)[0];
	}

	next_block_offset = ((pos.slice*lanes + pos.lane)*segment_length + start)*BLOCK_SIZE;
	for(i = start; i < segment_length; i++)
	{
		// Compute block2 index
		uint barrier1 = pos.slice * segment_length*lanes; //Number of blocks generated in previous slices

		uint barrier2;  //Number of blocks that we can reference in total (including the previous block in the lane that we can not reference in the first block of the segment)
		uint barrier3, r, reference_block_offset;

		if(pos.pass==0)
			barrier2 = barrier1;
		else
		{
			barrier2 = barrier1 + (SYNC_POINTS - pos.slice - 1) *  segment_length*lanes;
		}

		barrier3 = (i==0)? (barrier2 -lanes):(barrier2+ i-1);

		r = barrier3;

		reference_block_offset = (phi % r);

		/*Excluding the previous block from referencing*/
		if(i==0)
		{
			if (reference_block_offset >= prev_block_recalc)
			{
				uint shift = (reference_block_offset - prev_block_recalc) / (segment_length - 1);
				reference_block_offset += (shift > lanes) ? lanes : shift;
			}
		}

		//Mapping the reference block address into the memory
		if(reference_block_offset < barrier1)
			reference_block_offset *= BLOCK_SIZE;
		else
		{
			if(reference_block_offset >= barrier1 && reference_block_offset < barrier2)
				reference_block_offset = (reference_block_offset + segment_length*lanes) * BLOCK_SIZE;
			else
				reference_block_offset = (reference_block_offset - (barrier2 - barrier1) + pos.lane *  segment_length) * BLOCK_SIZE;
		}

		// compute block
		ComputeBlock_pgg(prev_block, memory + MAP(reference_block_offset/16), memory+MAP(next_block_offset/16));
		phi = ((ulong *)prev_block)[0];
		next_block_offset += BLOCK_SIZE;
	}
}

static void FillMemory(scheme_info_t* info)//Main loop: filling memory <t_cost> times
{
	uint p,s,t;
	position_info_t position;
	position_info_t_init(&position,0,0,0,0);
	for (p = 0; p < info->passes; p++)
	{
		position.pass = p;
		for (s = 0; s < SYNC_POINTS; s++)
		{
			position.slice = s;
			for (t = 0; t < info->lanes; t++)
			{
				position.lane = t;
				FillSegment(info, position);
			}
		}
	}
}

static int argon2d(__global uchar *out, uint outlen, const uchar *msg, uint msglen, const uchar *nonce, uint noncelen, const uchar *secret,
	uchar secretlen, const uchar *ad, uint adlen, uint t_cost, uint m_cost, uchar lanes, __global ulong2 *memory)
{
	uchar blockhash[BLAKE_INPUT_HASH_SIZE];//H_0 in the document
	uchar out_tmp[BINARY_SIZE*10];
	uchar version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	scheme_info_t info;

	if (outlen>MAX_OUTLEN)
		outlen = MAX_OUTLEN;
	if (outlen < MIN_OUTLEN)
		return -1;  //Tag too short

	if (msglen> MAX_MSG)
		msglen = MAX_MSG;

	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;

	if (adlen> MAX_AD)
		adlen = MAX_AD;

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*(uint)lanes)
		m_cost = 2 * SYNC_POINTS*(uint)lanes;
	if (m_cost>MAX_MEMORY)
		return -6;

	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =3
	if (t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;


	//Initial hashing
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE);
	blake2b_init(&BlakeHash, BLAKE_INPUT_HASH_SIZE);

	blake2b_update(&BlakeHash, (const uchar*)&lanes, sizeof(lanes));
	blake2b_update(&BlakeHash, (const uchar*)&outlen, sizeof(outlen));
	blake2b_update(&BlakeHash, (const uchar*)&m_cost, sizeof(m_cost));
	blake2b_update(&BlakeHash, (const uchar*)&t_cost, sizeof(t_cost));
	blake2b_update(&BlakeHash, (const uchar*)&version, sizeof(version));
	blake2b_update(&BlakeHash, (const uchar*)&msglen, sizeof(msglen));
	blake2b_update(&BlakeHash, (const uchar*)msg, msglen);
	blake2b_update(&BlakeHash, (const uchar*)&noncelen, sizeof(noncelen));
	blake2b_update(&BlakeHash, (const uchar*)nonce, noncelen);
	blake2b_update(&BlakeHash, (const uchar*)&secretlen, sizeof(secretlen));
	blake2b_update(&BlakeHash, (const uchar*)secret, secretlen);
	blake2b_update(&BlakeHash, (const uchar*)&adlen, sizeof(adlen));
	blake2b_update(&BlakeHash, (const uchar*)ad, adlen);


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE); //Calculating H0

	scheme_info_t_init(&info, memory, m_cost, t_cost, lanes);
	//2433K
	Initialize(&info,blockhash); //Computing first two blocks in each segment


	FillMemory(&info);  //Filling memory with <t_cost> passes
	//11K
	Finalize_g(memory, out_tmp, outlen , lanes, m_cost);
	memcpy_g(out, out_tmp, outlen);

	return 0;
}


__kernel void argon2d_crypt_kernel(
    __global const uchar * in,
    __global const uint * lengths,
    __global uchar *out,
    __global struct argon2d_salt *salt,
    __global ulong2 *memory
)
{
	uint i;
	uint gid;

	uint m_cost, t_cost;
	uchar lanes;
	uint outlen, noncelen;

	uint inlen;

	uchar passwd[PLAINTEXT_LENGTH];
	uchar nonce[SALT_SIZE];

	gid = get_global_id(0);

	out += gid * BINARY_SIZE;

	inlen = lengths[gid];

	outlen = salt->hash_size;
	noncelen = salt->salt_length;

	t_cost = salt->t_cost;
	m_cost = salt->m_cost;
	lanes=salt->lanes;

	in += gid*PLAINTEXT_LENGTH;
#if USE_COALESCING == 1
	memory+=gid;
#else
	memory+=gid*(((ulong)m_cost)<<10)/sizeof(ulong2);
#endif

	//copying password
	for(i=0;i<inlen;i++)
		passwd[i]=in[i];

	//copying salt
	for(i=0;i<noncelen;i++)
		nonce[i]=salt->salt[i];

	argon2d(out, outlen, passwd, inlen, nonce, noncelen, 0, 0, 0, 0, t_cost, m_cost, lanes, memory);
}
