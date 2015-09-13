/*****Argon2i optimized implementation*
*  Code written by Daniel Dinu and Dmitry Khovratovich
* khovratovich@gmail.com
* modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
**/


#include <stdio.h>
#include <stdlib.h>

#include <stdint.h> 
#include <string.h>

#include "blake2-round-no-msg.h"
#include "blake2-impl.h"
#include "blake2.h"
#include "argon2i.h"

static void scheme_info_t_init(scheme_info_t *scheme, uint8_t* s, uint32_t m, uint32_t p, uint8_t l)
{ 
	scheme->state = s;
	scheme->mem_size = m;
	scheme->passes = p;
	scheme->lanes = l;
}

static void position_info_t_init(position_info_t *position, uint32_t p, uint8_t s, uint8_t l, uint32_t i)
{
	position->pass = p;
	position->slice = s;
	position->lane = l;
	position->index = i;
}

static int blake2b_long(uint8_t *out, const void *in, const uint32_t outlen, const uint64_t inlen)
{
	uint32_t toproduce;	
	blake2b_state blake_state;
	if (outlen <= BLAKE2B_OUTBYTES)
	{
		blake2b_init(&blake_state, outlen);
		blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
		blake2b_update(&blake_state, (const uint8_t *)in, inlen);
		blake2b_final(&blake_state, out, outlen);
	}
	else
	{
		uint8_t out_buffer[BLAKE2B_OUTBYTES];
		uint8_t in_buffer[BLAKE2B_OUTBYTES];
		blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
		blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
		blake2b_update(&blake_state, (const uint8_t *)in, inlen);
		blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
		memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
		out += BLAKE2B_OUTBYTES / 2;
		toproduce = outlen - BLAKE2B_OUTBYTES / 2;
		while (toproduce > BLAKE2B_OUTBYTES)
		{
			memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
			blake2b(out_buffer, in_buffer, NULL, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
			memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			toproduce -= BLAKE2B_OUTBYTES / 2;
		}
		memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
		blake2b(out_buffer, in_buffer, NULL, toproduce, BLAKE2B_OUTBYTES, 0);
		memcpy(out, out_buffer, toproduce);
		
	}
	return 0;
}

static void ComputeBlock(uint64_t *v, uint8_t* ref_block_ptr, uint8_t* next_block_ptr)
{
	uint64_t ref_block[128];
	uint8_t i;

	for (i = 0; i < 128; i++)
	{
		ref_block[i] = ((uint64_t *)ref_block_ptr)[i];
	}


	for (i = 0; i < 128; i++)
	{
		ref_block[i] = v[i] = v[i]^ref_block[i]; //XORing the reference block to the state and storing the copy of the result
	}

	// BLAKE2 - begin
	for (i = 0; i < 8; ++i)//Applying Blake2 on columns of 64-bit words: (0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
	{

		BLAKE2_ROUND_NOMSG(v[16 * i], v[16 * i + 1], v[16 * i + 2], v[16 * i + 3], v[16 * i + 4],
			v[16 * i + 5], v[16 * i + 6], v[16 * i + 7], v[16 * i + 8], v[16 * i + 9], v[16 * i + 10],
			v[16 * i + 11], v[16 * i + 12], v[16 * i + 13], v[16 * i + 14], v[16 * i + 15]);
	}
	for (i = 0; i < 8; i++) //(0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
	{
		BLAKE2_ROUND_NOMSG(v[2*i], v[2*i + 1], v[2*i + 16], v[2*i + 17], v[2*i + 32], v[2*i + 33], v[2*i + 48],
			v[2*i + 49], v[2*i + 64], v[2*i + 65], v[2*i + 80], v[2*i + 81], v[2*i + 96], v[2*i + 97],
			v[2*i + 112], v[2*i + 113]);
	}// BLAKE2 - end


	for (i = 0; i< 128; i++)
	{
		v[i] = v[i] ^ ref_block[i]; //Feedback
		((uint64_t *) next_block_ptr)[i]= v[i];
	}
}


static void Initialize(scheme_info_t* info,uint8_t* input_hash)
{
	uint8_t l;
	uint8_t block_input[BLAKE_INPUT_HASH_SIZE + 8];
	uint32_t segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, BLAKE_INPUT_HASH_SIZE);
	memset(block_input + BLAKE_INPUT_HASH_SIZE, 0, 8);
	for (l = 0; l < info->lanes; ++l)
	{
		block_input[BLAKE_INPUT_HASH_SIZE + 4] = l;
		block_input[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long(info->state + l * segment_length*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		block_input[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long(info->state + (l * segment_length + 1)*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(block_input, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

static void Finalize(uint8_t *state, uint8_t* out, uint32_t outlen, uint8_t lanes, uint32_t m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	uint8_t l;
	uint32_t j;
	uint64_t blockhash[BLOCK_SIZE/sizeof(uint64_t)];
	memset(blockhash, 0, BLOCK_SIZE);
	for (l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint32_t segment_length = m_cost / (SYNC_POINTS*lanes);
		uint8_t* block_ptr = state + (((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE; //points to the last block of the first lane

		for (j = 0; j < BLOCK_SIZE / sizeof(uint64_t); ++j)
		{
			blockhash[j] = blockhash[j]^( *(uint64_t*)block_ptr);
			block_ptr += sizeof(uint64_t);
		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);
}

static void GenerateAddresses(const scheme_info_t* info, position_info_t* position, uint32_t* addresses)//generate 256 addresses 
{
	uint32_t i;
	uint8_t zero_block[BLOCK_SIZE];
	uint32_t input_block[BLOCK_SIZE/4];
	uint32_t segment_length;
	uint32_t barrier1; //Number of blocks generated in previous slices
	uint32_t barrier2; //Number of blocks that we can reference in total (including the last blocks of each lane
	uint32_t start = 0;
	memset(zero_block, 0,BLOCK_SIZE);
	memset(input_block, 0, 256 * sizeof(uint32_t));
	input_block[0] = position->pass;
	input_block[1] = position->lane;
	input_block[2] = position->slice;
	input_block[3] = position->index;
	input_block[4] = 0xFFFFFFFF;
	ComputeBlock((uint64_t*)input_block, zero_block, (uint8_t*)addresses);
	ComputeBlock((uint64_t*)zero_block, (uint8_t*)addresses, (uint8_t*)addresses);


	/*Making block offsets*/
	segment_length = info->mem_size / ((info->lanes)*SYNC_POINTS);
	barrier1 = (position->slice) * segment_length*(info->lanes);

	if (position->pass == 0)//Including later slices for second and later passes
	{
		barrier2 = barrier1;
		if (position->slice == 0 && position->index==0)
			start = 2;
	}
	else
		barrier2 = barrier1 + (SYNC_POINTS - position->slice - 1) *  segment_length*(info->lanes);
	
	if (position->index == 0 && start==0)/*Special rule for first block of the segment, if not very first blocks*/
	{
		uint32_t r = barrier2 - (info->lanes);
		uint32_t reference_block_index = addresses[0] % r;
		uint32_t prev_block_recalc = (position->slice > 0) ? ((position->slice - 1)*(info->lanes)*segment_length) : (SYNC_POINTS - 2)*(info->lanes)*segment_length;

		/*Shifting <reference_block_index> to have gaps in the last blocks of each lane*/
		if (reference_block_index >= prev_block_recalc)
		{
			uint32_t shift = (reference_block_index - prev_block_recalc) / (segment_length - 1);
			reference_block_index += (shift > info->lanes) ? info->lanes : shift;
		}
		if (reference_block_index < barrier1)
			addresses[0] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[0] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[0] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
		start = 1;
	}
	
	for (i = start; i < ADDRESSES_PER_BLOCK; ++i)
	{
		uint32_t r = barrier2 + (position->index)*ADDRESSES_PER_BLOCK+i - 1;
		uint32_t reference_block_index = addresses[i] % r;
		//Mapping the reference block address into the memory
		if (reference_block_index < barrier1)
			addresses[i] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[i] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[i] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
	}
}

static void FillSegment(const scheme_info_t* info, const position_info_t position)
{
	uint32_t i;
	uint64_t prev_block[128];
	uint32_t addresses[ADDRESSES_PER_BLOCK];
	uint32_t next_block_offset;
	uint8_t *memory = info->state;
	uint32_t pass = position.pass;
	uint32_t slice = position.slice;
	uint8_t lane = position.lane;
	uint8_t lanes = info->lanes;
	uint32_t m_cost = info->mem_size;
	position_info_t position_local = position;

	uint32_t segment_length = m_cost / (lanes*SYNC_POINTS);
	//uint32_t stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint32_t start=0;

	uint32_t prev_block_offset; //offset of previous block

	if(0 == pass && 0 == slice) // First pass; first slice
	{
		uint32_t bi;
		uint32_t reference_block_offset;

		start += 3;
		if (segment_length <= 2)
			return;

		bi = prev_block_offset = (lane * segment_length + 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 128; i++)
		{
			prev_block[i] = *(uint64_t *) (&memory[bi]);
			bi += 8;
		}
		
		next_block_offset = (lane * segment_length + 2) * BLOCK_SIZE;

		reference_block_offset = (lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock(prev_block, memory+ reference_block_offset, memory+next_block_offset);//Computing third block in the segment
		position_local.index = 0;
		GenerateAddresses(info, &position_local, addresses);
	}
	else
	{
		uint32_t prev_slice = (slice>0)?(slice-1):(SYNC_POINTS-1);
		uint32_t bi = prev_block_offset = ((prev_slice * lanes + lane + 1) * segment_length - 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 128; i++)
		{
			prev_block[i] = *(uint64_t *) (&memory[bi]);
			bi += 8;
		}
	}

	next_block_offset = ((slice*lanes + lane)*segment_length + start)*BLOCK_SIZE;
	for(i = start; i < segment_length; i++)
	{
		// compute block
		if ((i&ADDRESSES_MASK) == 0)
		{
			position_local.index = i / ADDRESSES_PER_BLOCK;
			GenerateAddresses(info, &position_local, addresses);
		}
		ComputeBlock(prev_block, memory+addresses[i&ADDRESSES_MASK], memory + next_block_offset);
		next_block_offset += BLOCK_SIZE;
	}
}



static void FillMemory(const scheme_info_t* info)//Main loop: filling memory <t_cost> times
{
	uint32_t p,s,t;
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


static int Argon2i(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes, void *memory_)
{
	uint8_t *memory=(uint8_t*) memory_;
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE];//H_0 in the document
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	scheme_info_t info;

	if (outlen>MAX_OUTLEN)
		outlen = MAX_OUTLEN;
	if (outlen < MIN_OUTLEN)
		return -1;  //Tag too short

	if (msglen> MAX_MSG)
		msglen = MAX_MSG;
	if (msglen < MIN_MSG)
		return -2; //Password too short

	if (noncelen < MIN_NONCE)
		return -3; //Salt too short
	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;
	if (secretlen < MIN_SECRET)
		return -4; //Secret too short

	if (adlen> MAX_AD)
		adlen = MAX_AD;
	if (adlen < MIN_AD)
		return -5; //Associated data too short

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*(uint32_t)lanes)
		m_cost = 2 * SYNC_POINTS*(uint32_t)lanes;
	if (m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;

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

	blake2b_update(&BlakeHash, (const uint8_t*)&lanes, sizeof(lanes));
	blake2b_update(&BlakeHash, (const uint8_t*)&outlen, sizeof(outlen));
	blake2b_update(&BlakeHash, (const uint8_t*)&m_cost, sizeof(m_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&t_cost, sizeof(t_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&version, sizeof(version));
	blake2b_update(&BlakeHash, (const uint8_t*)&msglen, sizeof(msglen));
	blake2b_update(&BlakeHash, (const uint8_t*)msg, msglen);
	blake2b_update(&BlakeHash, (const uint8_t*)&noncelen, sizeof(noncelen));
	blake2b_update(&BlakeHash, (const uint8_t*)nonce, noncelen);
	blake2b_update(&BlakeHash, (const uint8_t*)&secretlen, sizeof(secretlen));
	blake2b_update(&BlakeHash, (const uint8_t*)secret, secretlen);
	blake2b_update(&BlakeHash, (const uint8_t*)&adlen, sizeof(adlen));
	blake2b_update(&BlakeHash, (const uint8_t*)ad, adlen);


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE); //Calculating H0

	scheme_info_t_init(&info, memory, m_cost, t_cost, lanes);
	
	Initialize(&info,blockhash); //Computing first two blocks in each segment


	FillMemory(&info);  //Filling memory with <t_cost> passes

	Finalize(memory, out,outlen, lanes, m_cost);

	return 0;
}

int ARGON2i(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	 unsigned int t_cost, unsigned int m_cost, uint8_t lanes, void *memory)
 {
	return Argon2i((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, lanes, memory);
 }
