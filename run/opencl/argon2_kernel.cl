//-------------------------------------------------------------------------------------
// JtR OpenCL format to crack hashes from argon2.
//
// This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
// is hereby released to the general public under the following terms:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//
//-------------------------------------------------------------------------------------
//
// Based on OpenCL code from https://gitlab.com/omos/argon2-gpu.
//
// MIT License
//
// Copyright (c) 2016 Ondrej Mosnáček
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//-------------------------------------------------------------------------------------

#define ARGON2_D  0
#define ARGON2_I  1
#define ARGON2_ID 2

#ifndef ONLY_KERNEL_DEFINITION

// Define the first kernel
#define ARGON2_TYPE ARGON2_D

#define ARGON2_VERSION_10 0x10
#define ARGON2_VERSION_13 0x13

#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)
#define ARGON2_SYNC_POINTS 4

#define THREADS_PER_LANE 32
#define QWORDS_PER_THREAD (ARGON2_QWORDS_IN_BLOCK / 32)

#ifndef ARGON2_VERSION
#define ARGON2_VERSION ARGON2_VERSION_13
#endif

#include "opencl_rotate.h"

// Define when we will use warp_shuffle instructions and not local memory
#if USE_WARP_SHUFFLE
#define u64_shuffle(v, thread_src, thread, buf) u64_shuffle_warp(v, thread_src)
ulong u64_shuffle_warp(ulong v, uint thread_src)
#else
//#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
ulong u64_shuffle(ulong v, uint thread_src, uint thread, __local ulong *buf)
#endif
{
#if USE_WARP_SHUFFLE && !__OS_X__ && gpu_nvidia(DEVICE_INFO) && SM_MAJOR >= 3
	ulong result;

	asm("{\n\t"
		".reg .b32 v_lo;\n\t"
		".reg .b32 v_hi;\n\t"
		".reg .b32 r_lo;\n\t"
		".reg .b32 r_hi;\n\t"

		"mov.b64  {v_hi,v_lo}, %1;\n\t"

		"shfl.sync.idx.b32  r_lo, v_lo, %2, 0x1f, 0xffffffff;\n\t"
		"shfl.sync.idx.b32  r_hi, v_hi, %2, 0x1f, 0xffffffff;\n\t"

		"mov.b64  %0, {r_hi,r_lo};\n\t"
		"}"
		: "=l" (result) : "l" (v), "r" (thread_src));

	return result;
#else // Using local memory
	buf[thread] = v;
	// Another option instead of the barrier. Maybe worth testing on CPUs because
	// in C++ default atomic operations DO a memory barrier.
	// atom_xchg(buf + thread, v);

	// GPUs don't need this as their warp size is at least 32 and that's what we need
	// TODO: Test on other device types to add support
#if !gpu_nvidia(DEVICE_INFO) && !gpu_amd(DEVICE_INFO)
	barrier(CLK_LOCAL_MEM_FENCE);
#elif !__OS_X__ && gpu_amd(DEVICE_INFO) && DEV_VER_MAJOR < 2500
	asm("" ::: "memory");
#endif
	return buf[thread_src];
#endif
}

struct block_g {
	ulong data[ARGON2_QWORDS_IN_BLOCK];
};

struct block_th {
	ulong a, b, c, d;
};

ulong block_th_get(const struct block_th *b, uint idx)
{
	ulong res;
	if (idx == 0) res = b->a;
	if (idx == 1) res = b->b;
	if (idx == 2) res = b->c;
	if (idx == 3) res = b->d;
	return res;
}

void block_th_set(struct block_th *b, uint idx, ulong v)
{
	if (idx == 0) b->a = v;
	if (idx == 1) b->b = v;
	if (idx == 2) b->c = v;
	if (idx == 3) b->d = v;
}

ulong mul_wide_u32(ulong a, ulong b)
{
#if gpu_nvidia(DEVICE_INFO)
	// Very small performance improvement ~0.5%. The mad instruction is doing the heavy lifting here.
	ulong result;
	uint aa = a;
	uint bb = b;
	asm("mul.wide.u32 %0, %1, %2;\n\t"
		"mad.lo.u64   %0, %0, 2, %3;"
		: "+l" (result) : "r" (aa), "r" (bb), "l" (b));
	return result;
#else
	return (a & 0xffffffff) * (b & 0xffffffff) * 2 + b;
#endif
}

void g(struct block_th *block)
{
	ulong a = block->a;
	ulong b = block->b;
	ulong c = block->c;
	ulong d = block->d;

	a += mul_wide_u32(a, b);
	d = ror64(d ^ a, 32);
	c += mul_wide_u32(c, d);
	b = ror64(b ^ c, 24);
	a += mul_wide_u32(a, b);
	d = ror64(d ^ a, 16);
	c += mul_wide_u32(c, d);
	b = ror64(b ^ c, 63);

	block->a = a;
	block->b = b;
	block->c = c;
	block->d = d;
}

uint apply_shuffle_shift2(uint thread, uint idx)
{
	uint lo = (thread & 0x1) | ((thread & 0x10) >> 3);
	lo = (lo + idx) & 0x3;
	return ((lo & 0x2) << 3) | (thread & 0xe) | (lo & 0x1);
}

#if USE_WARP_SHUFFLE
#define shuffle_block(block, thread, buf) shuffle_block_warp(block, thread)
void shuffle_block_warp(struct block_th *block, uint thread)
#else
void shuffle_block(struct block_th *block, uint thread, __local ulong *buf)
#endif
{
	// transpose(block, thread, buf);
	uint thread_group = (thread & 0x0C) >> 2;
	for (uint i = 1; i < QWORDS_PER_THREAD; i++) {
		// TODO: Try to optimize 'block_th_*et' with LUT
		uint idx = thread_group ^ i;

		ulong v = block_th_get(block, idx);
		v = u64_shuffle(v, (i << 2) ^ thread, thread, buf);
		block_th_set(block, idx, v);
	}

	g(block);

	// shuffle_shift1(block, thread, buf);
	//uint thread_src0 = thread & 0x1f;
	uint thread_src1 = (thread & 0x1c) | ((thread + 3) & 0x3);
	uint thread_src2 = (thread & 0x1c) | ((thread + 2) & 0x3);
	uint thread_src3 = (thread & 0x1c) | ((thread + 1) & 0x3);
	//block->a = u64_shuffle(block->a, thread_src0, thread, buf);
	block->b = u64_shuffle(block->b, thread_src3, thread, buf);
	block->c = u64_shuffle(block->c, thread_src2, thread, buf);
	block->d = u64_shuffle(block->d, thread_src1, thread, buf);

	g(block);

	// shuffle_unshift1(block, thread, buf);
	//block->a = u64_shuffle(block->a, thread_src0, thread, buf);
	block->b = u64_shuffle(block->b, thread_src1, thread, buf);
	block->c = u64_shuffle(block->c, thread_src2, thread, buf);
	block->d = u64_shuffle(block->d, thread_src3, thread, buf);

	// transpose(block, thread, buf);
	for (uint i = 1; i < QWORDS_PER_THREAD; i++) {
		// TODO: Try to optimize 'block_th_*et' with LUT
		uint idx = thread_group ^ i;

		ulong v = block_th_get(block, idx);
		v = u64_shuffle(v, (i << 2) ^ thread, thread, buf);
		block_th_set(block, idx, v);
	}

	g(block);

	// shuffle_shift2(block, thread, buf);
#if nvidia_sm_5plus(DEVICE_INFO) && !nvidia_sm_5x(DEVICE_INFO)
#define DUMMY_WRITES_TO_A
	// This speeds things up on GTX 1080 despite of PTX code size increase
	uint thread_src0 = apply_shuffle_shift2(thread, 0);
#endif
	thread_src1 = apply_shuffle_shift2(thread, 1);
	thread_src2 = apply_shuffle_shift2(thread, 2);
	thread_src3 = apply_shuffle_shift2(thread, 3);
	// TODO: Try to optimize 'apply_shuffle_shift2' with LUT

#ifdef DUMMY_WRITES_TO_A
	block->a = u64_shuffle(block->a, thread_src0, thread, buf);
#endif
	block->b = u64_shuffle(block->b, thread_src1, thread, buf);
	block->c = u64_shuffle(block->c, thread_src2, thread, buf);
	block->d = u64_shuffle(block->d, thread_src3, thread, buf);

	g(block);

#ifdef DUMMY_WRITES_TO_A
	block->a = u64_shuffle(block->a, thread_src0, thread, buf);
#endif
	block->b = u64_shuffle(block->b, thread_src3, thread, buf);
	block->c = u64_shuffle(block->c, thread_src2, thread, buf);
	block->d = u64_shuffle(block->d, thread_src1, thread, buf);
}

#if USE_WARP_SHUFFLE
#define next_addresses(addr, thread_input, thread, buf) next_addresses_warp(addr, thread_input, thread)
void next_addresses_warp(struct block_th *addr, uint thread_input, uint thread)
#else
void next_addresses(struct block_th *addr, uint thread_input, uint thread, __local ulong *buf)
#endif
{
	addr->a = upsample(0, thread_input);
	addr->b = 0;
	addr->c = 0;
	addr->d = 0;

	shuffle_block(addr, thread, buf);

	addr->a ^= upsample(0, thread_input);
	struct block_th tmp = *addr;

	shuffle_block(addr, thread, buf);

	//xor_block(addr, tmp);
	addr->a ^= tmp.a;
	addr->b ^= tmp.b;
	addr->c ^= tmp.c;
	addr->d ^= tmp.d;
}

// Begin pre-processing kernel code

// Blake2b G Mixing function.
#define B2B_G(a, b, c, d, x, y) { \
	v[a] = v[a] + v[b] + x; \
	v[d] = ror64(v[d] ^ v[a], 32); \
	v[c] = v[c] + v[d]; \
	v[b] = ror64(v[b] ^ v[c], 24); \
	v[a] = v[a] + v[b] + y; \
	v[d] = ror64(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d]; \
	v[b] = ror64(v[b] ^ v[c], 63); }

void blake2b_block(ulong m[16], ulong out_len, ulong message_size)
{
	const ulong blake2b_iv[8] = {
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
		0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
		0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
		0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
	};

	const uchar sigma[12][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
	};

	ulong v[16];
	// Init work variables
	for (int i = 0; i < 8; i++)
		v[i] = v[i + 8] = blake2b_iv[i];
	v[0] ^= 0x01010000 ^ out_len;

	v[12] ^= message_size;// low 64 bits of offset
	//v[13] ^= 0;		 // high 64 bits
	v[14] = ~v[14];	   // last block flag set ?

	// Rounds
	for (int i = 0; i < 12; i++) {
		B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
		B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
		B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
		B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
		B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
		B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
		B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
		B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
	}

	// Save data to message
	for(int i = 0; i < 8; i++)
		m[i] = blake2b_iv[i] ^ v[i] ^ v[i + 8];
	m[0] ^= 0x01010000 ^ out_len;
}
#undef B2B_G

#define BLAKE2B_OUTBYTES 64

__kernel void pre_processing(__global uint* in_memory, __global ulong* out_memory, uint buffer_row_pitch, uint max_job_id)
{
	size_t lane_id  = get_global_id(1);
	uint lanes = get_global_size(1);

	size_t job_id  = get_global_id(0) / 2;
	uint pos = get_global_id(0) % 2;
	if (job_id >= max_job_id) return; // Don't pre-process more keys than needed

	// Global memory
	__global uint* in = in_memory + job_id * BLAKE2B_OUTBYTES / sizeof(uint);
	__global ulong* out = out_memory + lane_id * ARGON2_BLOCK_SIZE / sizeof(ulong) +
		pos * lanes * ARGON2_BLOCK_SIZE / sizeof(ulong) +
		job_id * buffer_row_pitch;

	// Load message from memory
	ulong message[16];
	message[0] = upsample(in[0], ARGON2_BLOCK_SIZE);
	for (int i = 1; i < 8; i++)
		message[i] = upsample(in[2 * i], in[2 * i - 1]);
	message[8] = upsample(pos, in[15]);
	message[9] = lane_id;
	for (int i = 10; i < 16; i++)
		message[i] = 0;

	// blake2b cycle
	for (int i = 0; i < 31; i++) {
		blake2b_block(message, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES + (i ? 0 : 3 * sizeof(uint)));

		// Save to global memory
		for (int i = 0; i < 4; i++)
			out[i] = message[i];
		out += 4;
		message[8] = 0;
		message[9] = 0;
	}

	// Save to global memory
	for (int i = 0; i < 4; i++)
		out[i] = message[4 + i];
}

// end pre-processing

#define MAKE_KERNEL_NAME(type) argon2_kernel_segment_ ## type
#define KERNEL_NAME(type) MAKE_KERNEL_NAME(type)

#endif

// Kernel definition
__kernel void KERNEL_NAME(ARGON2_TYPE)(__global struct block_g* memory, uint passes, uint lanes, uint segment_blocks, uint pass, uint slice, uint type
#if !USE_WARP_SHUFFLE
	, __local ulong* shuffle_bufs
#endif
	)
{
	uint job_id = get_global_id(1);
	uint lane   = get_global_id(0) / THREADS_PER_LANE;
	uint thread = get_local_id(0) % THREADS_PER_LANE;

#if !USE_WARP_SHUFFLE
	uint warp   = (get_local_id(1) * get_local_size(0) + get_local_id(0)) / THREADS_PER_LANE;
	__local ulong* shuffle_buf = shuffle_bufs + warp * THREADS_PER_LANE;
#endif

	uint lane_blocks = ARGON2_SYNC_POINTS * segment_blocks;

	/* select job's memory region: */
	memory += (size_t)job_id * lanes * lane_blocks;

#if ARGON2_TYPE == ARGON2_I || ARGON2_TYPE == ARGON2_ID
	uint thread_input = 0;

	switch (thread) {
	case 0:
		thread_input = pass;
		break;
	case 1:
		thread_input = lane;
		break;
	case 2:
		thread_input = slice;
		break;
	case 3:
		thread_input = lanes * lane_blocks;
		break;
	case 4:
		thread_input = passes;
		break;
	case 5:
		thread_input = type; // ARGON2_TYPE;
		break;
	default:
		thread_input = 0;
		break;
	}

	struct block_th addr;
	if (pass == 0 && slice == 0 && segment_blocks > 2) {
		if (thread == 6) {
			++thread_input;
		}
		next_addresses(&addr, thread_input, thread, shuffle_buf);
	}
#endif

	__global struct block_g* mem_segment = memory + slice * segment_blocks * lanes + lane;
	__global ulong* mem_prev, *mem_curr;
	uint start_offset = 0;
	if (pass == 0) {
		if (slice == 0) {
			mem_prev = (mem_segment + 1 * lanes)->data + thread;
			mem_curr = (mem_segment + 2 * lanes)->data + thread;
			start_offset = 2;
		} else {
			mem_prev = (mem_segment - lanes)->data + thread;
			mem_curr = mem_segment->data + thread;
		}
	} else {
		mem_prev = (mem_segment + (slice == 0 ? lane_blocks * lanes : 0) - lanes)->data + thread;
		mem_curr = mem_segment->data + thread;
	}

	struct block_th prev;
	//load_block(&prev, mem_prev, thread);
	prev.a = mem_prev[0 * THREADS_PER_LANE];
	prev.b = mem_prev[1 * THREADS_PER_LANE];
	prev.c = mem_prev[2 * THREADS_PER_LANE];
	prev.d = mem_prev[3 * THREADS_PER_LANE];

	uint lanes_rec = 0xffffffffU / lanes;

	// Cycle
	for (uint offset = start_offset; offset < segment_blocks; ++offset) {
		// argon2_step(memory, mem_curr, &prev, &tmp, &addr, shuffle_buf, lanes, segment_blocks, thread, &thread_input, lane, pass, slice, offset);
#if ARGON2_TYPE == ARGON2_I
		uint addr_index = offset % ARGON2_QWORDS_IN_BLOCK;
		if (addr_index == 0) {
			if (thread == 6)
				++thread_input;

			next_addresses(&addr, thread_input, thread, shuffle_buf);
		}

		uint thr = addr_index % THREADS_PER_LANE;
		uint idx = addr_index / THREADS_PER_LANE;

		ulong v = block_th_get(&addr, idx);
		v = u64_shuffle(v, thr, thread, shuffle_buf);
		uint ref_index = (uint)v;
		uint ref_lane  = (uint)(v >> 32);
#elif ARGON2_TYPE == ARGON2_D
		ulong v = u64_shuffle(prev.a, 0, thread, shuffle_buf);
		uint ref_index = (uint)v;
		uint ref_lane  = (uint)(v >> 32);
#else
#error ARGON2_TYPE not supported
#endif

		//compute_ref_pos(lanes, segment_blocks, pass, lane, slice, offset, &ref_lane, &ref_index);
		//uint lane_blocks = ARGON2_SYNC_POINTS * segment_blocks;
		//ref_lane %= lanes;
		if (lanes & (lanes - 1)) {
#if 0
			if (lanes <= 5) {
				ref_lane = mul_hi(ref_lane * lanes_rec + lanes_rec, lanes);
			} else
#endif
			{
				ref_lane -= mul_hi(ref_lane, lanes_rec) * lanes;
				if (ref_lane >= lanes)
					ref_lane -= lanes;
			}
		} else {
			ref_lane &= lanes - 1;
		}

		uint base;
		if (pass != 0) {
			base = lane_blocks - segment_blocks;
		} else {
			if (slice == 0)
				ref_lane = lane;
			base = slice * segment_blocks;
		}

		uint ref_area_size = base + offset - 1;
		if (ref_lane != lane)
			ref_area_size = min(ref_area_size, base);

		ref_index = mul_hi(ref_index, ref_index);
		ref_index = ref_area_size - 1 - mul_hi(ref_area_size, ref_index);

		if (pass != 0 && slice != ARGON2_SYNC_POINTS - 1) {
			ref_index += (slice + 1) * segment_blocks;
			if (ref_index >= lane_blocks)
				ref_index -= lane_blocks;
		}

		//argon2_core(memory, mem_curr, &prev, &tmp, shuffle_buf, lanes, thread, pass, ref_index, ref_lane);
		__global ulong* mem_ref = (memory + ref_index * lanes + ref_lane)->data + thread;

		struct block_th tmp;
#if ARGON2_VERSION == ARGON2_VERSION_10
		//load_block_xor(prev, mem_ref, thread);
		prev.a ^= mem_ref[0 * THREADS_PER_LANE];
		prev.b ^= mem_ref[1 * THREADS_PER_LANE];
		prev.c ^= mem_ref[2 * THREADS_PER_LANE];
		prev.d ^= mem_ref[3 * THREADS_PER_LANE];
		tmp = prev;
#else
		if (pass != 0) {
			//load_block(tmp, mem_curr, thread);
			tmp.a = mem_curr[0 * THREADS_PER_LANE];
			tmp.b = mem_curr[1 * THREADS_PER_LANE];
			tmp.c = mem_curr[2 * THREADS_PER_LANE];
			tmp.d = mem_curr[3 * THREADS_PER_LANE];

			//load_block_xor(prev, mem_ref, thread);
			prev.a ^= mem_ref[0 * THREADS_PER_LANE];
			prev.b ^= mem_ref[1 * THREADS_PER_LANE];
			prev.c ^= mem_ref[2 * THREADS_PER_LANE];
			prev.d ^= mem_ref[3 * THREADS_PER_LANE];

			//xor_block(tmp, prev);
			tmp.a ^= prev.a;
			tmp.b ^= prev.b;
			tmp.c ^= prev.c;
			tmp.d ^= prev.d;
		} else {
			//load_block_xor(prev, mem_ref, thread);
			prev.a ^= mem_ref[0 * THREADS_PER_LANE];
			prev.b ^= mem_ref[1 * THREADS_PER_LANE];
			prev.c ^= mem_ref[2 * THREADS_PER_LANE];
			prev.d ^= mem_ref[3 * THREADS_PER_LANE];

			tmp = prev;
		}
#endif

		shuffle_block(&prev, thread, shuffle_buf);

		//xor_block(prev, tmp);
		prev.a ^= tmp.a;
		prev.b ^= tmp.b;
		prev.c ^= tmp.c;
		prev.d ^= tmp.d;

		//store_block(mem_curr, prev, thread);
		mem_curr[0 * THREADS_PER_LANE] = prev.a;
		mem_curr[1 * THREADS_PER_LANE] = prev.b;
		mem_curr[2 * THREADS_PER_LANE] = prev.c;
		mem_curr[3 * THREADS_PER_LANE] = prev.d;

		// End
		mem_curr += lanes * ARGON2_QWORDS_IN_BLOCK;
	}
}

// If we are in the first pass
#ifndef ONLY_KERNEL_DEFINITION

// No more passes
#define ONLY_KERNEL_DEFINITION
// Define new kernel
#undef ARGON2_TYPE
#define ARGON2_TYPE ARGON2_I
#include "argon2_kernel.cl"

#endif
