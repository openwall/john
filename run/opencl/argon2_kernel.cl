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

#ifndef ONLY_KERNEL_DEFINITION

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

#include "rotate.h"

// Define when we will use warp_shuffle instructions and not local memory
#if USE_WARP_SHUFFLE
#define u64_shuffle(v, thread_src, thread, buf) u64_shuffle_warp(v, thread_src)
ulong u64_shuffle_warp(ulong v, uint thread_src)
#else
//#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
ulong u64_shuffle(ulong v, uint thread_src, uint thread, __local ulong *buf)
#endif
{
#if USE_WARP_SHUFFLE && gpu_nvidia(DEVICE_INFO) && SM_MAJOR >= 3
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
#endif
    return buf[thread_src];
#endif
}

struct u64_shuffle_buf {
    uint lo[THREADS_PER_LANE];
    uint hi[THREADS_PER_LANE];
};

ulong u64_shuffle(ulong v, uint thread_src, uint thread, __local struct u64_shuffle_buf *buf)
{
    buf[thread] = v;
    // Another option instead of the barrier
    // atom_xchg(buf + thread, v);

    // GPUs don't need this as their warp size is at least 32 that is what we need
    // barrier(CLK_LOCAL_MEM_FENCE);

    return buf[thread_src];
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
    for (uint i = 1; i < QWORDS_PER_THREAD; i++)
    {
        // TODO: Try to optimize 'block_th_*et' with LUT
        uint idx = thread_group ^ i;

        ulong v = block_th_get(block, idx);
        v = u64_shuffle(v, (i << 2) ^ thread, thread, buf);
        block_th_set(block, idx, v);
    }

    g(block);

    // shuffle_shift1(block, thread, buf);
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
    for (uint i = 1; i < QWORDS_PER_THREAD; i++)
    {
        // TODO: Try to optimize 'block_th_*et' with LUT
        uint idx = thread_group ^ i;

        ulong v = block_th_get(block, idx);
        v = u64_shuffle(v, (i << 2) ^ thread, thread, buf);
        block_th_set(block, idx, v);
    }

    g(block);

    // shuffle_shift2(block, thread, buf);
    uint thread_src0 = apply_shuffle_shift2(thread, 0);
    thread_src1 = apply_shuffle_shift2(thread, 1);
    thread_src2 = apply_shuffle_shift2(thread, 2);
    thread_src3 = apply_shuffle_shift2(thread, 3);
    // TODO: Try to optimize 'apply_shuffle_shift2' with LUT
    block->a = u64_shuffle(block->a, thread_src0, thread, buf);
    block->b = u64_shuffle(block->b, thread_src1, thread, buf);
    block->c = u64_shuffle(block->c, thread_src2, thread, buf);
    block->d = u64_shuffle(block->d, thread_src3, thread, buf);

    g(block);

    block->a = u64_shuffle(block->a, thread_src0, thread, buf);
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

#define MAKE_KERNEL_NAME(type) argon2_kernel_segment_ ## type
#define KERNEL_NAME(type) MAKE_KERNEL_NAME(type)

#endif

// Kernel definition
__kernel void KERNEL_NAME(ARGON2_TYPE)(__global struct block_g* memory, uint passes, uint lanes, uint segment_blocks, uint pass, uint slice, uint type
#if USE_WARP_SHUFFLE
                               )
#else
    , __local ulong* shuffle_bufs)
#endif
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

    uint thread_input = 0;

#if ARGON2_TYPE == ARGON2_I || ARGON2_TYPE == ARGON2_ID
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
        thread_input = type;// ARGON2_TYPE;
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

    // Cycle
    for (uint offset = start_offset; offset < segment_blocks; ++offset)
{
        // argon2_step(memory, mem_curr, &prev, &tmp, &addr, shuffle_buf, lanes, segment_blocks, thread, &thread_input, lane, pass, slice, offset);
#if ARGON2_TYPE == ARGON2_I
        uint addr_index = offset % ARGON2_QWORDS_IN_BLOCK;
        if (addr_index == 0)
        {
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
//#elif ARGON2_TYPE == ARGON2_ID
//      bool data_independent = pass == 0 && slice < ARGON2_SYNC_POINTS / 2;
//          => And then select ARGON2_I or ARGON2_D based on 'data_independent' value
#else
    #error ARGON2_TYPE not supported
#endif

        //compute_ref_pos(lanes, segment_blocks, pass, lane, slice, offset, &ref_lane, &ref_index);
        //uint lane_blocks = ARGON2_SYNC_POINTS * segment_blocks;
        ref_lane %= lanes;

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
