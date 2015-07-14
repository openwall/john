#include "opencl_lm_hst_dev_shared.h"
#include "opencl_device_info.h"

typedef unsigned WORD vtype;

/*
 * Some devices/drivers has problems with the optimized 'goto' program flow.
 * Some AMD driver versions can't build the "fast goto" version but those who
 * can runs faster. Hawaii on 14.9 fails, Tahiti on 14.9 does not (!?).
 *
 * Nvidia can build either kernel but GTX980 is significantly faster with the
 * "safe goto" version (7% faster for one salt, 16% for many salts).
 *
 * OSX' Intel HD4000 driver [1.2(Sep25 2014 22:26:04)] fails building the
 * "fast goto" version.
 */
#if nvidia_sm_5x(DEVICE_INFO) || gpu_intel(DEVICE_INFO) ||	  \
	(gpu_amd(DEVICE_INFO) && DEV_VER_MAJOR >= 1573 && !defined(__Tahiti__)) || \
	(gpu_amd(DEVICE_INFO) && DEV_VER_MAJOR >= 1702)
//#warning Using 'safe goto' kernel
#define SAFE_GOTO
#else
//#warning Using 'fast goto' kernel
#endif

#if no_byte_addressable(DEVICE_INFO)
#define RV7xx
#endif
#if gpu_nvidia(DEVICE_INFO)
#define _NV
#endif

#define vxorf(a, b) 					\
	((a) ^ (b))
#define vnot(dst, a) 					\
	(dst) = ~(a)
#define vand(dst, a, b) 				\
	(dst) = (a) & (b)
#define vor(dst, a, b) 					\
	(dst) = (a) | (b)
#define vandn(dst, a, b) 				\
	(dst) = (a) & ~(b)
#define vxor(dst, a, b) 				\
	(dst) = vxorf((a), (b))
#define vshl(dst, src, shift) 				\
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) 				\
	(dst) = (src) >> (shift)
#define vshl1(dst, src) 				\
	vshl((dst), (src), 1)

#if defined(_NV) || __CPU__
#define vsel(dst, a, b, c) 				\
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))
#else
#define vsel(dst, a, b, c) 				\
	(dst) = bitselect((a),(b),(c))
#endif

#if defined(_NV) || __CPU__
#include "opencl_sboxes.h"
#else
#include "opencl_sboxes-s.h"
#endif

#define vst_private(dst, ofs, src) 			\
	*((__private vtype *)((__private lm_vector *)&(dst) + (ofs))) = (src)

#define lm_clear_block_8(j) 			\
	vst_private(B[j] , 0, zero); 			\
	vst_private(B[j] , 1, zero); 			\
	vst_private(B[j] , 2, zero); 			\
	vst_private(B[j] , 3, zero); 			\
	vst_private(B[j] , 4, zero); 			\
	vst_private(B[j] , 5, zero); 			\
	vst_private(B[j] , 6, zero); 			\
	vst_private(B[j] , 7, zero);

#define lm_clear_block 				\
	lm_clear_block_8(0); 			\
	lm_clear_block_8(8); 			\
	lm_clear_block_8(16); 			\
	lm_clear_block_8(24); 			\
	lm_clear_block_8(32); 			\
	lm_clear_block_8(40); 			\
	lm_clear_block_8(48); 			\
	lm_clear_block_8(56);

inline void cmp( __private unsigned lm_vector *B,
	  __global int *binary,
	  volatile __global uint *output,
	  volatile __global uint *bitmap,
	  __global lm_vector *B_global,
	  int section) {

	int value[2] , mask, i, bit;

	for(i = 0; i < NUM_LOADED_HASHES; i++) {

		value[0] = binary[i];
		value[1] = binary[i + NUM_LOADED_HASHES];

		mask = B[0] ^ -(value[0] & 1);

		for (bit = 1; bit < 32; bit++)
			mask |= B[bit] ^ -((value[0] >> bit) & 1);

		for (; bit < 64; bit += 2) {
			mask |= B[bit] ^ -((value[1] >> (bit & 0x1F)) & 1);
			mask |= B[bit + 1] ^ -((value[1] >> ((bit + 1) & 0x1F)) & 1);
		}

		if (mask != ~(int)0) {
			if (!(atomic_or(&bitmap[i/32], (1U << (i % 32))) & (1U << (i % 32)))) {
				mask = atomic_inc(&output[0]);
				output[1 + 2 * mask] = section;
				output[2 + 2 * mask] = 0;
				for (bit = 0; bit < 64; bit++)
					B_global[mask * 64 + bit] = (lm_vector)B[bit];

			}
		}
	}
}
