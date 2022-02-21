#ifndef _OPENCL_DES_HST_DEV_SHARED_H
#define _OPENCL_DES_HST_DEV_SHARED_H

/*
 * There are three kernels. All run bit-sliced DES, but:
 *
 * bs_b is "basic" kernel, for any salt
 * bs_h is "hardcoded salts" kernel
 * bs_f is "fully unrolled" kernel
 *
 * To avoid run-time build of salts, set OVERRIDE_AUTO_CONFIG and neither of HARDCODE_SALT or FULL_UNROLL
 *
 * Note that a rebuild of the host-code is then needed, despite this file's location.
 *
 * A better option for run-time selection is setting environment variable JOHN_DES_KERNEL to
 * "bs_b", "bs_h" or "bs_f". This works for LM as well although "bs_h" is not supported then.
 */
#define OVERRIDE_AUTO_CONFIG	0
#define HARDCODE_SALT 		0
#define FULL_UNROLL		0
#define PARALLEL_BUILD		0

#define WORD     		int
#define DES_bs_vector		WORD

typedef struct{
	union {
		unsigned char c[8][8][sizeof(DES_bs_vector)];
		DES_bs_vector v[8][8];
	} xkeys;
} opencl_DES_bs_transfer;

typedef struct {
	unsigned int num_uncracked_hashes;
	unsigned int offset_table_size;
	unsigned int hash_table_size;
	unsigned int bitmap_size_bits;
	unsigned int cmp_steps;
	unsigned int cmp_bits;
} DES_hash_check_params;

#endif /* _OPENCL_DES_HST_DEV_SHARED_H */
