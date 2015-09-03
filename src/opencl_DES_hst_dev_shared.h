#ifndef _OPENCL_DES_HST_DEV_SHARED_H
#define _OPENCL_DES_HST_DEV_SHARED_H

#define WORK_GROUP_SIZE		64
#define HARDCODE_SALT 		1
#define FULL_UNROLL		1

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
