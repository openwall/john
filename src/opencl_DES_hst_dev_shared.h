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

#endif /* _OPENCL_DES_HST_DEV_SHARED_H */
