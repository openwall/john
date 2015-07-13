#ifndef _OPENCL_LM_HST_DEV_SHARED_H
#define _OPENCL_LM_HST_DEV_SHARED_H

#define WORK_GROUP_SIZE		64
#define HARDCODE_SALT 		0
#define FULL_UNROLL		0

#define WORD     		int
#define LM_bs_vector		WORD

typedef struct{
	union {
		unsigned char c[8][8][sizeof(LM_bs_vector)];
		LM_bs_vector v[8][8];
	} xkeys;
} opencl_LM_bs_transfer;

#endif /* _OPENCL_LM_HST_DEV_SHARED_H */
