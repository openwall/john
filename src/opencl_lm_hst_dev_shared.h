#ifndef _OPENCL_LM_HST_DEV_SHARED_H
#define _OPENCL_LM_HST_DEV_SHARED_H

#define WORD     		int
#define lm_vector		WORD

typedef struct{
	union {
		unsigned char c[8][8][sizeof(lm_vector)];
		lm_vector v[8][8];
	} xkeys;
} opencl_lm_transfer;

#endif /* _OPENCL_LM_HST_DEV_SHARED_H */
