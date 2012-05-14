#ifndef _OPENCL_RAR_H 
#define _OPENCL_RAR_H

/* NOTE if you alter this file, touch rar_fmt.c too, or make clean */

/* Note that enabling debugging also enables
   lots of self tests that skews benchmarks */
//#define DEBUG

#define PLAINTEXT_LENGTH	16
//#define FIXED_LEN		6

#define LWS_CONFIG		"rar_LWS"
#define KPC_CONFIG		"rar_KPC"

#define ROUNDS			0x40000

/* Good for AMD, bad for nvidia */
//#define RAR_VECTORIZE

#endif /* _OPENCL_RAR_H */
