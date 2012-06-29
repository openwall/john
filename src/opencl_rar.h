#ifndef _OPENCL_RAR_H
#define _OPENCL_RAR_H

/* NOTE if you alter this file, touch rar_fmt.c too, or make clean */

/* Note that enabling debugging also enables
   lots of self tests that skews benchmarks */
//#define DEBUG

#define PLAINTEXT_LENGTH	16
//#define FIXED_LEN		6

#define LWS_CONFIG		"rar_LWS"
#define GWS_CONFIG		"rar_GWS"

#define ROUNDS			0x40000

/* Good for AMD, bad for nvidia. Note that this can't be used until
   we support fixed-length kernels, this was only a test */
//#define RAR_VECTORIZE

#endif /* _OPENCL_RAR_H */
