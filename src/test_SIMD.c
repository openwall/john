/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2017
 *
 * Copyright (c) 2017 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

/*
 * gcc -DAC_BUILT -DCPU_REQ_AVX2 -Wall -c test_SIMD.c -o test_SIMD.o
 * gcc -DAC_BUILT -DCPU_REQ_AVX2 -DCPU_REQ -Wall -c x86-64.S -o x86-64.o
 * gcc test_SIMD.o x86-64.o -g -o test_SIMD
 * ./test_SIMD; echo $?
 *
 */

#include <stdlib.h>
#include <stdio.h>

extern int CPU_detect(void);
extern char CPU_req_name[];

// Needed (but not used) stuff
unsigned int nt_buffer8x[4];
unsigned int output8x[4];

int main(int argc, char *argv[]) {

    int result = CPU_detect();

#ifdef DEBUG_SIMD
    char *name;

#if CPU_REQ_SSSE3
    name = "SSSE3";
#elif CPU_REQ_SSE4_1
    name = "SSE 4.1";
#elif CPU_REQ_AVX
    name = "AVX"
#elif CPU_REQ_XOP
     name = "XOP";
#elif CPU_REQ_AVX2
    name = "AVX2";
#elif CPU_REQ_AVX512F
    name = "AVX-512F";
#elif CPU_REQ_AVX512BW
    name = "AVX-512BW";
#else
    name = "unknown";
#endif

    fprintf(stderr, "CPU %s detected (%d: %s):\n", name, result,
            result ? "yes" : "no");
#endif
    exit(result);
}