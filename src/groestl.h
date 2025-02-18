#ifndef __hash_h
#define __hash_h

#include <stdint.h>

/* some sizes (number of bytes) */
#define ROWS 8
#define LENGTHFIELDLEN ROWS
#define COLS512 8

#define SIZE512 (ROWS*COLS512)

#define HASH_BIT_LEN 256


/* NIST API begin */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef struct {
	uint32_t chaining[SIZE512/sizeof(uint32_t)]; /* actual state */
	uint32_t block_counter1,
		 block_counter2; /* message block counter(s) */
	BitSequence buffer[SIZE512]; /* data buffer */
	int buf_ptr; /* data buffer pointer */
	int bits_in_last_byte; /* no. of message bits in last byte of data buffer */
} hashState;

void groestl(const BitSequence*, DataLength, BitSequence*);

#endif /* __hash_h */
