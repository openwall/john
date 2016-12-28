#ifndef _LOTUS5_H
#define _LOTUS5_H

#define PLAINTEXT_LENGTH               16
#define BINARY_SIZE                    16
#define BINARY_SIZE_IN_uint32_t    (BINARY_SIZE >> 2)

typedef struct {
	union {
		char c[PLAINTEXT_LENGTH];
		unsigned int w[PLAINTEXT_LENGTH / 4];
	} v;
	int l;
} lotus5_key;

#endif
