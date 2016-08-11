#ifndef _opencl_argon2i_
#define _opencl_argon2i_

#define MIN_LANES  1
#define SYNC_POINTS 4
#define MAX_OUTLEN 0xFFFFFFFF
#define MIN_OUTLEN 4
#define MIN_MEMORY 1
#define MAX_MEMORY 0xFFFFFFFF
#define MIN_TIME 1
#define MAX_MSG 0xFFFFFFFF
#define MAX_AD 0xFFFFFFFF
#define MAX_NONCE  0xFFFFFFFF
#define MAX_SECRET 32
#define BLOCK_SIZE_KILOBYTE 1
#define BYTES_IN_BLOCK (1024*BLOCK_SIZE_KILOBYTE)
#define BLOCK_SIZE BYTES_IN_BLOCK
#define VERSION_NUMBER 0x11
#define BLAKE_INPUT_HASH_SIZE 64
#define BLAKE_OUTPUT_HASH_SIZE 64
#define ADDRESSES_PER_BLOCK (BLOCK_SIZE/4)
#define ADDRESSES_MASK (BLOCK_SIZE/4-1)

#ifndef CPU

typedef struct scheme_info_t_
{
	__global ulong2 *state;
	uint mem_size;
	uint passes;
	uint lanes;
} scheme_info_t;

typedef struct position_info_t_
{
	uint pass;
	uint slice;
	uint lane;
	uint index;
} position_info_t;

#endif

#endif //#ifndef _opencl_argon2i_
