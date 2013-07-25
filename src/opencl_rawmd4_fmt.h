#define LWS 		    64
#define BITMAP_SIZE_0 	    0x80000000
#define BITMAP_SIZE_1	    0x4000

struct bitmap_ctx{
	unsigned int bitmap0[BITMAP_SIZE_1>>5];
	unsigned int bitmap1[BITMAP_SIZE_1>>5];
};
