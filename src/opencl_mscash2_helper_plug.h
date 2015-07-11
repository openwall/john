#include "common-opencl.h"

#define FORMAT_LABEL	           "mscash2-opencl"

/*
 * Acceptable Values : 2 , 4 , 8 ,16 , 32 , 64 , 128 ,256 , 512 , 1024 , 2048 , 5120 , 10240
 */
#define ITERATION_COUNT_PER_CALL  	1024
#define MAX_SALT_LENGTH           	128
#define SALT_BUFFER_SIZE		((((MAX_SALT_LENGTH + 1) << 1) + sizeof(cl_uint)) / sizeof(cl_uint) * sizeof(cl_uint))

extern void initNumDevices(void);
extern size_t selectDevice(int jtrUniqDevId, struct fmt_main *self);
extern void releaseAll(void);
extern void dcc2_execute(cl_uint *hostDccHashes, cl_uint *hostSha1Hashes, cl_uint *hostSalt, cl_uint saltlen, cl_uint iterCount, cl_uint *hostDcc2Hashes, cl_uint numKeys);