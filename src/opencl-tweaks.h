/* Keep values shared by code and the OpenCL kernels here. This file is
 * prepended to the OpenCL kernels during make. */

#define MD4_NUM_KEYS          1024*2048
#define MD4_PLAINTEXT_LENGTH  15
#ifdef MD4
#define PLAINTEXT_LENGTH      15
#endif

#define MD5_NUM_KEYS          1024*2048
#define MD5_PLAINTEXT_LENGTH  15
#ifdef MD5
#define PLAINTEXT_LENGTH      15
#endif

