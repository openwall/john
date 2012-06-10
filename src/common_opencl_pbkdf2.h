/* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
* This format supports salts upto 19 characters. Origial S3nf implementation supports only upto 8 charcters.
*/

#ifndef _COMMON_OPENCL_PBKDF2_H
#define _COMMON_OPENCL_PBKDF2_H

#include "common-opencl.h"

#define MAX_DEVICES_PER_PLATFORM  8

#define MAX_KEYS_PER_CRYPT        65536*4

#define MIN_KEYS_PER_CRYPT        65536*4

#define MAX_SALT_LENGTH           19

typedef struct { 
	cl_mem pass_gpu;
 
	cl_mem salt_gpu;
	 
	cl_mem hash_out_gpu;
	
} gpu_mem_buffer;

	
/* select_device(int platform_no,int device_no)
 * Use clinfo to view all available platfroms and devices.
 * platform_no = i selects the (i+1)th platform  e.g. platform_no = 1 selects second platform if available and so on..
 *dev_no = j seclcts the (j+1)th device on (i+1) th platform.  
 * Returns optimal work group size for selected device
 */
extern size_t select_device(int,int);

/*Same as above with platform_no and dev_no both set to 0.
 * It selects the first device of the first platform.
 * Returns optimal work group size.
 */
extern size_t select_default_device(void); 

/*void pbkdf2_divide_work(cl_uint *pass_api,cl_uint *salt_api,cl_uint saltlen_api,cl_uint *hash_out_api,cl_uint num)
 * Arguments: 
 *  cl_uint *pass_api is the pointer to the array containing 32byte input pass keys. e.g First set of four consecutive integer contains first key, Second set of four contains second key and so on... 
 *  cl_uint *salt_api is the pointer to the aaray containig unicoded salt string.
 *  cl_uint saltlen_api is the length of salt in terms of number of charcters NOT bytes. Max supported saltlength is upto 19 charchters long.
 *  cl_uint hash_out_api is the pointer to the array containing 32byte pbkdf2_hmac_sha1 encrypted hashes. First set of four consecutive integer contains the encrypted hash for first input key.
 *                        Second set of four contains encrypted hash for second input key and so on...
 *  cl_uint num is the number of keys to be encrypted.
  */
extern void pbkdf2_divide_work(cl_uint*,cl_uint*,cl_uint,cl_uint*,cl_uint);

/*Clean all OpenCL GPU buffers.
 */
extern void clean_all_buffer(void);

/*IMPORTANT NOTE:
 *  1. Max Keys per crypt must be an integral multiple of 8192. Preferred multiple is 65536 for higher performance.  
 *  2. More than one device can be selected to run simultaneously.
 *  3. If two or more devices are selected the task will be divided automatically among all the devices accoriding to their speed by the pbkdf2_divide_work() function. The function does not return until
 *     the whole task is complete.
 *  4. Always allocate pass_api and hash_out_api memory of size 4*MAX_KEYS_PER_CRYPT bytes.Also initialize them to zero.
 *  5. Fastest device should be initialize at last for better performance i.e arrange devices from low to high speed.
 *  6. Implementation assumes endianity to be little endian.     . 
 */
#endif


        

