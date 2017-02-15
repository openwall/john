 /*
 * BitCracker OpenCL version developed by Elenago 
 * <elena dot ago at gmail dot com> in 2015
 *
 * Copyright (c) 2015-2017 Elenago <elena dot ago at gmail dot com>
 * and Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Please contact or cite if you want to use this source code.
 * More information at http://openwall.info/wiki/john/OpenCL-BitCracker
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_bitcracker;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_bitcracker);
#else

#include <string.h>
#include "common-opencl.h"
#include "opencl_device_info.h"
#include "config.h"
#include "options.h"
#include <time.h> 

#define CIPHERTEXT_LENGTH	64
#define BINARY_SIZE		32
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define FORMAT_LABEL            "bitcracker-opencl"
#define FORMAT_NAME             "BitCracker-OpenCL"
#define ALGORITHM_NAME          "BitCracker OpenCL"

#define MAX_PASSWORD_THREAD 8
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 172032
/* 
 * On a GeForce Titan X: Assuming 896 threads for 24 SMs, 
 * 8 password for each thread -> 896x24x8
*/

#define BITCRACKER_HASH_SIZE 8 //32
#define BITCRACKER_ROUND_SHA_NUM 64
#define BITCRACKER_SINGLE_BLOCK_SHA_SIZE 64
#define BITCRACKER_SINGLE_BLOCK_W_SIZE 64
#define BITCRACKER_PADDING_SIZE 40
#define BITCRACKER_ITERATION_NUMBER 0x100000
#define BITCRACKER_WORD_SIZE 4
#define BITCRACKER_INPUT_SIZE 512
#define BITCRACKER_FIXED_PART_INPUT_CHAIN_HASH 88
#define BITCRACKER_BLOCK_UNIT 32
#define BITCRACKER_HASH_SIZE_STRING 32
#define BITCRACKER_MAX_INPUT_PASSWORD_LEN 16
#define BITCRACKER_MIN_INPUT_PASSWORD_LEN 8

#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define BITCRACKER_SALT_SIZE 16
#define BITCRACKER_MAC_SIZE 16
#define BITCRACKER_NONCE_SIZE 12
#define BITCRACKER_IV_SIZE 16
#define BITCRACKER_VMK_SIZE 44
#define VMK_DECRYPT_SIZE 16
#define DICT_BUFSIZE	(50*1024*1024)
#define MAX_PLEN 32
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

static cl_kernel prepare_kernel;
static struct fmt_main *self;

static cl_mem 			salt_d, padding_d, w_blocks_d, deviceEncryptedVMK, devicePassword, devicePasswordSize, deviceFound;
static cl_int           ciErr1;
static size_t 			szGlobalWorkSize, szLocalWorkSize, maxDeviceWorkgroupSize;
static unsigned int 	* w_blocks_h;
static unsigned char 	salt_bitcracker[BITCRACKER_SALT_SIZE], mac[BITCRACKER_MAC_SIZE], nonce[BITCRACKER_NONCE_SIZE], encryptedVMK[BITCRACKER_VMK_SIZE];
static uint8_t 			tmpIV[BITCRACKER_IV_SIZE], *inbuffer, *outbuffer;
static int 			*inbuffer_size;
static FILE *diskImage;
static int *hostFound, passwordBufferSize, numPassword, totPsw, i;
static int max_compute_units=0;

static void w_block_precomputed(unsigned char * salt);
void cpu_print_hex(unsigned char hash[], int size);
void readData(FILE * diskImage);
void fillBuffer(FILE *fp, unsigned char *buffer, int size);

#include "opencl-autotune.h"

static void reset(struct db_main *db)
{
	return;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *_self)
{
	size_t deviceGlobalMem=0;
	long int globalmemRequires;
	self = _self;
	
	opencl_prepare_dev(gpu_id);
	max_compute_units = get_max_compute_units(gpu_id);
	maxDeviceWorkgroupSize = get_device_max_lws(gpu_id);
//	self->params.max_keys_per_crypt = max_compute_units*maxDeviceWorkgroupSize*MAX_PASSWORD_THREAD;

	deviceGlobalMem = get_max_mem_alloc_size(gpu_id);
	globalmemRequires = (BITCRACKER_SINGLE_BLOCK_SHA_SIZE * BITCRACKER_ITERATION_NUMBER * sizeof(int)) + 40 + 16 + 
								 (maxDeviceWorkgroupSize*max_compute_units*BITCRACKER_MAX_INPUT_PASSWORD_LEN) * BITCRACKER_MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char);
    if(globalmemRequires > deviceGlobalMem)
    {
    	fprintf(stderr, "[BitCracker] -> Error global memory size! Required: %ld, Available: %ld GPU_ID: %d\n", globalmemRequires, deviceGlobalMem, gpu_id);
    	exit(1);
    }

    inbuffer = NULL;
	inbuffer_size = NULL;
	outbuffer = NULL;

    numPassword = (int) maxDeviceWorkgroupSize*max_compute_units*BITCRACKER_MAX_INPUT_PASSWORD_LEN;
    passwordBufferSize = (int) numPassword * BITCRACKER_MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char);

	inbuffer = (unsigned char *) calloc(passwordBufferSize, sizeof(unsigned char));
	inbuffer_size = (int *) calloc(MAX_KEYS_PER_CRYPT, sizeof(int));
    hostFound = (int *) calloc(1, sizeof(int));
	outbuffer = (unsigned char *) calloc(BITCRACKER_MAX_INPUT_PASSWORD_LEN+2, sizeof(unsigned char));

	memset(inbuffer, 0, (sizeof(uint8_t) * (BITCRACKER_MAX_INPUT_PASSWORD_LEN+2) * MAX_KEYS_PER_CRYPT));
	memset(inbuffer_size, 0, (sizeof(int) * MAX_KEYS_PER_CRYPT));
	memset(outbuffer, 0, (sizeof(uint8_t) * (BITCRACKER_MAX_INPUT_PASSWORD_LEN+2) * 1));

	w_block_precomputed(salt_bitcracker);
	if(!w_blocks_h)
	{
		fprintf(stderr, "[BitCracker] -> Error W blocks... Exit\n");
		exit(1);
	}
}

void w_block_precomputed(unsigned char * salt)
{
    char fileNameWBlocks[] = "$JOHN/kernels/bitcracker_kernel.cl";
	char * opt=NULL;
	unsigned char * padding;
	uint64_t msgLen;
	int iter_num = BITCRACKER_ITERATION_NUMBER;

	if(salt == NULL) return;

    padding = (unsigned char *) calloc(BITCRACKER_PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding+1, 0, 31);
	msgLen = (BITCRACKER_FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[BITCRACKER_PADDING_SIZE-1-i] = (uint8_t)(msgLen >> (i * 8));

    salt_d = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BITCRACKER_SALT_SIZE * sizeof(unsigned char), NULL, &ciErr1);
    HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 
    
    padding_d = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BITCRACKER_PADDING_SIZE * sizeof(unsigned char), NULL, &ciErr1);
    HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

    w_blocks_d = clCreateBuffer(context[gpu_id],  CL_MEM_WRITE_ONLY, BITCRACKER_SINGLE_BLOCK_SHA_SIZE * BITCRACKER_ITERATION_NUMBER * sizeof(int), NULL, &ciErr1);
    HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

   	w_blocks_h = (unsigned int *) calloc((BITCRACKER_SINGLE_BLOCK_SHA_SIZE*BITCRACKER_ITERATION_NUMBER), sizeof(unsigned int));
   	if(!w_blocks_h)
   		goto out;

	opencl_build_kernel(fileNameWBlocks, gpu_id, opt, 0);
	prepare_kernel = clCreateKernel(program[gpu_id], "opencl_bitcracker_wblocks", &ciErr1);
	HANDLE_CLERROR(ciErr1, "Error creating kernel_prepare. Double-check kernel name?");

    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], salt_d, CL_TRUE, 0, BITCRACKER_SALT_SIZE * sizeof(unsigned char), salt, 0, NULL, NULL);      
    HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 
    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], padding_d, CL_TRUE, 0, BITCRACKER_PADDING_SIZE * sizeof(unsigned char), padding, 0, NULL, NULL);      
    HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 

    ciErr1 = clSetKernelArg(prepare_kernel, 0, sizeof(cl_int), (void*)&iter_num);
    HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 
    ciErr1 = clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem), (void*)&salt_d);
    HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 
    ciErr1 = clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem), (void*)&padding_d);
    HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 
    ciErr1 = clSetKernelArg(prepare_kernel, 3, sizeof(cl_mem), (void*)&w_blocks_d);
    HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 
    
    szLocalWorkSize = get_kernel_max_lws(gpu_id, prepare_kernel);
    szGlobalWorkSize = szLocalWorkSize*max_compute_units;
	
	ciErr1 = clEnqueueNDRangeKernel(
									queue[gpu_id], prepare_kernel, 1, NULL, &szGlobalWorkSize, 
									&szLocalWorkSize, 0, NULL, NULL
								);
    HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel"); 

    ciErr1 = clEnqueueReadBuffer(	queue[gpu_id], w_blocks_d, CL_TRUE, 0, 
    								BITCRACKER_SINGLE_BLOCK_SHA_SIZE*BITCRACKER_ITERATION_NUMBER*sizeof(unsigned int), 
    								w_blocks_h, 0, NULL, NULL
    							);
    HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel"); 

    HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush"); 
    HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish"); 

out:

	HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "[BitCracker] -> Release kernel w blocks");

	clReleaseMemObject(salt_d);
	clReleaseMemObject(padding_d);
	clReleaseMemObject(w_blocks_d);     
	free(padding);

	return;
}

static int valid(char *ciphertext, struct fmt_main *self)
{	
	if(!ciphertext)
	{
		printf("\n[BitCracker] -> Error: target encrypted unit not found!\n");
		return 0;
	}

	printf("\n[BitCracker] -> **** Extracting metadata from disk image \"%s\" **** \n", ciphertext);
	diskImage = fopen(ciphertext, "r");
	if (diskImage == NULL){
		printf("[BitCracker] -> Failed to open memory area target, please check if device exists or if you have right permissions\n");
		exit(1);
	}
	readData(diskImage);
	printf("[BitCracker] -> ********************************************* \n\n");

	return 1;
}


static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	return ciphertext;
}

static void *get_binary(char *ciphertext)
{
	return (void *) ciphertext;
}

static void *get_salt(char *ciphertext)
{
	return tmpIV;
}

static void set_salt(void *salt)
{
	memset(tmpIV, 0, BITCRACKER_IV_SIZE);
	memcpy(tmpIV + 1, nonce, BITCRACKER_NONCE_SIZE);
	if(BITCRACKER_IV_SIZE-1 - BITCRACKER_NONCE_SIZE - 1 < 0)
	{
		fprintf(stderr, "Nonce error\n");
		return;
	}
	*tmpIV = (unsigned char)(BITCRACKER_IV_SIZE - 1 - BITCRACKER_NONCE_SIZE - 1);
	tmpIV[BITCRACKER_IV_SIZE-1] = 1; 
}

void cpu_print_hex(unsigned char hash[], int size)
{
   int idx;
   for (idx=0; idx < size; idx++)
      printf("0x%02x,",hash[idx]);
   printf("\n");
}

void fillBuffer(FILE *fp, unsigned char *buffer, int size){
	int k;
	for(k=0;k<size;k++){
		buffer[k] = (unsigned char)fgetc(fp);
	}
}

void readData(FILE * diskImage){
	int match = 0;
	char signature[9] = "-FVE-FS-";
	int version = 0;
	unsigned char vmk_entry[4] = {0x02,0x00,0x08,0x00};
	unsigned char key_protection_type[2] = {0x00, 0x20};
	unsigned char value_type[2] = {0x00, 0x05};
	char c;
	int i = 0;
	int j, fileLen;
	
	if(!diskImage)
		exit(1);

	fseek(diskImage, 0, SEEK_END);
    fileLen=ftell(diskImage);
    fseek(diskImage, 0, SEEK_SET);
	for (j=0;j<fileLen;j++){
		c = fgetc(diskImage);
		while ((unsigned char)c == signature[i]){
			c = fgetc(diskImage);
			i++;
		}
		if (i == 8) {
			match=1;
			printf("[BitCracker] -> Signature found at 0x%08lx\n", (ftell(diskImage)-i-1));
			fseek(diskImage, 1, SEEK_CUR);
			version = fgetc(diskImage);
			printf("[BitCracker] -> Version: %d ", version);
			if (version == 1)
				printf("(Windows Vista)\n");
			else if (version == 2)
				printf("(Windows 7 or later)\n");
			else{
				printf("\nBitCracker] -> Invalid version, looking for a signature with valid version..\n");
			}
		}
		i=0;
		while ((unsigned char)c == vmk_entry[i]){
			c = fgetc(diskImage);
			i++;
		}
		if (i == 4){
			printf("[BitCracker] -> VMK entry found at 0x%08lx\n", (ftell(diskImage)-i-3));
			fseek(diskImage, 27, SEEK_CUR);
			if (((unsigned char)fgetc(diskImage) == key_protection_type[0]) && ((unsigned char)fgetc(diskImage) == key_protection_type[1])) {
				printf("[BitCracker] -> Key protector with user password found\n");
				fseek(diskImage, 12, SEEK_CUR);
				fillBuffer(diskImage, salt_bitcracker, 16);
				printf("[BitCracker] -> Salt:");
				cpu_print_hex(salt_bitcracker, 16);
				fseek(diskImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(diskImage) != value_type[0]) || ((unsigned char)fgetc(diskImage) != value_type[1])){
					printf("[BitCracker] -> Error: VMK not encrypted with AES-CCM\n");
					exit(1);
				}
				fseek(diskImage, 3, SEEK_CUR);
				fillBuffer(diskImage, nonce, 12);
				printf("[BitCracker] -> Nonce:");
				cpu_print_hex(nonce, 12);
				fillBuffer(diskImage, mac, 16);
				printf("[BitCracker] -> MAC:");
				cpu_print_hex(mac, 16);
				fillBuffer(diskImage, encryptedVMK, 44);
				printf("[BitCracker] -> Encrypted VMK:");
				cpu_print_hex(encryptedVMK, 44);
				break;
			}
		}
		i=0;
		
	}
	fclose(diskImage);
	if (match==0){
		printf("BitCracker] -> Error while extracting data: No signature found!\n");
		exit(1);
	}
}

static void set_key(char *key, int index)
{
	char tmp[BITCRACKER_MAX_INPUT_PASSWORD_LEN+2];
	int size = strlen(key);

	inbuffer_size[index] = size;
	memset(tmp, 0, BITCRACKER_MAX_INPUT_PASSWORD_LEN+2);
	memcpy(tmp, key, size);
	if(size < 16) tmp[size] = 0x80;
	memcpy((inbuffer+(index*BITCRACKER_MAX_INPUT_PASSWORD_LEN)), tmp, BITCRACKER_MAX_INPUT_PASSWORD_LEN);
}

static char *get_key(int index)
{
	static char ret[BITCRACKER_MAX_INPUT_PASSWORD_LEN + 1];
	memcpy(ret, inbuffer+(index*BITCRACKER_MAX_INPUT_PASSWORD_LEN), inbuffer_size[index]);
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int numPassword = count;
	char fileNameAttack[] = "$JOHN/kernels/bitcracker_kernel.cl";
   	char opt[1024];
    unsigned int tmp_global, IV0, IV4, IV8, IV12;
    time_t start,end;
    double dif;

	numPassword = count;
	passwordBufferSize = numPassword * BITCRACKER_MAX_INPUT_PASSWORD_LEN * sizeof(uint8_t);

	if( gpu_nvidia(device_info[gpu_id]) )
	{
		if(nvidia_sm_5x(device_info[gpu_id]))
			snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=1"); //-cl-nv-verbose 
		else
			snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=0");
	}
	else
		snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=0");

	opencl_build_kernel(fileNameAttack, gpu_id, opt, 0);
    crypt_kernel = clCreateKernel(program[gpu_id], "opencl_bitcracker_attack", &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateKernel"); 

    deviceEncryptedVMK = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, VMK_DECRYPT_SIZE*sizeof(unsigned char), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

    devicePassword = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, passwordBufferSize*sizeof(unsigned char), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

	devicePasswordSize = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, MAX_KEYS_PER_CRYPT*sizeof(int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

    deviceFound = clCreateBuffer(context[gpu_id],  CL_MEM_WRITE_ONLY, sizeof(unsigned int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

    w_blocks_d = clCreateBuffer(context[gpu_id],  CL_MEM_READ_ONLY, BITCRACKER_SINGLE_BLOCK_SHA_SIZE * BITCRACKER_ITERATION_NUMBER * sizeof(unsigned int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer"); 

    tmp_global = (unsigned int) ( ((unsigned int *)tmpIV)[0] );
    IV0=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
    
    tmp_global = ((unsigned int *)(tmpIV+4))[0];
    IV4=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
   
    tmp_global = ((unsigned int *)(tmpIV+8))[0];
    IV8=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
    
    tmp_global = ((unsigned int *)(tmpIV+12))[0];
    IV12=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 

    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0, BITCRACKER_SINGLE_BLOCK_SHA_SIZE * BITCRACKER_ITERATION_NUMBER * sizeof(int), w_blocks_h, 0, NULL, NULL);      
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 
    
    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], deviceEncryptedVMK, CL_TRUE, 0, VMK_DECRYPT_SIZE*sizeof(char), encryptedVMK, 0, NULL, NULL);      
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 

    szLocalWorkSize = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);  //get_kernel_max_lws(gpu_id, crypt_kernel);
	szGlobalWorkSize = autotune_get_task_max_size(1, 0, MAX_PASSWORD_THREAD, crypt_kernel);

    printf("\n[BitCracker] -> Starting Attack, #Passwords: %d, Global Work Size: %zu, Local Work Size: %zu\n",  numPassword, szGlobalWorkSize, szLocalWorkSize);

    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], devicePassword, CL_TRUE, 0, passwordBufferSize * sizeof(char), inbuffer, 0, NULL, NULL);      
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 

	ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], devicePasswordSize, CL_TRUE, 0, MAX_KEYS_PER_CRYPT * sizeof(int), inbuffer_size, 0, NULL, NULL);      
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

    hostFound[0] = -1;
    ciErr1 = clEnqueueWriteBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0, sizeof(int), hostFound, 0, NULL, NULL);      
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer"); 

    ciErr1 = clSetKernelArg(crypt_kernel, 0, sizeof(cl_int), (void*)&numPassword);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&devicePassword);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

	ciErr1 |= clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&devicePasswordSize);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&deviceFound);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), (void*)&deviceEncryptedVMK);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem), (void*)&w_blocks_d);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 6, sizeof(cl_int), (void*)&IV0);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 7, sizeof(cl_int), (void*)&IV4);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 8, sizeof(cl_int), (void*)&IV8);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    ciErr1 |= clSetKernelArg(crypt_kernel, 9, sizeof(cl_int), (void*)&IV12);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg"); 

    time (&start);
    ciErr1 = clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel"); 

    ciErr1 = clEnqueueReadBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0, sizeof(unsigned int), hostFound, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel"); 
    HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush"); 
    time (&end);
    dif = difftime (end,start);

    printf ("[BitCracker] -> Attack stats: %d passwords evaluated in %.2lf seconds => %.2f pwd/s\n",  numPassword, dif, (double)(numPassword/dif) );

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish"); 

    totPsw += numPassword;
    
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "[BitCracker] ->  Release prepare_kernel");

    if(w_blocks_d)clReleaseMemObject(w_blocks_d);
    if(devicePassword)clReleaseMemObject(devicePassword);
	if(devicePasswordSize)clReleaseMemObject(devicePasswordSize);
    if(deviceEncryptedVMK)clReleaseMemObject(deviceEncryptedVMK);
    if(deviceFound)clReleaseMemObject(deviceFound);

	return count;
}


static int cmp_all(void *binary, int count)
{
	if (hostFound[0] >= 0) {
        fprintf(stdout, "\n[BitCracker] -> Password found: #%d, %.*s\n",
        				hostFound[0]+1, BITCRACKER_MAX_INPUT_PASSWORD_LEN, (char *)(inbuffer+(hostFound[0]*BITCRACKER_MAX_INPUT_PASSWORD_LEN)));
        return hostFound[0];
    }
	else
		return 0;
}

static int cmp_one(void *binary, int index)
{
	if(hostFound[0] == index) return 1;
	else return 0;
}

static int cmp_exact(char *source, int index)
{
	if(hostFound[0] == index) return 1;
	else return 0;
}

static int binary_hash_0(void *binary)
{
	return 0;
}

static int salt_hash(void *salt)
{
	return 0;
}


static void done(void)
{
    printf("\n[BitCracker] -> Total passwords evaluated=%d\n", totPsw);
	return;
}


static int get_hash_0(int index)
{
	return 0;
}

struct fmt_main fmt_opencl_bitcracker = {
	{

		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		BITCRACKER_MIN_INPUT_PASSWORD_LEN,
		BITCRACKER_MAX_INPUT_PASSWORD_LEN, //PLAINTEXT_LENGTH,
		BINARY_SIZE,
		MEM_ALIGN_WORD, //BINARY_ALIGN,
		10, //BITCRACKER_SALT_SIZE,
		MEM_ALIGN_WORD, //SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_OMP, // ??
		{ NULL } // ??
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{NULL},
		fmt_default_source,
		{
			binary_hash_0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif                          /* plugin stanza */

#endif                          /* HAVE_OPENCL */
