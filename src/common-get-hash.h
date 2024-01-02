/*
 * This software is Copyright (c) 2017 jfoug : jfoug AT cox dot net
 *  Parts taken from code previously written by:
 *    magnumripper
 *    Alain Espinosa
 *    Simon Marechal
 *    and possibly others.
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if defined (COMMON_GET_HASH_LINK)
	common_code_get_hash_0,
	common_code_get_hash_1,
	common_code_get_hash_2,
	common_code_get_hash_3,
	common_code_get_hash_4,
	common_code_get_hash_5,
	common_code_get_hash_6
#undef COMMON_GET_HASH_LINK
#endif

#if defined(COMMON_GET_HASH_VAR)
#if defined(SIMD_COEF_64) && defined(COMMON_GET_HASH_SIMD64)
#if defined (COMMON_GET_HASH_SIMD_VAR)
#undef COMMON_GET_HASH_VAR
#define COMMON_GET_HASH_VAR COMMON_GET_HASH_SIMD_VAR
#endif
#undef HASH_IDX
#define HASH_IDX ((((unsigned int)index)&(SIMD_COEF_64-1))+(((unsigned int)index)/SIMD_COEF_64)*SIMD_COEF_64*COMMON_GET_HASH_SIMD64)
static int common_code_get_hash_0(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_0; }
static int common_code_get_hash_1(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_1; }
static int common_code_get_hash_2(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_2; }
static int common_code_get_hash_3(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_3; }
static int common_code_get_hash_4(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_4; }
static int common_code_get_hash_5(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_5; }
static int common_code_get_hash_6(int index) { return ((uint64_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_6; }
#elif defined(SIMD_COEF_32) && defined(COMMON_GET_HASH_SIMD32)
#if defined (COMMON_GET_HASH_SIMD_VAR)
#undef COMMON_GET_HASH_VAR
#define COMMON_GET_HASH_VAR COMMON_GET_HASH_SIMD_VAR
#endif
#undef HASH_IDX
#define HASH_IDX ((((unsigned int)index)&(SIMD_COEF_32-1))+(((unsigned int)index)/SIMD_COEF_32)*SIMD_COEF_32*COMMON_GET_HASH_SIMD32)
static int common_code_get_hash_0(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_0; }
static int common_code_get_hash_1(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_1; }
static int common_code_get_hash_2(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_2; }
static int common_code_get_hash_3(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_3; }
static int common_code_get_hash_4(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_4; }
static int common_code_get_hash_5(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_5; }
static int common_code_get_hash_6(int index) { return ((uint32_t*)COMMON_GET_HASH_VAR)[HASH_IDX] & PH_MASK_6; }
#else
	// this code works for 'all' types.  Deref address of element [index], then casing and getting element 0, works
	// properly for types such as:
	//   static uint32_t (*crypt_out)[(BINARY_SIZE + 1) / sizeof(uint32_t)];
	//   static uint32_t *crypt_out  (flat array, i.e. each with 1 element, crc32 uses this)
	//   static unsigned char (*crypt_out)p[BINARY_SIZE];
	//    probably others.  As long as it is a flat array of uint32, or an indexed array (double dim) to uint32, it works.
	//    also now ported for 64 bit hashes.  if we do not deal with those as 64 bits, we end up with problems on BE machines.
#if defined (COMMON_GET_HASH_64BIT_HASH)
static int common_code_get_hash_0(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_0; }
static int common_code_get_hash_1(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_1; }
static int common_code_get_hash_2(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_2; }
static int common_code_get_hash_3(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_3; }
static int common_code_get_hash_4(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_4; }
static int common_code_get_hash_5(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_5; }
static int common_code_get_hash_6(int index) { 	return ((uint64_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_6; }
#else
static int common_code_get_hash_0(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_0; }
static int common_code_get_hash_1(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_1; }
static int common_code_get_hash_2(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_2; }
static int common_code_get_hash_3(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_3; }
static int common_code_get_hash_4(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_4; }
static int common_code_get_hash_5(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_5; }
static int common_code_get_hash_6(int index) { 	return ((uint32_t *)(&(COMMON_GET_HASH_VAR[index])))[0] & PH_MASK_6; }
#endif
#endif
#undef COMMON_GET_HASH_VAR
#undef COMMON_GET_HASH_SIMD64
#undef COMMON_GET_HASH_SIMD32
#undef HASH_IDX
#endif
