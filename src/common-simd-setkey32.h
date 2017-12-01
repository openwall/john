
/*
 * This software was written by JimF : jfoug AT cox dot net
 * in 2017. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2017 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 */

/*
 * this include file is CODE.  It includes a 'standard' set_key() function,
 * for both SIMD and flat loading.  The requisites for this function to work:
 *   straight keys saved (no encoding, just ascii).
 *   if built for SIMD, this this properly build static must be available:
 *     static uint32_t (*saved_key)[MD5_BUF_SIZ*NBKEYS];
 *       the important thing here, is the buffer must be large enough, aligned
 *       to 16 bytes, and NAMED saved_key.  Also, saved_key should be expected
 *       to be filled from the start with the password, and properly 'cleaned'
 *       and then size filled when the function completes.
 *     Proper GETPOS and GETPOSW macros myst be set for the format.
 * for non_simd builds, these buffers must be there:
 *    static int (*saved_len);
 *    static char (*saved_key)[PLAINTEXT_LENGTH + 1];
 */


#if defined(SIMD_COEF_32)

#if !defined SALT_APPENDED
#define SALT_APPENDED 0
#endif
#if !defined SALT_PREPENDED
#define SALT_PREPENDED 0
#endif


#undef COMMON_SWAP

#if defined(FMT_IS_BE)
#  if ARCH_LITTLE_ENDIAN
#    define COMMON_SWAP(a) JOHNSWAP(a)
#  else
#    define COMMON_SWAP(a) (a)
#  endif
#else
#  if ARCH_LITTLE_ENDIAN
#    define COMMON_SWAP(a) (a)
#  else
#    define COMMON_SWAP(a) JOHNSWAP(a)
#  endif
#endif

static void set_key(char *_key, int index)
{
#if ARCH_ALLOWS_UNALIGNED
	const uint32_t *key = (uint32_t*)_key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const uint32_t *key = (uint32_t*)(is_aligned(_key, sizeof(uint32_t)) ?
	                                      _key : strcpy(buf_aligned, _key));
#endif
	uint32_t *keybuffer = &((uint32_t*)saved_key)[GETPOSW32(0,index)];
	uint32_t *keybuf_word = keybuffer;
	unsigned int len=0;
	uint32_t temp;

#if SALT_PREPENDED
#if SALT_PREPENDED/4*4 != SALT_PREPENDED
#error the code in common-setkey32.h ONLY works for appended salts of fixed length evenly divisible by 4
#endif
	keybuf_word  += (SALT_PREPENDED/4)*SIMD_COEF_32;
	len = SALT_PREPENDED;
#endif

#if ARCH_LITTLE_ENDIAN
	while((temp = *key++) & 0xff) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = COMMON_SWAP(temp | (0x80U << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = COMMON_SWAP(temp);
#else
	while((temp = *key++) & 0xff000000) {
		if (!(temp & 0xff0000))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xff000000) | (0x80 << 16));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff00))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffff0000) | (0x80 << 8));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff))
		{
			*keybuf_word = COMMON_SWAP(temp | 0x80U);
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = COMMON_SWAP(temp);
#endif
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = COMMON_SWAP(0x80);
#ifdef DEBUG
	/* This function is higly optimized and assumes that we are
	   never ever given a key longer than fmt_params.plaintext_length.
	   If we are, buffer overflows WILL happen */
	if (len > PLAINTEXT_LENGTH) {
		fprintf(stderr, "\n** Core bug: got len %u\n'%s'\n", len, _key);
		error();
	}
#endif
key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
#if defined (INCLUDE_TRAILING_NULL)
	((unsigned char*)saved_key)[GETPOS(len,index)] = 0;
	++len; /* Trailing null is included */
	((unsigned char*)saved_key)[GETPOS(len,index)] = 0x80;
#endif

#if defined(SET_SAVED_LEN)
	// some formats append salt, so need length, and outputting the length to
	// uint32[14] is worthless.
	saved_len[index] = len;
#else
#if SALT_APPENDED
	len += SALT_APPENDED;
	((unsigned char*)saved_key)[GETPOS(len,index)] = 0x80;
#endif

	// Normal key setting, set the bit length since we know it.
#	if defined(FMT_IS_BE)
	keybuffer[15*SIMD_COEF_32] = len << 3;
#	else
	keybuffer[14*SIMD_COEF_32] = len << 3;
#	endif
#endif
}
#else	// !defined SIMD_COEF_32
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}
#endif  // SIMD_COEF_32

#if defined(SIMD_COEF_32)
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int32_t i;
#if defined(SET_SAVED_LEN)
	int32_t len = saved_len[index];
#else
# if defined(FMT_IS_BE)
	uint32_t len = (((uint32_t*)saved_key)[GETPOSW32(15,index)] >> 3) - SALT_APPENDED - SALT_PREPENDED;
# else
	uint32_t len = (((uint32_t*)saved_key)[GETPOSW32(14,index)] >> 3) - SALT_APPENDED - SALT_PREPENDED;
# endif
#endif
#if defined (INCLUDE_TRAILING_NULL)
	--len;
#endif

	for (i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i+SALT_PREPENDED, index)];
	out[i] = 0;
	return (char*)out;
}
#else // !defined SIMD_COEF_32
static char *get_key(int index)
{
	static char out [PLAINTEXT_LENGTH + 1];
	return strnzcpy(out, saved_key[index], sizeof(out));
}
#endif  // SIMD_COEF_32
