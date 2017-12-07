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

/*
 * this include file is CODE.  It includes a 'standard' set_key() function,
 * for both SIMD and flat loading.  The requisites for this function to work:
 *   straight keys saved (no encoding, just ascii).
 *   if built for SIMD, this this properly build static must be available:
 *     static uint64_t (*saved_key)[MD5_BUF_SIZ*NBKEYS];
 *       the important thing here, is the buffer must be large enough, aligned
 *       to 16 bytes, and NAMED saved_key.  Also, saved_key should be expected
 *       to be filled from the start with the password, and properly 'cleaned'
 *       and then size filled when the function completes.
 *     Proper GETPOS and GETPOSW macros myst be set for the format.
 * for non_simd builds, these buffers must be there:
 *    static int (*saved_len);
 *    static char (*saved_key)[PLAINTEXT_LENGTH + 1];
 *
 * NOTE, the above requirements have been relaxed, to allow more formats to be
 *  able to use this code.  To do this, #if logic was added at appropriate
 *  locations in the code, to handle slightly different format behaviors and
 *  requirements.  Here are a list of things which can be be predefined
 *  before including this file, so that it behaves in a manner which the
 *  format expects (variables, setup usages, etc).
 *
 *   SALT_APPENDED        Define to FIXED length of the salt!
 *        The format will append a salt to the block of data. This code
 *        will place the 0x80 AFTER the password and salt (salt is a place
 *        holder buffer), and put the length of pw+salt_len into the
 *        length field bits.  It is also used in get_key to return JUST
 *        the password, and not the key.  ONLY impacts SIMD builds.

 *   SALT_PREPENDED       Define to FIXED length of the salt!
 *        Similar to the APPEND, but places the password SALT_PREPENDED
 *        bytes INTO the buffer.  Also within getkey, the code skips over
 *        the salt, and only returns the password.
 *
 *   FMT_IS_BE            Simple define (set or not)
 *        This needs set for any BE format (SHAx, etc). NOTE, this define
 *        should have already been set before calling common-simd-getpos.h
 *        so it normally is NOT a concern before including this file.
 *
 * INCLUDE_TRAILING_NULL  Simple define
 *        citrix includes the NULL byte (before the 0x80) in the SIMD
 *        code, so that logic was kept.  A pretty simple block of code
 *        controlled by this define, impacting only that format, BUT
 *        if other formats want a NULL trailing the password, simply
 *        define this flag.
 *
 * SET_SAVED_LEN          Simple define
 *        The format wants to save the length into 'saved_len'. This
 *        logic will set the length (password) into saved_len[] array
 *        in simd code. It will save it into saved_len[] array OR into
 *        saved_len variable, based upon the next variable.  NOTE, simd
 *        will ALWAYS use an array, IF it uses saved_len at all.
 *
 * NON_SIMD_SET_SAVED_LEN  Simple define
 *        If this variable is set, then in the non-simd code, there is
 *        a simple variable (not an array), so we store (and later use)
 *        the save_len into a single variable.
 *
 * NON_SIMD_SINGLE_SAVED_KEY  simple define.
 *        In a non-simd mode, there is only 1 saved_key variable (not
 *        an array of them).
 *
 */


#if defined(SIMD_COEF_64)

#if !defined SALT_APPENDED
#define SALT_APPENDED 0
#endif
#if !defined SALT_PREPENDED
#define SALT_PREPENDED 0
#endif

#undef COMMON_SWAP

#if defined(FMT_IS_BE)
#  if ARCH_LITTLE_ENDIAN
#    define COMMON_SWAP(a) JOHNSWAP64(a)
#  else
#    define COMMON_SWAP(a) (a)
#  endif
#else
#  if ARCH_LITTLE_ENDIAN
#    define COMMON_SWAP(a) (a)
#  else
#    define COMMON_SWAP(a) JOHNSWAP64(a)
#  endif
#endif

static void set_key(char *_key, int index)
{
	const uint64_t *wkey;
#if !ARCH_ALLOWS_UNALIGNED
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint64_t));
#endif
	uint64_t *keybuffer = &((uint64_t*)saved_key)[GETPOSW64(0,index)];
	uint64_t *keybuf_word = keybuffer;
	unsigned int len=0;
	uint64_t temp;

#if SALT_PREPENDED
	// Note, salts do NOT have to be evenly divisible by 8 bytes in size!
	int til = ((SALT_PREPENDED+7)/8)*8;
	int idx = 0;
	keybuf_word  += ((SALT_PREPENDED+7)/8)*SIMD_COEF_64;
	len = SALT_PREPENDED;
	while (SALT_PREPENDED+idx < til) {
		if (!_key[0]) {
			((unsigned char*)saved_key)[GETPOS(idx+SALT_PREPENDED, index)] = 0x80;
			while (++idx + SALT_PREPENDED < til)
				((unsigned char*)saved_key)[GETPOS(idx+SALT_PREPENDED, index)] = 0;
			keybuf_word -= SIMD_COEF_64;
			goto key_cleaning;
		}
		((unsigned char*)saved_key)[GETPOS(idx+SALT_PREPENDED, index)] = *_key++;
		++idx;
		++len;
	}
#endif

#if ARCH_ALLOWS_UNALIGNED
	wkey = (uint64_t*)_key;
#else
	wkey = (uint64_t*)(is_aligned(_key, sizeof(uint64_t)) ? _key : strcpy(buf_aligned, _key));
#endif

#if ARCH_LITTLE_ENDIAN
	while((unsigned char)(temp = *wkey++)) {
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
			*keybuf_word = COMMON_SWAP((temp & 0xffffff) | (0x80ULL << 24));
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffff) | (0x80ULL << 32));
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffffffULL) | (0x80ULL << 40));
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffffffffULL) | (0x80ULL << 48));
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffffffffffULL) | (0x80ULL << 56));
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = COMMON_SWAP(temp);
#else
	while((temp = *wkey++)  & 0xff00000000000000ULL) {
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xff00000000000000ULL) | (0x80ULL << 48));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffff000000000000ULL) | (0x80ULL << 40));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffff0000000000ULL) | (0x80ULL << 32));
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffff00000000ULL) | (0x80ULL << 24));
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffffff000000ULL) | (0x80 << 16));
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff00))
		{
			*keybuf_word = COMMON_SWAP((temp & 0xffffffffffff0000ULL) | (0x80 << 8));
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff))
		{
			*keybuf_word = COMMON_SWAP(temp | 0x80);
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = COMMON_SWAP(temp);
#endif
		len += 8;
		keybuf_word += SIMD_COEF_64;
	}
#if ARCH_LITTLE_ENDIAN
	*keybuf_word = COMMON_SWAP(0x80LL);
#else
	*keybuf_word = COMMON_SWAP(0x8000000000000000ULL);
#endif

key_cleaning:
	keybuf_word += SIMD_COEF_64;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_64;
	}
#if defined(SET_SAVED_LEN)
	// some formats append salt, so need length, and outputting the length to
	// uint64[14] is worthless.
	saved_len[index] = len;
#else
#if SALT_APPENDED
	len += SALT_APPENDED;
	((unsigned char*)saved_key)[GETPOS(len,index)] = 0x80;
#endif
#	if defined(FMT_IS_BE)
	keybuffer[15*SIMD_COEF_64] = len << 3;
#	else
	keybuffer[14*SIMD_COEF_64] = len << 3;
#	endif
#endif
}
#else	// !defined SIMD_COEF_64
static void set_key(char *key, int index)
{
#if defined (NON_SIMD_SINGLE_SAVED_KEY)
#  if defined(SET_SAVED_LEN) || defined (NON_SIMD_SET_SAVED_LEN)
	saved_len =
#  endif
	strnzcpyn(saved_key, key, sizeof(saved_key));
#else
#  if defined(SET_SAVED_LEN) || defined (NON_SIMD_SET_SAVED_LEN)
	saved_len[index] =
#  endif
	strnzcpyn(saved_key[index], key, sizeof(*saved_key));
#endif
}
#endif  // SIMD_COEF_64


#if defined(SIMD_COEF_64)
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	uint64_t i;
#if defined(SET_SAVED_LEN)
	int32_t len = saved_len[index];
#else
#	if defined(FMT_IS_BE)
	uint64_t len = (((uint64_t*)saved_key)[GETPOSW64(15,index)] >> 3) - SALT_PREPENDED - SALT_APPENDED;
#	else
	uint64_t len = (((uint64_t*)saved_key)[GETPOSW64(14,index)] >> 3) - SALT_PREPENDED - SALT_APPENDED;
#	endif
#endif
#if defined (INCLUDE_TRAILING_NULL)
	--len;
#endif

	for (i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i+SALT_PREPENDED, index)];
	out[i] = 0;
	return (char*)out;
}
#else // !defined SIMD_COEF_64
static char *get_key(int index)
{
#if defined (NON_SIMD_SINGLE_SAVED_KEY)
#  if defined(SET_SAVED_LEN) || defined (NON_SIMD_SET_SAVED_LEN)
	saved_key[saved_len] = 0;
#  endif
	return saved_key;
#else
	static char out [PLAINTEXT_LENGTH + 1];
#  if defined(SET_SAVED_LEN) || defined (NON_SIMD_SET_SAVED_LEN)
	return strnzcpy(out, saved_key[index], saved_len[index]+1);
#  else
	return strnzcpy(out, saved_key[index], sizeof(out));
#  endif
#endif
}
#endif  // SIMD_COEF_64
