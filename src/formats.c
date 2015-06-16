/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010-2013 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "memory.h"
#include "formats.h"
#include "dyna_salt.h"
#include "misc.h"
#include "unicode.h"
#ifndef BENCH_BUILD
#include "options.h"
#else
#if ARCH_INT_GT_32
typedef unsigned short ARCH_WORD_32;
#else
typedef unsigned int ARCH_WORD_32;
#endif
#include "loader.h"
#endif

/* this is just for advance_cursor() */
#ifdef HAVE_OPENCL
#include "common-opencl.h"
#elif HAVE_CUDA
#include "cuda_common.h"
#endif
#include "jumbo.h"
#include "memdbg.h"

struct fmt_main *fmt_list = NULL;
static struct fmt_main **fmt_tail = &fmt_list;

extern volatile int bench_running;

#ifndef BENCH_BUILD
static int orig_min, orig_max, orig_len;
#endif

void fmt_register(struct fmt_main *format)
{
	format->private.initialized = 0;
	format->next = NULL;
	*fmt_tail = format;
	fmt_tail = &format->next;
}

void fmt_init(struct fmt_main *format)
{
	if (!format->private.initialized) {
#ifndef BENCH_BUILD
		if (options.flags & FLG_LOOPTEST) {
			orig_min = format->params.min_keys_per_crypt;
			orig_max = format->params.max_keys_per_crypt;
			orig_len = format->params.plaintext_length;
		}
#endif
		format->methods.init(format);
#ifndef BENCH_BUILD
		/* NOTE, we have to grab these values (the first time), from after
		   the format has been initialized for thin dynamic formats */
		if (options.flags & FLG_LOOPTEST && orig_len == 0 && format->params.plaintext_length) {
			orig_min = format->params.min_keys_per_crypt;
			orig_max = format->params.max_keys_per_crypt;
			orig_len = format->params.plaintext_length;
		}
#endif
		format->private.initialized = 1;
	}
#ifndef BENCH_BUILD
	if (options.flags & FLG_KEEP_GUESSING)
		format->params.flags |= FMT_NOT_EXACT;

	if (options.force_maxkeys) {
		if (options.force_maxkeys > format->params.max_keys_per_crypt) {
			fprintf(stderr,
			    "Can't set mkpc larger than %u for %s format\n",
			    format->params.max_keys_per_crypt,
			    format->params.label);
			error();
		}
		if (options.force_maxkeys < format->params.min_keys_per_crypt)
			format->params.min_keys_per_crypt =
				options.force_maxkeys;
	}
	if (options.force_maxlength > format->params.plaintext_length) {
		fprintf(stderr, "Can't set max length larger than %u "
		        "for %s format\n",
		        format->params.plaintext_length,
		        format->params.label);
		error();
	}
#endif
}

void fmt_done(struct fmt_main *format)
{
	if (format->private.initialized) {
		format->methods.done();
		format->private.initialized = 0;
#ifdef HAVE_OPENCL
		opencl_done();
#endif
#ifndef BENCH_BUILD
		if (options.flags & FLG_LOOPTEST) {
			format->params.min_keys_per_crypt = orig_min;
			format->params.max_keys_per_crypt = orig_max;
			format->params.plaintext_length = orig_len;
		}
#endif

	}
}

void fmt_all_done(void)
{
	struct fmt_main *format = fmt_list;

	while (format) {
		if (format->private.initialized) {
			format->methods.done();
			format->private.initialized = 0;
		}
		format = format->next;
	}
#ifdef HAVE_OPENCL
	opencl_done();
#endif
}

static int is_poweroftwo(size_t align)
{
	return align != 0 && (align & (align - 1)) == 0;
}

#undef is_aligned /* clash with common.h */
static int is_aligned(void *p, size_t align)
{
	return ((size_t)p & (align - 1)) == 0;
}

/* Mutes ASan problems. We pass a buffer long enough for any use */
#define fmt_set_key(key, index)	  \
	{ \
		static char buf_key[PLAINTEXT_BUFFER_SIZE]; \
		char *s = key, *d = buf_key; \
		while ((*d++ = *s++)); \
		format->methods.set_key(buf_key, index); \
	}

#define MAXLABEL        "MAXLENGTH" /* must be upper-case ASCII chars only */
#define MAXLABEL_SIMD   "0X80_IS_NOT_EOW\x80" /* Catch a common bug */
static char *longcand(struct fmt_main *format, int index, int ml)
{
	static char out[PLAINTEXT_BUFFER_SIZE];

	memset(out, 'A' + (index % 23), ml);
	if (!(format->params.flags & FMT_8_BIT) ||
#ifndef BENCH_BUILD
	    !(format->params.flags & FMT_CASE) || pers_opts.target_enc == UTF_8
#else
	    !(format->params.flags & FMT_CASE)
#endif
	   )
		memcpy(out, MAXLABEL, strlen(MAXLABEL));
	else
		memcpy(out, MAXLABEL_SIMD, strlen(MAXLABEL_SIMD));
	out[ml] = 0;

	return out;
}

static char *fmt_self_test_body(struct fmt_main *format,
    void *binary_copy, void *salt_copy)
{
	static char s_size[100];
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int i, ntests, done, index, max, size;
	void *binary, *salt;
	int binary_align_warned = 0, salt_align_warned = 0;
	int salt_cleaned_warned = 0, binary_cleaned_warned = 0;
	int salt_dupe_warned = 0;
#ifndef BENCH_BUILD
	int dhirutest = 0;
	int maxlength = 0;
	int extra_tests = options.flags & FLG_TEST_SET;
#else
	int extra_tests = 0;
#endif
	int ml;

	// validate that there are no NULL function pointers
	if (format->methods.prepare == NULL)    return "method prepare NULL";
	if (format->methods.valid == NULL)      return "method valid NULL";
	if (format->methods.split == NULL)      return "method split NULL";
	if (format->methods.init == NULL)       return "method init NULL";

/*
 * Test each format just once unless we're debugging.
 */
#ifndef DEBUG
	if (format->private.initialized == 2)
		return NULL;
#endif

#ifndef BENCH_BUILD
	if (options.flags & FLG_NOTESTS) {
		fmt_init(format);
		dyna_salt_init(format);
		format->methods.reset(NULL);
		format->private.initialized = 2;
		format->methods.clear_keys();
		return NULL;
	}
#endif

	MemDbg_Validate_msg(MEMDBG_VALIDATE_DEEPEST,
	                    "\nAt start of self-test:");

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;
#ifdef _MSC_VER
	if (current->ciphertext[0] == 0 && !strcmp(format->params.label, "LUKS")) {
		// luks has a string that is longer than the 64k max string length of
		// VC. So to get it to work, we post load the the test value.
		void LUKS_test_fixup();
		LUKS_test_fixup();
		current = format->params.tests;
	}
#endif

	if (ntests==0) return NULL;

	/* Check prepare, valid, split before init */
	if (!current->fields[1])
		current->fields[1] = current->ciphertext;
	ciphertext = format->methods.prepare(current->fields, format);
	if (!ciphertext || strlen(ciphertext) < 7)
		return "prepare (before init)";
	if (format->methods.valid(ciphertext, format) != 1)
		return "valid (before init)";
	if (!format->methods.split(ciphertext, 0, format))
		return "split() returned NULL (before init)";
	fmt_init(format);

	// validate that there are no NULL function pointers after init()
	if (format->methods.done == NULL)       return "method done NULL";
	if (format->methods.reset == NULL)      return "method reset NULL";
	if (format->methods.binary == NULL)     return "method binary NULL";
	if (format->methods.salt == NULL)       return "method salt NULL";
	if (format->methods.source == NULL)     return "method source NULL";
	if (!format->methods.binary_hash[0])    return "method binary_hash[0] NULL";
	if (format->methods.salt_hash == NULL)  return "method salt_hash NULL";
	if (format->methods.set_salt == NULL)   return "method set_salt NULL";
	if (format->methods.set_key == NULL)    return "method set_key NULL";
	if (format->methods.get_key == NULL)    return "method get_key NULL";
	if (format->methods.clear_keys == NULL) return "method clear_keys NULL";
	if (format->methods.crypt_all == NULL)  return "method crypt_all NULL";
	if (format->methods.get_hash[0]==NULL)  return "method get_hash[0] NULL";
	if (format->methods.cmp_all == NULL)    return "method cmp_all NULL";
	if (format->methods.cmp_one == NULL)    return "method cmp_one NULL";
	if (format->methods.cmp_exact == NULL)  return "method cmp_exact NULL";

	if (format->params.plaintext_length < 1 ||
	    format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "plaintext_length";

	if (!is_poweroftwo(format->params.binary_align))
		return "binary_align";

	if (!is_poweroftwo(format->params.salt_align))
		return "salt_align";

	if (format->methods.valid("*", format))
		return "valid";

	ml = format->params.plaintext_length;
#ifndef BENCH_BUILD
	/* UTF-8 bodge in reverse. Otherwise we will get truncated keys back
	   from the max-length self-test */
	if ((pers_opts.target_enc == UTF_8) &&
	    (format->params.flags & FMT_UTF8) &&
	    (format->params.flags & FMT_UNICODE))
		ml /= 3;
#endif

	format->methods.reset(NULL);
	dyna_salt_init(format);

	if ((format->methods.split == fmt_default_split) &&
	    (format->params.flags & FMT_SPLIT_UNIFIES_CASE))
		return "FMT_SPLIT_UNIFIES_CASE";

	if ((format->params.flags & FMT_OMP_BAD) &&
	    !(format->params.flags & FMT_OMP))
		return "FMT_OMP_BAD";

	if ((format->methods.binary == fmt_default_binary) &&
	    (format->params.binary_size > 0))
		puts("Warning: Using default binary() with a "
		     "non-zero BINARY_SIZE");

	if ((format->methods.salt == fmt_default_salt) &&
	    (format->params.salt_size > 0))
		puts("Warning: Using default salt() with a non-zero SALT_SIZE");

	if (format->params.min_keys_per_crypt < 1)
		return "min keys per crypt";

	if (format->params.max_keys_per_crypt < 1)
		return "max keys per crypt";

	if (format->params.max_keys_per_crypt <
	    format->params.min_keys_per_crypt)
		return "max < min keys per crypt";

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;

	do {
		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		ciphertext = format->methods.prepare(current->fields, format);
		if (!ciphertext || (strcmp(format->params.label, "plaintext") &&
		                    strlen(ciphertext) < 7))
			return "prepare";
		if (format->methods.valid(ciphertext, format) != 1) {
			snprintf(s_size, sizeof(s_size), "valid (%s)", ciphertext);
			return s_size;
		}

#if !defined(BENCH_BUILD)
		if (extra_tests && !dhirutest++ &&
		    strcmp(format->params.label, "plaintext") &&
		    strcmp(format->params.label, "dummy") &&
		    strcmp(format->params.label, "crypt")) {
			if (*ciphertext == '$') {
				char *p, *k = strdup(ciphertext);

				p = k + 1;
				while (*p) {
					if (*p++ == '$') {
						*p = 0;
						// $tag$ only
						if (format->methods.valid(k, format)) {
							sprintf(s_size, "promiscuous valid (%s)", k);
							return s_size;
						}
						*p = '$';
						while (*p)
							*p++ = '$';
						// $tag$$$$$$$$$$$$$$$$$$
						if (format->methods.valid(k, format)) {
							sprintf(s_size, "promiscuous valid");
							return s_size;
						}
						break;
					}
				}
				MEM_FREE(k);
			}
		}
#endif

		ciphertext = format->methods.split(ciphertext, 0, format);
		if (!ciphertext)
			return "split() returned NULL";
		plaintext = current->plaintext;

/*
 * Make sure the declared binary_size and salt_size are sufficient to actually
 * hold the binary ciphertexts and salts.  We do this by copying the values
 * returned by binary() and salt() only to the declared sizes.
 */
		if (!(binary = format->methods.binary(ciphertext)))
			return "binary() returned NULL";
#if ARCH_ALLOWS_UNALIGNED
		if (mem_saving_level <= 2 || format->params.binary_align >= MEM_ALIGN_SIMD)
#endif
		if (!binary_align_warned &&
			!is_aligned(binary, format->params.binary_align) &&
		    format->params.binary_size > 0) {
			puts("Warning: binary() returned misaligned pointer");
			binary_align_warned = 1;
		}

		/* validate that binary() returns cleaned buffer */
		if (extra_tests && !binary_cleaned_warned && format->params.binary_size) {
			memset(binary, 0xAF, format->params.binary_size);
			binary = format->methods.binary(ciphertext);
			if (((unsigned char*)binary)[format->params.binary_size-1] == 0xAF)
			{
				memset(binary, 0xCC, format->params.binary_size);
				binary = format->methods.binary(ciphertext);
				if (((unsigned char*)binary)[format->params.binary_size-1] == 0xCC)
				{
					/* possibly did not clean the binary. */
					puts("Warning: binary() not pre-cleaning buffer");
					binary_cleaned_warned = 1;
				}
			}
			/* Clean up the mess we might have caused */
			memset(binary, 0, format->params.binary_size);
			binary = format->methods.binary(ciphertext);
		}
		*((char*)binary_copy) = 0;
		if (format->params.binary_size)
			memcpy(binary_copy, binary, format->params.binary_size);
		binary = binary_copy;

		salt = format->methods.salt(ciphertext);
		dyna_salt_create(salt);
		if (!salt)
			return "salt() returned NULL";
#if ARCH_ALLOWS_UNALIGNED
		if (mem_saving_level <= 2 || format->params.salt_align >= MEM_ALIGN_SIMD)
#endif
		if (!salt_align_warned &&
			!is_aligned(salt, format->params.salt_align) &&
		    format->params.salt_size > 0) {
			puts("Warning: salt() returned misaligned pointer");
			salt_align_warned = 1;
		}

		/* validate that salt dupe checks will work */
		if (!salt_dupe_warned && format->params.salt_size) {
			char *copy = mem_alloc(format->params.salt_size);

			memcpy(copy, salt, format->params.salt_size);
			salt = format->methods.salt(ciphertext);
			dyna_salt_create(salt);
			if (dyna_salt_cmp(copy, salt, format->params.salt_size))
			{
				puts("Warning: No dupe-salt detection");
				salt_dupe_warned = 1;
				// These can be useful in tracking down salt
				// dupe problems.
				//fprintf(stderr, "%s\n", ciphertext);
				//dump_stuff(copy, format->params.salt_size);
				//dump_stuff(salt, format->params.salt_size);
			}
			dyna_salt_remove(copy);
			MEM_FREE(copy);
		}

		/* validate that salt() returns cleaned buffer */
		if (extra_tests && !salt_cleaned_warned && format->params.salt_size) {
			if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
				dyna_salt *p1, *p2=0, *p3=0;
				p1 = *((dyna_salt**)salt);
				dyna_salt_smash(salt, 0xAF);
				salt = format->methods.salt(ciphertext);
				dyna_salt_create(salt);
				p2 = *((dyna_salt**)salt);
				if (dyna_salt_smash_check(salt, 0xAF))
				{
					dyna_salt_smash(salt, 0xC3);
					salt = format->methods.salt(ciphertext);
					dyna_salt_create(salt);
					p3 = *((dyna_salt**)salt);
					if (dyna_salt_smash_check(salt, 0xC3)) {
						/* possibly did not clean the salt. */
						puts("Warning: salt() not pre-cleaning buffer");
						salt_cleaned_warned = 1;
					}
				}
				/* Clean up the mess we might have caused */
				dyna_salt_remove(&p1);
				dyna_salt_remove(&p2);
				dyna_salt_remove(&p3);
			} else {
				memset(salt, 0xAF, format->params.salt_size);
				salt = format->methods.salt(ciphertext);
				if (((unsigned char*)salt)[format->params.salt_size-1] == 0xAF)
				{
					memset(salt, 0xC3, format->params.salt_size);
					salt = format->methods.salt(ciphertext);
					if (((unsigned char*)salt)[format->params.salt_size-1] == 0xC3) {
						/* possibly did not clean the salt. */
						puts("Warning: salt() not pre-cleaning buffer");
						salt_cleaned_warned = 1;
					}
				}
				/* Clean up the mess we might have caused */
				memset(salt, 0, format->params.salt_size);
			}
			salt = format->methods.salt(ciphertext);
			dyna_salt_create(salt);
		}

		*((char*)salt_copy) = 0;
		if (format->params.salt_size)
			memcpy(salt_copy, salt, format->params.salt_size);
		salt = salt_copy;

		if (strcmp(ciphertext,
		    format->methods.source(ciphertext, binary)))
			return "source";

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);

#ifndef BENCH_BUILD
		if (extra_tests && maxlength == 0) {
			//int min = format->params.min_keys_per_crypt;
			maxlength = 1;

			/* Check that claimed max. length is actually supported:
			   1. Fill the buffer with maximum length keys */
			format->methods.clear_keys();
			for (i = 0; i < max; i++) {
				char *pCand = longcand(format, i, ml);
				format->methods.set_key(pCand, i);
			}

#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
			advance_cursor();
#endif
			/* 2. Perform a limited crypt (in case it matters) */
		/*	if (format->methods.crypt_all(&min, NULL) != min)
				return "crypt_all";*/

#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
			advance_cursor();
#endif
			/* 3. Now read them back and verify they are intact */
			for (i = 0; i < max; i++) {
				char *getkey = format->methods.get_key(i);
				char *setkey = longcand(format, i, ml);

				if (!getkey)
					return "get_key() returned NULL";

				if (strncmp(getkey, setkey, ml + 1)) {
					if (strnlen(getkey, ml + 1) > ml)
					sprintf(s_size, "max. length in index "
					        "%d: wrote %d, got longer back",
					        i, ml);
					else
					sprintf(s_size, "max. length in index "
					        "%d: wrote %d, got %d back", i,
					        ml, (int)strlen(getkey));
					return s_size;
				}
			}
		}
#endif

		if (index == 0)
			format->methods.clear_keys();
		fmt_set_key(current->plaintext, index);

#if !defined(BENCH_BUILD) && (defined(HAVE_OPENCL) || defined(HAVE_CUDA))
		advance_cursor();
#endif
		{
			int count = index + 1;
			int match = format->methods.crypt_all(&count, NULL);

			if (!format->methods.cmp_all(binary, match)) {
				sprintf(s_size, "cmp_all(%d)", match);
				return s_size;
			}

			for (i = match - 1; i >= 0; i--) {
				if (format->methods.cmp_one(binary, i))
					break;
			}

			if (i == -1) {
				sprintf(s_size, "cmp_one(%d)", match);
				return s_size;
			}

			for (size = 0; size < PASSWORD_HASH_SIZES; size++)
			if (format->methods.binary_hash[size] &&
			    format->methods.get_hash[size](i) !=
			    format->methods.binary_hash[size](binary)) {
#ifndef DEBUG
				sprintf(s_size, "get_hash[%d](%d) %x!=%x", size, index, format->methods.get_hash[size](index), format->methods.binary_hash[size](binary));
#else
				// Dump out as much as possible (up to 3 full bytes). This can
				// help in trying to track down problems, like needing to SWAP
				// the binary or other issues, when doing BE ports.  Here
				// PASSWORD_HASH_SIZES is assumed to be 7. This loop will max
				// out at 6, in that case (i.e. 3 full bytes).
				int maxi=size;
				while (maxi+2 < PASSWORD_HASH_SIZES && format->methods.binary_hash[maxi]) {
					if (format->methods.binary_hash[++maxi] == NULL) {
						--maxi;
						break;
					}
				}
				if (format->methods.get_hash[maxi] && format->methods.binary_hash[maxi])
					sprintf(s_size, "get_hash[%d](%d) %x!=%x", size, index,
					        format->methods.get_hash[maxi](index),
					        format->methods.binary_hash[maxi](binary));
				else
					sprintf(s_size, "get_hash[%d](%d)", size, index);
#endif
				return s_size;
			}

			if (!format->methods.cmp_exact(ciphertext, i)) {
				sprintf(s_size, "cmp_exact(%d)", i);
				return s_size;
			}

			if (strncmp(format->methods.get_key(i), plaintext,
				format->params.plaintext_length)) {
				sprintf(s_size, "get_key(%d)", i);
				return s_size;
			}
		}

/* Remove some old keys to better test cmp_all() */
		if (index & 1)
			fmt_set_key("", index);

/* 0 1 2 3 4 6 9 13 19 28 42 63 94 141 211 316 474 711 1066 ... */
		if (index >= 2 && max > ntests) {
/* Always call set_key() even if skipping. Some formats depend on it. */
			for (i = index + 1;
			     i < max && i < (index + (index >> 1)); i++)
				format->methods.set_key(longcand(format, i, ml), i);
			index = i;
		} else
			index++;

		if (index >= max) {
			format->methods.clear_keys();
			index = (max > 5 && max > ntests && done != 1) ? 5 : 0;
/* Always call set_key() even if skipping. Some formats depend on it. */
			if (index == 5)
			for (i = 0; i < 5; i++)
				fmt_set_key("", i);
			done |= 1;
		}

		if (!(++current)->ciphertext) {
#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
/* Jump straight to last index for GPU formats but always call set_key() */
			if (strstr(format->params.label, "-opencl") ||
			    strstr(format->params.label, "-cuda")) {
				for (i = index + 1; i < max - 1; i++)
				    format->methods.set_key(longcand(format, i, ml), i);
				index = max - 1;
			} else
#endif
/* Jump straight to last index for non-bitslice DES */
			if (!(format->params.flags & FMT_BS) &&
			    (!strcmp(format->params.label, "descrypt") ||
			    !strcmp(format->params.label, "bsdicrypt") ||
			    !strcmp(format->params.label, "AFS")))
				index = max - 1;

			current = format->params.tests;
			done |= 2;
		}
		dyna_salt_remove(salt);
	} while (done != 3);

	format->methods.clear_keys();
	format->private.initialized = 2;

	MemDbg_Validate_msg(MEMDBG_VALIDATE_DEEPEST, "At end of self-test:");

	return NULL;
}

/*
 * Allocate memory for a copy of a binary ciphertext or salt with only the
 * minimum guaranteed alignment.  We do this to test that binary_hash*(),
 * cmp_*(), and salt_hash() do accept such pointers.
 */
static void *alloc_binary(void **alloc, size_t size, size_t align)
{
	size_t mask = align - 1;
	char *p;

/* Ensure minimum required alignment and leave room for "align" bytes more */
	p = *alloc = mem_alloc(size + mask + align);
	p += mask;
	p -= (size_t)p & mask;

/* If the alignment is too great, reduce it to the minimum */
	if (!((size_t)p & align))
		p += align;

	return p;
}

char *fmt_self_test(struct fmt_main *format)
{
	char *retval;
	void *binary_alloc, *salt_alloc;
	void *binary_copy, *salt_copy;

	binary_copy = alloc_binary(&binary_alloc,
	    format->params.binary_size?format->params.binary_size:1, format->params.binary_align);
	salt_copy = alloc_binary(&salt_alloc,
	    format->params.salt_size?format->params.salt_size:1, format->params.salt_align);

	/* We use this to keep opencl_process_event() from doing stuff
	 * while self-test is running. */
	bench_running = 1;

	retval = fmt_self_test_body(format, binary_copy, salt_copy);

	bench_running = 0;

	MEM_FREE(salt_alloc);
	MEM_FREE(binary_alloc);

	return retval;
}

void fmt_default_init(struct fmt_main *self)
{
}

void fmt_default_done(void)
{
}

void fmt_default_reset(struct db_main *db)
{
}

char *fmt_default_prepare(char *fields[10], struct fmt_main *self)
{
	return fields[1];
}

char *fmt_default_split(char *ciphertext, int index, struct fmt_main *self)
{
	return ciphertext;
}

void *fmt_default_binary(char *ciphertext)
{
	return ciphertext;
}

void *fmt_default_salt(char *ciphertext)
{
	return ciphertext;
}

char *fmt_default_source(char *source, void *binary)
{
	return source;
}

int fmt_default_binary_hash(void *binary)
{
	return 0;
}

int fmt_default_binary_hash_0(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xF;
}

int fmt_default_binary_hash_1(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xFF;
}

int fmt_default_binary_hash_2(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xFFF;
}

int fmt_default_binary_hash_3(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xFFFF;
}

int fmt_default_binary_hash_4(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xFFFFF;
}

int fmt_default_binary_hash_5(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0xFFFFFF;
}

int fmt_default_binary_hash_6(void * binary)
{
	return *(ARCH_WORD_32 *) binary & 0x7FFFFFF;
}

int fmt_default_salt_hash(void *salt)
{
	return 0;
}

int fmt_default_dyna_salt_hash(void *salt)
{
	/* if the hash is a dyna_salt type hash, it can simply use this function */
	dyna_salt_john_core *mysalt = *(dyna_salt_john_core **)salt;
	unsigned v;
	int i;
	unsigned char *p;

	p = (unsigned char*)mysalt;
	p += mysalt->dyna_salt.salt_cmp_offset;
#ifdef DYNA_SALT_DEBUG
	dump_stuff_msg((void*)__FUNCTION__, p, mysalt->dyna_salt.salt_cmp_size>48?48:mysalt->dyna_salt.salt_cmp_size);
	fprintf(stderr, "fmt_default_dyna_salt_hash(): cmp size %u\n", (unsigned)mysalt->dyna_salt.salt_cmp_size);
#endif
	v = 0;
	for (i = 0; i < mysalt->dyna_salt.salt_cmp_size; ++i) {
		v *= 11;
		v += *p++;
	}
#ifdef DYNA_SALT_DEBUG
	fprintf(stderr, "fmt_default_dyna_salt_hash(): return %d\n", v & (SALT_HASH_SIZE - 1));
#endif
	return v & (SALT_HASH_SIZE - 1);
}

void fmt_default_set_salt(void *salt)
{
}

void fmt_default_clear_keys(void)
{
}

int fmt_default_get_hash(int index)
{
	return 0;
}
