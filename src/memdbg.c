/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 *  memdbg.c
 *  Memory management debugging (at runtime)
 *
 *   memdbg.c contains routines detect, and report memory
 *   problems, such as double frees, passing bad pointers to
 *   free, most buffer overwrites.  Also, tracking of non-freed
 *   data, showing memory leaks, can also be shown.
 *
 *  Compilation Options (provided from Makefile CFLAGS)
 *
 *   MEMDBG_ON     If this is NOT defined, then memdbg will
 *       get out of your way, and most normal memory functions
 *       will be called with no overhead at all.
 *
 *   MEMDBG_EXTRA_CHECKS   If defined, then we do not 'really' free
 *       the memory.  We simply set the fence posts to deleted status,
 *       and proceed.  This allows us finding double frees, and other
 *       usages of smashes.  NOTE, when this is set, and there are a
 *       LOT of memory alloc/frees, then at some point the calls to
 *       free will fail.  If this happens, there is code in place that
 *       frees the oldest freed block (really frees it), and does that
 *       over and over again, until either we have no freed blocks left
 *       OR the app is able to allocate this new buffer. In this situation
 *       we do lose track of those older freed blocks of memory, but it
 *       allows the application to continue forward, even though this
 *       debugging code exausted all memory.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#define __MEMDBG__
#include "memdbg.h"

#ifdef _OPENMP
#include <omp.h>
#endif

/*
 * This function ALWAYS must be defined. It is (HAS) to be used if there is code which
 * has some library code that allocates memory which was NOT handled by one of the allocation
 * functions within this wrapper class, BUT which really needs to be freed. Thus the user code
 * really needs to have straight access to the libc function free().  We give them that access,
 * but they have to call this function, and not the 'free' function, which would get wrapped
 * and call into MEMDBG_free(p, filename, fileline).
 */
void MEMDBG_libc_free(void *p) {
	free(p);
}

void *MEMDBG_libc_alloc(size_t size) {
	return malloc(size);
}

void *MEMDBG_libc_calloc(size_t size) {
	return calloc(1, size);
}

#if defined (MEMDBG_ON)

/*
 * these fence posts (first fence post guarding underflow), are:
 *  MEMFPOST  == allocated memory
 *  MEMFPOSTt == allocated 'tiny' memory (allocated with mem_alloc_tiny() from memory.c)
 *  MEMFPOSTd == freed (deleted) memory.  Will only be set this way, and stored in the
 *               freed_memlist, if MEMDBG_EXTRA_CHECKS is set.
 */
#define MEMFPOST   0xa5a5a5a5
#define MEMFPOSTt  0xa555a5a5
#define MEMFPOSTd  0x5a5a5a5a
const char *cpMEMFPOST  = "\xa5\xa5\xa5\xa5";
const char *cpMEMFPOSTd = "\x5a\x5a\x5a\x5a";

/*
 * this structure will contain data that is butted RIGHT against
 * the tail end of the allocated block. We put a fence post here,
 * and thus can detect buffer overwrite.
 */
typedef struct _hdr2 {
	/* we use a unsigned char, and do not care about alignment. We ALWAYS treat this var with
	 * a memcpy, memcmp, etc, so that this works the same on aligned required CPU or non-aligned required.
	 */
	unsigned char mdbg_fpst[4];
} MEMDBG_HDR2;

/*
 *  This structure is carefully crafted. It contains exactly
 *  4 32 bit values (possibly 6 on non-aligned hw), and 4 pointers
 *  In the end, we should have alignment as good as we would
 *  get from the allocator. This puts our mdbg_fpst2 RIGHT against
 *  the start of the allocated block.  We later will put the
 *  HDR2 RIGHT against the tail end of the buffer.  This will
 *  allow us to catch a single byte over or underflow.
 */
typedef struct _hdr {
   struct _hdr *mdbg_next;
   struct _hdr *mdbg_prev;
   MEMDBG_HDR2 *mdbg_hdr2; /* points to just 'right' after allocated memory, for overflow catching */
   const char  *mdbg_file;
   ARCH_WORD_32 mdbg_line;
   ARCH_WORD_32 mdbg_cnt;
   size_t mdbg_size;
   ARCH_WORD_32 mdbg_fpst; /* this should be 'right' against the allocated memory, for underflow catching */
} MEMDBG_HDR;

static size_t   mem_size = 0;
static size_t   max_mem_size = 0;
static size_t   mem_sizet = 0;
static size_t   max_mem_sizet = 0;
static MEMDBG_HDR		*memlist = NULL;
static unsigned long	alloc_cnt = 0;

#ifdef MEMDBG_EXTRA_CHECKS
static MEMDBG_HDR		*freed_memlist = NULL;
static size_t			freed_mem_size = 0;
static unsigned long	freed_cnt = 0;
#endif

#define RESERVE_SZ (sizeof(MEMDBG_HDR))

#define CLIENT_2_HDR(a) ((MEMDBG_HDR *) (((char *) (a)) - RESERVE_SZ))
#define HDR_2_CLIENT(a) ((void *) (((char *) (a)) + RESERVE_SZ))

static void   mem_fence_post_err_fp    (void *, const char *, int, char *fp, int line);
static void   mem_fence_post_err_ne_fp (void *, const char *, int, char *fp, int line);
static void   mem_fence_post_errd_fp   (void *, const char *, int, char *fp, int line);
static void   mem_fence_post_errd_ne_fp(void *, const char *, int, char *fp, int line);

#define mem_fence_post_err(a,b,c)      mem_fence_post_err_fp(a,b,c,__FILE__,__LINE__)
#define mem_fence_post_err_ne(a,b,c)   mem_fence_post_err_ne_fp(a,b,c,__FILE__,__LINE__)
#define mem_fence_post_errd(a,b,c)     mem_fence_post_errd_fp(a,b,c,__FILE__,__LINE__)
#define mem_fence_post_errd_ne(a,b,c)  mem_fence_post_errd_ne_fp(a,b,c,__FILE__,__LINE__)

#ifdef MEMDBG_EXTRA_CHECKS
/* NOTE, which this function is called, the memory (client memory) gets SMASHED   */
/* If this starts causing the program to crash, then it is likely that the client */
/* code is using dangling pointers by accessing the memory after a free or realloc */
static void   MEMDBG_FREEDLIST_add(MEMDBG_HDR *);
#endif

/*
 * these are now macros.  This makes it easier for doing omp critical
 * sections. It is illegal to branch into or out of a CRITICAL block
 */
#define MEMDBG_LIST_delete(p) \
	if (p->mdbg_next != NULL) \
		p->mdbg_next->mdbg_prev = p->mdbg_prev; \
	if (p->mdbg_prev != NULL) \
		p->mdbg_prev->mdbg_next = p->mdbg_next; \
	else \
		memlist = p->mdbg_next

#define MEMDBG_LIST_add(p) \
	p->mdbg_next = memlist; \
	p->mdbg_prev = NULL; \
	if (memlist != NULL) \
		memlist->mdbg_prev = p; \
	memlist = p

/*
 * This function can be called directly by client code.
 * it lists how much memory is currently allocated.
 * a good check before program exit, is are there 0
 * bytes allocated.
 */
size_t MemDbg_Used(int show_freed) {
#ifdef MEMDBG_EXTRA_CHECKS
	if (show_freed)
		return freed_mem_size;
#endif
	return mem_size+mem_sizet;
}

/*
 * This function can be called directly by client code.
 * It writes out all non-freed memory.
 */
void MemDbg_Display(FILE *fp) {
	MEMDBG_HDR *p;
	int idx;
	if (!(mem_size+mem_sizet)) return;

	fprintf(fp, "\n------------------------------\n");
	fprintf(fp, "MEMDBG: allocation information (display):\n");
	fprintf(fp, "   current normal alloc mem (leaks)%llu  max normal mem allocated: %llu\n", (unsigned long long)mem_size, (unsigned long long)max_mem_size);
	fprintf(fp, "   current 'tiny' alloc mem (leaks)%llu  max  tiny  mem allocated: %llu\n", (unsigned long long)mem_sizet, (unsigned long long)max_mem_sizet);
#ifdef MEMDBG_EXTRA_CHECKS
	fprintf(fp, "  Freed mem size: %llu (freed cnt: %lu)", (unsigned long long)freed_mem_size, freed_cnt);
#endif
	fprintf(fp, "\n");
	fprintf(fp, "Index : alloc# :   Size : File(Line)  [first 20 bytes, or size of bytes]\n");
	idx = 0;
	p = memlist;
	while (p != NULL) {
		int bfreed = 0, bbad=0;
		fprintf(fp, "%-5d : %-6d : %6llu : %s(%u)", idx++, p->mdbg_cnt, (unsigned long long)p->mdbg_size, p->mdbg_file, p->mdbg_line);
		if (p->mdbg_fpst != MEMFPOST && p->mdbg_fpst != MEMFPOSTt) {
			bbad=1;
			if (p->mdbg_fpst == MEMFPOSTd) {
				fprintf(fp, " INVALID ( freed already? )");
				bfreed = 1;
			}
			else
				fprintf(fp, " INVALID ( buffer underflow )");

		}
		if (memcmp(p->mdbg_hdr2->mdbg_fpst, cpMEMFPOST, 4)) {
			if (bfreed && !memcmp(p->mdbg_hdr2->mdbg_fpst, cpMEMFPOSTd, 4)) {
				bbad=1;
				fprintf(fp, " YES Data was freed.");
			}
			else {
				unsigned i;
				char *cp = ((char*)p)+RESERVE_SZ;
				fprintf(fp, " INVALID (buffer overflow) tail of block: ");
				cp = (char*)p->mdbg_hdr2->mdbg_fpst;
				cp -= 16;
				for (i = 0; i < 20; ++i) {
					if(*cp < ' ' || *cp > '~')
						fprintf(fp, ".");
					else
						fprintf(fp, "%c", *cp);
					++cp;
				}
				fprintf(fp, "  and the head of the block was: ");
			}
		}
		if (!bbad) {
			unsigned i;
			char *cp = ((char*)p)+RESERVE_SZ;
			fprintf(fp, "  ");
			for (i = 0; i < 20 && i < p->mdbg_size; ++i) {
				if(*cp < ' ' || *cp > '~')
					fprintf(fp, ".");
				else
					fprintf(fp, "%c", *cp);
				++cp;
			}
		}
		fprintf(fp, "\n");
		p = p->mdbg_next;
	}
}
/*
 * This function can be called directly by client code.
 * It will walk the list of memory, 'looking' for errors.
 */
void MemDbg_Validate(int level) {
	MemDbg_Validate_msg2(level, NULL, 0);
}
void MemDbg_Validate_msg(int level, const char *pMsg) {
	MemDbg_Validate_msg2(level, pMsg, 0);
}
void MemDbg_Validate_msg2(int level, const char *pMsg, int bShowExMessages) {
	/* Level 0 we ALWAYS walk the alloc list, looking for over/underwrite, and validate a few other items. */
	MEMDBG_HDR  *p = memlist;
	int error = 0;
	int cnt=0;
#ifdef MEMDBG_EXTRA_CHECKS
	unsigned char *cp;
	unsigned i;
#endif
	if (bShowExMessages) {
		if (pMsg)
			fprintf(stderr, "%s\n", pMsg);
		fprintf(stderr, "MemDbg_Validate level 0 checking");
	}
	while (p) {
		if (p->mdbg_fpst != MEMFPOST && p->mdbg_fpst != MEMFPOSTt) {
			++cnt;
			if (cnt < 100) {
				if (p->mdbg_fpst == MEMFPOSTd)
					fprintf(stderr, "\nDeleted memory still in chain\n");
				else {
					fprintf(stderr, "\nMemory buffer underwrite found! Will try to list what file/line allocated the buffer\n");
					mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
				}
			}
			error = 1;
		}
		if (memcmp(p->mdbg_hdr2->mdbg_fpst, cpMEMFPOST, 4)) {
			++cnt;
			if (cnt < 100) {
				if (p->mdbg_fpst == MEMFPOSTd) {
				} else {
					fprintf(stderr, "\nMemory buffer overwrite found! Will try to list what file/line allocated the buffer\n");
					mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
				}
			}
			error = 1;
		}
		// Loop detect code
		{
			MEMDBG_HDR  volatile *p2 = p->mdbg_next;
			while (p2) {
				if (p2 == p || p2 == p2->mdbg_next) {
					fprintf (stderr, "Error, internal loop in the memdbg linked list, aborting\n");
					break;
				}
				p2 = p2->mdbg_next;
			}
		}
		if (cnt > 1000)
			break;
		p = p->mdbg_next;
	}
	if (error) {
		fprintf(stderr, "\nExiting due to the error detected\n");
		if (cnt > 100)
			fprintf(stderr, "There were %d total errors, only first 100 shown\n", cnt);
		exit(1);
	}
	if (bShowExMessages)
		fprintf(stderr, " Passed\n");
	if (level == MEMDBG_VALIDATE_MIN) return;

#ifdef MEMDBG_EXTRA_CHECKS
	// Ok, we have a list of all freed items. We will do work on this.
	p = freed_memlist;
	if (!p) return;
	cnt = 0;
	if (bShowExMessages)
		fprintf(stderr, "MemDbg_Validate level 1 checking");
	while (p) {
		if (p->mdbg_fpst != MEMFPOSTd) {
			++cnt;
			if (cnt < 100)
				fprintf(stderr, "\nFreed Memory buffer underwrite found! Will try to list what file/line allocated the buffer\n");
			mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
			error = 1;
		}
		if (memcmp(p->mdbg_hdr2->mdbg_fpst, cpMEMFPOSTd, 4)) {
			++cnt;
			if (cnt < 100)
				fprintf(stderr, "\nFreed Memory buffer overwrite found! Will try to list what file/line allocated the buffer\n");
			mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
			error = 1;
		}
		// Loop detect code
		{
			MEMDBG_HDR  *p2 = p->mdbg_next;
			while (p2) {
				if (p2 == p || p2 == p2->mdbg_next) {
					fprintf (stderr, "Error, internal loop in the memdbg linked list, aborting\n");
					break;
				}
				p2 = p2->mdbg_next;
			}
		}
		if (cnt > 1000)
			break;
		p = p->mdbg_next;
	}
	if (error) {
		fprintf(stderr, "\nExiting due to the error detected\n");
		if (cnt > 100)
			fprintf(stderr, "There were %d total errors, only first 100 shown\n", cnt);
		exit(1);
	}
	if (bShowExMessages)
		fprintf(stderr, " Passed\n");
	if (level == MEMDBG_VALIDATE_DEEP) return;

	p = freed_memlist;
	cnt = 0;
	if (bShowExMessages)
		fprintf(stderr, "MemDbg_Validate level 2 checking");
	while (p) {
		cp = ((unsigned char*)p)+RESERVE_SZ;
		if (p->mdbg_size != p->mdbg_hdr2->mdbg_fpst - cp) {
			fprintf(stderr, "\nFreed Memory buffer underwrite found (size var busted)! Will try to list what file/line allocated the buffer\n");
			mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
			error = 1;
		} else {
			for (i = 0; i < p->mdbg_size; ++i) {
				// in 'deeper' mode, we only look at first 8 bytes.  If these are not overwritten, it is less likely that the buffer
				// has been written to.  It 'can' be written to later on, and if we use deepest, we will look at the FULL buffer.
				if (i == 8)
					break;
				if (*cp++ != 0xCD) {
					++cnt;
					if (cnt < 100)
						fprintf(stderr, "\nFreed Memory buffer modification found! Will try to list what file/line allocated the buffer\n");
					mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
					error = 1;
					break;
				}
			}
		}
		// Loop detect code
		{
			MEMDBG_HDR  *p2 = p->mdbg_next;
			while (p2) {
				if (p2 == p || p2 == p2->mdbg_next) {
					fprintf (stderr, "Error, internal loop in the memdbg linked list, aborting\n");
					break;
				}
				p2 = p2->mdbg_next;
			}
		}
		if (cnt > 1000)
			break;
		p = p->mdbg_next;
	}
	if (error) {
		fprintf(stderr, "\nExiting due to the error detected\n");
		if (cnt > 100)
			fprintf(stderr, "There were %d total errors, only first 100 shown\n", cnt);
		exit(1);
	}
	if (bShowExMessages)
		fprintf(stderr, " Passed\n");
	if (level == MEMDBG_VALIDATE_DEEPER) return;

	p = freed_memlist;
	cnt = 0;
	if (bShowExMessages)
		fprintf(stderr, "MemDbg_Validate level 3 checking");
	while (p) {
		cp = ((unsigned char*)p)+RESERVE_SZ;
		// in this deepest mode, we look at the ENTIRE buffer.  In deeper, we looked at first 8, so here, we just start from 8 and look forward.
		for (i = 8; i < p->mdbg_size; ++i) {
			if (*cp++ != 0xCD) {
				++cnt;
				if (cnt < 100)
					fprintf(stderr, "\nFreed Memory buffer modification found! Will try to list what file/line allocated the buffer\n");
				mem_fence_post_err_ne(p, p->mdbg_file, p->mdbg_line);
				error = 1;
				break;
			}
		}
		// Loop detect code
		{
			MEMDBG_HDR  *p2 = p->mdbg_next;
			while (p2) {
				if (p2 == p || p2 == p2->mdbg_next) {
					fprintf (stderr, "Error, internal loop in the memdbg linked list, aborting\n");
					break;
				}
				p2 = p2->mdbg_next;
			}
		}
		if (cnt > 1000)
			break;
		p = p->mdbg_next;
	}
	if (error) {
		fprintf(stderr, "\nExiting due to the error detected\n");
		if (cnt > 100)
			fprintf(stderr, "There were %d total errors, only first 100 shown\n", cnt);
		exit(1);
	}
	if (bShowExMessages)
		fprintf(stderr, " Passed\n");
#endif
}

#ifdef MEMDBG_EXTRA_CHECKS
/* Ok, if we are out of memory, due to keeping too much freed memory around, then free
 * up oldest blocks until we can malloc this block.  the rar format is a bad actor,
 * as could be many of the 'non-hash' (old zip for sure), as these have to decrypt
 * a full file, to be assured the password is correct.
 */
static void release_oldest_freed_block() {
	MEMDBG_HDR *p = freed_memlist, *pp;
	if (!p) return;

#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		p = freed_memlist;
		while (p->mdbg_next)
			p = p->mdbg_next;
		// now unlink it.
		freed_mem_size -= p->mdbg_size;
		--freed_cnt;
		p->mdbg_prev->mdbg_next = NULL;
		pp = p->mdbg_prev;
	}
	// now free it
	free(p);

	if (freed_cnt > 10) {
		// free one more.
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
		{
			// NOTE, we can not be assured that pp was still pointing
			// to the last item in the list. We have to look AGAIN,
			// within a critical section.
			pp = freed_memlist;
			while (pp->mdbg_next)
				pp = pp->mdbg_next;
#endif
			freed_mem_size -= pp->mdbg_size;
			--freed_cnt;
			pp->mdbg_prev->mdbg_next = NULL;
#ifdef _OPENMP
		}
#endif
		// now free it
		free(pp);
	}
}
#endif

void * MEMDBG_calloc(size_t size, char *file, int line)
{
	char *p;
	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_calloc %lld %s:%d  mem:%lld\n", (unsigned long long)size, file, line, (unsigned long long)mem_size);
	p = (char*)MEMDBG_alloc(size,file,line);
	memset(p, 0, size);
	return p;
}

/*
 *  MEMDBG_alloc
 *  Allocate a memory block. makes a protected call to malloc(), allocating
 *  extra data, and adding data to all required structures.
 */
void * MEMDBG_alloc(size_t size, char *file, int line)
{
	MEMDBG_HDR      *p;

	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_alloc %lld %s:%d  mem:%lld\n", (unsigned long long)size, file, line, (unsigned long long)mem_size);

	p = (MEMDBG_HDR*)malloc(RESERVE_SZ + size + 4);
#ifdef MEMDBG_EXTRA_CHECKS
#ifdef _OPENMP
	{
		int i = 0;
		do {
#pragma omp critical (memdbg_crit)
			{
				if (!p && freed_mem_size > (RESERVE_SZ + size + 4) && !p && freed_cnt)
					i = 1;
			}
			if (i) {
				release_oldest_freed_block();
				p = (MEMDBG_HDR*)malloc(RESERVE_SZ + size + 4);
			}
		} while (i && !p);
	}
#else
	/* this is the 'right' block, but hard to do with the restrictions of no branching out that omp critical places on us */
	if (!p && freed_mem_size > (RESERVE_SZ + size + 4)) {
		while (!p && freed_cnt) {
			release_oldest_freed_block();
			p = (MEMDBG_HDR*)malloc(RESERVE_SZ + size + 4);
		}
	}
#endif
#endif
	if (!p) {
		if ( ((signed long long)mem_size) < 0)
			fprintf(stderr, "MEMDBG_alloc (end) %lld %s:%d  mem:%lld\n", (unsigned long long)size, file, line, (unsigned long long)mem_size);
		return NULL;
	}
	p->mdbg_fpst = MEMFPOST;
	p->mdbg_size = size;
	p->mdbg_file = file;
	p->mdbg_line = line;
	p->mdbg_hdr2 = (MEMDBG_HDR2*)(((char*)p)+RESERVE_SZ + size);
	memcpy(p->mdbg_hdr2, cpMEMFPOST, 4);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		p->mdbg_cnt = ++alloc_cnt;
		mem_size += size;
		if (mem_size > max_mem_size)
			max_mem_size = mem_size;
		MEMDBG_LIST_add(p);
	}
	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_alloc (end) %lld %s:%d  mem:%lld\n", (unsigned long long)size, file, line, (unsigned long long)mem_size);
	return HDR_2_CLIENT(p);
}

/*
 *  MEMDBG_realloc
 *  Reallocate a memory block makes a protected call to realloc(), allocating
 *  extra data, and adding data to all required structures.
 *  *** realloc is a NASTY function.  The code here has taken a few turns,
 *  trying to handle all of the nuances of this function, and how we hook it,
 *  and how we deal with trying to not free data (if in MEMDBG_EXTRA_CHECKS mode)
 */
void *
MEMDBG_realloc(const void *ptr, size_t size, char *file, int line)
{
	MEMDBG_HDR *p;
	int istiny=0;
	int err=0, i;

	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_realloc(%lld) %s:%d  mem:%lld\n", (unsigned long long)size, file, line, (unsigned long long)mem_size);

	/* if ptr is null, this function works just like alloc, so simply use alloc */
	if (!ptr)
		return MEMDBG_alloc(size, file, line);

#ifdef _OPENMP
#pragma omp critical
#endif
	{
		p = CLIENT_2_HDR(ptr);
		if (p->mdbg_fpst == MEMFPOSTt)
			istiny = 1;
		else if (p->mdbg_fpst != MEMFPOST)
			err = 1;
		else {
			for (i = 0; i < 4; ++i)
				if (((char*)(p->mdbg_hdr2->mdbg_fpst))[i] != cpMEMFPOST[i]) {
					err = 1;
					break;
				}
		}
		if (err) {
			if (p->mdbg_fpst == MEMFPOSTd)
				err = 2;
			else {
				for (i = 0; i < 4; ++i)
					if (((char*)(p->mdbg_hdr2->mdbg_fpst))[i] != cpMEMFPOSTd[i]) {
						break;
					}
				if (i < 4)
					err = 2;
			}

		}
	}
	if (err) {
		if (err == 2)
			mem_fence_post_errd(p, file, line);
		else
			mem_fence_post_err(p, file, line);
		return NULL;
	}
	/* if size == 0, this function works exactly like free, so just use free */
	if (!size) {
		/* NOTE, use ptr, and NOT p */
		MEMDBG_free(ptr, file, line);
		return NULL;
	}
	p->mdbg_fpst = MEMFPOSTd;
	memcpy(p->mdbg_hdr2->mdbg_fpst, cpMEMFPOSTd, 4);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		if (istiny)
			mem_sizet -= p->mdbg_size;
		else
			mem_size -= p->mdbg_size;
		MEMDBG_LIST_delete(p);
	}
#ifdef MEMDBG_EXTRA_CHECKS
	if (size > p->mdbg_size) {
		void *p2 = MEMDBG_alloc(size, file, line);
		if (p2) {
			if (istiny)
				MEMDBG_tag_mem_from_alloc_tiny(p);
			memcpy(p2, ((char*)p)+RESERVE_SZ, p->mdbg_size);
			/* we had to keep the original data 'clean' until now.
			 * but Now, we can put it on free list (which smashes
			 * the original memory block
			 */
			MEMDBG_FREEDLIST_add(p);
			return p2;
		}
		/* We have to undo the MEMDBG_LIST_delete(p); because realloc should
		 * leave the ORIGINAL buffer alone, if we can not allocate more
		 * memory.  Thus we need to 'leave' the leak alone. This is a leak
		 * unless the client code frees the original pointer.  'undoing' the
		 * MEMDBG_LIST_delete(p) keeps our code knowing this is a lost pointer.
		 */
		p->mdbg_fpst = MEMFPOST;
		memcpy(p->mdbg_hdr2, cpMEMFPOST, 4);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
		{
			mem_size += p->mdbg_size;
			if (mem_size > max_mem_size)
				max_mem_size = mem_size;
			MEMDBG_LIST_add(p);
		}
		if (istiny)
			MEMDBG_tag_mem_from_alloc_tiny(p);
		return NULL;
	}
	/* NOTE, it is assumed that the memory will NOT be freed, so we simply drop
	   through, and allow normal realloc to work, and DO NOT try to put anything
	   onto the FREEDLIST, since it will just be the same block */
#endif
	p = (MEMDBG_HDR *) realloc(p, RESERVE_SZ + size + 4);
#ifdef MEMDBG_EXTRA_CHECKS
#ifdef _OPENMP
	{
		int i = 0;
		do {
#pragma omp critical (memdbg_crit)
			{
				if (!p && freed_mem_size > (RESERVE_SZ + size + 4) && !p && freed_cnt)
					i = 1;
			}
			if (i) {
				release_oldest_freed_block();
				p = (MEMDBG_HDR*)realloc(CLIENT_2_HDR(ptr), RESERVE_SZ + size + 4);
			}
		} while (i && !p);
	}
#else
	/* this is the 'right' block, but hard to do with the restrictions of no branching out that omp critical places on us */
	if (!p && freed_mem_size > (RESERVE_SZ + size + 4)) {
		while (!p && freed_cnt) {
			release_oldest_freed_block();
			p = (MEMDBG_HDR*)realloc(CLIENT_2_HDR(ptr), RESERVE_SZ + size + 4);
		}
	}
#endif
#endif
	if (!p)
	{
		/* We have to undo the MEMDBG_LIST_delete(p); because realloc should
			* leave the ORIGINAL buffer alone, if we can not allocate more
			* memory.  Thus we need to 'leave' the leak alone.
			*/
		p = CLIENT_2_HDR(ptr);	/* we have to get 'original' pointer again */
		p->mdbg_fpst = MEMFPOST;
		memcpy(p->mdbg_hdr2, cpMEMFPOST, 4);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
		{
			mem_size += p->mdbg_size;
			if (mem_size > max_mem_size)
				max_mem_size = mem_size;
			MEMDBG_LIST_add(p);
		}
		if (istiny)
			MEMDBG_tag_mem_from_alloc_tiny(p);
		return NULL;
	}
	p->mdbg_fpst = MEMFPOST;
	p->mdbg_size = size;
	p->mdbg_file = file;
	p->mdbg_line = line;
	p->mdbg_hdr2 = (MEMDBG_HDR2*)(((char*)p)+RESERVE_SZ + size);
	memcpy(p->mdbg_hdr2, cpMEMFPOST, 4);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		p->mdbg_cnt = ++alloc_cnt;
		mem_size += size;
		if (mem_size > max_mem_size)
			max_mem_size = mem_size;
		MEMDBG_LIST_add(p);
	}
	if (istiny)
		MEMDBG_tag_mem_from_alloc_tiny(p);
	return HDR_2_CLIENT(p);
}

/*
 *  MEMDBG_strdup
 *  Duplicate a ASCIIZ string in memory, with a protected call to strdup,
 *  allocating extra data, and adding data to all required structures.
 */
char *MEMDBG_strdup(const char *str, char *file, int line)
{
	char * s;
	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_strdup(%ld) %s:%d  mem:%lld\n", strlen(str), file, line, (unsigned long long)mem_size);
	s = (char*)MEMDBG_alloc(strlen(str)+1, file, line);
	if (s != NULL)
		strcpy(s, str);
	return s;
}

/*
 *  MEMDBG_free
 *  Free a memory block, checking a lot of data, which would have been
 *  set at allocation time.
 */
void MEMDBG_free(const void *ptr, char *file, int line)
{
	MEMDBG_HDR *p;
	int err=0, i;

#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		p = CLIENT_2_HDR(ptr);
		if (p->mdbg_fpst == MEMFPOSTt)
			mem_sizet -= p->mdbg_size;
		else if (p->mdbg_fpst == MEMFPOST)
			mem_size -= p->mdbg_size;
		else if (p->mdbg_fpst != MEMFPOST)
			err = 1;
		else {
			for (i = 0; i < 4; ++i)
				if (((char*)(p->mdbg_hdr2->mdbg_fpst))[i] != cpMEMFPOST[i]) {
					err = 1;
					break;
				}
		}
		if (err && p->mdbg_fpst == MEMFPOSTd)
			err = 2;
		MEMDBG_LIST_delete(p);
		p->mdbg_fpst = MEMFPOSTd;
		for (i = 0; i < 4; ++i)
			((char*)(p->mdbg_hdr2->mdbg_fpst))[i] = cpMEMFPOSTd[i];
	}
	if (err) {
		if (err == 2)
			mem_fence_post_errd(p, file, line);
		else
			mem_fence_post_err(p, file, line);
		return;
	}
#ifndef MEMDBG_EXTRA_CHECKS
	free(p);
#else
	MEMDBG_FREEDLIST_add(p);
#endif
	if ( ((signed long long)mem_size) < 0)
		fprintf(stderr, "MEMDBG_free (end) %s:%d  mem:%lld\n", file, line, (unsigned long long)mem_size);
}

#ifdef MEMDBG_EXTRA_CHECKS
/* NOTE, there is no LIST_delete() for the freed list. We only put
 * data onto this list, it is kept for full runtime. We may want to
 * later add some way for the app to clean it up, but for now, we
 * add it, and keep it all.
 */
static void   MEMDBG_FREEDLIST_add(MEMDBG_HDR *p)
{
	unsigned char *cp;
	size_t i;

#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		freed_mem_size += p->mdbg_size;
		++freed_cnt;
		p->mdbg_next = freed_memlist;
		p->mdbg_prev = NULL;
		if (freed_memlist != NULL)
			freed_memlist->mdbg_prev = p;
		freed_memlist = p;
		/* Ok, now 'DEADBEEF' the original data buffer */
		cp = ((unsigned char*)p)+RESERVE_SZ;
		for (i = 0; i < p->mdbg_size; ++i)
			*cp++ = 0xCD;
	}
}
#endif

/*
 *these functions allow taking a memory snapshot,
 * calling some code, then validating that memory
 * is the same after the code.  This will help
 * catch memory leaks and other such problems, within
 * formats and such.  Simply get the snapshot,
 * run self tests (or other), when it exits, check
 * the snapshot to make sure nothing leaked.
 */
MEMDBG_HANDLE MEMDBG_getSnapshot(int id) {
	MEMDBG_HANDLE h;
	h.id = id;
	h.mem_size = mem_size;
	h.alloc_cnt = alloc_cnt;
	return h;
}

void MEMDBG_checkSnapshot(MEMDBG_HANDLE h) {
	/* call the real function, but list do not exit on leak */
	MEMDBG_checkSnapshot_possible_exit_on_error(h,0);
}
/* NOT needed to be thread safe, must be called from single threaded code */
void MEMDBG_checkSnapshot_possible_exit_on_error(MEMDBG_HANDLE h, int exit_on_any_leaks) {
	/* ok, we do several things.
	 * 1 walk allocation change, showing any memory 'newer' than in the handle (not tiny alloc stuff).
	 * 2 validate allocation chain (and free chain if in extra mode).
	 * if there were any errors in #2, then exit.
	 * if any memory leaks (#1) and exit_on_any_leaks true, we also exit. */
	MEMDBG_HDR  *p = memlist;
	int leak = 0;

	/* first step, walk allocation list, looking for leaks */
	while (p) {
		if (p->mdbg_cnt > h.alloc_cnt && p->mdbg_fpst == MEMFPOST) {
			leak = 1;
			fprintf(stderr, "Mem leak: %llu bytes, alloc_num %d, file %s, line %d\n", (unsigned long long)p->mdbg_size, p->mdbg_cnt, p->mdbg_file, p->mdbg_line);
		}
		p = p->mdbg_next;
	}
	MemDbg_Validate_msg2(3, "MEMDBG_checkSnapshot", 0);
	if (leak) {
		exit(1);
	}
}
/* MUST be thread safe */
void MEMDBG_tag_mem_from_alloc_tiny(void *ptr) {
	MEMDBG_HDR *p;

	p = CLIENT_2_HDR(ptr);
#ifdef _OPENMP
#pragma omp critical (memdbg_crit)
#endif
	{
		if (p->mdbg_fpst == MEMFPOST) {
			p->mdbg_fpst = MEMFPOSTt;
			mem_size -= p->mdbg_size;
			mem_sizet += p->mdbg_size;
			if (mem_sizet > max_mem_sizet)
				max_mem_sizet = mem_sizet;
		}
	}
}

static void mem_fence_post_err_fp(void *p, const char *file, int line, char *fp, int line2)
{
	mem_fence_post_err_ne_fp(p, file, line,fp,line2);
	MemDbg_Display(stderr);
	exit(1);
}
static void mem_fence_post_errd_fp(void *p, const char *file, int line, char *fp, int line2)
{
	mem_fence_post_errd_ne_fp(p, file, line,fp,line2);
	MemDbg_Display(stderr);
	exit(1);
}
static void mem_fence_post_err_ne_fp(void *p, const char *file, int line, char *fp, int line2)
{
	char buf[120], *cp=buf, *ip;
	int i;

	ip = (char*) p;
	for (i = 0; i < 16; ++i) {
		if (ip[i] >= ' ' && ip[i] <= '~')
			*cp++ = ip[i];
		else
			*cp++ = '.';
	}
	*cp++ = ' ';
	for (i = 0; i < 16; ++i)
		cp += sprintf(cp, " %02x", (unsigned char)ip[i]);

	fprintf(stderr, "Memory fence_post error - %p - %s(%d) (%d)\n\tdata:  (%s)\n", p, file, line, line2, buf);
}
static void mem_fence_post_errd_ne_fp(void *p, const char *file, int line, char *fp, int line2)
{
	fprintf(stderr, "Memory fence_postd error, using dangling pointer, memory already freed - %p - %s(%d) (%d)\n", p, file, line, line2);
}

#else

void MEMDBG_off_free(void *a) {
	free(a);
}
#endif /* MEMDBG_ON */
