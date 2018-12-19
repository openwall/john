/*
 *  Extract RAR archives
 *
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "arch.h"

#include <stdio.h>
#include <string.h>
#include "aes.h"

#include "unrar.h"
#include "unrarppm.h"
#include "common.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
//static void rar_dbgmsg(const char* fmt,...){}
#endif

#define MAX_O 64

const unsigned int UNIT_SIZE=MAX(sizeof(struct ppm_context), sizeof(struct rar_mem_blk_tag));
const unsigned int FIXED_UNIT_SIZE=12;
const int INT_BITS=7, PERIOD_BITS=7, TOT_BITS=14;
const int INTERVAL=1 << 7, BIN_SCALE=1 << 14, MAX_FREQ=124;
const unsigned int TOP=1 << 24, BOT=1 << 15;

/************* Start of Allocator code block ********************/
static void sub_allocator_init(sub_allocator_t *sub_alloc)
{
	sub_alloc->sub_allocator_size = 0;
}

static void sub_allocator_insert_node(sub_allocator_t *sub_alloc, void *p, int indx)
{
	((struct rar_node *) p)->next = sub_alloc->free_list[indx].next;
	sub_alloc->free_list[indx].next = (struct rar_node *) p;
}

static void *sub_allocator_remove_node(sub_allocator_t *sub_alloc, int indx)
{
	struct rar_node *ret_val;

	ret_val = sub_alloc->free_list[indx].next;
	sub_alloc->free_list[indx].next = ret_val->next;
	return ret_val;
}

static int sub_allocator_u2b(int nu)
{
	return UNIT_SIZE*nu;
}

static rar_mem_blk_t* sub_allocator_mbptr(rar_mem_blk_t* base_ptr, int items)
{
        return ((rar_mem_blk_t*) (((unsigned char *)(base_ptr)) + sub_allocator_u2b(items) ));
}

static void sub_allocator_split_block(sub_allocator_t *sub_alloc, void *pv,
				int old_indx, int new_indx)
{
	int i, udiff;
	unsigned char *p;

	udiff = sub_alloc->indx2units[old_indx] - sub_alloc->indx2units[new_indx];
	p = ((unsigned char *) pv) + sub_allocator_u2b(sub_alloc->indx2units[new_indx]);
	if (sub_alloc->indx2units[i=sub_alloc->units2indx[udiff-1]] != udiff) {
		sub_allocator_insert_node(sub_alloc, p, --i);
		p += sub_allocator_u2b(i=sub_alloc->indx2units[i]);
		udiff -= i;
	}
	sub_allocator_insert_node(sub_alloc, p, sub_alloc->units2indx[udiff-1]);
}

static long sub_allocator_get_allocated_memory(sub_allocator_t *sub_alloc)
{
	return sub_alloc->sub_allocator_size;
}

static void sub_allocator_stop_sub_allocator(sub_allocator_t *sub_alloc)
{
	if (sub_alloc->sub_allocator_size) {
		sub_alloc->sub_allocator_size = 0;
		MEM_FREE(sub_alloc->heap_start);
	}
}

static int sub_allocator_start_sub_allocator(sub_allocator_t *sub_alloc, int sa_size)
{
	unsigned int t, alloc_size;

	t = sa_size << 20;
	if (sub_alloc->sub_allocator_size == t) {
		return 1;
	}
	sub_allocator_stop_sub_allocator(sub_alloc);
	if (t>138412020) {
		//rar_dbgmsg("too much memory needed for uncompressing this file\n");
		return 0;
	}
	alloc_size = t/FIXED_UNIT_SIZE*UNIT_SIZE+UNIT_SIZE;
#if defined(__sparc) || defined(sparc) || defined(__sparcv9)
	/* Allow for aligned access requirements */
	alloc_size += UNIT_SIZE;
#endif
	if ((sub_alloc->heap_start = (unsigned char *) rar_malloc(alloc_size)) == NULL) {
		//rar_dbgmsg("sub_alloc start failed\n");
		return 0;
	}
	sub_alloc->heap_end = sub_alloc->heap_start + alloc_size - UNIT_SIZE;
	sub_alloc->sub_allocator_size = t;
	return 1;
}

static void sub_allocator_init_sub_allocator(sub_allocator_t *sub_alloc)
{
	int i, k;
	unsigned int size1, real_size1, size2, real_size2;

	memset(sub_alloc->free_list, 0, sizeof(sub_alloc->free_list));
	sub_alloc->ptext = sub_alloc->heap_start;

	size2 = FIXED_UNIT_SIZE*(sub_alloc->sub_allocator_size/8/FIXED_UNIT_SIZE*7);
	real_size2 = size2/FIXED_UNIT_SIZE*UNIT_SIZE;
	size1 = sub_alloc->sub_allocator_size - size2;
	real_size1 = size1/FIXED_UNIT_SIZE*UNIT_SIZE+size1%FIXED_UNIT_SIZE;
#if defined(__sparc) || defined(sparc) || defined(__sparcv9)
	/* Allow for aligned access requirements */
	if (size1%FIXED_UNIT_SIZE != 0) {
		real_size1 += UNIT_SIZE - size1%FIXED_UNIT_SIZE;
	}
#endif
	sub_alloc->hi_unit = sub_alloc->heap_start + sub_alloc->sub_allocator_size;
	sub_alloc->lo_unit = sub_alloc->units_start = sub_alloc->heap_start + real_size1;
	sub_alloc->fake_units_start = sub_alloc->heap_start + size1;
	sub_alloc->hi_unit = sub_alloc->lo_unit + real_size2;

	for (i=0,k=1; i < N1 ; i++, k+=1) {
		sub_alloc->indx2units[i] = k;
	}
	for (k++; i < N1+N2 ; i++, k+=2) {
		sub_alloc->indx2units[i] = k;
	}
	for (k++; i < N1+N2+N3 ; i++, k+=3) {
		sub_alloc->indx2units[i] = k;
	}
	for (k++; i < N1+N2+N3+N4 ; i++, k+=4) {
		sub_alloc->indx2units[i] = k;
	}

	for (sub_alloc->glue_count=k=i=0; k < 128; k++) {
		i += (sub_alloc->indx2units[i] < k+1);
		sub_alloc->units2indx[k] = i;
	}
}

static void rar_mem_blk_insertAt(rar_mem_blk_t *a, rar_mem_blk_t *p)
{
	a->next = (a->prev=p)->next;
	p->next = a->next->prev = a;
}

static void rar_mem_blk_remove(rar_mem_blk_t *a)
{
	a->prev->next = a->next;
	a->next->prev = a->prev;
}

static void sub_allocator_glue_free_blocks(sub_allocator_t *sub_alloc)
{
	rar_mem_blk_t s0, *p, *p1;
	int i, k, sz;

	if (sub_alloc->lo_unit != sub_alloc->hi_unit) {
		*sub_alloc->lo_unit = 0;
	}
	for (i=0, s0.next=s0.prev=&s0; i < N_INDEXES; i++) {
		while (sub_alloc->free_list[i].next) {
			p = (rar_mem_blk_t *) sub_allocator_remove_node(sub_alloc, i);
			rar_mem_blk_insertAt(p, &s0);
			p->stamp = 0xFFFF;
			p->nu = sub_alloc->indx2units[i];
		}
	}

	for (p=s0.next ; p != &s0 ; p=p->next) {
		while ((p1 = sub_allocator_mbptr(p,p->nu))->stamp == 0xFFFF &&
				((int)p->nu)+p1->nu < 0x10000) {
			rar_mem_blk_remove(p1);
			p->nu += p1->nu;
		}
	}

	while ((p=s0.next) != &s0) {
		for (rar_mem_blk_remove(p), sz=p->nu; sz > 128; sz-=128, p=sub_allocator_mbptr(p, 128)) {
			sub_allocator_insert_node(sub_alloc, p, N_INDEXES-1);
		}
		if (sub_alloc->indx2units[i=sub_alloc->units2indx[sz-1]] != sz) {
			k = sz-sub_alloc->indx2units[--i];
			sub_allocator_insert_node(sub_alloc, sub_allocator_mbptr(p,sz-k), k-1);
		}
		sub_allocator_insert_node(sub_alloc, p, i);
	}
}

static void *sub_allocator_alloc_units_rare(sub_allocator_t *sub_alloc, int indx)
{
	int i, j;
	void *ret_val;

	if (!sub_alloc->glue_count) {
		sub_alloc->glue_count = 255;
		sub_allocator_glue_free_blocks(sub_alloc);
		if (sub_alloc->free_list[indx].next) {
			return sub_allocator_remove_node(sub_alloc, indx);
		}
	}
	i=indx;
	do {
		if (++i == N_INDEXES) {
			sub_alloc->glue_count--;
			i = sub_allocator_u2b(sub_alloc->indx2units[indx]);
			j = 12 * sub_alloc->indx2units[indx];
			if (sub_alloc->fake_units_start - sub_alloc->ptext > j) {
				sub_alloc->fake_units_start -= j;
				sub_alloc->units_start -= i;
				return sub_alloc->units_start;
			}
			return NULL;
		}
	} while ( !sub_alloc->free_list[i].next);
	ret_val = sub_allocator_remove_node(sub_alloc, i);
	sub_allocator_split_block(sub_alloc, ret_val, i, indx);
	return ret_val;
}

static void *sub_allocator_alloc_units(sub_allocator_t *sub_alloc, int nu)
{
	int indx;
	void *ret_val;

	indx = sub_alloc->units2indx[nu-1];
	if (sub_alloc->free_list[indx].next) {
		return sub_allocator_remove_node(sub_alloc, indx);
	}
	ret_val = sub_alloc->lo_unit;
	sub_alloc->lo_unit += sub_allocator_u2b(sub_alloc->indx2units[indx]);
	if (sub_alloc->lo_unit <= sub_alloc->hi_unit) {
		return ret_val;
	}
	sub_alloc->lo_unit -= sub_allocator_u2b(sub_alloc->indx2units[indx]);
	return sub_allocator_alloc_units_rare(sub_alloc, indx);
}

static void *sub_allocator_alloc_context(sub_allocator_t *sub_alloc)
{
	if (sub_alloc->hi_unit != sub_alloc->lo_unit) {
		return (sub_alloc->hi_unit -= UNIT_SIZE);
	}
	if (sub_alloc->free_list->next) {
		return sub_allocator_remove_node(sub_alloc, 0);
	}
	return sub_allocator_alloc_units_rare(sub_alloc, 0);
}

static void *sub_allocator_expand_units(sub_allocator_t *sub_alloc, void *old_ptr, int old_nu)
{
	int i0, i1;
	void *ptr;

	i0 = sub_alloc->units2indx[old_nu-1];
	i1 = sub_alloc->units2indx[old_nu];
	if (i0 == i1) {
		return old_ptr;
	}
	ptr = sub_allocator_alloc_units(sub_alloc, old_nu+1);
	if (ptr) {
		memcpy(ptr, old_ptr, sub_allocator_u2b(old_nu));
		sub_allocator_insert_node(sub_alloc, old_ptr, i0);
	}
	return ptr;
}

static void *sub_allocator_shrink_units(sub_allocator_t *sub_alloc, void *old_ptr,
			int old_nu, int new_nu)
{
	int i0, i1;
	void *ptr;

	i0 = sub_alloc->units2indx[old_nu-1];
	i1 = sub_alloc->units2indx[new_nu-1];
	if (i0 == i1) {
		return old_ptr;
	}
	if (sub_alloc->free_list[i1].next) {
		ptr = sub_allocator_remove_node(sub_alloc, i1);
		memcpy(ptr, old_ptr, sub_allocator_u2b(new_nu));
		sub_allocator_insert_node(sub_alloc, old_ptr, i0);
		return ptr;
	} else {
		sub_allocator_split_block(sub_alloc, old_ptr, i0, i1);
		return old_ptr;
	}
}

static void  sub_allocator_free_units(sub_allocator_t *sub_alloc, void *ptr, int old_nu)
{
	sub_allocator_insert_node(sub_alloc, ptr, sub_alloc->units2indx[old_nu-1]);
}

/************** End of Allocator code block *********************/

/************** Start of Range Coder code block *********************/
static void range_coder_init_decoder(range_coder_t *coder, const unsigned char **fd,
			unpack_data_t *unpack_data)
{
	int i;
	coder->low = coder->code = 0;
	coder->range = (unsigned int) -1;

	for (i=0; i < 4 ; i++) {
		coder->code = (coder->code << 8) | rar_get_char(fd, unpack_data);
	}
}

static int coder_get_current_count(range_coder_t *coder)
{
	return (coder->code - coder->low) / (coder->range /= coder->scale);
}

static unsigned int  coder_get_current_shift_count(range_coder_t *coder, unsigned int shift)
{
	return (coder->code - coder->low) / (coder->range >>= shift);
}

#define ARI_DEC_NORMALISE(fd, unpack_data, code, low, range)					\
{												\
	while ((low^(low+range)) < TOP || (range < BOT && ((range=-low&(BOT-1)),1))) {		\
		code = (code << 8) | rar_get_char(fd, unpack_data);				\
		range <<= 8;									\
		low <<= 8;									\
	}											\
}

static void coder_decode(range_coder_t *coder)
{
	coder->low += coder->range * coder->low_count;
	coder->range *= coder->high_count - coder->low_count;
}

/******(******** End of Range Coder code block ***********(**********/

static void see2_init(struct see2_context_tag *see2_cont, int init_val)
{
	see2_cont->summ = init_val << (see2_cont->shift=PERIOD_BITS-4);
	see2_cont->count = 4;
}

static unsigned int get_mean(struct see2_context_tag *see2_cont)
{
	unsigned int ret_val;

	ret_val = see2_cont->summ >> see2_cont->shift;
	see2_cont->summ -= ret_val;
	return ret_val + (ret_val == 0);
}

static void update(struct see2_context_tag *see2_cont)
{
	if (see2_cont->shift < PERIOD_BITS && --see2_cont->count == 0) {
		see2_cont->summ += see2_cont->summ;
		see2_cont->count = 3 << see2_cont->shift++;
	}
}

static int restart_model_rare(ppm_data_t *ppm_data)
{
	int i, k, m;
	static const unsigned short init_bin_esc[] = {
		0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051
	};
	//rar_dbgmsg("in restart_model_rare\n");
	memset(ppm_data->char_mask, 0, sizeof(ppm_data->char_mask));

	sub_allocator_init_sub_allocator(&ppm_data->sub_alloc);

	ppm_data->init_rl=-(ppm_data->max_order < 12 ? ppm_data->max_order:12)-1;
	ppm_data->min_context = ppm_data->max_context =
		(struct ppm_context *) sub_allocator_alloc_context(&ppm_data->sub_alloc);
	if (!ppm_data->min_context) {
	    //rar_dbgmsg("unrar: restart_model_rare: sub_allocator_alloc_context failed\n");
	    return 0;
	}
	ppm_data->min_context->suffix = NULL;
	ppm_data->order_fall = ppm_data->max_order;
	ppm_data->min_context->con_ut.u.summ_freq = (ppm_data->min_context->num_stats=256)+1;
	ppm_data->found_state = ppm_data->min_context->con_ut.u.stats=
		(struct state_tag *)sub_allocator_alloc_units(&ppm_data->sub_alloc, 256/2);
	if (!ppm_data->found_state) {
	    //rar_dbgmsg("unrar: restart_model_rare: sub_allocator_alloc_units failed\n");
	    return 0;
	}
	for (ppm_data->run_length = ppm_data->init_rl, ppm_data->prev_success=i=0; i < 256 ; i++) {
		ppm_data->min_context->con_ut.u.stats[i].symbol = i;
		ppm_data->min_context->con_ut.u.stats[i].freq = 1;
		ppm_data->min_context->con_ut.u.stats[i].successor = NULL;
	}

	for (i=0 ; i < 128 ; i++) {
		for (k=0 ; k < 8 ; k++) {
			for (m=0 ; m < 64 ; m+=8) {
				ppm_data->bin_summ[i][k+m]=BIN_SCALE-init_bin_esc[k]/(i+2);
			}
		}
	}
	for (i=0; i < 25; i++) {
		for (k=0 ; k < 16 ; k++) {
			see2_init(&ppm_data->see2cont[i][k], 5*i+10);
		}
	}

	return 1;
}

static int start_model_rare(ppm_data_t *ppm_data, int max_order)
{
	int i, k, m, step;

	ppm_data->esc_count = 1;
	ppm_data->max_order = max_order;

	if (!restart_model_rare(ppm_data)) {
	    //rar_dbgmsg("unrar: start_model_rare: restart_model_rare failed\n");
	    return 0;
	}

	ppm_data->ns2bsindx[0] = 2*0;
	ppm_data->ns2bsindx[1] = 2*1;

	memset(ppm_data->ns2bsindx+2, 2*2, 9);
	memset(ppm_data->ns2bsindx+11, 2*3, 256-11);

	for (i=0 ; i < 3; i++) {
		ppm_data->ns2indx[i] = i;
	}
	for (m=i, k=step=1; i < 256; i++) {
		ppm_data->ns2indx[i]=m;
		if (!--k) {
			k = ++step;
			m++;
		}
	}
	memset(ppm_data->hb2flag, 0, 0x40);
	memset(ppm_data->hb2flag+0x40, 0x08, 0x100-0x40);
	ppm_data->dummy_sse2cont.shift = PERIOD_BITS;
	return 1;
}


/* ****************** PPM Code ***************/

static void ppmd_swap(struct state_tag *p0, struct state_tag *p1)
{
	struct state_tag tmp;

	tmp = *p0;
	*p0 = *p1;
	*p1 = tmp;
}

static void rescale(ppm_data_t *ppm_data, struct ppm_context *context)
{
	int old_ns, i, adder, esc_freq, n0, n1;
	struct state_tag *p1, *p;

	//rar_dbgmsg("in rescale\n");
	old_ns = context->num_stats;
	i = context->num_stats-1;

	for (p=ppm_data->found_state ; p != context->con_ut.u.stats ; p--) {
		ppmd_swap(&p[0], &p[-1]);
	}
	context->con_ut.u.stats->freq += 4;
	context->con_ut.u.summ_freq += 4;
	esc_freq = context->con_ut.u.summ_freq - p->freq;
	adder = (ppm_data->order_fall != 0);
	context->con_ut.u.summ_freq = (p->freq = (p->freq+adder) >> 1);
	do {
		esc_freq -= (++p)->freq;
		context->con_ut.u.summ_freq += (p->freq = (p->freq + adder) >> 1);
		if (p[0].freq > p[-1].freq) {
			struct state_tag tmp = *(p1=p);
			do {
				p1[0] = p1[-1];
			} while (--p1 != context->con_ut.u.stats && tmp.freq > p1[-1].freq);
			*p1 = tmp;
		}
	} while (--i);

	if (p->freq == 0) {
		do {
			i++;
		} while ((--p)->freq == 0);
		esc_freq += i;
		if ((context->num_stats -= i) == 1) {
			struct state_tag tmp = *context->con_ut.u.stats;
			do {
				tmp.freq -= (tmp.freq >> 1);
				esc_freq >>= 1;
			} while (esc_freq > 1);
			sub_allocator_free_units(&ppm_data->sub_alloc,
					context->con_ut.u.stats, (old_ns+1)>>1);
			*(ppm_data->found_state=&context->con_ut.one_state)=tmp;
			return;
		}
	}
	context->con_ut.u.summ_freq += (esc_freq -= (esc_freq >> 1));
	n0 = (old_ns+1) >> 1;
	n1 = (context->num_stats+1) >> 1;
	if (n0 != n1) {
		context->con_ut.u.stats = (struct state_tag *) sub_allocator_shrink_units(&ppm_data->sub_alloc,
						context->con_ut.u.stats, n0, n1);
	}
	ppm_data->found_state = context->con_ut.u.stats;
}

static struct ppm_context *create_child(ppm_data_t *ppm_data, struct ppm_context *context,
				struct state_tag *pstats, struct state_tag *first_state)
{
	struct ppm_context *pc;
	//rar_dbgmsg("in create_child\n");
	pc = (struct ppm_context *) sub_allocator_alloc_context(&ppm_data->sub_alloc);
	if (pc) {
		pc->num_stats = 1;
		pc->con_ut.one_state = *first_state;
		pc->suffix = context;
		pstats->successor = pc;
	}
	return pc;
}

static struct ppm_context *create_successors(ppm_data_t *ppm_data,
			int skip, struct state_tag *p1)
{
	struct state_tag up_state;
	struct ppm_context *pc, *up_branch;
	struct state_tag *p, *ps[MAX_O], **pps;
	unsigned int cf, s0;

	//rar_dbgmsg("in create_successors\n");
	pc = ppm_data->min_context;
	up_branch = ppm_data->found_state->successor;
	pps = ps;

	if (!skip) {
		*pps++ = ppm_data->found_state;
		if (!pc->suffix) {
			goto NO_LOOP;
		}
	}
	if (p1) {
		p = p1;
		pc = pc->suffix;
		goto LOOP_ENTRY;
	}
	do {
		pc = pc->suffix;
		if (pc->num_stats != 1) {
			if ((p=pc->con_ut.u.stats)->symbol != ppm_data->found_state->symbol) {
				do {
					p++;
				} while (p->symbol != ppm_data->found_state->symbol);
			}
		} else {
			p = &(pc->con_ut.one_state);
		}
LOOP_ENTRY:
		if (p->successor != up_branch) {
			pc = p->successor;
			break;
		}
		*pps++ = p;
	} while (pc->suffix);
NO_LOOP:
	if (pps == ps) {
		return pc;
	}
	up_state.symbol= *(unsigned char *) up_branch;
	up_state.successor = (struct ppm_context *) (((unsigned char *) up_branch)+1);
	if (pc->num_stats != 1) {
		if ((unsigned char *) pc <= ppm_data->sub_alloc.ptext) {
			return NULL;
		}
		if ((p=pc->con_ut.u.stats)->symbol != up_state.symbol) {
			do {
				p++;
				if ((void *)p > (void *) ppm_data->sub_alloc.heap_end) {
					return NULL;
				}
			} while (p->symbol != up_state.symbol);
		}
		cf = p->freq - 1;
		s0 = pc->con_ut.u.summ_freq - pc->num_stats - cf;
		up_state.freq = 1 + ((2*cf <= s0)?(5*cf > s0):((2*cf+3*s0-1)/(2*s0)));
	} else {
		up_state.freq = pc->con_ut.one_state.freq;
	}
	do {
		pc = create_child(ppm_data, pc, *--pps, &up_state);
		if (!pc) {
			//rar_dbgmsg("create_child failed\n");
			return NULL;
		}
	} while (pps != ps);
	return pc;
}

static int update_model(ppm_data_t *ppm_data)
{
	struct state_tag fs, *p;
	struct ppm_context *pc, *successor;
	unsigned int ns1, ns, cf, sf, s0;

	//rar_dbgmsg("in update_model\n");
	fs = *ppm_data->found_state;
	p = NULL;

	if (fs.freq < MAX_FREQ/4 && (pc=ppm_data->min_context->suffix) != NULL) {
		if (pc->num_stats != 1) {
			if ((p=pc->con_ut.u.stats)->symbol != fs.symbol) {
				do {
					p++;
				} while (p->symbol != fs.symbol);
				if (p[0].freq >= p[-1].freq) {
					ppmd_swap(&p[0], &p[-1]);
					p--;
				}
			}
			if (p->freq < MAX_FREQ-9) {
				p->freq += 2;
				pc->con_ut.u.summ_freq += 2;
			}
		} else {
			p = &(pc->con_ut.one_state);
			p->freq += (p->freq < 32);
		}
	}
	if (!ppm_data->order_fall) {
		ppm_data->min_context = ppm_data->max_context =
			ppm_data->found_state->successor = create_successors(ppm_data, 1, p);
		if (!ppm_data->min_context) {
			goto RESTART_MODEL;
		}
		return 1;
	}
	*ppm_data->sub_alloc.ptext++ = fs.symbol;
	successor = (struct ppm_context *) ppm_data->sub_alloc.ptext;
	if (ppm_data->sub_alloc.ptext >= ppm_data->sub_alloc.fake_units_start) {
		goto RESTART_MODEL;
	}
	if (fs.successor) {
		if ((unsigned char *)fs.successor <= ppm_data->sub_alloc.ptext &&
				(fs.successor = create_successors(ppm_data, 0, p)) == NULL) {
			goto RESTART_MODEL;
		}
		if (!--ppm_data->order_fall) {
			successor = fs.successor;
			ppm_data->sub_alloc.ptext -= (ppm_data->max_context != ppm_data->min_context);
		}
	} else {
		ppm_data->found_state->successor = successor;
		fs.successor = ppm_data->min_context;
	}
	s0 = ppm_data->min_context->con_ut.u.summ_freq-(ns=ppm_data->min_context->num_stats)-(fs.freq-1);
	for (pc=ppm_data->max_context; pc != ppm_data->min_context ; pc=pc->suffix) {
		if ((ns1=pc->num_stats) != 1) {
			if ((ns1 & 1) == 0) {
				pc->con_ut.u.stats = (struct state_tag *)
					sub_allocator_expand_units(&ppm_data->sub_alloc,
								pc->con_ut.u.stats, ns1>>1);
				if (!pc->con_ut.u.stats) {
					goto RESTART_MODEL;
				}
			}
			pc->con_ut.u.summ_freq += (2*ns1 < ns)+2*((4*ns1 <= ns) & (pc->con_ut.u.summ_freq <= 8*ns1));
		} else {
			p = (struct state_tag *) sub_allocator_alloc_units(&ppm_data->sub_alloc, 1);
			if (!p) {
				goto RESTART_MODEL;
			}
			*p = pc->con_ut.one_state;
			pc->con_ut.u.stats = p;
			if (p->freq < MAX_FREQ/4-1) {
				p->freq += p->freq;
			} else {
				p->freq = MAX_FREQ - 4;
			}
			pc->con_ut.u.summ_freq = p->freq + ppm_data->init_esc + (ns > 3);
		}
		cf = 2*fs.freq*(pc->con_ut.u.summ_freq+6);
		sf = s0 + pc->con_ut.u.summ_freq;
		if (cf < 6*sf) {
			cf = 1 + (cf > sf) + (cf >= 4*sf);
			pc->con_ut.u.summ_freq += 3;
		} else {
			cf = 4 + (cf >= 9*sf) + (cf >= 12*sf) + (cf >= 15*sf);
			pc->con_ut.u.summ_freq += cf;
		}
		p = pc->con_ut.u.stats + ns1;
		p->successor = successor;
		p->symbol = fs.symbol;
		p->freq = cf;
		pc->num_stats = ++ns1;
	}
	ppm_data->max_context = ppm_data->min_context = fs.successor;
	return 1;

RESTART_MODEL:
	if (!restart_model_rare(ppm_data)) {
	    //rar_dbgmsg("unrar: update_model: restart_model_rare: failed\n");
	    return 0;
	}
	ppm_data->esc_count = 0;
	return 1;
}

static void update1(ppm_data_t *ppm_data, struct state_tag *p, struct ppm_context *context)
{
	//rar_dbgmsg("in update1\n");
	(ppm_data->found_state=p)->freq += 4;
	context->con_ut.u.summ_freq += 4;
	if (p[0].freq > p[-1].freq) {
		ppmd_swap(&p[0], &p[-1]);
		ppm_data->found_state = --p;
		if (p->freq > MAX_FREQ) {
			rescale(ppm_data, context);
		}
	}
}

static int ppm_decode_symbol1(ppm_data_t *ppm_data, struct ppm_context *context)
{
	struct state_tag *p;
	int i, hi_cnt, count;

	//rar_dbgmsg("in ppm_decode_symbol1\n");
	ppm_data->coder.scale = context->con_ut.u.summ_freq;
	p = context->con_ut.u.stats;
	count = coder_get_current_count(&ppm_data->coder);
	if (count >= ppm_data->coder.scale) {
		return 0;
	}
	if (count < (hi_cnt = p->freq)) {
		ppm_data->prev_success = (2 * (ppm_data->coder.high_count=hi_cnt) >
						ppm_data->coder.scale);
		ppm_data->run_length += ppm_data->prev_success;
		(ppm_data->found_state=p)->freq=(hi_cnt += 4);
		context->con_ut.u.summ_freq += 4;
		if (hi_cnt > MAX_FREQ) {
			rescale(ppm_data, context);
		}
		ppm_data->coder.low_count = 0;
		return 1;
	} else if (ppm_data->found_state == NULL) {
		return 0;
	}
	ppm_data->prev_success = 0;
	i = context->num_stats-1;
	while ((hi_cnt += (++p)->freq) <= count) {
		if (--i == 0) {
			ppm_data->hi_bits_flag = ppm_data->hb2flag[ppm_data->found_state->symbol];
			ppm_data->coder.low_count = hi_cnt;
			ppm_data->char_mask[p->symbol] = ppm_data->esc_count;
			i = (ppm_data->num_masked=context->num_stats) - 1;
			ppm_data->found_state = NULL;
			do {
				ppm_data->char_mask[(--p)->symbol] = ppm_data->esc_count;
			} while (--i);
			ppm_data->coder.high_count = ppm_data->coder.scale;
			return 1;
		}
	}
	ppm_data->coder.low_count = (ppm_data->coder.high_count = hi_cnt) - p->freq;
	update1(ppm_data, p, context);
	return 1;
}

static const unsigned char ExpEscape[16]={ 25,14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
#define GET_MEAN(SUMM,SHIFT,ROUND) ((SUMM+(1 << (SHIFT-ROUND))) >> (SHIFT))

static void ppm_decode_bin_symbol(ppm_data_t *ppm_data, struct ppm_context *context)
{
	struct state_tag *rs;
	unsigned short *bs;

	//rar_dbgmsg("in ppm_decode_bin_symbol\n");

	rs = &context->con_ut.one_state;

	ppm_data->hi_bits_flag = ppm_data->hb2flag[ppm_data->found_state->symbol];
	bs = &ppm_data->bin_summ[rs->freq-1][ppm_data->prev_success +
		ppm_data->ns2bsindx[context->suffix->num_stats-1] +
		ppm_data->hi_bits_flag+2*ppm_data->hb2flag[rs->symbol] +
		((ppm_data->run_length >> 26) & 0x20)];
	if (coder_get_current_shift_count(&ppm_data->coder, TOT_BITS) < *bs) {
		ppm_data->found_state = rs;
		rs->freq += (rs->freq < 128);
		ppm_data->coder.low_count = 0;
		ppm_data->coder.high_count = *bs;
		*bs = (unsigned short) (*bs + INTERVAL - GET_MEAN(*bs, PERIOD_BITS, 2));
		ppm_data->prev_success = 1;
		ppm_data->run_length++;
	} else {
		ppm_data->coder.low_count = *bs;
		*bs = (unsigned short) (*bs - GET_MEAN(*bs, PERIOD_BITS, 2));
		ppm_data->coder.high_count = BIN_SCALE;
		ppm_data->init_esc = ExpEscape[*bs >> 10];
		ppm_data->num_masked = 1;
		ppm_data->char_mask[rs->symbol] = ppm_data->esc_count;
		ppm_data->prev_success = 0;
		ppm_data->found_state = NULL;
	}
}

static void update2(ppm_data_t *ppm_data, struct state_tag *p, struct ppm_context *context)
{
	//rar_dbgmsg("in update2\n");
	(ppm_data->found_state = p)->freq += 4;
	context->con_ut.u.summ_freq += 4;
	if (p->freq > MAX_FREQ) {
		rescale(ppm_data, context);
	}
	ppm_data->esc_count++;
	ppm_data->run_length = ppm_data->init_rl;
}

static struct see2_context_tag *make_esc_freq(ppm_data_t *ppm_data,
			struct ppm_context *context, int diff)
{
	struct see2_context_tag *psee2c;

	if (context->num_stats != 256) {
		psee2c = ppm_data->see2cont[ppm_data->ns2indx[diff-1]] +
			(diff < context->suffix->num_stats-context->num_stats) +
			2 * (context->con_ut.u.summ_freq < 11*context->num_stats)+4*
			(ppm_data->num_masked > diff) +	ppm_data->hi_bits_flag;
		ppm_data->coder.scale = get_mean(psee2c);
	} else {
		psee2c = &ppm_data->dummy_sse2cont;
		ppm_data->coder.scale = 1;
	}
	return psee2c;
}

static int ppm_decode_symbol2(ppm_data_t *ppm_data, struct ppm_context *context)
{
	int count, hi_cnt, i;
	struct see2_context_tag *psee2c;
	struct state_tag *ps[256], **pps, *p;

	//rar_dbgmsg("in ppm_decode_symbol2\n");
	i = context->num_stats - ppm_data->num_masked;
	psee2c = make_esc_freq(ppm_data, context, i);
	pps = ps;
	p = context->con_ut.u.stats - 1;
	hi_cnt = 0;

	do {
		do {
			p++;
		} while (ppm_data->char_mask[p->symbol] == ppm_data->esc_count);
		hi_cnt += p->freq;
		*pps++ = p;
	} while (--i);
	ppm_data->coder.scale += hi_cnt;
	count = coder_get_current_count(&ppm_data->coder);
	if (count >= ppm_data->coder.scale) {
		return 0;
	}
	p=*(pps=ps);
	if (count < hi_cnt) {
		hi_cnt = 0;
		while ((hi_cnt += p->freq) <= count) {
			p=*++pps;
		}
		ppm_data->coder.low_count = (ppm_data->coder.high_count=hi_cnt) - p->freq;
		update(psee2c);
		update2(ppm_data, p, context);
	} else {
		ppm_data->coder.low_count = hi_cnt;
		ppm_data->coder.high_count = ppm_data->coder.scale;
		i = context->num_stats - ppm_data->num_masked;
		pps--;
		do {
			ppm_data->char_mask[(*++pps)->symbol] = ppm_data->esc_count;
		} while (--i);
		psee2c->summ += ppm_data->coder.scale;
		ppm_data->num_masked = context->num_stats;
	}
	return 1;
}

static void clear_mask(ppm_data_t *ppm_data)
{
	ppm_data->esc_count = 1;
	memset(ppm_data->char_mask, 0, sizeof(ppm_data->char_mask));
}

void ppm_constructor(ppm_data_t *ppm_data)
{
	sub_allocator_init(&ppm_data->sub_alloc);
	ppm_data->min_context = NULL;
	ppm_data->max_context = NULL;
}

void ppm_destructor(ppm_data_t *ppm_data)
{
	sub_allocator_stop_sub_allocator(&ppm_data->sub_alloc);
}

void ppm_cleanup(ppm_data_t *ppm_data)
{
	sub_allocator_stop_sub_allocator(&ppm_data->sub_alloc);
	sub_allocator_start_sub_allocator(&ppm_data->sub_alloc, 1);
	start_model_rare(ppm_data, 2);     // This line HANGS the compiler on sparc
}

int ppm_decode_init(ppm_data_t *ppm_data, const unsigned char **fd, unpack_data_t *unpack_data, int *EscChar)
{
	int max_order, Reset, MaxMB = 0;

	max_order = rar_get_char(fd, unpack_data);
	//rar_dbgmsg("ppm_decode_init max_order=%d\n", max_order);
	Reset = (max_order & 0x20) ? 1 : 0;
	//rar_dbgmsg("ppm_decode_init Reset=%d\n", Reset);
	if (Reset) {
		MaxMB = rar_get_char(fd, unpack_data);
		//rar_dbgmsg("ppm_decode_init MaxMB=%d\n", MaxMB);
		if (MaxMB > 128) {
			//rar_dbgmsg("MaxMB > 128 MB (%d, 0x%02x) reject\n", MaxMB, MaxMB);
			return 0;
		}
	} else {
		if (sub_allocator_get_allocated_memory(&ppm_data->sub_alloc) == 0) {
			return 0;
		}
	}
	if (max_order & 0x40) {
		*EscChar = rar_get_char(fd, unpack_data);
		//rar_dbgmsg("ppm_decode_init EscChar=%d\n", *EscChar);
	}
	range_coder_init_decoder(&ppm_data->coder, fd, unpack_data);
	if (Reset) {
		max_order = (max_order & 0x1f) + 1;
		if (max_order > 16) {
			max_order = 16 + (max_order - 16) * 3;
		}
		if (max_order == 1) {
			sub_allocator_stop_sub_allocator(&ppm_data->sub_alloc);
			return 0;
		}
		if (!sub_allocator_start_sub_allocator(&ppm_data->sub_alloc, MaxMB+1)) {
		    sub_allocator_stop_sub_allocator(&ppm_data->sub_alloc);
		    return 0;
		}
		if (!start_model_rare(ppm_data, max_order)) {      // This line HANGS the compiler on sparc
		    sub_allocator_stop_sub_allocator(&ppm_data->sub_alloc);
		    return 0;
		}
	}
	//rar_dbgmsg("ppm_decode_init done: %d\n", ppm_data->min_context != NULL);
	return (ppm_data->min_context != NULL);
}

int ppm_decode_char(ppm_data_t *ppm_data, const unsigned char **fd, unpack_data_t *unpack_data)
{
	int symbol;

	if ((unsigned char *) ppm_data->min_context <= ppm_data->sub_alloc.ptext ||
			(unsigned char *)ppm_data->min_context > ppm_data->sub_alloc.heap_end) {
		return -1;
	}
	if (ppm_data->min_context->num_stats != 1) {
		if ((unsigned char *) ppm_data->min_context->con_ut.u.stats <= ppm_data->sub_alloc.ptext ||
			(unsigned char *) ppm_data->min_context->con_ut.u.stats > ppm_data->sub_alloc.heap_end) {
			return -1;
		}
		if (!ppm_decode_symbol1(ppm_data, ppm_data->min_context)) {
			return -1;
		}
	} else {
		ppm_decode_bin_symbol(ppm_data, ppm_data->min_context);
	}
	coder_decode(&ppm_data->coder);

	while (!ppm_data->found_state) {
		ARI_DEC_NORMALISE(fd, unpack_data, ppm_data->coder.code,
				ppm_data->coder.low, ppm_data->coder.range);
		do {
			ppm_data->order_fall++;
			ppm_data->min_context = ppm_data->min_context->suffix;
			if ((unsigned char *)ppm_data->min_context <= ppm_data->sub_alloc.ptext ||
					(unsigned char *)ppm_data->min_context >
					ppm_data->sub_alloc.heap_end) {
				return -1;
			}
		} while (ppm_data->min_context->num_stats == ppm_data->num_masked);
		if (!ppm_decode_symbol2(ppm_data, ppm_data->min_context)) {
			return -1;
		}
		coder_decode(&ppm_data->coder);
	}

	symbol = ppm_data->found_state->symbol;
	if (!ppm_data->order_fall && (unsigned char *) ppm_data->found_state->successor > ppm_data->sub_alloc.ptext) {
		ppm_data->min_context = ppm_data->max_context = ppm_data->found_state->successor;
	} else {

		if (!update_model(ppm_data)) {   // This line HANGS the compiler on sparc
		    //rar_dbgmsg("unrar: ppm_decode_char: update_model failed\n");
		    return -1;
		}

		if (ppm_data->esc_count == 0) {
			clear_mask(ppm_data);
		}
	}
	ARI_DEC_NORMALISE(fd, unpack_data, ppm_data->coder.code, ppm_data->coder.low, ppm_data->coder.range);
	return symbol;
}
