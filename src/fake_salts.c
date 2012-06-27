/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2012 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Salt finder. This will allow JtR to process a few salted type
 * hashes, if the original salt has been lost.  The only 2 types
 * done at this time, are PHPS (VB), and osCommerce. PHPS is dynamic_6
 * which is md5(md5($p).$s) with a 3 byte salt.  osCommerce is dynamic_4
 * of md5($s.$p) with a 2 type salt.
 *
 */


#include <stdio.h>
#include "memory.h"
#include "options.h"

void build_fake_salts_for_regen_lost(struct db_salt *salts) {
	if (options.regen_lost_salts == 1)  // this is for PHPS, with a raw 32 byte hash input file (i.e. missing the salts)
	{
		static struct db_salt *sp, *fake_salts;
		int i, j, k, idx=0;
		char *buf, *cp;
		unsigned long *ptr;

		if (!fake_salts)
			fake_salts = mem_calloc_tiny(sizeof(struct db_salt) * (('~'-' '+1)*('~'-' '+1)*('~'-' '+1)+1), MEM_ALIGN_WORD);

		// Find the 'real' salt. We loaded ALL of the file into 1 salt.
		// we then take THAT salt record, and build a list pointing to these fake salts, 
		// AND build 'proper' dynamic salts for all of our data.
		sp = salts;
		while (sp->next) {
			sp = sp->next;
		}

		// a dynamic salt is 030000[3-byte-salt] for ALL of the salts.
		buf = mem_alloc_tiny(('~'-' '+1)*('~'-' '+1)*('~'-' '+1)*9+1, MEM_ALIGN_NONE);
		cp = buf;
		for (i = ' '; i <= '~'; ++i) {
			for (j = ' '; j <= '~'; ++j) {
				for (k = ' '; k <= '~'; ++k) {
					sprintf(cp, "030000%c%c%c", i, j, k);
					sp->next = &fake_salts[idx];
					fake_salts[idx].next = NULL;
					fake_salts[idx].count = sp->count;
					fake_salts[idx].hash = sp->hash;
					fake_salts[idx].hash_size = sp->hash_size;
					fake_salts[idx].index = sp->index;
					fake_salts[idx].keys = sp->keys;
					fake_salts[idx].list = sp->list;
					ptr=mem_alloc_tiny(sizeof(char*), MEM_ALIGN_WORD);
					*ptr = (unsigned long) (buf + (cp-buf));
					fake_salts[idx].salt = ptr;
					++idx;
					cp += 9;
					sp = sp->next;
				}
			}
		}
	}
	else if (options.regen_lost_salts == 2)  // this is for osCommerce, with a raw 32 byte hash input file (i.e. missing the salts)
	{
		static struct db_salt *sp, *fake_salts;
		int i, j, idx=0;
		char *buf, *cp;
		unsigned long *ptr;

		if (!fake_salts)
			fake_salts = mem_calloc_tiny(sizeof(struct db_salt) * (('~'-' '+1)*('~'-' '+1)+1), MEM_ALIGN_WORD);

		// Find the 'real' salt. We loaded ALL of the file into 1 salt.
		// we then take THAT salt record, and build a list pointing to these fake salts, 
		// AND build 'proper' dynamic salts for all of our data.
		sp = salts;
		while (sp->next) {
			sp = sp->next;
		}

		// a dynamic salt is 020000[2-byte-salt] for ALL of the salts.
		buf = mem_alloc_tiny(('~'-' '+1)*('~'-' '+1)*8+1, MEM_ALIGN_NONE);
		cp = buf;
		for (i = ' '; i <= '~'; ++i) {
			for (j = ' '; j <= '~'; ++j) {
				sprintf(cp, "020000%c%c", i, j);
				sp->next = &fake_salts[idx];
				fake_salts[idx].next = NULL;
				fake_salts[idx].count = sp->count;
				fake_salts[idx].hash = sp->hash;
				fake_salts[idx].hash_size = sp->hash_size;
				fake_salts[idx].index = sp->index;
				fake_salts[idx].keys = sp->keys;
				fake_salts[idx].list = sp->list;
				ptr=mem_alloc_tiny(sizeof(char*), MEM_ALIGN_WORD);
				*ptr = (unsigned long) (buf + (cp-buf));
				fake_salts[idx].salt = ptr;
				++idx;
				cp += 8;
				sp = sp->next;
			}
		}
	}
	else if (options.regen_lost_salts >= 3 && options.regen_lost_salts <= 5)  // this is for media-wiki, with a raw 32 byte hash input file (i.e. missing the salts)
	{
		// 3 gets salts from 0- to 999-  4 salts from 1000- to 9999- 5 salts from 10000- to 99999-
		static struct db_salt *sp, *fake_salts;
		int i, idx=0;
		char *buf, *cp;
		unsigned long *ptr;
		int max, min;
		// Find the 'real' salt. We loaded ALL of the file into 1 salt.
		// we then take THAT salt record, and build a list pointing to these fake salts, 
		// AND build 'proper' dynamic salts for all of our data.
		sp = salts;
		while (sp->next) {
			sp = sp->next;
		}

		max = 1000;
		min = 0;
		switch(options.regen_lost_salts) {
			case 4:
				max = 10000;
				min = 1000;
				break;
			case 5:
				max = 100000;
				min = 10000;
				break;
		}

		fake_salts = mem_calloc_tiny( ((max-min)+1) * sizeof(struct db_salt), MEM_ALIGN_WORD);

		// for type 3, we do not use 100% of this buffer, but we do use 'most' of it. 
		buf = mem_alloc_tiny(((max-min)+1)*(7+options.regen_lost_salts), MEM_ALIGN_NONE);
		cp = buf;
		for (i = min; i < max; ++i) {
			int l;
			char *cp2 = cp;
			if (i > 9999) l = 6;
			else if (i > 999) l = 5;
			else if (i > 99) l = 4;
			else if (i > 9) l = 3;
			else l = 2;
			cp += sprintf(cp, "0%d0000%d-", l, i);
			sp->next = &fake_salts[idx];
			fake_salts[idx].next = NULL;
			fake_salts[idx].count = sp->count;
			fake_salts[idx].hash = sp->hash;
			fake_salts[idx].hash_size = sp->hash_size;
			fake_salts[idx].index = sp->index;
			fake_salts[idx].keys = sp->keys;
			fake_salts[idx].list = sp->list;
			ptr=mem_alloc_tiny(sizeof(char*), MEM_ALIGN_WORD);
			*ptr = (unsigned long) (buf + (cp2-buf));
			fake_salts[idx].salt = ptr;
			++idx;
			sp = sp->next;
		}
	}
}
