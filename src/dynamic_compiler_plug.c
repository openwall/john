/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Expression to Generic 'scriptable' compiler/builder for the
 * existing dynamic format.
 */


#include "arch.h"
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "list.h"
#include "crc32.h"
#include "dynamic_compiler.h"

typedef struct DC_list {
	struct DC_list *next;
	DC_struct *value;
} DC_list;

static DC_list *pList;
static DC_struct *pLastFind;

static uint32_t compute_checksum(const char *expr);
static DC_HANDLE find_checksum(uint32_t crc32);
static DC_HANDLE do_compile(const char *expr, uint32_t crc32);
static void add_checksum_list(DC_HANDLE pHand);

int dynamic_compile(const char *expr, DC_HANDLE *p) {
	uint32_t crc32 = compute_checksum(expr);
	DC_HANDLE pHand;
	if (pLastFind && pLastFind->crc32 == crc32) {
		*p = (DC_HANDLE)pLastFind;
		return 0;
	}

	pHand = find_checksum(crc32);
	if (pHand) {
		*p = pHand;
		pLastFind = (DC_struct*)pHand;
		return 0;
	}
	/* this is the real 'workhorse' function */
	pHand = do_compile(expr, crc32);
	if (!pHand)
		return 1;
	add_checksum_list(pHand);
	*p = pHand;
	return 0;
}

int dynamic_load(DC_HANDLE p) {
	return 0;
}

int dynamic_print_script(DC_HANDLE p) {
	return 0;
}

static DC_HANDLE do_compile(const char *expr, uint32_t crc32) {
	DC_struct *p;
	p = mem_calloc(sizeof(DC_struct), sizeof(void*));
	p->magic = DC_MAGIC;
	p->crc32 = crc32;
	p->pFmt = NULL; // not setup yet
	p->pExpr = expr;

	if (!strcmp(expr, "@dynamic=sha1($p)@")) {
		p->pScript = "Expression=sha1($p)\nFlag=MGF_KEYS_INPUT\nFlag=MGF_FLAT_BUFFERS\nFlag=MGF_INPUT_20_BYTE\nFunc=DynamicFunc__SHA1_crypt_input1_to_output1_FINAL\nTest=@dynamic=sha1($p)@a9993e364706816aba3e25717850c26c9cd0d89d:abc";
		p->pSignature = "@dynamic=sha1($p)@";
		p->pOneLine = "@dynamic=sha1($p)@a9993e364706816aba3e25717850c26c9cd0d89d";

	} else if (!strcmp(expr, "@dynamic=md5($p)@")) {
		p->pScript = "Expression=md5($p)\nFlag=MGF_KEYS_INPUT\nFlag=MGF_FLAT_BUFFERS\nFunc=DynamicFunc__MD5_crypt_input1_to_output1_FINAL\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc";
		p->pSignature = "@dynamic=md5($p)@";
		p->pOneLine = "@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72";

	} else if (!strcmp(expr, "@dynamic=sha1($p.$p)@")) {
		p->pScript = "Expression=sha1($p.$p)\nFlag=MGF_FLAT_BUFFERS\nFlag=MGF_INPUT_20_BYTE\nFunc=DynamicFunc__clean_input_kwik\nFunc=DynamicFunc__append_keys\nFunc=DynamicFunc__append_keys\nFunc=DynamicFunc__SHA1_crypt_input1_to_output1_FINAL\nTest=@dynamic=sha1($p.$p)@f8c1d87006fbf7e5cc4b026c3138bc046883dc71:abc";
		p->pSignature = "@dynamic=sha1($p.$p)@";
		p->pOneLine = "@dynamic=sha1($p.$p)@f8c1d87006fbf7e5cc4b026c3138bc046883dc71";

	} else if (!strcmp(expr, "@dynamic=sha1(md5($p))@")) {
		p->pScript = "Expression=sha1(md5($p))\nFlag=MGF_KEYS_INPUT\nFlag=MGF_FLAT_BUFFERS\nFlag=MGF_INPUT_20_BYTE\nFunc=DynamicFunc__clean_input2_kwik\nFunc=DynamicFunc__MD5_crypt_input1_overwrite_input2\nFunc=DynamicFunc__SHA1_crypt_input2_to_output1_FINAL\nTest=@dynamic=sha1(md5($p))@b349e67445488ae1fad84633400057e759a46fb3:abc";
		p->pSignature = "@dynamic=sha1(md5($p))@";
		p->pOneLine = "@dynamic=sha1(md5($p))@b349e67445488ae1fad84633400057e759a46fb3";

	} else
		return 0;

	return p;
}

static uint32_t compute_checksum(const char *expr) {
	uint32_t crc32 = 0xffffffff;
	/* we should 'normalize' the expression 'first' */
	while (*expr) {
		crc32 = jtr_crc32(crc32,*expr);
		++expr;
	}
	return crc32;
}

static DC_HANDLE find_checksum(uint32_t crc32) {
	DC_list *p;
	if (!pList)
		pList = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	p = pList->next;
	while (p) {
		if (p->value->crc32 == crc32)
			return p->value;
		p = p->next;
	}
	return 0;
}

static void add_checksum_list(DC_HANDLE pHand) {
	DC_list *p;
	p = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	p->next = pList->next;
	pList->next = p;
}
