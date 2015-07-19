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
 *
 * This is a 'library' where optimized formats can be placed. This will
 * allow hashes which are more optimal than the current parser/compiler
 * can generate.
 */

#include "arch.h"

#ifndef DYNAMIC_DISABLED
#include "formats.h"
#include "dynamic.h"
#include "dynamic_compiler.h"

#include "memdbg.h"

/* typedef struct DC_struct {
	uint32_t magic;
	uint32_t crc32; // hash of pExpr
	struct fmt_main *pFmt;
	char *pExpr;
	char *pExtraParams;
	char *pScript;
	char *pSignature;
	char *pLine1;
	char *pLine2;
	char *pLine3;
} DC_struct;
*/
typedef struct LIB_struct {
	int nlegacy_types;
	int legacy_types[10];
	DC_struct code;
}LIB_struct;

static LIB_struct lib[] = {
	// might want to add a extra param of ,MaxInputLen=55 ??
	{ 1, {0}, {DC_MAGIC, 0x09ABB6B4, NULL, "dynamic=md5($p)", "", "Expression=dynamic=md5($p)\nFlag=MGF_KEYS_INPUT\nFunc=DynamicFunc__crypt_md5\nMaxInputLenX86=110\nMaxInputLen=55\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc\nTest=@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785:john\nTest=@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb:passweird", "@dynamic=md5($p)@", "@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72", "@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785","@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb"} },
	{ 0, {0}, {0} }
};

char *copy_str(const char *_p) {
	char *p;
	if (!_p)
		return mem_calloc(1,1);		
	p = mem_alloc(strlen(_p)+1);
	strcpy(p,_p);
	return p;
}

static DC_HANDLE deep_copy(int idx) {
	//DC_struct *p = (DC_struct*)mem_calloc(1, sizeof(DC_struct));
	//p->crc32 = lib[idx].code.crc32;
	//p->pFmt = lib[idx].code.pFmt;
	//p->magic = DC_MAGIC;
	//p->pExpr = copy_str(lib[idx].code.pExpr);
	//p->pExtraParams = copy_str(lib[idx].code.pExtraParams);
	//p->pLine1 = copy_str(lib[idx].code.pLine1);
	//p->pLine2 = copy_str(lib[idx].code.pLine2);
	//p->pLine3 = copy_str(lib[idx].code.pLine3);
	//p->pScript = copy_str(lib[idx].code.pScript);
	//p->pSignature = copy_str(lib[idx].code.pSignature);
	//return (DC_HANDLE)p;
	return (DC_HANDLE)&(lib[idx].code);
}

DC_HANDLE dynamic_compile_library(const char *expr, uint32_t crc32) {
	int i = 0;
	while (lib[i].code.magic == DC_MAGIC) {
		if (crc32 == lib[i].code.crc32)
			return deep_copy(i);
		++i;
	}
	return NULL;
}

#endif /* DYNAMIC_DISABLED */
