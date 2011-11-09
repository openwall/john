/* PKZIP patch for john to handle 'old' pkzip passwords (old 'native' format)
 *
 * Written by Jim Fougeron <jfoug at cox.net> in 2011.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2011 Jim Fougeron and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 */

#include <string.h>

#include "common.h"
#include "arch.h"
#include "misc.h"
#include "formats.h"
#define USE_PKZIP_MAGIC 1
#include "pkzip.h"

#include "zlib.h"
#include "pkzip_inffixed.h"  // This file is a data file, taken from zlib

#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"pkzip"
#define FORMAT_NAME				"pkzip"
#define ALGORITHM_NAME			"N/A"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1000

#define PLAINTEXT_LENGTH		31

#define BINARY_SIZE				1
#define SALT_SIZE				(sizeof(PKZ_SALT*))

#define MIN_KEYS_PER_CRYPT		1
/* max keys allows 256 words per thread on a 16 thread OMP build */
/* for non-OMP builds, we only want 64 keys */
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT		(16*256)
#else
#define MAX_KEYS_PER_CRYPT		64
#endif

//#define ZIP_DEBUG 1
//#define ZIP_DEBUG 2

/*
 * It is likely that this should be put into the arch.h files for the different systems,
 * IF we find a system which operates faster doing the non-table work.
 * However, in current testing, it is always faster to use the multiply table. It only
 * takes 16kb, and almost always stays in the cache for any system newer than a 386.
 */
#define PKZIP_USE_MULT_TABLE

#if ARCH_LITTLE_ENDIAN
#define KB1 0
#define KB2 3
#else
#define KB1 3
#define KB2 0
#endif

/*
 *  format:  filename:$pkzip$C*B*[DT*MT{CL*UL*CR*OF*OX}*CT*DL*DA]*$/pkzip$
 *
 * All numeric and 'binary data' fields are stored in hex.
 *
 * C   is the count of hashes present (the array of items, inside the []  C can be 1 to 3.).
 * B   is number of valid bytes in the checksum (1 or 2).  Unix zip is 2 bytes, all others are 1
 * ARRAY of data starts here (there will be C array elements)
 *   DT  is a "Data Type enum".  This will be 1 2 or 3.  1 is 'partial'. 2 and 3 are full file data (2 is inline, 3 is load from file).
 *   MT  Magic Type enum.  0 is no 'type'.  255 is 'text'. Other types (like MS Doc, GIF, etc), see source.
 *     NOTE, CL, DL, CRC, OFF are only present if DT != 1
 *     CL  Compressed length of file blob data (includes 12 byte IV).
 *     UL  Uncompressed length of the file.
 *     CR  CRC32 of the 'final' file.
 *     OF  Offset to the PK\x3\x4 record for this file data. If DT==2, then this will be a 0, as it is not needed, all of the data is already included in the line.
 *     OX  Additional offset (past OF), to get to the zip data within the file.
 *     END OF 'optional' fields.
 *   CT  Compression type  (0 or 8)  0 is stored, 8 is imploded.
 *   DL  Length of the DA data.
 *   DA  This is the 'data'.  It will be hex data if DT==1 or 2. If DT==3, then it is a filename (name of the .zip file).
 * END of array items.
 * The format string will end with $/pkzip$
 *
 * NOTE, after some code testing, it has come to show, that the 'magic' may not be needed, or very useful. The problem with it, is IF the file
 * ends up NOT starting with any of the magic values, then we will have a false negative, and NEVER be able to crack the zip's password. For now
 * we have a #define (right before the #include "pkzip.h").  If that define is uncommented, then pkzip format will be built with magic logic.
 * However, right now it is not being built that way.
 *
 */
static struct fmt_tests tests[] = {

	/* compression of a perl file. We have the same password, same file used twice in a row (pkzip, 1 byte checksum).  NOTE, pkzip uses random IV, so both encrypted blobs are different */
	{"\
$pkzip$1*1*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*194883130e4c7419bd735c53dec36f0c4b6de6daefea0f507d67ff7256a49b5ea93ccfd9b12f2ee99053ee0b1c9e1c2b88aeaeb6bd4e60094a1ea118785d4ded6dae94\
cade41199330f4f11b37cba7cda5d69529bdfa43e2700ba517bd2f7ff4a0d4b3d7f2559690ec044deb818c44844d6dd50adbebf02cec663ae8ebb0dde05d2abc31eaf6de36a2fc19fda65dd6a7e449f669d1f8c75e9daa0a3f7b\
e8feaa43bf84762d6dbcc9424285a93cedfa3a75dadc11e969065f94fe3991bc23c9b09eaa5318aa29fa02e83b6bee26cafec0a5e189242ac9e562c7a5ed673f599cefcd398617*$/pkzip$", "password" },
	{"\
$pkzip$1*1*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*581f798527109cbadfca0b3318435a000be84366caf9723f841a2b13e27c2ed8cdb5628705a98c3fbbfb34552ed498c51a172641bf231f9948bca304a6be2138ab718f\
6a5b1c513a2fb80c49030ff1a404f7bd04dd47c684317adea4107e5d70ce13edc356c60bebd532418e0855428f9dd582265956e39a0b446a10fd8b7ffb2b4af559351bbd549407381c0d2acc270f3bcaffb275cbe2f628cb09e2\
978e87cd023d4ccb50caaa92b6c952ba779980d65f59f664dde2451cc456d435188be59301a5df1b1b4fed6b7509196334556c44208a9d7e2d9e237f591d6c9fc467b408bf0aaa*$/pkzip$", "password" },
	/* Now the same file, compressed twice, using unix zip (info-zip), with 2 byte checksums */
	{"\
$pkzip$1*2*2*0*e4*1c5*eda7a8de*0*47*8*e4*4bb6*436c9ffa4328870f6272349b591095e1b1126420c3041744650282bc4f575d0d4a5fc5fb34724e6a1cde742192387b9ed749ab5c72cd6bb0206f102e9216538f095fb7\
73661cfde82c2e2a619332998124648bf4cd0da56279f0c297567d9b5d684125ee92920dd513fd18c27afba2a9633614f75d8f8b9a14095e3fafe8165330871287222e6681dd9c0f830cf5d464457b257d0900eed29107fad8af\
3ac4f87cf5af5183ff0516ccd9aeac1186006c8d11b18742dfb526aadbf2906772fbfe8fb18798967fd397a724d59f6fcd4c32736550986d227a6b447ef70585c049a1a4d7bf25*$/pkzip$", "password" },
	{"\
$pkzip$1*2*2*0*e4*1c5*eda7a8de*0*47*8*e4*4bb6*436c9ffa4328870f6272349b591095e1b1126420c3041744650282bc4f575d0d4a5fc5fb34724e6a1cde742192387b9ed749ab5c72cd6bb0206f102e9216538f095fb7\
73661cfde82c2e2a619332998124648bf4cd0da56279f0c297567d9b5d684125ee92920dd513fd18c27afba2a9633614f75d8f8b9a14095e3fafe8165330871287222e6681dd9c0f830cf5d464457b257d0900eed29107fad8af\
3ac4f87cf5af5183ff0516ccd9aeac1186006c8d11b18742dfb526aadbf2906772fbfe8fb18798967fd397a724d59f6fcd4c32736550986d227a6b447ef70585c049a1a4d7bf25*$/pkzip$", "password"},
	/* now a pkzip archive, with 3 files, 1 byte checksum */
	{"\
$pkzip$3*1*1*0*8*24*4001*8986ec4d693e86c1a42c1bd2e6a994cb0b98507a6ec937fe0a41681c02fe52c61e3cc046*1*0*8*24*4003*a087adcda58de2e14e73db0043a4ff0ed3acc6a9aee3985d7cb81d5ddb32b840ea20\
57d9*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*89a792af804bf38e31fdccc8919a75ab6eb75d1fd6e7ecefa3c5b9c78c3d50d656f42e582af95882a38168a8493b2de5031bb8b39797463cb4769a955a2ba72abe48ee75b103\
f93ef9984ae740559b9bd84cf848d693d86acabd84749853675fb1a79edd747867ef52f4ee82435af332d43f0d0bb056c49384d740523fa75b86a6d29a138da90a8de31dbfa89f2f6b0550c2b47c43d907395904453ddf42a665\
b5f7662de170986f89d46d944b519e1db9d13d4254a6b0a5ac02b3cfdd468d7a4965e4af05699a920e6f3ddcedb57d956a6b2754835b14e174070ba6aec4882d581c9f30*$/pkzip$", "3!files"},

	{NULL}
};

/* these static fields are used in the crypt_all loop, and the cmp_all/cmp_one we */
/* perform the pkzip 'checksum' checking. If we do get a 'hit', then that pass &  */
/* salt pair is checked fully within the cmp_exact, where it gets inflated  and   */
/* checked (possibly also a 'sample TEXT record is done first, as a quick check   */
static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static u32  K12[MAX_KEYS_PER_CRYPT*3];
static PKZ_SALT *salt;
static u8 chk[MAX_KEYS_PER_CRYPT];
static int dirty=1;
#if USE_PKZIP_MAGIC
static ZIP_SIGS SIGS[256];
#endif
#ifdef PKZIP_USE_MULT_TABLE
static u8 mult_tab[16384];
#define PKZ_MULT(b,w) b^mult_tab[(u16)(w.u)>>2]
#else
inline u8 PKZ_MULT(u8 b, MY_WORD w) {u16 t = w.u|2; return b ^ (u8)(((u16)(t*(t^1))>>8)); }
#endif

extern struct fmt_main fmt_pkzip;
static const char *ValidateZipContents(FILE *in, long offset, u32 offex, int len, u32 crc);

/* Similar to strtok, but written specifically for the format. */
static u8 *GetFld(u8 *p, u8 **pRet) {
	if (!p || *p==0) {
		*pRet = (u8*)"";
		return p;
	}
	if (p && *p && *p == '*') {
		*pRet = (u8*)"";
		return ++p;
	}
	*pRet = p;
	while (*p && *p != '*')
		++p;
	if (*p)
	  *p++ = 0;
	return p;
}

static int is_hex_str(const u8 *cp) {
	int len, i;

	if (!cp)
		return 1; /* empty is 'fine' */
	len = strlen((c8*)cp);
	for (i = 0; i < len; ++i) {
		if (atoi16[ARCH_INDEX(cp[i])] == 0x7F)
			return 0;
	}
	return 1;
}

unsigned get_hex_num(const u8 *cp) {
	char b[3];
	unsigned u;
	b[0] = (c8)cp[0];
	b[1] = (c8)cp[1];
	b[2] = 0;
	sscanf(b, "%x", &u);
	return u;
}

/* Since the pkzip format textual representation is pretty complex, with multiple   */
/* 'optional' sections, we have a VERY complete valid.  Valid will make SURE that   */
/* the format is completely valid. Thus, there is little or no error checking later */
/* in the rest of the code.  It 'should' not be needed, and is done here.  There is */
/* a little error checking later in the file, for some of the file opening stuff,   */
/* since the file can change from the time of this 'valid' call, until when the data */
/* is actually read from the file.                                                   */
/*                                                                                   */
/* NOTE, we may want to later make a 'prepare()' function, and do all file loading   */
/* there, so that we have a 'complete' format line, with the zip data contained.     */
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	u8 *p, *cp;
	int cnt, len, data_len;
	u32 crc;
	FILE *in;
	const char *sFailStr;
	long offset;
	u32 offex;
	int type;

	if (strncmp(ciphertext, "$pkzip$", 6))
		return 0;

	cp = (u8*)str_alloc_copy(ciphertext);

	p = &cp[7];
	p = GetFld(p, &cp);
	if (!p || *p==0) {
		sFailStr = "Out of data, reading count of hashes field"; goto Bail; }
	sscanf((c8*)cp, "%x", &cnt);
	if (cnt < 1 || cnt > MAX_PKZ_FILES) {
		sFailStr = "Count of hashes field out of range"; goto Bail; }
	p = GetFld(p, &cp);
	if (!p || *p==0 || *cp < '1' || *cp > '2') {
		sFailStr = "Number of valid hash bytes empty or out of range"; goto Bail; }

	while (cnt--) {
		p = GetFld(p, &cp);
		if ( !p || *cp<'1' || *cp>'3') {
			sFailStr = "Invalid data enumeration type"; goto Bail; }
		type = *cp - '0';
		p = GetFld(p, &cp);
		if ( !p || !is_hex_str(cp)) {
			sFailStr = "Invalid type enumeration"; goto Bail; }
		if (type > 1) {
			p = GetFld(p, &cp);
			if ( !p || !cp[0] || !is_hex_str(cp)) {
				sFailStr = "Invalid compressed length"; goto Bail; }
			sscanf((c8*)cp, "%x", &len);
			p = GetFld(p, &cp);
			if ( !p || !cp[0] || !is_hex_str(cp)) {
				sFailStr = "Invalid data length value"; goto Bail; }
			p = GetFld(p, &cp);
			if ( !p || !cp[0] || !is_hex_str(cp)) {
				sFailStr = "Invalid CRC value"; goto Bail; }
			sscanf((c8*)cp, "%x", &crc);
			p = GetFld(p, &cp);
			if ( !p || !cp[0] || !is_hex_str(cp)) {
				sFailStr = "Invalid offset length"; goto Bail; }
			sscanf((c8*)cp, "%lx", &offset);
			p = GetFld(p, &cp);
			if ( !p || !cp[0] || !is_hex_str(cp)) {
				sFailStr = "Invalid offset length"; goto Bail; }
			sscanf((c8*)cp, "%x", &offex);
		}
		p = GetFld(p, &cp);
		if ( !p || (*cp != '0' && *cp != '8')) {
			sFailStr = "Compression type enumeration"; goto Bail; }
		p = GetFld(p, &cp);
		if ( !p || !is_hex_str(cp)) {
			sFailStr = "data length value"; goto Bail; }
		sscanf((c8*)cp, "%x", &data_len);
		p = GetFld(p, &cp);
		if ( !p || !is_hex_str(cp) || strlen((c8*)cp) != 4) {
			sFailStr = "invalid checksum value"; goto Bail; }
		p = GetFld(p, &cp);
		if (type == 3) {
			if ( !p || strlen((c8*)cp) != data_len) {
				sFailStr = "invalid checksum value"; goto Bail; }
			in = fopen((c8*)cp, "rb"); /* have to open in bin mode for OS's where this matters, DOS/Win32 */
			if (!in) {
				/* this error is listed, even if not in pkzip debugging mode. */
				fprintf(stderr, "Error loading a pkzip hash line. The ZIP file '%s' could NOT be found\n", cp);
				return 0;
			}
			sFailStr = ValidateZipContents(in, offset, offex, len, crc);
			fclose(in);
			if (*sFailStr) {
				/* this error is listed, even if not in pkzip debugging mode. */
				fprintf(stderr, "pkzip validation failed [%s] Hash is %s\n", sFailStr, ciphertext);
				return 0;
			}
		} else {
			if ( !p || !is_hex_str(cp) || strlen((c8*)cp) != data_len<<1) {
				sFailStr = "invalid checksum value"; goto Bail; }
		}
	}
	p = GetFld(p, &cp);
	return !strcmp((c8*)cp, "$/pkzip$");

Bail:;
#ifdef ZIP_DEBUG
	fprintf (stderr, "pkzip validation failed [%s]  Hash is %s\n", sFailStr, ciphertext);
#endif
	return 0;
}

/* helper functions for reading binary data of known little endian */
/* format from a file. Works whether BE or LE system.              */
static u32 fget32(FILE * fp)
{
	u32 v = fgetc(fp);
	v |= fgetc(fp) << 8;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 24;
	return v;
}

static u16 fget16(FILE * fp)
{
	u16 v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

static const char *ValidateZipContents(FILE *fp, long offset, u32 offex, int _len, u32 _crc) {
	u32 id;
	u16 version, flags, method, modtm, moddt, namelen, exlen;
	u32 crc, complen, uncomplen;

	if (fseek(fp, offset, SEEK_SET) != 0)
		return "Not able to seek to specified offset in the .zip file, to read the zip blob data.";

	id = fget32(fp);
	if (id != 0x04034b50U)
		return "Compressed zip file offset does not point to start of zip blob";

	/* Ok, see if this IS the correct file blob. */
	version = fget16(fp);
	flags = fget16(fp);
	method = fget16(fp);
	modtm = fget16(fp);
	moddt = fget16(fp);
	crc = fget32(fp);
	complen = fget32(fp);
	uncomplen = fget32(fp);
	namelen = fget16(fp);
	exlen = fget16(fp);

	/* unused vars. */
	(void)uncomplen;
	(void)modtm;
	(void)moddt;

	/* Even if we 'miss', we keep walking back. We 'can' miss if the CRC of file, or some other       */
	/* binary data happens to have the 0x04034b50 signature, thus giving us a false local header hit. */
	if (_crc == crc && _len == complen &&  (0x14 == version || 0xA == version) && (flags & 1) && (method == 8 || method == 0) && offex==30+namelen+exlen)
		return "";
	return "We could NOT find the internal zip data in this ZIP file";
}
static u8 *buf_copy (char *p, int len) {
	u8 *op = mem_alloc_tiny(len, MEM_ALIGN_NONE);
	memcpy(op, p, len);
	return op;
}
static void init(struct fmt_main *pFmt)
{
	unsigned short n=0;
	/*
	 * Precompute the multiply mangling, within several parts of the hash. There is a pattern,
	 * 64k entries long.  However the exact same value is produced 4 times in a row, every
	 * time.  Thus, we can build a 16k wide array, and then access the array using this
	 * ((val&0xFFFF) >> 2)  This is faster on all current HW, since the 16kb array access
	 * (and the and/shift) is faster than performing the whole mult, 2 shifts, 2 adds and
	 * an and (if the compiler can optimize it to that)
	 *
	 * There is a # define at the top of this file that turns this OFF. if that define is
	 * not set, then these mult's will be done in the crypt_all and decrypt functions
	 */
#ifdef PKZIP_USE_MULT_TABLE
	for (n = 0; n < 16384; n++)
		mult_tab[n] = ((n*4+3) * (n*4+2) >> 8) & 0xff;
#endif

#ifdef _OPENMP
	/* This can be tuned but it's tedious. */
	n = omp_get_max_threads();
	if (n*256 < MAX_KEYS_PER_CRYPT)
		fmt_pkzip.params.max_keys_per_crypt = n*256;
#endif
	/* if not openmp and not use mult_tab, make sure we quiet the unused warning. */
	(void)n;

#if USE_PKZIP_MAGIC

	//static char *MagicTypes[]= { "", "DOC", "XLS", "DOT", "XLT", "EXE", "DLL", "ZIP", "BMP", "DIB", "GIF", "PDF", "GZ", "TGZ", "BZ2", "TZ2", "FLV", "SWF", "MP3", NULL };
	//static int  MagicToEnum[] = {0,  1,    1,     1,     1,     2,     2,     3,     4,     4,     5,     6,     7,    7,     8,     8,     9,     10,    11,  0};
	// decent sources of these:
	// http://www.garykessler.net/library/file_sigs.html
	// http://en.wikipedia.org/wiki/List_of_file_signatures
	// http://toorcon.techpathways.com/uploads/headersig.txt
	// there are many more.

//case 1: // DOC/XLS
	SIGS[1].magic_signature[0] = (u8*)str_alloc_copy("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
	SIGS[1].magic_sig_len[0] = 8;
	SIGS[1].magic_signature[1] = buf_copy("\x50\x4B\x03\x04\x14\x00\x06\x00\x08", 10);  // a .zip file 'sort of'
	SIGS[1].magic_sig_len[1] = 9;
	SIGS[1].magic_signature[2] = buf_copy("\x09\x04\x06\x00\x00\x00\x10\x00\xF6\x05\x5C\x00", 13); // older XLS format (office 95)
	SIGS[1].magic_sig_len[2] = 12;
	SIGS[1].magic_signature[3] = buf_copy("\x09\x02\x06\x00\x00\x00\x10\x00\xB9\x04\x5C\x00", 13); // older XLS v2
	SIGS[1].magic_sig_len[3] = 12;
	SIGS[1].magic_signature[4] = buf_copy("\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00", 11); //DOC Star Writer 6.0
	SIGS[1].magic_sig_len[4] = 10;
	SIGS[1].magic_signature[5] = buf_copy("\x31\xBE\x00\x00\x00\xAB\x00\x00", 9); //DOC MS Word for DOS v6 File
	SIGS[1].magic_sig_len[5] = 8;
	SIGS[1].magic_signature[6] = (u8*)str_alloc_copy("\x12\x34\x56\x78\x90\xFF"); //DOC MS Word 6.0 File
	SIGS[1].magic_sig_len[6] = 6;
	SIGS[1].magic_signature[7] = (u8*)str_alloc_copy("\x7F\xFE\x34\x0A");  //MS Word File
	SIGS[1].magic_sig_len[7] = 4;
	SIGS[1].magic_count = 8;
	SIGS[1].max_len = 12;
//case 2: // Win32/DOS exe file MZ
	SIGS[2].magic_signature[0] = (u8*)str_alloc_copy("MZ");
	SIGS[2].magic_sig_len[0] = 2;
	SIGS[2].magic_count = 1;
	SIGS[2].max_len = 2;
//case 3: // PKZIP
	SIGS[3].magic_signature[0] = (u8*)str_alloc_copy("\x50\x4B\x03\x04");
	SIGS[3].magic_sig_len[0] = 4;
	SIGS[3].magic_count = 1;
	SIGS[3].max_len = 4;
//case 4: // BMP
	SIGS[4].magic_signature[0] = (u8*)str_alloc_copy("BM");
	SIGS[4].magic_sig_len[0] = 2;
	SIGS[4].magic_count = 1;
	SIGS[4].max_len = 2;
//case 5: // GIF
	SIGS[5].magic_signature[0] = (u8*)str_alloc_copy("GIF87a");
	SIGS[5].magic_sig_len[0] = 6;
	SIGS[5].magic_signature[1] = (u8*)str_alloc_copy("GIF89a");
	SIGS[5].magic_sig_len[1] = 6;
	SIGS[5].magic_count = 2;
	SIGS[5].max_len = 6;
//case 6: // PDF
	SIGS[6].magic_signature[0] = (u8*)str_alloc_copy("%PDF");
	SIGS[6].magic_sig_len[0] = 4;
	SIGS[6].magic_count = 1;
	SIGS[6].max_len = 4;
//case 7: // GZ
	SIGS[7].magic_signature[0] = (u8*)str_alloc_copy("\x1F\x8B\x08");
	SIGS[7].magic_sig_len[0] = 3;
	SIGS[7].magic_count = 1;
	SIGS[7].max_len = 3;
//case 8: // BZ2  (there is a 'magic' pi, but byte 4 is 1 to 9, so skip the 'pi')
	SIGS[8].magic_signature[0] = (u8*)str_alloc_copy("BZh");
	SIGS[8].magic_sig_len[0] = 3;
	SIGS[8].magic_signature[1] = (u8*)str_alloc_copy("BZ0");
	SIGS[8].magic_sig_len[1] = 3;
	SIGS[8].magic_count = 2;
	SIGS[8].max_len = 3;
//case 9: // FLV
	SIGS[9].magic_signature[0] = (u8*)str_alloc_copy("FLV\x01");
	SIGS[9].magic_sig_len[0] = 4;
	SIGS[9].magic_count = 1;
	SIGS[9].max_len = 4;
//case 10: // SWF
	SIGS[10].magic_signature[0] = (u8*)str_alloc_copy("FWS");
	SIGS[10].magic_sig_len[0] = 5;
	SIGS[10].magic_count = 1;
	SIGS[10].max_len = 5;
//case 11: // MP3
	SIGS[11].magic_signature[0] = (u8*)str_alloc_copy("ID3");
	SIGS[11].magic_sig_len[0] = 3;
	SIGS[11].magic_count = 1;
	SIGS[11].max_len = 3;

	SIGS[255].max_len = 64;
#endif
}

static void set_salt(void *_salt) {
	salt = *((PKZ_SALT**)_salt);
}

static void *get_salt(char *ciphertext)
{
	/* NOTE, almost NO error checking at all in this function.  Proper error checking done in valid() */
	static unsigned char salt_p[8];
	PKZ_SALT *salt;
	long offset=0;
	u32 offex;
	int i, j;
	u8 *p, *cp, *cpalloc = (unsigned char*)mem_alloc(strlen(ciphertext)+1);

	/* Needs word align on REQ_ALIGN systems.  May crash otherwise (in the sscanf) */
	salt = mem_alloc_tiny(sizeof(PKZ_SALT), MEM_ALIGN_WORD);
	memcpy(salt_p, &salt, sizeof(salt));
	memset(salt, 0, sizeof(PKZ_SALT));

	cp = cpalloc;
	strcpy((c8*)cp, ciphertext);
	p = &cp[7];
	p = GetFld(p, &cp);
	sscanf((c8*)cp, "%x", &(salt->cnt));
	p = GetFld(p, &cp);
	sscanf((c8*)cp, "%x", &(salt->chk_bytes));
	for(i = 0; i < salt->cnt; ++i) {
		int data_enum;
		p = GetFld(p, &cp);
		data_enum = *cp - '0';
		p = GetFld(p, &cp);
#if USE_PKZIP_MAGIC
		sscanf((c8*)cp, "%hhx", &(salt->H[i].magic));
		salt->H[i].pSig = &SIGS[salt->H[i].magic];
#endif

		if (data_enum > 1) {
			p = GetFld(p, &cp);
			sscanf((c8*)cp, "%x", &(salt->compLen));
			p = GetFld(p, &cp);
			sscanf((c8*)cp, "%x", &(salt->deCompLen));
			p = GetFld(p, &cp);
			sscanf((c8*)cp, "%x", &(salt->crc32));
			p = GetFld(p, &cp);
			sscanf((c8*)cp, "%lx", &offset);
			p = GetFld(p, &cp);
			sscanf((c8*)cp, "%x", &offex);
		}
		p = GetFld(p, &cp);
		sscanf((c8*)cp, "%x", &(salt->H[i].compType));
		p = GetFld(p, &cp);
		sscanf((c8*)cp, "%x", &(salt->H[i].datlen));
		p = GetFld(p, &cp);

		for (j = 0; j < 4; ++j) {
			salt->H[i].c <<= 4;
			salt->H[i].c |= atoi16[ARCH_INDEX(cp[j])];
		}
		p = GetFld(p, &cp);
		if (data_enum > 1) {
			/* if 2 or 3, we have the FULL zip blob for decrypting. */
			if (data_enum == 3) {
				/* read from file. */
				FILE *fp;
				fp = fopen((c8*)cp, "rb");
				if (!fp) {
					fprintf (stderr, "Error opening file for pkzip data:  %s\n", cp);
					MEM_FREE(cpalloc);
					return 0;
				}
				fseek(fp, offset+offex, SEEK_SET);
				if (salt->compLen < 16*1024) {
					/* simply load the whole blob */
					salt->H[i].h = mem_alloc_tiny(salt->compLen, MEM_ALIGN_WORD);
					if (fread(salt->H[i].h, 1, salt->compLen, fp) != salt->compLen) {
						fprintf (stderr, "Error reading zip file for pkzip data:  %s\n", cp);
						fclose(fp);
						MEM_FREE(cpalloc);
						return 0;
					}
					fclose(fp);
					salt->H[i].datlen = salt->compLen;
				}
				else {
					/* Only load a small part (to be used in crypt_all), and set the filename in */
					/* the salt->fname string, so that cmp_all can open the file, and buffered   */
					/* read the zip data only when it 'needs' it.                                */
					salt->fname = str_alloc_copy((c8*)cp);
					salt->offset = offset+offex;
					salt->H[i].h = mem_alloc_tiny(384, MEM_ALIGN_WORD);
					if (fread(salt->H[i].h, 1, 384, fp) != 384) {
						fprintf (stderr, "Error reading zip file for pkzip data:  %s\n", cp);
						fclose(fp);
						MEM_FREE(cpalloc);
						return 0;
					}
					fclose(fp);
					salt->H[i].datlen = 384;
				}
			} else {
				/* 'inline' data. */
				if (salt->compLen != salt->H[i].datlen) {
					fprintf(stderr, "Error, length of full data does not match the salt len. %s\n", ciphertext);
					return 0;
				}
				salt->H[i].h = mem_alloc_tiny(salt->compLen, MEM_ALIGN_WORD);
				for (j = 0; j < salt->H[i].datlen; ++j)
					salt->H[i].h[j] = (atoi16[ARCH_INDEX(cp[j*2])]<<4) + atoi16[ARCH_INDEX(cp[j*2+1])];
			}

			/* we also load this into the 'building' salt */
			salt->compType = salt->H[i].compType;

			/* Now, set the 'is full zip' flag, so we later process as a zip file. */
			salt->H[i].full_zip = 1;
			salt->full_zip_idx = i;
		} else {
			salt->H[i].h = mem_alloc_tiny(salt->H[i].datlen, MEM_ALIGN_WORD);
			for (j = 0; j < salt->H[i].datlen; ++j)
				salt->H[i].h[j] = (atoi16[ARCH_INDEX(cp[j*2])]<<4) + atoi16[ARCH_INDEX(cp[j*2+1])];
		}
	}

	MEM_FREE(cpalloc);

	// Ok, we want to add some 'logic' to remove the magic testing, except for specific cases.
	//  If the only file blobs we have are stored, and long blobs, then we want magic (3 file, 2 byte checksum does not need magic).
	//  A single 1 byte file, even if deflated, we want to keep magic. (possibly).
	j = 0;
	for (i = 0; i < salt->cnt; ++i) {
		if (salt->H[i].compType == 8) {
			if (salt->cnt == 1 && salt->chk_bytes == 1)
				j += 10;
			else
				break;
		}
		j += 1;
	}
	// ok, if j == 1, then we 'might' want to use magic. Otherwise, we want to 'clear' all magic values.
	if (j >= 20)
		j = 0;
	if (j && salt->chk_bytes == 2 && salt->cnt > 1)
		j = 0;  // we do not need to use magic, on 2 or 3 stored 2 byte checksum files.  We already have 2^32 or 2^48 in the checksum checking
	if (j && salt->chk_bytes == 1 && salt->cnt == 3)
		j = 0;  // we do not need to use magic, on 3 stored 2 byte checksum files.  We already have 2^32 or 2^48 in the checksum checking
	if (!j) {
		for (i = 0; i < salt->cnt; ++i)
			salt->H[i].magic = 0;	// remove any 'magic' logic from this hash.
	}


	return salt_p;
}

static int binary_hash0(void *binary) { return 1; }
static int get_hash0(int index)       { return chk[index]; }

static void set_key(char *key, int index)
{
	/* Keep the PW, so we can return it in get_key if asked to do so */
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH);
	dirty = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_one(void *binary, int idx)
{
	return chk[idx] == 1;
}

static int cmp_all(void *binary, int count)
{
	int i,j;
	for (i=j=0; i<count; ++i)
		j+=chk[i]; /* hopefully addition like this is faster then 'count' conditional if statments */
	return j;
}

/* this function is used by cmp_exact_loadfile.  It will load the next
 * part of the file then decrypt the data, and return just how many
 * bytes were loaded.
 *
 * This function is 'similar' to an fread().  However, it also decrypts data
 */
static int get_next_decrypted_block(u8 *in, int sizeof_n, FILE *fp, u32 *inp_used, MY_WORD *pkey0, MY_WORD *pkey1, MY_WORD *pkey2) {
	u32 new_bytes = sizeof_n, k;
	u8 C;

	/* we have read all the bytes, we're done */
	if (*inp_used >= salt->compLen)
		return 0;
	if (*inp_used + new_bytes > salt->compLen)
		/* this is the last block.  Only load the bytes that are left */
		new_bytes = salt->compLen - *inp_used;
	/* return the correct 'offset', so we can track when the file buffer has been fully read */
	*inp_used += new_bytes;
	/* read the data */
	if (fread(in, 1, new_bytes, fp) != new_bytes)
		return 0;

	/* decrypt the data bytes (in place, in same buffer). Easy to do, only requires 1 temp character variable.  */
	for (k = 0; k < new_bytes; ++k) {
		C = PKZ_MULT(in[k],(*pkey2));
		pkey0->u = pkzip_crc32 (pkey0->u, C);
		pkey1->u = (pkey1->u + pkey0->c[KB1]) * 134775813 + 1;
		pkey2->u = pkzip_crc32 (pkey2->u, pkey1->c[KB2]);
		in[k] = C;
	}
	/* return the number of bytes we read from the file on this read */
	return new_bytes;
}

/* Ok, this is the more complex example.  Here we have to load the file (which may be HUGE)
 * decrypt the bytes from this file, and then inflate that data, and crc the bytes which we
 * have inflated from that stream. Then in the end, when we use all input bytes, if we have
 * inflated the right amount of data, ended up with a Z_STREAM_END, and the proper sized
 * decompression buffer, and the CRC matches, then we know we have the correct password
 *
 * This function is called from cmp_exact(), when cmp_exact finds out we have to decrypt from
 * the stored .zip file.
 *
 * this code is modifications made to the zpipe.c 'example' code from the zlib web site.
 */
#define CHUNK (64*1024)
static int cmp_exact_loadfile(int index) {

    int ret;
    u32 have, k;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
	FILE *fp;
	MY_WORD key0, key1, key2;
	u8 *b, C;
	u32 inp_used, decomp_len=0;
	u32 crc = 0xFFFFFFFF;

	/* Open the zip file, and 'seek' to the proper offset of the binary zip blob */
	fp = fopen(salt->fname, "rb");
	if (!fp) {
		fprintf (stderr, "\nERROR, the zip file: %s has been removed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		return 1;
	}
	if (fseek(fp, salt->offset, SEEK_SET)) {
		fprintf (stderr, "\nERROR, the zip file: %s fseek() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		fclose(fp);
		return 1;
	}

	/* 'seed' the decryption with the IV. We do NOT use these bytes, they simply seed us. */
	key0.u = K12[index*3], key1.u = K12[index*3+1], key2.u = K12[index*3+2];
	k=12;
	if (fread(in, 1, 12, fp) != 12) {
		fprintf (stderr, "\nERROR, the zip file: %s fread() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		fclose(fp);
		return 1;
	}

	b = salt->H[salt->full_zip_idx].h;
	do {
		C = PKZ_MULT(*b++,key2);
		key0.u = pkzip_crc32 (key0.u, C);
		key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
		key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
	}
	while(--k);

	/* this is 'sort of' our file pointer.  It is the 'index' into the file's encrypted, compressed data buffer. */
	/* we have read the 12 bytes of IV data, and updated our keys. Now we start processing the rest of the bytes */
	/* to get the data to inflate, and crc check                                                                 */
	inp_used = 12;

	if (salt->H[salt->full_zip_idx].compType == 0) {
		// handle a stored blob (we do not have to decrypt it.
		int avail_in;
		crc = 0xFFFFFFFF;
        avail_in = get_next_decrypted_block(in, CHUNK, fp, &inp_used, &key0, &key1, &key2);
		while (avail_in) {
			for (k = 0; k < avail_in; ++k)
				crc = pkzip_crc32(crc,in[k]);
			avail_in = get_next_decrypted_block(in, CHUNK, fp, &inp_used, &key0, &key1, &key2);
		}
		fclose(fp);
		return ~crc == salt->crc32;
	}

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, -15);
	if (ret != Z_OK) /* if zlib is hosed, then likely there is no reason at all to continue.  Better to exit, and let the user 'fix' the system */
		perror("Error, initializing the libz inflateInit2() system\n");

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = get_next_decrypted_block(in, CHUNK, fp, &inp_used, &key0, &key1, &key2);
        if (ferror(fp)) {
            inflateEnd(&strm);
			fclose(fp);
			fprintf (stderr, "\nERROR, the zip file: %s fread() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
            return 1;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret) {
	            case Z_NEED_DICT:
			    case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					inflateEnd(&strm);
					fclose(fp);
					return 0;
            }
            have = CHUNK - strm.avail_out;
			/* now update our crc value */
			for (k = 0; k < have; ++k)
				crc = pkzip_crc32(crc,out[k]);
			decomp_len += have;
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    inflateEnd(&strm);
	fclose(fp);
	return ret == Z_STREAM_END && inp_used == salt->compLen && decomp_len == salt->deCompLen && salt->crc32 == ~crc;
}


static int cmp_exact(char *source, int index)
{
	const u8 *b;
	u8 C, *decompBuf, *decrBuf, *B;
	u32 k, crc;
	MY_WORD key0, key1, key2;
	z_stream strm;
	int ret;

	if (salt->H[salt->full_zip_idx].full_zip == 0)
		/* we do not have a zip file, this is 'checksum' only
		 * POSSIBLY, we should log and output to screen that
		 * we are not 100% 'sure' we have the right password!! */
		return 1;

#ifdef ZIP_DEBUG
	fprintf(stderr, "FULL zip test being done. (pass=%s)\n", saved_key[index]);
#endif

	if (salt->fname == NULL) {
		/* we have the whole zip blob in memory, simply allocate a decrypt buffer, decrypt
		 * in one step, crc and be done with it. This is the 'trivial' type. */

		decrBuf = mem_alloc(salt->compLen-12);

		key0.u = K12[index*3], key1.u = K12[index*3+1], key2.u = K12[index*3+2];

		b = salt->H[salt->full_zip_idx].h;
		k=12;
		do {
			C = PKZ_MULT(*b++,key2);
			key0.u = pkzip_crc32 (key0.u, C);
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
		}
		while(--k);
		B = decrBuf;
		k = salt->compLen-12;
		do {
			C = PKZ_MULT(*b++,key2);
			key0.u = pkzip_crc32 (key0.u, C);
			*B++ = C;
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
		} while (--k);

		if (salt->H[salt->full_zip_idx].compType == 0) {
			// handle a stored blob (we do not have to decrypt it.
			crc = 0xFFFFFFFF;
			for (k = 0; k < salt->compLen-12; ++k)
				crc = pkzip_crc32(crc,decrBuf[k]);
			MEM_FREE(decrBuf);
			return ~crc == salt->crc32;
		}

		strm.zalloc = Z_NULL; strm.zfree = Z_NULL; strm.opaque = Z_NULL; strm.next_in = Z_NULL; strm.avail_in = 0;

		ret = inflateInit2(&strm, -15); /* 'raw', since we do not have gzip header, or gzip crc. .ZIP files are 'raw' implode data. */
		if (ret != Z_OK)
		   perror("Error, initializing the libz inflateInit2() system\n");

		decompBuf = mem_alloc(salt->deCompLen);

		strm.next_in = decrBuf;
		strm.avail_in = salt->compLen-12;
		strm.avail_out = salt->deCompLen;
		strm.next_out = decompBuf;

		ret = inflate(&strm, Z_SYNC_FLUSH);
		inflateEnd(&strm);
		if (ret != Z_STREAM_END || strm.total_out != salt->deCompLen) {
			MEM_FREE(decompBuf);
			MEM_FREE(decrBuf);
			return 0;
		}

		crc = 0xFFFFFFFF;
		for (k = 0; k < strm.total_out; ++k)
			crc = pkzip_crc32(crc,decompBuf[k]);
		MEM_FREE(decompBuf);
		MEM_FREE(decrBuf);
		return ~crc == salt->crc32;
	}
	/* we have a stand alone function to handle this more complex method of
	 * loading from file, decrypting, decompressing, and crc'ing the data
	 * It is complex enough of a task, to have it's own function. */
	return cmp_exact_loadfile(index);
}

#if USE_PKZIP_MAGIC
const char exBytesUTF8[64] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};
static int isLegalUTF8_char(const u8 *source, int length) {
    u8 a;
	int len;
    const u8 *srcptr;

	if (*source < 0xC0)
		return 1;
	len = exBytesUTF8[*source&0x3f];
	srcptr = source+len;
	if (len+1 > length)
		return -1;

    switch (len) {
		default: return -1;
		/* Everything else falls through when "true"... */
		case 4: if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return -1;
		case 3: if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return -1;
		case 2: if ((a = (*--srcptr)) > 0xBF) return -1;

		switch (*source) {
			/* no fall-through in this inner switch */
			case 0xE0: if (a < 0xA0) return -1; break;
			case 0xED: if (a > 0x9F) return -1; break;
			case 0xF0: if (a < 0x90) return -1; break;
			case 0xF4: if (a > 0x8F) return -1; break;
			default:   if (a < 0x80) return -1;
		}

	    case 1: if (*source >= 0x80 && *source < 0xC2) return -1;
    }
    if (*source > 0xF4) return -1;
    return len+1;
}
static int validate_ascii(const u8 *out, int inplen) {
	int i;
	int unicode=0;

	for (i = 0; i < inplen-1; ++i) {
		if (out[i] > 0x7E) {
			// first check to 'see' if this is a valid utf8 character.  If so, let it 'pass'.
			if (unicode)
				return 0; // in unicode mode, we ONLY handle 'ascii' bytes in the low byte.

			if (out[i] > 0xC0) {
				int len;
				if(i > inplen-4)
					return 1;
				len = isLegalUTF8_char(&out[i], 5);
				if (len < 0) return 0;
				i += (len-1);
			}
			else {
				if (i) {
					// check for utf8 BOM  \xEF \xBB \xBF
					if (out[0] == 0xEF && out[1] == 0xBB && out[2] == 0xBF) {
						i = 2;
						continue;
					}
					/* check for Unicode BOM  (FF FE for utf16le, FE FF for utf16be, FF FE 00 00 for utf32le, not sure if 00 00 FE FF is utf32be, but likely is) */
					if (out[0] == 0xFF && out[1] == 0xFE) {
						unicode = 1;
						i++;
						continue;
					}
					/* unicode BE bom */
					if (out[0] == 0xFE && out[1] == 0xFF) {
						unicode = 1;
						i += 2;
						continue;
					}
					/* utf32 LE */
					if (out[0] == 0xFF && out[1] == 0xFE && out[2] == 0 && out[3] == 0) {
						unicode = 3;
						i += 3;
						continue;
					}
					/* utf32 BE bom */
					if (out[0] == 0 && out[1] == 0 && out[2] == 0xFE && out[3] == 0xFF) {
						unicode = 3;
						i += 6;
						continue;
					}

					// allow a 'single' byte > 0x7E as long as bytes following are ascii.
					if (out[1] <= 0x7E && out[1] >= 0x20) {
						++i;
						continue;
					}
					return 0;
				}
			}
		} else if (out[i] < 0x20) {
			/* we do not need to deal with DOS EOF char 0x1a, since we will never have the 'end' of the file */
			/* we do allow the ESC character for ANSI files, however, they are frequently also binary, so will fail in other places */
			if (out[i]!='\n' && out[i]!='\r' && out[i]!='\t' && out[i]!=0x1B)
				return 0;
		}
		i += unicode; // skip the null bytes
	}
	return 1;
}
static int CheckSigs(const u8 *p, int len, ZIP_SIGS *pSig) {
	int i, j;

	for (i = 0; i < pSig->magic_count; ++i) {
		int fnd = 1;
		u8 *pS = pSig->magic_signature[i];
		for (j = 0; j < pSig->magic_sig_len[i]; ++j) {
			if (p[j] != pS[j]) {
				fnd = 0;
				break;
			}
		}
		if (fnd)
			return 1;
	}
	return 0;
}
#endif

#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
__attribute__((always_inline))
#else
__inline__
#endif
#endif
/* note, Buf is the 'full' decrypted zip buffer (len bytes long). It DOES contain the first 3 bits, which have already
 * been decoded, and have told us we had a code 2 (var table block)
 * all done without BITS(), PULLBYTE(), BITSNEEDED() macros.  We 'know' the data we need, and we know that we have
 * 'enough', so we do not worry about all of the overhead, and validation logic.
 *
 * In testing, this function catches ALL bad decryptions, except about 1/300 to 1/350. So, it is not too bad.
 */
static int check_inflate_CODE2(u8 *next) {
	u32 bits, hold, thisget, have, i;
	int left;
	u32 ncode;
	u32 ncount[2];	// ends up being an array of 8 u8 count values.  But we can clear it, and later 'check' it with 2 u32 instructions.
	u8 *count;		// this will point to ncount array. NOTE, this is alignment required 'safe' for Sparc systems or others requiring alignment.
#if (ARCH_LITTLE_ENDIAN==1) && (ARCH_ALLOWS_UNALIGNED==1)
	// 'speedup' for x86 type systems.  pkzip/inflate was designed here, so why not use it.
	hold = *((u32*)next);
#else
	hold = *next + (((u32)next[1])<<8) + (((u32)next[2])<<16) + (((u32)next[3])<<24);
#endif
	next += 3;	// we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
	hold >>= 3;	// we already processed 3 bits
	count = (u8*)ncount;

	if (257+(hold&0x1F) > 286) return 0;	// nlen, but we do not use it.
	hold >>= 5;
	if(1+(hold&0x1F) > 30) return 0;		// ndist, but we do not use it.
	hold >>= 5;
    ncode = 4+(hold&0xF);
	hold >>= 4;

	// we have 15 bits left.
	hold += ((u32)(*++next)) << 15;
	hold += ((u32)(*++next)) << 23;
	// we now have 31 bits.  We need to know this for the loop below.
	bits = 31;

	// We have 31 bits now, in accum.  If we are processing 19 codes, we do 7, then have 10 bits.
	// Add 16 more and have 26, then use 21, have 5.  Then load 16 more, then eat 15 of them.
	have = 0;

	ncount[0] = ncount[1] = 0;
	for (;;) {
		if (have+7>ncode)
			thisget = ncode-have;
		else
			thisget = 7;
		have += thisget;
		bits -= thisget*3;
		while (thisget--) {
			++count[hold&7];
			hold>>=3;
		}
		if (have == ncode)
			break;
		hold += ((u32)(*++next)) << bits;
		bits += 8;
		hold += ((u32)(*++next)) << bits;
		bits += 8;
	}
	count[0] = 0;
	if (!ncount[0] && !ncount[1]) return 0; /* if no codes at all, then simply bail, that is invalid */

    /* check for an over-subscribed or incomplete set of lengths */
	/* this will catch about 319 out of 320 'bad' passwords that */
	/* have made it into this function. Note, only 1/4 of the    */
	/* passwords which pass the checksum, can make it here.  Of  */
	/* those, we drop 319/320 or about that many (a good check!) */
    left = 1;
    for (i = 1; i <= 7; ++i) {
        left <<= 1;
        left -= count[i];
        if (left < 0)
			return 0;	/* over-subscribed */
    }
    if (left > 0)
        return 0;		/* incomplete set */

	return 1;			/* Passed this check! */
}

//static code const * const lcode = lenfix;
//static code const * const dcode = distfix;

#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
__attribute__((always_inline))
#else
__inline__
#endif
#endif
/* This function handles inflate CODE type 1. This is a 'fixed' table code.  We set the fixed table, */
/* and then inflate some data (without writing anything.  If we find any BAD lookback data, we can   */
/* return a failure.  We have 24 bytes of inflate data, and this almost always is more than enough   */
/* to turn up an error.  If we find we need more, we will do more than 24                            */
static int check_inflate_CODE1(u8 *next, int left) {
	u32 whave = 0, op, bits, hold,len;
	code here;

#if (ARCH_LITTLE_ENDIAN==1) && (ARCH_ALLOWS_UNALIGNED==1)
	// 'speedup' for x86 type systems.  pkzip/inflate was designed here, so why not use it.
	hold = *((u32*)next);
#else
	hold = *next + (((u32)next[1])<<8) + (((u32)next[2])<<16) + (((u32)next[3])<<24);
#endif
	next += 3; // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
	left -= 4;
	hold >>= 3;  // we already processed 3 bits
	bits = 32-3;
	for (;;) {
		if (bits < 15) {
			if (left < 2)
				return 1;	// we are out of bytes.  Return we had no error.
			left -= 2;
            hold += (u32)(*++next) << bits;
            bits += 8;
            hold += (u32)(*++next) << bits;
            bits += 8;
		}
		here=lenfix[hold & 0x1FF];
        op = (unsigned)(here.bits);
        hold >>= op;
        bits -= op;
        op = (unsigned)(here.op);
        if (op == 0)							/* literal */
			++whave;
        else if (op & 16) {						/* length base */
            len = (unsigned)(here.val);
            op &= 15;							/* number of extra bits */
            if (op) {
                if (bits < op) {
					if (!left)
						return 1;	/*we are out of bytes.  Return we had no error.*/
					--left;
                    hold += (u32)(*++next) << bits;
                    bits += 8;
                }
                len += (unsigned)hold & ((1U << op) - 1);
                hold >>= op;
                bits -= op;
            }
            if (bits < 15) {
				if (left < 2)
					return 1;	/*we are out of bytes.  Return we had no error.*/
				left -= 2;
                hold += (u32)(*++next) << bits;
                bits += 8;
                hold += (u32)(*++next) << bits;
                bits += 8;
            }
            here = distfix[hold & 0x1F];
          dodist:
            op = (unsigned)(here.bits);
            hold >>= op;
            bits -= op;
            op = (unsigned)(here.op);
            if (op & 16) {                      /* distance base */
                u32 dist = (unsigned)(here.val);
                op &= 15;                       /* number of extra bits */
                if (bits < op) {
					if (!left)
						return 1;	/*we are out of bytes.  Return we had no error.*/
					--left;
                    hold += (u32)(*++next) << bits;
                    bits += 8;
                    if (bits < op) {
						if (!left)
							return 1;	/*we are out of bytes.  Return we had no error.*/
						--left;
                        hold += (u32)(*++next) << bits;
                        bits += 8;
                    }
                }
                dist += (unsigned)hold & ((1U << op) - 1);
                if (dist > whave)
					return 0;  /*invalid distance too far back*/
                hold >>= op;
                bits -= op;
				whave += dist;
            }
            else if ((op & 64) == 0) {	/* 2nd level distance code */
                here = distfix[here.val + (hold & ((1U << op) - 1))];
                goto dodist;
            }
            else
				return 0;		/*invalid distance code*/
        }
		else if (op & 64) {
			// 2nd level length code.
            //here = lcode[here.val + (hold & ((1U << op) - 1))];
            //goto dolen;

			// this causes an infinite loop. Also, I VERY seriously doubt, this will EVER happen in the first
			// 24 bytes of code.  NOTE, there may be problems, in the fact this causes a inf loop!, but for now,
			// simply return 0, then debug later.
			return 0;
		}
		else if (op & 32) {
			// end of block  NOTE, we need to find out if we EVER hit the end of a block, at only 24 bytes???
			// It is VERY likely we do SHOULD NOT EVER hit this. If that is the case, return that this block is bogus.
			// check next OP (if we have enough bits left), if CODE=3, fail.  If code==0, check
			return 0;
		}
		else {
			return 0; // invalid literal/length code.
		}
	}
}

/*
 * Crypt_all simply performs the checksum .zip validatation of the data. It performs
 * this for ALL hashes provided. If any of them fail to match, then crypt all puts the
 * complement of the 'proper' checksum of the first hash into the output. These 2 bytes
 * are checked against the binary for this salt/password combination.  Thus, if any
 * checksum fails, it will never match binary.  However, if ALL of the checksums match
 * we then put the checksum bytes from the first hash, into our output data. Then, when
 * the binary check (cmp_all, cmp_one) is performed, it WILL match.  NOTE, this does
 * not mean we have found the password.  Just that all hashes quick check checksums
 * for this password 'work'.
 */
static void crypt_all(int _count)
{
	int idx;
#if (ZIP_DEBUG==2)
	static int CNT, FAILED, FAILED2;
	++CNT;
#endif

	// pkzip kinda sucks a little for multi-threading, since there is different amount of work to be
	// done, depenging upon the password.  Thus, we pack in OMP_MOD passwords into each thread, and
	// hopefully some of the differnces will even themselves out in the end.  If we have 2 threads
	// then thread 1 gets 0 to 127 password, and thread 2 gets 128-256.  Once they 'get' their data,
	// there should be no mutexing of the runtime data, thus the threads should run fast.
	// Also, since we have 'multiple' files in a .zip file (and multiple checksums), we bail as at the
	// first time we fail to match checksum.  So, there may be some threads which check more checksums.
	// Again, hopefully globbing many tests into a threads working set will flatten out these differences.
#ifdef _OPENMP
#pragma omp parallel for private(idx)
#endif
	for (idx = 0; idx < _count; ++idx) {
		int cur_hash_count = salt->cnt;
		int cur_hash_idx = -1;
		MY_WORD key0, key1, key2;
		u8 C;
		const u8 *b;
		u8 curDecryBuf[256];
#if USE_PKZIP_MAGIC
		u8 curInfBuf[128];
#endif
		int k, SigChecked;
		u16 e, v1, v2;
		z_stream strm;
		int ret;

		/* use the pwkey for each hash.  We mangle on the 12 bytes of IV to what  was computed in the pwkey load. */

		if (dirty) {
			u8 *p = (u8*)saved_key[idx];

			/* load the 'pwkey' one time, put it into the K12 array */
			key0.u = 0x12345678UL; key1.u = 0x23456789UL; key2.u = 0x34567890UL;
			do {
				key0.u = pkzip_crc32 (key0.u, *p++);
				key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
				key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
			} while (*p);
			K12[idx*3] = key0.u, K12[idx*3+1] = key1.u, K12[idx*3+2] = key2.u;
			goto SkipKeyLoadInit;
		}

		do
		{
			// 2nd, and later times through the loop, AND if keys are not dirty (i.e. multiple salts
			// for the same key load), we do NOT perform the key compute, but instead load the pre-computed
			// key data from the array.
			key0.u = K12[idx*3], key1.u = K12[idx*3+1], key2.u = K12[idx*3+2];

SkipKeyLoadInit:;
			b = salt->H[++cur_hash_idx].h;
			k=11;
			e = salt->H[cur_hash_idx].c;

			do
			{
				C = PKZ_MULT(*b++,key2);
				key0.u = pkzip_crc32 (key0.u, C);
				key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
				key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
			}
			while(--k);

			/* if the hash is a 2 byte checksum type, then check that value first */
			/* There is no reason to continue if this byte does not check out.  */
			if (salt->chk_bytes == 2 && C != (e&0xFF))
				goto Failed_Bailout;

			C = PKZ_MULT(*b++,key2);
			if (C != (e>>8))
				goto Failed_Bailout;

			// Now, update the key data (with that last byte.
			key0.u = pkzip_crc32 (key0.u, C);
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);

			// Ok, we now have validated this checksum.  We need to 'do some' extra pkzip validation work.
			// What we do here, is to decrypt a little data (possibly only 1 byte), and perform a single
			// 'inflate' check (if type is 8).  If type is 0 (stored), and we have a signature check, then
			// we do that here.  Also, if the inflate code is a 0 (stored block), and we do sig check, then
			// we can do that WITHOUT having to call inflate.  however, if there IS a sig check, we will have
			// to call inflate on 'some' data, to get a few bytes (or error code). Also, if this is a type
			// 2 or 3, then we do the FULL inflate, CRC check here.
			e = 0;

			// First, we want to get the inflate CODE byte (the first one).

			C = PKZ_MULT(*b++,key2);
			// Ok, if this is a code 3, we are done.
			if ( (C & 6) == 6)
				goto Failed_Bailout;
			SigChecked = 0;
			if ( salt->H[cur_hash_idx].compType == 0) {
				// handle a stored file.
				// We can ONLY deal with these IF we are handling 'magic' testing.

#if USE_PKZIP_MAGIC
				// Ok, if we have a signature, check it here, WITHOUT having to call zLib's inflate.
				if (salt->H[cur_hash_idx].pSig->max_len) {
					int len = salt->H[cur_hash_idx].pSig->max_len;
					if (len > salt->H[cur_hash_idx].datlen-12)
						len = salt->H[cur_hash_idx].datlen-12;
					SigChecked = 1;
					curDecryBuf[0] = C;
					for (; e < len;) {
						key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}

					if (salt->H[cur_hash_idx].magic == 255) {
						if (!validate_ascii(&curDecryBuf[5], len-5))
							goto Failed_Bailout;
					} else {
						if (!CheckSigs(curDecryBuf, len, salt->H[cur_hash_idx].pSig))
							goto Failed_Bailout;
					}
				}
#endif
				continue;
			}
			if ( (C & 6) == 0) {
				// Check that checksum2 is 0 or 1.  If not, I 'think' we can be done
				if (C > 1)
					goto Failed_Bailout;
				// now get 4 bytes.  This is the length.  It is made up of 2 16 bit values.
				// these 2 values are checksumed, so it is easy to tell if the data is WRONG.
				// correct data is u16_1 == (u16_2^0xFFFF)
				curDecryBuf[0] = C;
				for (e = 0; e <= 4; ) {
					key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
					key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
					key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
					curDecryBuf[++e] = PKZ_MULT(*b++,key2);
				}
				v1 = curDecryBuf[1] | (((u16)curDecryBuf[2])<<8);
				v2 = curDecryBuf[3] | (((u16)curDecryBuf[4])<<8);
				if (v1 != (v2^0xFFFF))
					goto Failed_Bailout;
#if USE_PKZIP_MAGIC
				// Ok, if we have a signature, check it here, WITHOUT having to call zLib's inflate.
				if (salt->H[cur_hash_idx].pSig->max_len) {
					int len = salt->H[cur_hash_idx].pSig->max_len + 5;
					if (len > salt->H[cur_hash_idx].datlen-12)
						len = salt->H[cur_hash_idx].datlen-12;
					SigChecked = 1;
					for (; e < len;) {
						key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}

					if (salt->H[cur_hash_idx].magic == 255) {
						if (!validate_ascii(&curDecryBuf[5], len-5))
							goto Failed_Bailout;
					} else {
						if (!CheckSigs(&curDecryBuf[5], len-5, salt->H[cur_hash_idx].pSig))
							goto Failed_Bailout;
					}
				}
#endif
			}
			else {
				// Ok, now we have handled inflate code type 3 and inflate code 0 (50% of 'random' data)
				// We now have the 2 'hard' ones left (fixed table, and variable table)

				curDecryBuf[0] = C;

				if ((C&6) == 4) { // inflate 'code' 2  (variable table)
#if (ZIP_DEBUG==2)
					static unsigned count, found;
					++count;
#endif
					// we need 4 bytes, + 2, + 4 at most.
					for (; e < 10;) {
						key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					if (!check_inflate_CODE2(curDecryBuf))
						goto Failed_Bailout;
#if (ZIP_DEBUG==2)
					fprintf (stderr, "CODE2 Pass=%s  count = %u, found = %u\n", saved_key[idx], count, ++found);
#endif
				}
				else {
					int til;
#if (ZIP_DEBUG==2)
					static unsigned count, found;
					++count;
#endif
					til = 36;
					if (salt->H[cur_hash_idx].datlen-12 < til)
						til = salt->H[cur_hash_idx].datlen-12;
					for (; e < til;) {
						key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					if (!check_inflate_CODE1(curDecryBuf, til))
						goto Failed_Bailout;
#if (ZIP_DEBUG==2)
					fprintf (stderr, "CODE1 Pass=%s  count = %u, found = %u\n", saved_key[idx], count, ++found);
#endif
				}
			}
#if USE_PKZIP_MAGIC
			// Ok, now see if we need to check sigs, or do a FULL inflate/crc check.
			if (!SigChecked && salt->H[cur_hash_idx].pSig->max_len) {
				int til = 180;
				if (salt->H[cur_hash_idx].datlen-12 < til)
					til = salt->H[cur_hash_idx].datlen-12;
				for (; e < til;) {
					key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
					key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
					key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
					curDecryBuf[++e] = PKZ_MULT(*b++,key2);
				}
				strm.zalloc = Z_NULL; strm.zfree = Z_NULL; strm.opaque = Z_NULL; strm.next_in = Z_NULL;
				strm.avail_in = til;

				ret = inflateInit2(&strm, -15); /* 'raw', since we do not have gzip header, or gzip crc. .ZIP files are 'raw' implode data. */
				if (ret != Z_OK)
				   perror("Error, initializing the libz inflateInit2() system\n");

				strm.next_in = curDecryBuf;
				strm.avail_out = sizeof(curInfBuf);
				strm.next_out = curInfBuf;

				ret = inflate(&strm, Z_SYNC_FLUSH);

				inflateEnd(&strm);
				if (ret != Z_OK)
					goto Failed_Bailout;
				if (!strm.total_out)
					goto Failed_Bailout;

				ret = salt->H[cur_hash_idx].pSig->max_len;
				if (salt->H[cur_hash_idx].magic == 255) {
					if (!validate_ascii(curInfBuf, strm.total_out))
						goto Failed_Bailout;
				} else {
					if (strm.total_out < ret)
						goto Failed_Bailout;
					if (!CheckSigs(curInfBuf, strm.total_out, salt->H[cur_hash_idx].pSig))
						goto Failed_Bailout;
				}
			}
#endif

			if (salt->H[cur_hash_idx].full_zip) {
				u8 inflateBufTmp[1024];
				if (salt->compLen > 240 && salt->H[cur_hash_idx].datlen >= 200) {
					for (;e < 200;) {
						key0.u = pkzip_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = pkzip_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					strm.zalloc = Z_NULL; strm.zfree = Z_NULL; strm.opaque = Z_NULL; strm.next_in = Z_NULL;
					strm.avail_in = e;

					ret = inflateInit2(&strm, -15); /* 'raw', since we do not have gzip header, or gzip crc. .ZIP files are 'raw' implode data. */
					if (ret != Z_OK)
					   perror("Error, initializing the libz inflateInit2() system\n");

					strm.next_in = curDecryBuf;
					strm.avail_out = sizeof(inflateBufTmp);
					strm.next_out = inflateBufTmp;

					ret = inflate(&strm, Z_SYNC_FLUSH);
					inflateEnd(&strm);

					if (ret != Z_OK) {
#if (ZIP_DEBUG==2)
#ifdef _MSC_VER
						fprintf(stderr, "fail=%d fail2=%d tot=%lld\n", ++FAILED, FAILED2, ((long long)CNT)*_count);
#else
						fprintf(stderr, "fail=%d fail2=%d tot=%lld\n", ++FAILED, FAILED2, ((long long)CNT)*_count);
#endif
#endif
						goto Failed_Bailout;
					}
				}
				goto KnownSuccess;
			}
		}
		while(--cur_hash_count);

		/* We got a checksum HIT!!!! All hash checksums matched. */
		/* We load the proper checksum value for the gethash */
KnownSuccess: ;
		chk[idx] = 1;

		continue;

Failed_Bailout: ;
		/* We load the wrong checksum value for the gethash */
		chk[idx] = 0;
	}

	/* clear the 'dirty' flag.  Then on multiple different salt calls, we will not have to */
	/* encrypt the passwords again. They will have already been loaded in the K12[] array. */
	dirty = 0;
}

struct fmt_main fmt_pkzip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			binary_hash0,
			NULL,
			NULL,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash0,
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
