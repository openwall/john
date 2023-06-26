/*
 * PKZIP patch for john to handle 'old' pkzip passwords (old 'native' format)
 *
 * This software is Copyright (c) 2011-2018 Jim Fougeron,
 * Copyright (c) 2013-2021 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "arch.h"
#if !AC_BUILT && !__MIC__
#define HAVE_LIBZ 1 /* legacy build has -lz in LDFLAGS */
#endif

#if HAVE_LIBZ

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pkzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pkzip);
#else

#include <string.h>
#include <zlib.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "common.h"
#include "misc.h"
#include "formats.h"
#define USE_PKZIP_MAGIC 1
#include "pkzip.h"
#include "pkzip_inffixed.h"  // This file is a data file, taken from zlib
#include "loader.h"

#define FORMAT_LABEL        "PKZIP"
#define FORMAT_NAME         ""
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define FORMAT_TAG          "$pkzip$"
#define FORMAT_TAG2         "$pkzip2$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG2_LEN     (sizeof(FORMAT_TAG2)-1)

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    7

#define PLAINTEXT_LENGTH    63

#define BINARY_SIZE         0
#define BINARY_ALIGN        1

#define SALT_SIZE           (sizeof(PKZ_SALT*))
#define SALT_ALIGN          (sizeof(uint64_t))

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  64

#ifndef OMP_SCALE
#define OMP_SCALE           32 // Tuned w/ MKPC for core i7
#endif

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
 * Format spec., see zip2john.c
 */
static struct fmt_tests tests[] = {
	/* compression of a perl file. We have the same password, same file used twice in a row (pkzip, 1 byte checksum).  NOTE, pkzip uses random IV, so both encrypted blobs are different */
	{"$pkzip$1*1*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*194883130e4c7419bd735c53dec36f0c4b6de6daefea0f507d67ff7256a49b5ea93ccfd9b12f2ee99053ee0b1c9e1c2b88aeaeb6bd4e60094a1ea118785d4ded6dae94cade41199330f4f11b37cba7cda5d69529bdfa43e2700ba517bd2f7ff4a0d4b3d7f2559690ec044deb818c44844d6dd50adbebf02cec663ae8ebb0dde05d2abc31eaf6de36a2fc19fda65dd6a7e449f669d1f8c75e9daa0a3f7be8feaa43bf84762d6dbcc9424285a93cedfa3a75dadc11e969065f94fe3991bc23c9b09eaa5318aa29fa02e83b6bee26cafec0a5e189242ac9e562c7a5ed673f599cefcd398617*$/pkzip$", "password" },
	{"$pkzip$1*1*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*581f798527109cbadfca0b3318435a000be84366caf9723f841a2b13e27c2ed8cdb5628705a98c3fbbfb34552ed498c51a172641bf231f9948bca304a6be2138ab718f6a5b1c513a2fb80c49030ff1a404f7bd04dd47c684317adea4107e5d70ce13edc356c60bebd532418e0855428f9dd582265956e39a0b446a10fd8b7ffb2b4af559351bbd549407381c0d2acc270f3bcaffb275cbe2f628cb09e2978e87cd023d4ccb50caaa92b6c952ba779980d65f59f664dde2451cc456d435188be59301a5df1b1b4fed6b7509196334556c44208a9d7e2d9e237f591d6c9fc467b408bf0aaa*$/pkzip$", "password" },
	/* Now the same file, compressed twice, using unix zip (info-zip), with 2 byte checksums */
	{"$pkzip$1*2*2*0*e4*1c5*eda7a8de*0*47*8*e4*4bb6*436c9ffa4328870f6272349b591095e1b1126420c3041744650282bc4f575d0d4a5fc5fb34724e6a1cde742192387b9ed749ab5c72cd6bb0206f102e9216538f095fb773661cfde82c2e2a619332998124648bf4cd0da56279f0c297567d9b5d684125ee92920dd513fd18c27afba2a9633614f75d8f8b9a14095e3fafe8165330871287222e6681dd9c0f830cf5d464457b257d0900eed29107fad8af3ac4f87cf5af5183ff0516ccd9aeac1186006c8d11b18742dfb526aadbf2906772fbfe8fb18798967fd397a724d59f6fcd4c32736550986d227a6b447ef70585c049a1a4d7bf25*$/pkzip$", "password" },
	{"$pkzip$1*2*2*0*e4*1c5*eda7a8de*0*47*8*e4*4bb6*436c9ffa4328870f6272349b591095e1b1126420c3041744650282bc4f575d0d4a5fc5fb34724e6a1cde742192387b9ed749ab5c72cd6bb0206f102e9216538f095fb773661cfde82c2e2a619332998124648bf4cd0da56279f0c297567d9b5d684125ee92920dd513fd18c27afba2a9633614f75d8f8b9a14095e3fafe8165330871287222e6681dd9c0f830cf5d464457b257d0900eed29107fad8af3ac4f87cf5af5183ff0516ccd9aeac1186006c8d11b18742dfb526aadbf2906772fbfe8fb18798967fd397a724d59f6fcd4c32736550986d227a6b447ef70585c049a1a4d7bf25*$/pkzip$", "password"},
	/* now a pkzip archive, with 3 files, 1 byte checksum */
	{"$pkzip$3*1*1*0*8*24*4001*8986ec4d693e86c1a42c1bd2e6a994cb0b98507a6ec937fe0a41681c02fe52c61e3cc046*1*0*8*24*4003*a087adcda58de2e14e73db0043a4ff0ed3acc6a9aee3985d7cb81d5ddb32b840ea2057d9*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*89a792af804bf38e31fdccc8919a75ab6eb75d1fd6e7ecefa3c5b9c78c3d50d656f42e582af95882a38168a8493b2de5031bb8b39797463cb4769a955a2ba72abe48ee75b103f93ef9984ae740559b9bd84cf848d693d86acabd84749853675fb1a79edd747867ef52f4ee82435af332d43f0d0bb056c49384d740523fa75b86a6d29a138da90a8de31dbfa89f2f6b0550c2b47c43d907395904453ddf42a665b5f7662de170986f89d46d944b519e1db9d13d4254a6b0a5ac02b3cfdd468d7a4965e4af05699a920e6f3ddcedb57d956a6b2754835b14e174070ba6aec4882d581c9f30*$/pkzip$", "3!files"},
	/* following are from CMIYC 2012 */
	{"$pkzip$1*1*2*0*163*2b5*cd154083*0*26*8*163*cd15*d6b094794b40116a8b387c10159225d776f815b178186e51faf16fa981fddbffdfa22f6c6f32d2f81dab35e141f2899841991f3cb8d53f8ee1f1d85657f7c7a82ebb2d63182803c6beee00e0bf6c72edeeb1b00dc9f07f917bb8544cc0e96ca01503cd0fb6632c296cebe3fb9b64543925daae6b7ea95cfd27c42f6f3465e0ab2c812b9aeeb15209ce3b691f27ea43a7a77b89c2387e31c4775866a044b6da783af8ddb72784ccaff4d9a246db96484e865ea208ade290b0131b4d2dd21f172693e6b5c90f2eb9b67572b55874b6d3a78763212b248629e744c07871a6054e24ef74b6d779e44970e1619df223b4e5a72a189bef40682b62be6fb7f65e087ca6ee19d1ebfc259fa7e3d98f3cb99347689f8360294352accffb146edafa9e91afba1f119f95145738ac366b332743d4ff40d49fac42b8758c43b0af5b60b8a1c63338359ffbff432774f2c92de3f8c49bd4611e134db98e6a3f2cfb148d2b20f75abab6*$/pkzip$", "passwort"},
	{"$pkzip$1*1*2*0*163*2b6*46abc149*0*28*8*163*46ab*0f539b23b761a347a329f362f7f1f0249515f000404c77ec0b0ffe06f29140e8fa3e8e5a6354e57f3252fae3d744212d4d425dc44389dd4450aa9a4f2f3c072bee39d6ac6662620812978f7ab166c66e1acb703602707ab2da96bb28033485ec192389f213e48eda8fc7d9dad1965b097fafebfda6703117db90e0295db9a653058cb28215c3245e6e0f6ad321065bf7b8cc5f66f6f2636e0d02ea35a6ba64bbf0191c308098fd836e278abbce7f10c3360a0a682663f59f92d9c2dcfc87cde2aae27ea18a14d2e4a0752b6b51e7a5c4c8c2bab88f4fb0aba27fb20e448655021bb3ac63752fdb01e6b7c99f9223f9e15d71eb1bd8e323f522fc3da467ff0aae1aa17824085d5d6f1cdfc9c7c689cd7cb057005d94ba691f388484cfb842c8775baac220a5490ed945c8b0414dbfc4589254b856aade49f1aa386db86e9fc87e6475b452bd72c5e2122df239f8c2fd462ca54c1a5bddac36918c5f5cf0cc94aa6ee820*$/pkzip$", "Credit11"},
	{"$pkzip$1*1*2*0*163*2b6*46abc149*0*26*8*163*46ab*7ea9a6b07ddc9419439311702b4800e7e1f620b0ab8535c5aa3b14287063557b176cf87a800b8ee496643c0b54a77684929cc160869db4443edc44338294458f1b6c8f056abb0fa27a5e5099e19a07735ff73dc91c6b20b05c023b3ef019529f6f67584343ac6d86fa3d12113f3d374b047efe90e2a325c0901598f31f7fb2a31a615c51ea8435a97d07e0bd4d4afbd228231dbc5e60bf1116ce49d6ce2547b63a1b057f286401acb7c21afbb673f3e26bc1b2114ab0b581f039c2739c7dd0af92c986fc4831b6c294783f1abb0765cf754eada132df751cf94cad7f29bb2fec0c7c47a7177dea82644fc17b455ba2b4ded6d9a24e268fcc4545cae73b14ceca1b429d74d1ebb6947274d9b0dcfb2e1ac6f6b7cd2be8f6141c3295c0dbe25b65ff89feb62cb24bd5be33853b88b8ac839fdd295f71e17a7ae1f054e27ba5e60ca03c6601b85c3055601ce41a33127938440600aaa16cfdd31afaa909fd80afc8690aaf*$/pkzip$", "7J0rdan!!"},
	/* CMIYC 2013 "pro" hard hash */
	{"$pkzip$1*2*2*0*6b*73*8e687a5b*0*46*8*6b*0d9d*636fedc7a78a7f80cda8542441e71092d87d13da94c93848c230ea43fab5978759e506110b77bd4bc10c95bc909598a10adfd4febc0d42f3cd31e4fec848d6f49ab24bb915cf939fb1ce09326378bb8ecafde7d3fe06b6013628a779e017be0f0ad278a5b04e41807ae9fc*$/pkzip$", "c00rslit3!"},
	/* https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/corkami/ChristmasGIFts.zip */
	{"$pkzip2$3*2*1*2*8*c0*7224*72f6*6195f9f3401076b22f006105c4323f7ac8bb8ebf8d570dc9c7f13ddacd8f071783f6bef08e09ce4f749af00178e56bc948ada1953a0263c706fd39e96bb46731f827a764c9d55945a89b952f0503747703d40ed4748a8e5c31cb7024366d0ef2b0eb4232e250d343416c12c7cbc15d41e01e986857d320fb6a2d23f4c44201c808be107912dbfe4586e3bf2c966d926073078b92a2a91568081daae85cbcddec75692485d0e89994634c71090271ac7b4a874ede424dafe1de795075d2916eae*1*6*8*c0*26ee*461b*944bebb405b5eab4322a9ce6f7030ace3d8ec776b0a989752cf29569acbdd1fb3f5bd5fe7e4775d71f9ba728bf6c17aad1516f3aebf096c26f0c40e19a042809074caa5ae22f06c7dcd1d8e3334243bca723d20875bd80c54944712562c4ff5fdb25be5f4eed04f75f79584bfd28f8b786dd82fd0ffc760893dac4025f301c2802b79b3cb6bbdf565ceb3190849afdf1f17688b8a65df7bc53bc83b01a15c375e34970ae080307638b763fb10783b18b5dec78d8dfac58f49e3c3be62d6d54f9*2*0*2a*1e*4a204eab*ce8*2c*0*2a*4a20*7235*6b6e1a8de47449a77e6f0d126b217d6b2b72227c0885f7dc10a2fb3e7cb0e611c5c219a78f98a9069f30*$/pkzip2$", "123456"},
	{"$pkzip$1*1*2*0*14*6*775f54d8*0*47*8*14*8cd0*11b75efed56a5795f07c509268a88b4a6ff362ef*$/pkzip$", "test"},
	{NULL}
};

/* these static fields are used in the crypt_all loop, and the cmp_all/cmp_one we */
/* perform the pkzip 'checksum' checking. If we do get a 'hit', then that pass &  */
/* salt pair is checked fully within the cmp_exact, where it gets inflated  and   */
/* checked (possibly also a 'sample TEXT record is done first, as a quick check   */
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static u32  *K12;
static PKZ_SALT *salt;
static u8 *chk;
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
static int valid(char *ciphertext, struct fmt_main *self)
{
	c8 *p, *cp, *cpkeep;
	int cnt, ret=0;
	u64 data_len;
	u32 crc;
	FILE *in;
	const char *sFailStr;
	long offset;
	u32 offex;
	int type;
	u64 complen = 0;
	int type2 = 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		if (!strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG2_LEN))
			type2 = 1;
		else
			return ret;
	}

	cpkeep = xstrdup(ciphertext);
	cp = cpkeep;

	p = &cp[FORMAT_TAG_LEN];
	if (type2)
		++p;
	if ((cp = strtokm(p, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
		sFailStr = "Out of data, reading count of hashes field";
		goto Bail;
	}
	sscanf(cp, "%x", &cnt);
	if (cnt < 1 || cnt > MAX_PKZ_FILES) {
		sFailStr = "Count of hashes field out of range";
		goto Bail;
	}
	if ((cp = strtokm(NULL, "*")) == NULL || cp[0] < '0' || cp[0] > '2' || cp[1]) {
		sFailStr = "Number of valid hash bytes empty or out of range";
		goto Bail;
	}

	while (cnt--) {
		if ((cp = strtokm(NULL, "*")) == NULL || cp[0]<'1' || cp[0]>'3' || cp[1]) {
			sFailStr = "Invalid data enumeration type";
			goto Bail;
		}
		type = cp[0] - '0';
		if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
			sFailStr = "Invalid type enumeration";
			goto Bail;
		}
		if (type > 1) {
			if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
				sFailStr = "Invalid compressed length";
				goto Bail;
			}
			sscanf(cp, "%"PRIx64, &complen);
			if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
				sFailStr = "Invalid data length value";
				goto Bail;
			}
			if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
				sFailStr = "Invalid CRC value";
				goto Bail;
			}
			sscanf(cp, "%x", &crc);
			if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
				sFailStr = "Invalid offset length";
				goto Bail;
			}
			sscanf(cp, "%lx", &offset);
			if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
				sFailStr = "Invalid offset length";
				goto Bail;
			}
			sscanf(cp, "%x", &offex);
		}
		if ((cp = strtokm(NULL, "*")) == NULL || (cp[0] != '0' && cp[0] != '8') || cp[1]) {
			sFailStr = "Compression type enumeration";
			goto Bail;
		}
		if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp)) {
			sFailStr = "Invalid data length value";
			goto Bail;
		}
		sscanf(cp, "%"PRIx64, &data_len);
		if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen(cp) != 4) {
			sFailStr = "invalid checksum value";
			goto Bail;
		}
		if (type2) {
			if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen(cp) != 4) {
				sFailStr = "invalid checksum2 value";
				goto Bail;}
		}
		if ((cp = strtokm(NULL, "*")) == NULL) goto Bail;
		if (type > 1) {
			if (type == 3) {
				if (strlen(cp) != data_len) {
					sFailStr = "invalid checksum value";
					goto Bail;
				}
				in = fopen(cp, "rb"); /* have to open in bin mode for OS's where this matters, DOS/Win32 */
				if (!in) {
					/* this error is listed, even if not in pkzip debugging mode. */
					/* But not if we're just reading old pot lines */
					if (!ldr_in_pot)
						fprintf(stderr, "Error loading a pkzip hash line. The ZIP file '%s' could NOT be found\n", cp);
					return 0;
				}
				sFailStr = ValidateZipContents(in, offset, offex, complen, crc);
				if (*sFailStr) {
					/* this error is listed, even if not in pkzip debugging mode. */
					fprintf(stderr, "pkzip validation failed [%s] Hash is %s\n", sFailStr, ciphertext);
					fclose(in);
					return 0;
				}
				fseek(in, offset+offex, SEEK_SET);
				if (complen < 16*1024) {
					/* simply load the whole blob */
					void *tbuf = mem_alloc(complen);
					if (fread(tbuf, 1, complen, in) != complen) {
						MEM_FREE(tbuf);
						fclose(in);
						return 0;
					}
					data_len = complen;
					MEM_FREE(tbuf);
				}
				fclose(in);
			} else {
				/* 'inline' data. */
				if (complen != data_len) {
					sFailStr = "length of full data does not match the salt len";
					goto Bail;
				}
				if (!ishexlc(cp) || strlen(cp) != data_len<<1) {
					sFailStr = "invalid inline data";
					goto Bail;
				}
			}
		} else {
			if (!ishexlc(cp) || strlen(cp) != data_len<<1) {
				sFailStr = "invalid partial data";
				goto Bail;
			}
		}
	}
	if ((cp = strtokm(NULL, "*")) == NULL) goto Bail;
	if (strtokm(NULL, "") != NULL) goto Bail;
	if (type2) ret = !strcmp(cp, "$/pkzip2$");
	else       ret = !strcmp(cp, "$/pkzip$");

Bail:;
#ifdef ZIP_DEBUG
	if (!ret) fprintf(stderr, "pkzip validation failed [%s]  Hash is %.64s\n", sFailStr, ciphertext);
#endif
	MEM_FREE(cpkeep);
	return ret;
}

static const char *ValidateZipContents(FILE *fp, long offset, u32 offex, int _len, u32 _crc)
{
	u32 id;
	u16 version, flags, method, modtm, moddt, namelen, exlen;
	u32 crc, complen, uncomplen;

	if (fseek(fp, offset, SEEK_SET) != 0)
		return "Not able to seek to specified offset in the .zip file, to read the zip blob data.";

	id = fget32LE(fp);
	if (id != 0x04034b50U)
		return "Compressed zip file offset does not point to start of zip blob";

	/* Ok, see if this IS the correct file blob. */
	version = fget16LE(fp);
	flags = fget16LE(fp);
	method = fget16LE(fp);
	modtm = fget16LE(fp);
	moddt = fget16LE(fp);
	crc = fget32LE(fp);
	complen = fget32LE(fp);
	uncomplen = fget32LE(fp);
	namelen = fget16LE(fp);
	exlen = fget16LE(fp);

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

static u8 *buf_copy (char *p, int len)
{
	u8 *op = mem_alloc_tiny(len, MEM_ALIGN_NONE);
	memcpy(op, p, len);
	return op;
}

static void init(struct fmt_main *self)
{
#ifdef PKZIP_USE_MULT_TABLE
	unsigned short n=0;
#endif

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	K12 = mem_calloc(sizeof(*K12) * 3, self->params.max_keys_per_crypt);
	chk = mem_calloc(sizeof(*chk), self->params.max_keys_per_crypt);

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
		mult_tab[n] = (((unsigned)(n*4+3) * (n*4+2)) >> 8) & 0xff;
#endif

#if USE_PKZIP_MAGIC

	//static char *MagicTypes[]= { "", "DOC", "XLS", "DOT", "XLT", "EXE", "DLL", "ZIP", "BMP", "DIB", "GIF", "PDF", "GZ", "TGZ", "BZ2", "TZ2", "FLV", "SWF", "MP3", NULL };
	//static int  MagicToEnum[] = {0,  1,    1,     1,     1,     2,     2,     3,     4,     4,     5,     6,     7,    7,     8,     8,     9,     10,    11,  0};
	// decent sources of these:
	// http://www.garykessler.net/library/file_sigs.html
	// http://en.wikipedia.org/wiki/List_of_file_signatures
	// http://toorcon.techpathways.com/uploads/headersig.txt
	// 	not available, 2012-12-28)
	// 	archive.org still has a version:
	// 	http://web.archive.org/web/20110725085828/http://toorcon.techpathways.com/uploads/headersig.txt
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
	SIGS[10].magic_sig_len[0] = 3;
	SIGS[10].magic_signature[1] = (u8*)str_alloc_copy("CWS");
	SIGS[10].magic_sig_len[1] = 3;
	SIGS[10].magic_signature[2] = (u8*)str_alloc_copy("ZWS");
	SIGS[10].magic_sig_len[2] = 3;
	SIGS[10].magic_count = 3;
	SIGS[10].max_len = 3;
//case 11: // MP3
	SIGS[11].magic_signature[0] = (u8*)str_alloc_copy("ID3");
	SIGS[11].magic_sig_len[0] = 3;
	SIGS[11].magic_count = 1;
	SIGS[11].max_len = 3;
//case 12: // PST
	SIGS[12].magic_signature[0] = (u8*)str_alloc_copy("!BDN");
	SIGS[12].magic_sig_len[0] = 4;
	SIGS[12].magic_count = 1;
	SIGS[12].max_len = 4;

	SIGS[255].max_len = 64;
#endif
}

static void done(void)
{
	MEM_FREE(chk);
	MEM_FREE(K12);
	MEM_FREE(saved_key);
}

static void set_salt(void *_salt)
{
	int i;
	int need_fixup = 0;
	long tot_len = 0;

	salt = *((PKZ_SALT**)_salt);

	for (i = 0; i < MAX_PKZ_FILES; i++) {
		if (!salt->H[i].h) {
			need_fixup = 1;
			break;
		}
	}

	// we 'late' fixup the salt.
	if (need_fixup) {
		for (i = 0; i < MAX_PKZ_FILES; i++) {
			salt->H[i].h = &salt->zip_data[i + tot_len];
			tot_len += salt->H[i].datlen;
		}
	}
}

static void *get_salt(char *ciphertext)
{
	/* NOTE, almost NO error checking at all in this function.  Proper error checking done in valid() */
	static union alignment {
		unsigned char c[8];
		uint64_t a[1];	// salt alignment of 8 bytes required. uint64_t values in the salt.
	} a;
	unsigned char *salt_p = a.c;
	PKZ_SALT *salt, *psalt;
	long offset=0;
	char *H[MAX_PKZ_FILES] = { 0 };
	long ex_len[MAX_PKZ_FILES] = { 0 };
	long tot_len;
	u32 offex;
	size_t i, j;
	c8 *p, *cp, *cpalloc = (char*)mem_alloc(strlen(ciphertext)+1);
	int type2 = 0;

	/* Needs word align on REQ_ALIGN systems.  May crash otherwise (in the sscanf) */
	salt = mem_calloc(1, sizeof(PKZ_SALT));

	cp = cpalloc;
	strcpy(cp, ciphertext);
	if (!strncmp(cp, FORMAT_TAG, FORMAT_TAG_LEN))
		p = &cp[FORMAT_TAG_LEN];
	else {
		p = &cp[FORMAT_TAG2_LEN];
		type2 = 1;
	}
	cp = strtokm(p, "*");
	sscanf(cp, "%x", &(salt->cnt));
	cp = strtokm(NULL, "*");
	sscanf(cp, "%x", &(salt->chk_bytes));
	for (i = 0; i < salt->cnt; ++i) {
		int data_enum;

		salt->H[i].type = type2 ? 2 : 1;
		cp = strtokm(NULL, "*");
		data_enum = *cp - '0';
		cp = strtokm(NULL, "*");
#if USE_PKZIP_MAGIC
		{
			// mingw can't handle %hhx.  Use 'normal' %x and assign back to uint_8 var
			unsigned jnk;
			sscanf(cp, "%x", &jnk);
			salt->H[i].magic = (unsigned char)jnk;
		}
		salt->H[i].pSig = &SIGS[salt->H[i].magic];
#endif

		if (data_enum > 1) {
			cp = strtokm(NULL, "*");
			sscanf(cp, "%"PRIx64, &(salt->compLen));
			cp = strtokm(NULL, "*");
			sscanf(cp, "%"PRIx64, &(salt->deCompLen));
			cp = strtokm(NULL, "*");
			sscanf(cp, "%x", &(salt->crc32));
			cp = strtokm(NULL, "*");
			sscanf(cp, "%lx", &offset);
			cp = strtokm(NULL, "*");
			sscanf(cp, "%x", &offex);
		}
		cp = strtokm(NULL, "*");
		sscanf(cp, "%x", &(salt->H[i].compType));
		cp = strtokm(NULL, "*");
		sscanf(cp, "%"PRIx64, &(salt->H[i].datlen));
		cp = strtokm(NULL, "*");

		for (j = 0; j < 4; ++j) {
			salt->H[i].c <<= 4;
			salt->H[i].c |= atoi16[ARCH_INDEX(cp[j])];
		}
		if (type2) {
			cp = strtokm(NULL, "*");
			for (j = 0; j < 4; ++j) {
				salt->H[i].c2 <<= 4;
				salt->H[i].c2 |= atoi16[ARCH_INDEX(cp[j])];
			}
		}
		cp = strtokm(NULL, "*");
		if (data_enum > 1) {
			/* if 2 or 3, we have the FULL zip blob for decrypting. */
			if (data_enum == 3) {
				/* read from file. */
				FILE *fp;
				fp = fopen(cp, "rb");
				if (!fp) {
					fprintf(stderr, "Error opening file for pkzip data:  %s\n", cp);
					MEM_FREE(cpalloc);
					return 0;
				}
				fseek(fp, offset+offex, SEEK_SET);
				if (salt->compLen < 16*1024) {
					/* simply load the whole blob */
					ex_len[i] = salt->compLen;
					H[i] = mem_alloc(salt->compLen);
					if (fread(H[i], 1, salt->compLen, fp) != salt->compLen) {
						fprintf(stderr, "Error reading zip file for pkzip data:  %s\n", cp);
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
					strnzcpy(salt->fname, (const char *)cp, sizeof(salt->fname));
					salt->offset = offset+offex;
					ex_len[i] = 384;
					H[i] = mem_alloc(384);
					if (fread(H[i], 1, 384, fp) != 384) {
						fprintf(stderr, "Error reading zip file for pkzip data:  %s\n", cp);
						fclose(fp);
						MEM_FREE(cpalloc);
						return 0;
					}
					fclose(fp);
					salt->H[i].datlen = 384;
				}
			} else {
				ex_len[i] = salt->compLen;
				H[i] = mem_alloc(salt->compLen);
				for (j = 0; j < salt->H[i].datlen; ++j)
					H[i][j] = (atoi16[ARCH_INDEX(cp[j*2])]<<4) + atoi16[ARCH_INDEX(cp[j*2+1])];
			}

			/* we also load this into the 'building' salt */
			salt->compType = salt->H[i].compType;

			/* Now, set the 'is full zip' flag, so we later process as a zip file. */
			salt->H[i].full_zip = 1;
			salt->full_zip_idx = i;
		} else {
			ex_len[i] = salt->H[i].datlen;
			H[i] = mem_alloc(salt->H[i].datlen);
			for (j = 0; j < salt->H[i].datlen; ++j)
				H[i][j] = (atoi16[ARCH_INDEX(cp[j*2])]<<4) + atoi16[ARCH_INDEX(cp[j*2+1])];
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

	tot_len = 0;
	for (i = 0; i < salt->cnt; i++)
		tot_len += ex_len[i];
	tot_len += salt->cnt - 1;
	psalt = mem_calloc(1, sizeof(PKZ_SALT) + tot_len);
	memcpy(psalt, salt, sizeof(*salt));

	tot_len = 0;
	for (i = 0; i < salt->cnt; i++) {
		memcpy(psalt->zip_data + i + tot_len, H[i], ex_len[i]);
		tot_len += ex_len[i];
		MEM_FREE(H[i]);
	}
	tot_len += salt->cnt - 1;

	MEM_FREE(salt);

	psalt->dsalt.salt_alloc_needs_free = 1;  // we used mem_calloc, so JtR CAN free our pointer when done with them.

	// set the JtR core linkage stuff for this dyna_salt
	memcpy(salt_p, &psalt, sizeof(psalt));
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(PKZ_SALT, cnt);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(PKZ_SALT, cnt, zip_data, tot_len);
	return salt_p;
}

static void set_key(char *key, int index)
{
	/* Keep the PW, so we can return it in get_key if asked to do so */
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
		j+=chk[i]; /* hopefully addition like this is faster than 'count' conditional if statments */
	return j;
}

/* this function is used by cmp_exact_loadfile.  It will load the next
 * part of the file then decrypt the data, and return just how many
 * bytes were loaded.
 *
 * This function is 'similar' to an fread().  However, it also decrypts data
 */
static int get_next_decrypted_block(u8 *in, int sizeof_n, FILE *fp, u32 *inp_used, MY_WORD *pkey0, MY_WORD *pkey1, MY_WORD *pkey2)
{
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
		pkey0->u = jtr_crc32 (pkey0->u, C);
		pkey1->u = (pkey1->u + pkey0->c[KB1]) * 134775813 + 1;
		pkey2->u = jtr_crc32 (pkey2->u, pkey1->c[KB2]);
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
static int cmp_exact_loadfile(int index)
{
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
		fprintf(stderr, "\nERROR, the zip file: %s has been removed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		return 1;
	}
	if (fseek(fp, salt->offset, SEEK_SET)) {
		fprintf(stderr, "\nERROR, the zip file: %s fseek() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		fclose(fp);
		return 1;
	}

	/* 'seed' the decryption with the IV. We do NOT use these bytes, they simply seed us. */
	key0.u = K12[index*3], key1.u = K12[index*3+1], key2.u = K12[index*3+2];
	k=12;
	if (fread(in, 1, 12, fp) != 12) {
		fprintf(stderr, "\nERROR, the zip file: %s fread() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
		fclose(fp);
		return 1;
	}

	b = salt->H[salt->full_zip_idx].h;
	do {
		C = PKZ_MULT(*b++,key2);
		key0.u = jtr_crc32 (key0.u, C);
		key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
		key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
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
				crc = jtr_crc32(crc,in[k]);
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
			fprintf(stderr, "\nERROR, the zip file: %s fread() failed.\nWe are a possible password has been found, but FULL validation can not be done!\n", salt->fname);
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
				crc = jtr_crc32(crc,out[k]);
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

	if (salt->fname[0] == 0) {
		/* we have the whole zip blob in memory, simply allocate a decrypt buffer, decrypt
		 * in one step, crc and be done with it. This is the 'trivial' type. */

		decrBuf = mem_alloc(salt->compLen-12);

		key0.u = K12[index*3], key1.u = K12[index*3+1], key2.u = K12[index*3+2];

		b = salt->H[salt->full_zip_idx].h;
		k=12;
		do {
			C = PKZ_MULT(*b++,key2);
			key0.u = jtr_crc32 (key0.u, C);
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
		}
		while(--k);
		B = decrBuf;
		k = salt->compLen-12;
		do {
			C = PKZ_MULT(*b++,key2);
			key0.u = jtr_crc32 (key0.u, C);
			*B++ = C;
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
		} while (--k);

		if (salt->H[salt->full_zip_idx].compType == 0) {
			// handle a stored blob (we do not have to decrypt it.
			crc = 0xFFFFFFFF;
			for (k = 0; k < salt->compLen-12; ++k)
				crc = jtr_crc32(crc,decrBuf[k]);
			MEM_FREE(decrBuf);
			return ~crc == salt->crc32;
		}

		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.next_in = Z_NULL;
		strm.avail_in = 0;

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
			crc = jtr_crc32(crc,decompBuf[k]);
		MEM_FREE(decompBuf);
		MEM_FREE(decrBuf);
		return ~crc == salt->crc32;
	}
	/* we have a stand alone function to handle this more complex method of
	 * loading from file, decrypting, decompressing, and crc'ing the data
	 * It is complex enough of a task, to have its own function. */
	return cmp_exact_loadfile(index);
}

#if USE_PKZIP_MAGIC
const char exBytesUTF8[64] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};

static int isLegalUTF8_char(const u8 *source, int length)
{
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
	case 2: if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return -1;

		switch (*source) {
			/* no fall-through in this inner switch */
		case 0xE0: if (a < 0xA0) return -1;
			break;
		case 0xED: if (a > 0x9F) return -1;
			break;
		case 0xF0: if (a < 0x90) return -1;
			break;
		case 0xF4: if (a > 0x8F) return -1;
		}

	case 1: if (*source >= 0x80 && *source < 0xC2) return -1;
	}
	if (*source > 0xF4) return -1;
	return len+1;
}

static int validate_ascii(const u8 *out, int inplen)
{
	int i;
	int unicode=0;

	for (i = 0; i < inplen-1; ++i) {
		if (out[i] > 0x7E) {
			// first check to 'see' if this is a valid utf8 character.  If so, let it 'pass'.
			if (unicode)
				return 0; // in unicode mode, we ONLY handle 'ascii' bytes in the low byte.

			if (out[i] > 0xC0) {
				int len;
				if (i > inplen-4)
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

static int CheckSigs(const u8 *p, int len, ZIP_SIGS *pSig)
{
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

/* note, Buf is the 'full' decrypted zip buffer (len bytes long). It DOES contain the first 3 bits, which have already
 * been decoded, and have told us we had a code 2 (var table block)
 * all done without BITS(), PULLBYTE(), BITSNEEDED() macros.  We 'know' the data we need, and we know that we have
 * 'enough', so we do not worry about all of the overhead, and validation logic.
 *
 * In testing, this function catches ALL bad decryptions, except about 1/300 to 1/350. So, it is not too bad.
 */
MAYBE_INLINE static int check_inflate_CODE2(u8 *next)
{
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

	if (257+(hold&0x1F) > 286)
		return 0;	// nlen, but we do not use it.
	hold >>= 5;
	if (1+(hold&0x1F) > 30)
		return 0;		// ndist, but we do not use it.
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
	if (!ncount[0] && !ncount[1])
		return 0; /* if no codes at all, then simply bail, that is invalid */

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

/* This function handles inflate CODE type 1. This is a 'fixed' table code.  We set the fixed table, */
/* and then inflate some data (without writing anything.  If we find any BAD lookback data, we can   */
/* return a failure.  We have 24 bytes of inflate data, and this almost always is more than enough   */
/* to turn up an error.  If we find we need more, we will do more than 24                            */
MAYBE_INLINE static int check_inflate_CODE1(u8 *next, int left)
{
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
//          dodist:
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

				//***** start of patched code from Pavel Semjanov (see original code below)
				whave += len;
			}
			else
				return 0;		/*invalid distance code*/
		}
		else if (op & 32) {
			// end of block [may present in short sequences, but only at the end.] NOTE, we need to find out if we EVER hit the end of a block, at only 24 bytes???
			if (left == 0)
				return 1;
			return 0;
		}
		else {
			return 0; // invalid literal/length code.
		}
		//***** End of patched code from Pavel
	}
}

// original code block (for above), prior to patch from Pavel Semjanov [pavel@semjanov.com]
// this code would be a direct drop in between the comments starting and stopping with //***** above
// also the dodist label was commented out (no longer used).
#if 0
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
#endif

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
static int crypt_all(int *pcount, struct db_salt *_salt)
{
	const int _count = *pcount;
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
				key0.u = jtr_crc32 (key0.u, *p++);
				key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
				key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
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
				key0.u = jtr_crc32 (key0.u, C);
				key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
				key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
			}
			while(--k);

			if (salt->H[cur_hash_idx].type == 2) {
				u16 e2 = salt->H[cur_hash_idx].c2;

				if (salt->chk_bytes == 2 && C != (e & 0xff) && C != (e2 & 0xff))
					goto Failed_Bailout;

				C = PKZ_MULT(*b++, key2);

				if (C != (e >> 8) && C != (e2 >> 8))
					goto Failed_Bailout;
			} else {
				if (salt->chk_bytes == 2 && C != (e & 0xff))
					goto Failed_Bailout;

				C = PKZ_MULT(*b++, key2);

				if (C != (e >> 8))
					goto Failed_Bailout;
			}

			// Now, update the key data (with that last byte.
			key0.u = jtr_crc32 (key0.u, C);
			key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
			key2.u = jtr_crc32 (key2.u, key1.c[KB2]);

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
			SigChecked = 0;
			if (salt->H[cur_hash_idx].compType == 0) {
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
						key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
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
#if 1
			// https://github.com/openwall/john/issues/467
			// Ok, if this is a code 3, we are done.
			// Code moved to after the check for stored type.  (FIXED)  This check was INVALID for a stored type file.
			if ((C & 6) == 6)
				goto Failed_Bailout;
#endif
			if ((C & 6) == 0) {
				// Check that checksum2 is 0 or 1.  If not, I 'think' we can be done
				if (C > 1)
					goto Failed_Bailout;
				// now get 4 bytes.  This is the length.  It is made up of 2 16 bit values.
				// these 2 values are checksumed, so it is easy to tell if the data is WRONG.
				// correct data is u16_1 == (u16_2^0xFFFF)
				curDecryBuf[0] = C;
				for (e = 0; e <= 4;) {
					key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
					key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
					key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
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
						key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
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

				if ((C & 6) == 4) { // inflate 'code' 2  (variable table)
#if (ZIP_DEBUG==2)
					static unsigned count, found;
					++count;
#endif
					// we need 4 bytes, + 2, + 4 at most.
					for (; e < 10;) {
						key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					if (!check_inflate_CODE2(curDecryBuf))
						goto Failed_Bailout;
#if (ZIP_DEBUG==2)
					fprintf(stderr, "CODE2 Pass=%s  count = %u, found = %u\n", saved_key[idx], count, ++found);
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
						key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					if (!check_inflate_CODE1(curDecryBuf, til))
						goto Failed_Bailout;
#if (ZIP_DEBUG==2)
					fprintf(stderr, "CODE1 Pass=%s  count = %u, found = %u\n", saved_key[idx], count, ++found);
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
					key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
					key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
					key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
					curDecryBuf[++e] = PKZ_MULT(*b++,key2);
				}
				strm.zalloc = Z_NULL;
				strm.zfree = Z_NULL;
				strm.opaque = Z_NULL;
				strm.next_in = Z_NULL;
				strm.avail_in = til;

				ret = inflateInit2(&strm, -15); /* 'raw', since we do not have gzip header, or gzip crc. .ZIP files are 'raw' implode data. */
				if (ret != Z_OK)
					perror("Error, initializing the libz inflateInit2() system\n");

				strm.next_in = curDecryBuf;
				strm.avail_out = sizeof(curInfBuf);
				strm.next_out = curInfBuf;

				ret = inflate(&strm, Z_SYNC_FLUSH);

				inflateEnd(&strm);
				if (ret != Z_OK) {
					// we need to handle zips smaller than sizeof curInfBuf.  If we find a zip of this
					// size, the return is Z_STREAM_END, BUT things are fine.
					if (ret == Z_STREAM_END && salt->deCompLen == strm.total_out)
						; // things are ok.
					else
						goto Failed_Bailout;
				}
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
						key0.u = jtr_crc32 (key0.u, curDecryBuf[e]);
						key1.u = (key1.u + key0.c[KB1]) * 134775813 + 1;
						key2.u = jtr_crc32 (key2.u, key1.c[KB2]);
						curDecryBuf[++e] = PKZ_MULT(*b++,key2);
					}
					strm.zalloc = Z_NULL;
					strm.zfree = Z_NULL;
					strm.opaque = Z_NULL;
					strm.next_in = Z_NULL;
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
						fprintf(stderr, "fail=%d fail2=%d tot="LLd"\n", ++FAILED, FAILED2, ((long long)CNT)*_count);
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

	return _count;
}

struct fmt_main fmt_pkzip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG2 },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#else

#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning pkzip format requires zlib to function. The format has been disabled
#elif _MSC_VER
#pragma message(": warning pkzip format requires zlib to function. The format has been disabled :")
#endif
#endif

#endif /* HAVE_LIBZ */
