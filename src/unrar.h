/*
 * Extract RAR archives
 *
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 * Copyright (C) 2005-2006 trog@uncon.org
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */

#ifndef UNRAR_H
#define UNRAR_H 1

#include "arch.h"

#include <sys/types.h>

struct unpack_data_tag;

#include "aes.h"
#include "unrarhlp.h"
#include "unrarppm.h"
#include "unrarvm.h"
#include "unrarcmd.h"
#include "unrarfilter.h"

#define SIZEOF_MARKHEAD 7
#define SIZEOF_NEWMHD 13
#define SIZEOF_NEWLHD 32
#define SIZEOF_SHORTBLOCKHEAD 7
#define SIZEOF_LONGBLOCKHEAD 11
#define SIZEOF_SUBBLOCKHEAD 14
#define SIZEOF_COMMHEAD 13
#define SIZEOF_PROTECTHEAD 26
#define SIZEOF_AVHEAD 14
#define SIZEOF_SIGNHEAD 15
#define SIZEOF_UOHEAD 18
#define SIZEOF_MACHEAD 22
#define SIZEOF_EAHEAD 24
#define SIZEOF_BEEAHEAD 24
#define SIZEOF_STREAMHEAD 26

#define MHD_VOLUME		0x0001
#define MHD_COMMENT		0x0002
#define MHD_LOCK		0x0004
#define MHD_SOLID		0x0008
#define MHD_PACK_COMMENT	0x0010
#define MHD_NEWNUMBERING	0x0010
#define MHD_AV			0x0020
#define MHD_PROTECT		0x0040
#define MHD_PASSWORD		0x0080
#define MHD_FIRSTVOLUME		0x0100
#define MHD_ENCRYPTVER		0x0200

#define LHD_SPLIT_BEFORE	0x0001
#define LHD_SPLIT_AFTER		0x0002
#define LHD_PASSWORD		0x0004
#define LHD_COMMENT		0x0008
#define LHD_SOLID		0x0010

#define LONG_BLOCK         0x8000

#define NC                 299  /* alphabet = {0, 1, 2, ..., NC - 1} */
#define DC                 60
#define RC		    28
#define LDC		    17
#define BC		    20
#define HUFF_TABLE_SIZE    (NC+DC+RC+LDC)

#define MAX_BUF_SIZE        32768
#define MAXWINSIZE          0x400000
#define MAXWINMASK          (MAXWINSIZE-1)
#define LOW_DIST_REP_COUNT  16

typedef struct mark_header_tag
{
	unsigned char mark[SIZEOF_MARKHEAD];
} mark_header_t;

struct Decode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[2];
};

struct LitDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[NC];
};

struct DistDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[DC];
};

struct LowDistDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[LDC];
};

struct RepDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[RC];
};

struct BitDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[BC];
};

struct UnpackFilter
{
  unsigned int block_start;
  unsigned int block_length;
  unsigned int exec_count;
  int next_window;
  struct rarvm_prepared_program prg;
};

typedef struct unpack_data_tag
{
	unsigned char in_buf[MAX_BUF_SIZE];
	unsigned char window[MAXWINSIZE];
	int in_addr;
	int in_bit;
	unsigned int unp_ptr;
	unsigned int wr_ptr;
	int tables_read;
	int read_top;
	int read_border;
	int unp_block_type;
	int prev_low_dist;
	int low_dist_rep_count;
	unsigned char unp_old_table[HUFF_TABLE_SIZE];
	union {
		struct LitDecode LD;
		struct Decode D;
	} LD;
	union {
		struct DistDecode DD;
		struct Decode D;
	} DD;
	union {
		struct LowDistDecode LDD;
		struct Decode D;
	} LDD;
	union {
		struct RepDecode RD;
		struct Decode D;
	} RD;
	union {
		struct BitDecode BD;
		struct Decode D;
	} BD;
	unsigned int old_dist[4];
	unsigned int old_dist_ptr;
	unsigned int last_dist;
	unsigned int last_length;
	ppm_data_t ppm_data;
	int ppm_esc_char;
	rar_filter_array_t Filters;
	rar_filter_array_t PrgStack;
	int *old_filter_lengths;
	unsigned int last_filter, old_filter_lengths_size;
	long long written_size;
	long long true_size;
	long long max_size;
	long long dest_unp_size;
	rarvm_data_t rarvm_data;
	unsigned int unp_crc;
	unsigned int pack_size;
	AES_KEY *ctx;
	unsigned char *key;
	unsigned char *iv;
} unpack_data_t;

typedef enum
{
	ALL_HEAD=0,
	MARK_HEAD=0x72,
	MAIN_HEAD=0x73,
	FILE_HEAD=0x74,
	COMM_HEAD=0x75,
	AV_HEAD=0x76,
	SUB_HEAD=0x77,
	PROTECT_HEAD=0x78,
	SIGN_HEAD=0x79,
	NEWSUB_HEAD=0x7a,
	ENDARC_HEAD=0x7b
} header_type;

enum BLOCK_TYPES
{
	BLOCK_LZ,
	BLOCK_PPM
};

// returns one (aligned) char of data regardless where inside it the bit pointer points
unsigned int rar_get_char(const unsigned char **fd, unpack_data_t *unpack_data);
// add bits to counters
void rar_addbits(unpack_data_t *unpack_data, int bits);
// returns next 16 bits of data
unsigned int rar_getbits(unpack_data_t *unpack_data);
int rar_unp_read_buf(const unsigned char **fd, unpack_data_t *unpack_data);
void rar_unpack_init_data(int solid, unpack_data_t *unpack_data);
void rar_make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size);
void rar_unp_write_buf_old(unpack_data_t *unpack_data);
int rar_decode_number(unpack_data_t *unpack_data, struct Decode *decode);
void rar_init_filters(unpack_data_t *unpack_data);
int rar_unpack29(const unsigned char *fd, int solid, unpack_data_t *unpack_data);

#endif
