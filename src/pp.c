/*
 * Implementation in John the Ripper Copyright (c) 2015, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * The MIT License (MIT)
 * Copyright (c) 2015 Jens Steube
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#include <sys/mman.h>
#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64
#define __USE_MINGW_ANSI_STDIO 1
#ifdef __SIZEOF_INT128__
#define HAVE___INT128 1
#endif
#endif

#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#if !AC_BUILT
#include <string.h>
#ifndef _MSC_VER
#include <strings.h>
#endif
#else
#if STRING_WITH_STRINGS
#include <string.h>
#include <strings.h>
#elif HAVE_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif
#endif
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#ifndef JTR_MODE
#include <getopt.h>
#endif
#include <ctype.h>
#include <signal.h>

#if HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
#include "mpz_int128.h"
#define REALGMP "int128"
#else
#define REALGMP "GMP"
#if HAVE_GMP_GMP_H
#include <gmp/gmp.h>
#else
#include <gmp.h>
#endif
#endif

/**
 * Name........: princeprocessor (pp)
 * Description.: Standalone password candidate generator using the PRINCE algorithm
 * Version.....: 0.22
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Steve Thomas (Sc00bz)
 *               magnum <john.magnum@hushmail.com>
 * License.....: MIT
 */

#ifdef JTR_MODE

#include "os.h"

#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "arch.h"
#include "jumbo.h"
#include "misc.h"
#include "config.h"
#include "math.h"
#include "params.h"
#include "common.h"
#include "path.h"
#include "signals.h"
#include "mem_map.h"
#include "memory.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "external.h"
#include "cracker.h"
#include "suppressor.h"
#include "john.h"
#include "unicode.h"
#include "prince.h"
#include "rpp.h"
#include "rules.h"
#include "mask.h"
#include "regex.h"

#define _STR_VALUE(arg) #arg
#define STR_MACRO(n)    _STR_VALUE(n)

int prince_elem_cnt_min;
int prince_elem_cnt_max;
int prince_wl_max;
char *prince_skip_str;
char *prince_limit_str;

static double progress;
static char *mem_map, *map_pos, *map_end;
#if HAVE_REXGEN
static char *regex_alpha;
static int regex_case;
static char *regex;
#endif

#else

#undef MIN
#undef MAX

#endif

#define IN_LEN_MIN    1
#define IN_LEN_MAX    32
#define OUT_LEN_MAX   32 /* Limited by (u32)(1 << pw_len - 1) */
#define PW_MIN        1
#define PW_MAX        16
#define ELEM_CNT_MIN  1
#define ELEM_CNT_MAX  8
#define WL_DIST_LEN   0
#define WL_MAX        10000000
#define CASE_PERMUTE  0
#define DUPE_CHECK    1
#define SAVE_POS      1
#define SAVE_FILE     "pp.save"

#define VERSION_BIN   22

#define ALLOC_NEW_ELEMS  0x40000
#define ALLOC_NEW_CHAINS 0x10
#define ALLOC_NEW_DUPES  0x100000

#define ENTRY_END_HASH   0xFFFFFFFF

#ifndef JTR_MODE
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct
{
  int len;
  u64 cnt;

} pw_order_t;

typedef struct
{
  u8   *buf;

} elem_t;

typedef struct
{
  u8   *buf;
  int   cnt;

  mpz_t ks_cnt;
  mpz_t ks_pos;

} chain_t;

typedef struct
{
  u32 next;

  char *element;

} uniq_data_t;

typedef struct
{
  u32 index;
  u32 alloc;

  u32 *hash;
  u32 hash_mask;

  uniq_data_t *data;

} uniq_t;

typedef struct
{
  elem_t  *elems_buf;
  u64      elems_cnt;
  u64      elems_alloc;

  chain_t *chains_buf;
  int      chains_cnt;
  int      chains_pos;
  int      chains_alloc;

  u64      cur_chain_ks_poses[OUT_LEN_MAX];

  uniq_t  *uniq;

} db_entry_t;

#ifndef JTR_MODE
typedef struct
{
  FILE *fp;

  char  buf[BUFSIZ];
  int   len;

} out_t;
#endif

/**
 * Default word-length distribution, calculated out of first 1,000,000 entries of rockyou.txt
 */

#define DEF_WORDLEN_DIST_CNT 25

static u64 DEF_WORDLEN_DIST[DEF_WORDLEN_DIST_CNT] =
{
  0,
  15,
  56,
  350,
  3315,
  43721,
  276252,
  201748,
  226412,
  119885,
  75075,
  26323,
  13373,
  6353,
  3540,
  1877,
  972,
  311,
  151,
  81,
  66,
  21,
  16,
  13,
  13
};

#ifndef JTR_MODE
/* Losely based on rockyou-with-dupes */
static const u32 DEF_HASH_LOG_SIZE[33] =
{  0,
   8, 12, 16, 20, 24, 24, 24, 24,
  24, 24, 23, 22, 21, 20, 19, 18,
  17, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16
};

static const char *USAGE_MINI[] =
{
  "Usage: %s [options] [<] wordlist",
  "",
  "Try --help for more help.",
  NULL
};

static const char *USAGE_BIG[] =
{
  "Usage: %s [options] [<] wordlist",
  "",
  "* Startup:",
  "",
  "  -V,  --version             Print version",
  "  -h,  --help                Print help",
  "",
  "* Misc:",
  "",
  "       --keyspace            Calculate number of combinations",
  "",
  "* Optimization:",
  "",
  "       --pw-min=NUM          Print candidate if length is greater than NUM",
  "       --pw-max=NUM          Print candidate if length is smaller than NUM",
  "       --elem-cnt-min=NUM    Minimum number of elements per chain",
  "       --elem-cnt-max=NUM    Maximum number of elements per chain",
  "       --wl-dist-len         Calculate output length distribution from wordlist",
  "       --wl-max=NUM          Load only NUM words from input wordlist or use 0 to disable",
  "  -c,  --dupe-check-disable  Disable dupes check for faster initial load",
  "       --save-pos-disable    Save the position for later resume with -s",
  "",
  "* Resources:",
  "",
  "  -s,  --skip=NUM            Skip NUM passwords from start (for distributed)",
  "  -l,  --limit=NUM           Limit output to NUM passwords (for distributed)",
  "",
  "* Files:",
  "",
  "  -o,  --output-file=FILE    Output-file",
  "",
  "* Amplifier:",
  "",
  "       --case-permute        For each word in the wordlist that begins with a letter",
  "                             generate a word with the opposite case of the first letter",
  "",
  NULL
};

static void *mem_alloc (const size_t size)
{
  void *res = malloc (size);

  if (res == NULL)
  {
    fprintf (stderr, "malloc: %s\n", strerror (ENOMEM));

    exit (-1);
  }

  return res;
}

static void *malloc_tiny (const size_t size)
{
  #ifdef DEBUG
  #define MEM_ALLOC_SIZE 0 /* It's hard to debug BOF with tiny alloc */
  #else
  #define MEM_ALLOC_SIZE 0x10000
  #endif

  if (size > MEM_ALLOC_SIZE)
  {
    // we can't handle it here

    return mem_alloc (size);
  }

  static char *buffer  = NULL;
  static size_t bufree = 0;

  if (size > bufree)
  {
    buffer = mem_alloc (MEM_ALLOC_SIZE);
    bufree = MEM_ALLOC_SIZE;
  }

  char *p = buffer;

  buffer += size;
  bufree -= size;

  return p;
}

static void usage_mini_print (const char *progname)
{
  int i;

  for (i = 0; USAGE_MINI[i] != NULL; i++)
  {
    printf (USAGE_MINI[i], progname);

    #ifdef OSX
    putchar ('\n');
    #endif

    #ifdef LINUX
    putchar ('\n');
    #endif

    #ifdef WINDOWS
    putchar ('\r');
    putchar ('\n');
    #endif
  }
}

static void usage_big_print (const char *progname)
{
  int i;

  for (i = 0; USAGE_BIG[i] != NULL; i++)
  {
    printf (USAGE_BIG[i], progname);

    #ifdef OSX
    putchar ('\n');
    #endif

    #ifdef LINUX
    putchar ('\n');
    #endif

    #ifdef WINDOWS
    putchar ('\r');
    putchar ('\n');
    #endif
  }
}
#else
#define malloc_tiny(size) mem_alloc_tiny(size, MEM_ALIGN_NONE)
#endif

static void check_realloc_elems (db_entry_t *db_entry)
{
  if (db_entry->elems_cnt == db_entry->elems_alloc)
  {
    const u64 elems_alloc = db_entry->elems_alloc;

    const u64 elems_alloc_new = elems_alloc + ALLOC_NEW_ELEMS;

    db_entry->elems_buf = (elem_t *) realloc (db_entry->elems_buf, elems_alloc_new * sizeof (elem_t));

    if (db_entry->elems_buf == NULL)
    {
#ifdef JTR_MODE
      fprintf (stderr, "Out of memory trying to allocate "Zu" bytes\n", (size_t) elems_alloc_new * sizeof (elem_t));
#else
      fprintf (stderr, "Out of memory trying to allocate %zu bytes\n", (size_t) elems_alloc_new * sizeof (elem_t));
#endif

#ifndef JTR_MODE
      exit (-1);
#else
      error();
#endif
    }

    memset (&db_entry->elems_buf[elems_alloc], 0, ALLOC_NEW_ELEMS * sizeof (elem_t));

    db_entry->elems_alloc = elems_alloc_new;
  }
}

static void check_realloc_chains (db_entry_t *db_entry)
{
  if (db_entry->chains_cnt == db_entry->chains_alloc)
  {
    const u64 chains_alloc = db_entry->chains_alloc;

    const u64 chains_alloc_new = chains_alloc + ALLOC_NEW_CHAINS;

    db_entry->chains_buf = (chain_t *) realloc (db_entry->chains_buf, chains_alloc_new * sizeof (chain_t));

    if (db_entry->chains_buf == NULL)
    {
#ifdef JTR_MODE
      fprintf (stderr, "Out of memory trying to allocate "Zu" bytes\n", (size_t) chains_alloc_new * sizeof (chain_t));
#else
      fprintf (stderr, "Out of memory trying to allocate %zu bytes\n", (size_t) chains_alloc_new * sizeof (chain_t));
#endif

#ifndef JTR_MODE
      exit (-1);
#else
      error();
#endif
    }

    memset (&db_entry->chains_buf[chains_alloc], 0, ALLOC_NEW_CHAINS * sizeof (chain_t));

    db_entry->chains_alloc = chains_alloc_new;
  }
}

static int in_superchop (char *buf)
{
  int len = strlen (buf);

  while (len)
  {
    if (buf[len - 1] == '\n')
    {
      len--;

      continue;
    }

    if (buf[len - 1] == '\r')
    {
      len--;

      continue;
    }

    break;
  }

  buf[len] = 0;

  return len;
}

#ifndef JTR_MODE
static void out_flush (out_t *out)
{
  const size_t n = fwrite (out->buf, 1, out->len, out->fp);

  if (n != (size_t) out->len)
  {
    const int err = ferror (out->fp);

    if (err == EPIPE)
    {
     // out->fp is probably closed

      exit (0);
    }

    exit (-1);
  }

  out->len = 0;
}

static void out_push (out_t *out, const char *pw_buf, const int pw_len)
{
  memcpy (out->buf + out->len, pw_buf, pw_len);

  out->len += pw_len;

  if (out->len >= BUFSIZ - 100)
  {
    out_flush (out);
  }
}
#endif

static int sort_by_cnt (const void *p1, const void *p2)
{
  const pw_order_t *o1 = (const pw_order_t *) p1;
  const pw_order_t *o2 = (const pw_order_t *) p2;

  // Descending order
  if (o1->cnt > o2->cnt) return -1;
  if (o1->cnt < o2->cnt) return  1;

  return 0;
}

static int sort_by_ks (const void *p1, const void *p2)
{
  const chain_t *f1 = (const chain_t *) p1;
  const chain_t *f2 = (const chain_t *) p2;

  return mpz_cmp (f1->ks_cnt, f2->ks_cnt);
}

static int chain_valid_with_db (const chain_t *chain_buf, const db_entry_t *db_entries)
{
  const u8 *buf = chain_buf->buf;
  const int cnt = chain_buf->cnt;

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    if (db_entry->elems_cnt == 0) return 0;
  }

  return 1;
}

static int chain_valid_with_cnt_min (const chain_t *chain_buf, const int elem_cnt_min)
{
  const int cnt = chain_buf->cnt;

  if (cnt < elem_cnt_min) return 0;

  return 1;
}

static int chain_valid_with_cnt_max (const chain_t *chain_buf, const int elem_cnt_max)
{
  const int cnt = chain_buf->cnt;

  if (cnt > elem_cnt_max) return 0;

  return 1;
}

static void chain_ks (const chain_t *chain_buf, const db_entry_t *db_entries, mpz_t *ks_cnt)
{
  const u8 *buf = chain_buf->buf;
  const int cnt = chain_buf->cnt;

  mpz_set_si (*ks_cnt, 1);

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    mpz_mul_ui (*ks_cnt, *ks_cnt, elems_cnt);
  }
}

static void set_chain_ks_poses (const chain_t *chain_buf, const db_entry_t *db_entries, mpz_t *tmp, u64 cur_chain_ks_poses[OUT_LEN_MAX])
{
  const u8 *buf = chain_buf->buf;

  const int cnt = chain_buf->cnt;

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    cur_chain_ks_poses[idx] = mpz_fdiv_ui (*tmp, elems_cnt);

    mpz_div_ui (*tmp, *tmp, elems_cnt);
  }
}

static void chain_set_pwbuf_init (const chain_t *chain_buf, const db_entry_t *db_entries, const u64 cur_chain_ks_poses[OUT_LEN_MAX], char *pw_buf)
{
  const u8 *buf = chain_buf->buf;

  const u32 cnt = chain_buf->cnt;

  for (u32 idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_idx = cur_chain_ks_poses[idx];

    memcpy (pw_buf, db_entry->elems_buf[elems_idx].buf, db_key);

    pw_buf += db_key;
  }
}

static void chain_set_pwbuf_increment (const chain_t *chain_buf, const db_entry_t *db_entries, u64 cur_chain_ks_poses[OUT_LEN_MAX], char *pw_buf)
{
  const u8 *buf = chain_buf->buf;

  const int cnt = chain_buf->cnt;

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    cur_chain_ks_poses[idx]++;

    const u64 elems_idx = cur_chain_ks_poses[idx];

    if (elems_idx < elems_cnt)
    {
      memcpy (pw_buf, db_entry->elems_buf[elems_idx].buf, db_key);

      break;
    }

    cur_chain_ks_poses[idx] = 0;

    memcpy (pw_buf, db_entry->elems_buf[0].buf, db_key);

    pw_buf += db_key;
  }
}

static void chain_gen_with_idx (chain_t *chain_buf, const int len1, const int chains_idx)
{
  chain_buf->cnt = 0;

  u8 db_key = 1;

  for (int chains_shr = 0; chains_shr < len1; chains_shr++)
  {
    if ((chains_idx >> chains_shr) & 1)
    {
      chain_buf->buf[chain_buf->cnt] = db_key;

      chain_buf->cnt++;

      db_key = 1;
    }
    else
    {
      db_key++;
    }
  }

  chain_buf->buf[chain_buf->cnt] = db_key;

  chain_buf->cnt++;
}

static char *add_elem (db_entry_t *db_entry, char *input_buf, int input_len)
{
  check_realloc_elems (db_entry);

  elem_t *elem_buf = &db_entry->elems_buf[db_entry->elems_cnt];

#ifndef JTR_MODE
  elem_buf->buf = malloc_tiny (input_len);

  memcpy (elem_buf->buf, input_buf, input_len);
#else
  if (mem_map && options.input_enc == options.target_enc)
  {
    elem_buf->buf = (u8*)input_buf;
  }
  else
  {
    elem_buf->buf = malloc_tiny (input_len);

    memcpy (elem_buf->buf, input_buf, input_len);
  }
#endif

  db_entry->elems_cnt++;

  return (char *) elem_buf->buf;
}

static u32 input_hash (char *input_buf, int input_len, const int hash_mask)
{
  u32 h = 0;

  for (int i = 0; i < input_len; i++)
  {
    h = (h * 33) + input_buf[i];
  }

  return h & hash_mask;
}

static void add_uniq (db_entry_t *db_entry, char *input_buf, int input_len)
{
  uniq_t *uniq = db_entry->uniq;

  const u32 h = input_hash (input_buf, input_len, uniq->hash_mask);

  u32 cur = uniq->hash[h];

  u32 prev = cur;

  while (cur != ENTRY_END_HASH)
  {
    if (memcmp (input_buf, uniq->data[cur].element, input_len) == 0) return;

    prev = cur;

    cur = uniq->data[cur].next;
  }

  const u32 index = uniq->index;

  if (prev == ENTRY_END_HASH)
  {
    uniq->hash[h] = index;
  }
  else
  {
    uniq->data[prev].next = index;
  }

  if (index == uniq->alloc)
  {
    uniq->alloc += ALLOC_NEW_DUPES;

    uniq->data = realloc (uniq->data, uniq->alloc * sizeof (uniq_data_t));
  }

  uniq->data[index].element = add_elem (db_entry, input_buf, input_len);
  uniq->data[index].next    = ENTRY_END_HASH;

  uniq->index++;
}

mpz_t save;

#ifndef JTR_MODE
static void catch_int (int signum)
{
  FILE *fp = fopen (SAVE_FILE, "w");

  if (fp == NULL) fp = stderr;

  mpz_out_str (fp, 10, save);

  fprintf (fp, "\n");

  fclose (fp);

  exit (signum==0?0:signum);
}

int main (int argc, char *argv[])
#else
static mpf_t count;
static mpz_t rec_pos;
static mpz_t hybrid_rec_pos;
static int rec_pos_destroyed;
static int rule_count;
static struct list_main *rule_list;

static void save_state(FILE *file)
{
  mpz_t half; mpz_init(half);

  mpz_fdiv_r_2exp(half, rec_pos, 64); // lower 64 bits
  fprintf(file, "%"PRIu64"\n", (uint64_t)mpz_get_ui(half));

  mpz_fdiv_q_2exp(half, rec_pos, 64); // upper 64 bits
  fprintf(file, "%"PRIu64"\n", (uint64_t)mpz_get_ui(half));
}

static int restore_state(FILE *file)
{
  uint64_t temp;
  mpz_t hi;

  if (fscanf(file, "%"PRIu64"\n", &temp) != 1)
    return 1;
  mpz_set_ui(rec_pos, temp);

  if (fscanf(file, "%"PRIu64"\n", &temp) != 1)
    return 1;
  mpz_init_set_ui(hi, temp);
  mpz_mul_2exp(hi, hi, 64); // hi = temp << 64
  mpz_add(rec_pos, rec_pos, hi);
  mpz_clear(hi);

  return 0;
}

static void fix_state(void)
{
  if (mpz_cmp_ui(hybrid_rec_pos, 0)) {
    mpz_set(rec_pos, hybrid_rec_pos);
    mpz_set_ui(hybrid_rec_pos, 0);
  } else {
    mpz_set(rec_pos, save);
  }
}

void pp_hybrid_fix_state(void)
{
  mpz_set(hybrid_rec_pos, save);
}

static double get_progress(void)
{
  mpf_t fpos, perc;

  if (rec_pos_destroyed)
    return progress;

  mpf_init(fpos); mpf_init(perc);

  mpf_set_z(fpos, rec_pos);
  if (mpf_sgn(count))
    mpf_div(perc, fpos, count);
  progress = 100.0 * mpf_get_d(perc);

  mpf_clear(fpos); mpf_clear(perc);

  return progress;
}

static int get_bits(mpz_t *op)
{
  mpz_t half; mpz_init(half);
  u64 h;
  int b;

  mpz_fdiv_q_2exp(half, *op, 64);
  h = mpz_get_ui(half);
  if (h) b = 64;
  else
  {
    mpz_fdiv_r_2exp(half, *op, 64);
    h = mpz_get_ui(half);
    b = 0;
  }
  while (h >>= 1) b++;

  return b;
}

/*
 * There should be legislation against adding a BOM to UTF-8, not to
 * mention calling UTF-16 a "text file".
 */
static MAYBE_INLINE char *check_bom(char *string)
{
  static int warned;

  if (((unsigned char*)string)[0] < 0xef)
    return string;
  if (!memcmp(string, "\xEF\xBB\xBF", 3))
    string += 3;
  if (options.input_enc == UTF_8 &&
      (!memcmp(string, "\xFE\xFF", 2) || !memcmp(string, "\xFF\xFE", 2))) {
    if (john_main_process && !warned++)
      fprintf(stderr, "Warning: UTF-16 BOM seen in wordlist.\n");
    string += 2;
  }
  return string;
}

/* Sort-of fgets() but for a memory-mapped file. Updates len, returns pointer to string */
static MAYBE_INLINE char *mgets(int *len)
{
  char *pos = map_pos;
  char *end = MIN(map_end, pos + BUFSIZ);

  if (map_pos >= map_end)
    return NULL;

  while (map_pos < end && *map_pos != '\n' && *map_pos != '\r')
    map_pos++;

  *len = map_pos - pos;

  while (map_pos < end && (*map_pos == '\n' || *map_pos == '\r'))
    map_pos++;

  return pos;
}

void do_prince_crack(struct db_main *db, const char *wordlist, int rules)
#endif
{
  mpz_t pw_ks_pos[OUT_LEN_MAX + 1];
  mpz_t pw_ks_cnt[OUT_LEN_MAX + 1];

  mpz_t iter_max;         mpz_init_set_si (iter_max,        0);
  mpz_t total_ks_cnt;     mpz_init_set_si (total_ks_cnt,    0);
  mpz_t total_ks_pos;     mpz_init_set_si (total_ks_pos,    0);
  mpz_t total_ks_left;    mpz_init_set_si (total_ks_left,   0);
  mpz_t skip;             mpz_init_set_si (skip,            0);
  mpz_t limit;            mpz_init_set_si (limit,           0);
  mpz_t tmp;              mpz_init_set_si (tmp,             0);

#ifndef JTR_MODE
  int     version       = 0;
  int     usage         = 0;
#else
  mpf_init_set_ui(count,     1);
  mpz_init_set_ui(rec_pos,   0);
  mpz_init_set_ui(hybrid_rec_pos,   0);
#endif
  int     keyspace      = 0;
  int     pw_min        = PW_MIN;
  int     pw_max        = PW_MAX;
  int     elem_cnt_min  = ELEM_CNT_MIN;
  int     elem_cnt_max  = ELEM_CNT_MAX;
  int     wl_dist_len   = WL_DIST_LEN;
  int     wl_max        = WL_MAX;
  int     case_permute  = CASE_PERMUTE;
  int     dupe_check    = DUPE_CHECK;
#ifndef JTR_MODE
  int     save_pos      = SAVE_POS;
  char   *output_file   = NULL;
#endif

  #define IDX_VERSION               'V'
  #define IDX_USAGE                 'h'
  #define IDX_PW_MIN                0x1000
  #define IDX_PW_MAX                0x2000
  #define IDX_ELEM_CNT_MIN          0x3000
  #define IDX_ELEM_CNT_MAX          0x4000
  #define IDX_KEYSPACE              0x5000
  #define IDX_WL_DIST_LEN           0x6000
  #define IDX_WL_MAX                0x7000
  #define IDX_CASE_PERMUTE          0x8000
  #define IDX_SAVE_POS_DISABLE      0x9000
  #define IDX_DUPE_CHECK_DISABLE    'c'
  #define IDX_SKIP                  's'
  #define IDX_LIMIT                 'l'
  #define IDX_OUTPUT_FILE           'o'

#ifndef JTR_MODE
  struct option long_options[] =
  {
    {"version",               no_argument,       0, IDX_VERSION},
    {"help",                  no_argument,       0, IDX_USAGE},
    {"keyspace",              no_argument,       0, IDX_KEYSPACE},
    {"pw-min",                required_argument, 0, IDX_PW_MIN},
    {"pw-max",                required_argument, 0, IDX_PW_MAX},
    {"elem-cnt-min",          required_argument, 0, IDX_ELEM_CNT_MIN},
    {"elem-cnt-max",          required_argument, 0, IDX_ELEM_CNT_MAX},
    {"wl-dist-len",           no_argument,       0, IDX_WL_DIST_LEN},
    {"wl-max",                required_argument, 0, IDX_WL_MAX},
    {"case-permute",          no_argument,       0, IDX_CASE_PERMUTE},
    {"dupe-check-disable",    no_argument,       0, IDX_DUPE_CHECK_DISABLE},
    {"save-pos-disable",      no_argument,       0, IDX_SAVE_POS_DISABLE},
    {"skip",                  required_argument, 0, IDX_SKIP},
    {"limit",                 required_argument, 0, IDX_LIMIT},
    {"output-file",           required_argument, 0, IDX_OUTPUT_FILE},
    {0, 0, 0, 0}
  };

  int elem_cnt_max_chgd = 0;

  int option_index = 0;

  int c;

  while ((c = getopt_long (argc, argv, "Vhs:l:o:c", long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_VERSION:               version           = 1;              break;
      case IDX_USAGE:                 usage             = 1;              break;
      case IDX_KEYSPACE:              keyspace          = 1;              break;
      case IDX_PW_MIN:                pw_min            = atoi (optarg);  break;
      case IDX_PW_MAX:                pw_max            = atoi (optarg);  break;
      case IDX_ELEM_CNT_MIN:          elem_cnt_min      = atoi (optarg);  break;
      case IDX_ELEM_CNT_MAX:          elem_cnt_max      = atoi (optarg);
                                      elem_cnt_max_chgd = 1;              break;
      case IDX_WL_DIST_LEN:           wl_dist_len       = 1;              break;
      case IDX_WL_MAX:                wl_max            = atoi (optarg);  break;
      case IDX_CASE_PERMUTE:          case_permute      = 1;              break;
      case IDX_DUPE_CHECK_DISABLE:    dupe_check        = 0;              break;
      case IDX_SAVE_POS_DISABLE:      save_pos          = 0;              break;
      case IDX_SKIP:                  mpz_set_str (skip,  optarg, 10);    break;
      case IDX_LIMIT:                 mpz_set_str (limit, optarg, 10);    break;
      case IDX_OUTPUT_FILE:           output_file       = optarg;         break;

      default: return (-1);
    }
  }

  if (elem_cnt_max_chgd == 0)
  {
    elem_cnt_max = MIN (pw_max, ELEM_CNT_MAX);
  }

  if (usage)
  {
    usage_big_print (argv[0]);

    return (-1);
  }

  if (version)
  {
    printf ("v%4.02f\n", (double) VERSION_BIN / 100);

    return (-1);
  }

  if ((optind != argc) && (optind + 1 != argc))
  {
    usage_mini_print (argv[0]);

    return (-1);
  }

  char *wordlist = NULL;

  if (optind + 1 == argc)
  {
    wordlist = argv[optind];
  }

  if (pw_min <= 0)
  {
    fprintf (stderr, "Value of --pw-min (%d) must be greater than %d\n", pw_min, 0);

    return (-1);
  }

  if (pw_max <= 0)
  {
    fprintf (stderr, "Value of --pw-max (%d) must be greater than %d\n", pw_max, 0);

    return (-1);
  }

  if (elem_cnt_min <= 0)
  {
    fprintf (stderr, "Value of --elem-cnt-min (%d) must be greater than %d\n", elem_cnt_min, 0);

    return (-1);
  }

  if (elem_cnt_max < (1 - pw_max))
  {
    fprintf (stderr, "Value of --elem-cnt-max (%d) must be greater than %d\n", elem_cnt_max, (0 - pw_max));

    return (-1);
  }

  if (pw_min > pw_max)
  {
    fprintf (stderr, "Value of --pw-min (%d) must be smaller or equal than value of --pw-max (%d)\n", pw_min, pw_max);

    return (-1);
  }

  if (elem_cnt_max > 0 && elem_cnt_min > elem_cnt_max)
  {
    fprintf (stderr, "Value of --elem-cnt-min (%d) must be smaller or equal than value of --elem-cnt-max (%d)\n", elem_cnt_min, elem_cnt_max);

    return (-1);
  }

  if (pw_min < IN_LEN_MIN)
  {
    fprintf (stderr, "Value of --pw-min (%d) must be greater or equal than %d\n", pw_min, IN_LEN_MIN);

    return (-1);
  }

  if (pw_max > OUT_LEN_MAX)
  {
    fprintf (stderr, "Value of --pw-max (%d) must be smaller or equal than %d\n", pw_max, OUT_LEN_MAX);

    return (-1);
  }

  if (elem_cnt_max > pw_max)
  {
    fprintf (stderr, "Value of --elem-cnt-max (%d) must be smaller or equal than value of --pw-max (%d)\n", elem_cnt_max, pw_max);

    return (-1);
  }

  /**
   * OS specific settings
   */

  #ifdef WINDOWS
  setmode (fileno (stdout), O_BINARY);
  #endif
#else
  union {
    char buffer[LINE_BUFFER_SIZE];
    ARCH_WORD dummy;
  } aligned;
  char *last = aligned.buffer;
  int loopback = (options.flags & FLG_PRINCE_LOOPBACK) ? 1 : 0;
  int mask_mult = MAX(1, mask_num_qw);
  int our_fmt_len = (db->format->params.plaintext_length + ((mask_mult - 1) * mask_add_len)) / mask_mult - mask_add_len;

  dupe_check = (options.flags & FLG_DUPESUPP) ? 1 : 0;

  if (john_main_process)
    log_event("Proceeding with PRINCE (" REALGMP " version)%s",
              loopback ? " in loopback mode" : "");

  /* This mode defaults to length 16 (unless lowered by format)... */
  pw_min = MAX(PW_MIN, options.eff_minlength);
  pw_max = MIN(PW_MAX, our_fmt_len);

  /* ...but can be bumped or decreased using -max-len */
  if (options.req_maxlength)
    pw_max = options.eff_maxlength;

#if HAVE_REXGEN
  /* Hybrid regex */
  if ((regex = prepare_regex(options.regex, &regex_case, &regex_alpha))) {
    if (pw_min > 1)
      pw_min--;
    if (pw_max)
      pw_max--;
    if (our_fmt_len)
      our_fmt_len--;
  }
#endif

  if (pw_max > OUT_LEN_MAX)
  {
    if (john_main_process)
    fprintf (stderr, "Error: net max length for PRINCE can't be greater than %d\n",
             OUT_LEN_MAX);

    error();
  }

  if (pw_min > pw_max) {
    log_event("! MinLen = %d exceeds MaxLen = %d",
              pw_min, pw_max);
    if (john_main_process)
      fprintf(stderr, "MinLen = %d exceeds MaxLen = %d\n",
              pw_min, pw_max);
    error();
  }

  if (pw_min > our_fmt_len) {
    log_event("! MinLen = %d is too large for this hash type",
              pw_min);
    if (john_main_process)
      fprintf(stderr,
              "MinLen = %d exceeds the maximum possible "
              "length for the current hash type (%d)\n",
              pw_min, db->format->params.plaintext_length);
    error();
  }

  if (pw_max > our_fmt_len) {
    log_event("! MaxLen = %d is too large for this hash type",
              pw_max);
    if (john_main_process)
      fprintf(stderr, "Warning: MaxLen = %d is too large "
              "for the current hash type, reduced to %d\n",
              pw_max,
              our_fmt_len);
    pw_max = our_fmt_len;
  }

  wl_max = prince_wl_max; /* JtR defaults to 0 as in unlimited */

  if (prince_elem_cnt_min)
    elem_cnt_min = MAX(1, prince_elem_cnt_min);
  if (prince_elem_cnt_max)
    elem_cnt_max = MIN(prince_elem_cnt_max, pw_max);
  else
    elem_cnt_max = MIN(ELEM_CNT_MAX, pw_max);
  if (options.flags & FLG_PRINCE_DIST)
    wl_dist_len = 1;
  if (options.flags & FLG_PRINCE_CASE_PERMUTE)
    case_permute = 1;
  if (options.flags & FLG_PRINCE_KEYSPACE)
    keyspace = 1;

  if (elem_cnt_max > 0 && elem_cnt_min > elem_cnt_max)
  {
    if (john_main_process)
    fprintf (stderr, "Error: --prince-elem-cnt-min (%d) must be smaller than or equal to\n--prince-elem-cnt-max (%d)\n", elem_cnt_min, elem_cnt_max);

    error();
  }

  if (prince_skip_str)
    mpz_set_str(skip, prince_skip_str, 0);

  if (prince_limit_str)
    mpz_set_str(limit, prince_limit_str, 0);

  /* If we did not give a name for loopback mode, we use the active pot file */
  if (loopback && !wordlist)
    wordlist = options.activepot;

  /* If we did not give a name for wordlist mode, we use one from john.conf */
  if (!wordlist)
  if (!(wordlist =
        cfg_get_param(SECTION_PRINCE, NULL, "Wordlist")) || !*wordlist)
  if (!(wordlist =
        cfg_get_param(SECTION_OPTIONS, NULL, "Wordlist")) || !*wordlist)
    wordlist = options.wordlist = WORDLIST_NAME;

  if (rec_restored && john_main_process) {
    fprintf(stderr, "Proceeding with prince%c%s",
            loopback ? '-' : ':',
            loopback ? "loopback" : path_expand(wordlist));
    if (options.flags & FLG_RULES_CHK) {
      if (options.rule_stack)
        fprintf(stderr, ", rules:(%s x %s)",
                options.activewordlistrules, options.rule_stack);
      else
        fprintf(stderr, ", rules:%s", options.activewordlistrules);
    }
    if (options.flags & FLG_MASK_CHK)
      fprintf(stderr, ", hybrid mask:%s", options.mask ?
              options.mask : options.eff_mask);
    if (!options.activewordlistrules && options.rule_stack)
      fprintf(stderr, ", rules-stack:%s", options.rule_stack);
    if (options.req_minlength >= 0 || options.req_maxlength)
      fprintf(stderr, ", lengths: %d-%d",
              options.eff_minlength + mask_add_len,
              pw_max + mask_add_len);
    fprintf(stderr, "\n");
  }

  log_event("- Wordlist file: %.100s", path_expand(wordlist));
  log_event("- Will generate candidates of length %d - %d", pw_min, pw_max);
  log_event("- Using chains with %d - %d elements.", elem_cnt_min,
            elem_cnt_max > 0 ? elem_cnt_max : pw_max + elem_cnt_max);

  if (rules) {
    char *prerule="";
    struct rpp_context ctx, *rule_ctx;
    int active_rules = 0, rule_number = 0;

    if (options.activewordlistrules)
      log_event("- Rules: %.100s", options.activewordlistrules);

    if (rpp_init(rule_ctx = &ctx, options.activewordlistrules)) {
      log_event("! No \"%s\" mode rules found",
                options.activewordlistrules);
      if (john_main_process)
        fprintf(stderr,
                "No \"%s\" mode rules found in %s\n",
                options.activewordlistrules, cfg_name);
      error();
    }

    rules_init(db, pw_max);
    rule_count = rules_count(&ctx, -1);

    if (rules_stacked_after)
      log_event("- Total %u (%d x %u) preprocessed word mangling rules",
                rule_count * crk_stacked_rule_count,
                rule_count, crk_stacked_rule_count);
    else
      log_event("- %d preprocessed word mangling rules", rule_count);

    list_init(&rule_list);

    rpp_real_run = 1;
    if ((prerule = rpp_next(&ctx)))
    do {
      char *rule;

      if ((rule = rules_reject(prerule, -1, last, db)))
      {
        list_add(rule_list, rule);
        active_rules++;

        if (strcmp(prerule, rule))
          log_event("- Rule #%d: '%.100s' accepted as '%.100s'",
                    rule_number + 1, prerule, rule);
        else
          log_event("- Rule #%d: '%.100s' accepted",
                    rule_number + 1, prerule);
      } else if (strncmp(prerule, "!!", 2))
        log_event("- Rule #%d: '%.100s' rejected",
                  rule_number + 1, prerule);

      if (!(rule = rpp_next(&ctx)))
        break;
      rule_number++;
    } while (rules);

    if (rule_count != active_rules)
    {
      rule_count = active_rules;
      log_event("- %d accepted word mangling rules", rule_count);
    }

    if (rule_count == 1 && rule_list->head->data[0] == 0)
    {
      rules = 0;
    }

    if (rule_count < 1)
    {
      rules = 0;
      rule_count = 1;
    }
  }
  else
  {
    log_event("- No word mangling rules");
    rule_count = 1;
  }
#endif

  /**
   * alloc some space
   */

#ifndef JTR_MODE
  db_entry_t *db_entries   = (db_entry_t *) calloc (pw_max + 1, sizeof (db_entry_t));
  pw_order_t *pw_orders    = (pw_order_t *) calloc (pw_max + 1, sizeof (pw_order_t));
  u64        *wordlen_dist = (u64 *)        calloc (pw_max + 1, sizeof (u64));

  out_t *out = (out_t *) mem_alloc (sizeof (out_t));

  out->fp  = stdout;
  out->len = 0;

  if (dupe_check)
  {
    int in_max = MIN(IN_LEN_MAX, pw_max);

    for (int pw_len = IN_LEN_MIN; pw_len <= in_max; pw_len++)
    {
      db_entry_t *db_entry = &db_entries[pw_len];

      const u32 hash_size = 1 << DEF_HASH_LOG_SIZE[pw_len];
      const u32 hash_alloc = ALLOC_NEW_DUPES;

      uniq_t *uniq = mem_alloc (sizeof (uniq_t));

      uniq->hash_mask = hash_size - 1;
      uniq->data  = mem_alloc (hash_alloc * sizeof (uniq_data_t));
      uniq->hash  = mem_alloc (hash_size  * sizeof (u32));
      uniq->index = 0;
      uniq->alloc = hash_alloc;

      memset (uniq->hash, 0xff, hash_size * sizeof (u32));

      db_entry->uniq = uniq;
    }
  }
#else
  db_entry_t *db_entries   = (db_entry_t *) mem_calloc(pw_max + 1, sizeof (db_entry_t));
  pw_order_t *pw_orders    = (pw_order_t *) mem_calloc(pw_max + 1, sizeof (pw_order_t));
  u64        *wordlen_dist = (u64 *)        mem_calloc(pw_max + 1, sizeof (u64));
#endif

  /**
   * files
   */

#ifndef JTR_MODE
  if (output_file)
  {
    out->fp = fopen (output_file, "ab");

    if (out->fp == NULL)
    {
      fprintf (stderr, "%s: %s\n", output_file, strerror (errno));

      return (-1);
    }
  }

  /*
   * catch signal user interrupt
   */

  if (save_pos)
  {
    signal (SIGINT, catch_int);
  }

  /**
   * load elems from stdin
   */

  FILE *read_fp = stdin;

  if (wordlist)
  {
    read_fp = fopen (wordlist, "rb");

    if (read_fp == NULL)
    {
      fprintf (stderr, "%s: %s\n", wordlist, strerror (errno));

      return (-1);
    }
  }

  int wl_cnt = 0;

  while (!feof (read_fp))
  {
    char buf[BUFSIZ];

    char *input_buf = fgets (buf, sizeof (buf), read_fp);
#else
  FILE *read_fp;
  uint64_t file_len;
  int warn = cfg_get_bool(SECTION_OPTIONS, NULL, "WarnEncoding", 0);
#ifdef HAVE_MMAP
  int mmap_max = cfg_get_int(SECTION_OPTIONS, NULL, "WordlistMemoryMapMaxSize");
#endif

  if (!john_main_process)
    warn = 0;

  wordlist = path_expand(wordlist);

  if (!(read_fp = jtr_fopen(wordlist, "rb")))
    pexit(STR_MACRO(jtr_fopen)": %s", wordlist);
  log_event("- Input file: %.100s", wordlist);

  jtr_fseek64(read_fp, 0, SEEK_END);
  if ((file_len = jtr_ftell64(read_fp)) == -1)
    pexit(STR_MACRO(jtr_ftell64));
  jtr_fseek64(read_fp, 0, SEEK_SET);
  if (file_len == 0) {
    if (john_main_process)
      fprintf(stderr, "Error, dictionary file is "
              "empty\n");
    error();
  }

#ifdef HAVE_MMAP
  if (mmap_max == -1)
  {
    mmap_max = 1 << 10;
  }
  if (options.flags & FLG_PRINCE_MMAP &&
      mmap_max && mmap_max >= (file_len >> 20))
  {
    log_event("- Memory mapping wordlist ("LLd" bytes)",
              (long long)file_len);
#if (SIZEOF_SIZE_T < 8)
    /* Now even though we are 64 bit file size, we must still
     * deal with some 32 bit functions ;) */
    mem_map = MAP_FAILED;
    if (file_len < ((1ULL)<<32))
#endif
      mem_map = mmap(NULL, file_len,
                     PROT_READ, MAP_SHARED,
                     fileno(read_fp), 0);
    if (mem_map == MAP_FAILED) {
      mem_map = NULL;
#ifdef DEBUG
      fprintf(stderr, "wordlist: memory mapping failed (%s) (non-fatal)\n",
              strerror(errno));
#endif
      log_event("! Memory mapping failed (%s) - but we'll do "
                "fine without it.", strerror(errno));
    } else {
      map_pos = mem_map;
      map_end = mem_map + file_len;
    }
  }
#endif
  log_event("Loading elements from %s", loopback ? ".pot file" : "wordlist");

  if (case_permute)
    log_event("- Permuting case of 1st character");

  size_t uniq_mem = 0;

  if (dupe_check) {
    long size = file_len / pw_max;

    u32 hash_log = 8;
    while (((1 << hash_log) < size) && hash_log < 27)
      hash_log++;

    if (john_main_process && options.verbosity <= VERB_DEFAULT)
      log_event("- Suppressing dupes");

    int in_max = MIN(IN_LEN_MAX, pw_max);

    for (int pw_len = IN_LEN_MIN; pw_len <= in_max; pw_len++)
    {
      db_entry_t *db_entry = &db_entries[pw_len];

      const u32 hash_size = 1 << MIN(hash_log, pw_len * 8);
      const u32 hash_alloc = MIN(ALLOC_NEW_DUPES, hash_size);

      uniq_t *uniq = mem_alloc (sizeof (uniq_t));

      uniq->hash_mask = hash_size - 1;
      uniq->data  = mem_alloc (hash_alloc * sizeof (uniq_data_t));
      uniq->hash  = mem_alloc (hash_size  * sizeof (u32));
      uniq->index = 0;
      uniq->alloc = hash_alloc;

      memset (uniq->hash, 0xff, hash_size * sizeof (u32));

      db_entry->uniq = uniq;

      if (john_main_process && options.verbosity > VERB_DEFAULT)
        log_event("- Dupe suppression len %d: hash size %u, "
                  "temporarily allocating "Zu" bytes", pw_len,
                  hash_size, sizeof(uniq_t) + hash_alloc * sizeof(uniq_data_t) +
                  hash_size * sizeof(u32));
    }
  }

  int wl_cnt = 0;

  while (!feof (read_fp))
  {
    char buf[BUFSIZ];
    char *input_buf;
    int input_len = 0;

    if (mem_map)
    {
      input_buf = mgets(&input_len);
      if (input_buf == NULL) break;
    }
    else
    {
      input_buf = fgets (buf, sizeof (buf), read_fp);
    }
#endif

    if (input_buf == NULL) continue;

#ifdef JTR_MODE
    char *p;

    if (loopback && (p = strchr(input_buf, options.loader.field_sep_char)))
    {
      p++;
      if (mem_map)
        input_len -= (p - input_buf);
      input_buf = p;
    }
    else
    if (!strncmp(input_buf, "#!comment", 9))
      continue;

    char *line = check_bom(input_buf);

    if (!mem_map)
      input_len = in_superchop (input_buf);

    if (warn) {
      if (options.input_enc == UTF_8) {
        if (!valid_utf8((UTF8*)line)) {
          warn = 0;
          fprintf(stderr, "Warning: invalid UTF-8 seen reading %s\n", wordlist);
        }
      } else if (line != input_buf || valid_utf8((UTF8*)line) > 1) {
        warn = 0;
        fprintf(stderr, "Warning: UTF-8 seen reading %s\n", wordlist);
      }
    }

    if (mem_map)
      input_len -= (line - input_buf);

    input_buf = line;

    if (options.input_enc != options.target_enc) {
      UTF16 u16[BUFSIZ];

      utf8_to_utf16(u16, OUT_LEN_MAX, (UTF8*)input_buf, input_len);
      input_buf = utf16_to_cp(u16);
      input_len = strlen(input_buf);
    }
#else
    const int input_len = in_superchop (input_buf);
#endif

    if (input_len < IN_LEN_MIN) continue;
    if (input_len > IN_LEN_MAX) continue;

    if (input_len > pw_max) continue;

    db_entry_t *db_entry = &db_entries[input_len];

    if (!dupe_check)
    {
      add_elem (db_entry, input_buf, input_len);
    }
    else
    {
      add_uniq (db_entry, input_buf, input_len);
    }

    if (case_permute)
    {
      const char old_c = input_buf[0];

#ifdef JTR_MODE
      const char new_cu = toupper (ARCH_INDEX(old_c));
      const char new_cl = tolower (ARCH_INDEX(old_c));
#else
      const char new_cu = toupper (old_c);
      const char new_cl = tolower (old_c);
#endif

      if (old_c != new_cu)
      {
        input_buf[0] = new_cu;

        if (!dupe_check)
        {
          add_elem (db_entry, input_buf, input_len);
        }
        else
        {
          add_uniq (db_entry, input_buf, input_len);
        }
      }

      if (old_c != new_cl)
      {
        input_buf[0] = new_cl;

        if (!dupe_check)
        {
          add_elem (db_entry, input_buf, input_len);
        }
        else
        {
          add_uniq (db_entry, input_buf, input_len);
        }
      }
    }

    wl_cnt++;

    if (wl_max > 0 && wl_cnt == wl_max) break;
  }

  if (wordlist)
  {
    fclose (read_fp);
  }

  if (dupe_check)
  {
    int in_max = MIN(IN_LEN_MAX, pw_max);

    for (int pw_len = IN_LEN_MIN; pw_len <= in_max; pw_len++)
    {
      db_entry_t *db_entry = &db_entries[pw_len];

      uniq_t *uniq = db_entry->uniq;

#ifdef JTR_MODE
      uniq_mem += sizeof(uniq_t);
      uniq_mem += uniq->alloc * sizeof(uniq_data_t);
      uniq_mem += (uniq->hash_mask + 1) * sizeof(u32);
#endif
      free (uniq->hash);
      free (uniq->data);
      free (uniq);
    }
  }

  /**
   * init chains
   */

#ifdef JTR_MODE
  log_event("Initializing chains");
#endif
  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    const int pw_len1 = pw_len - 1;

    const u32 chains_cnt = 1 << pw_len1;

    u8 buf[OUT_LEN_MAX];

    chain_t chain_buf_new;

    chain_buf_new.buf = buf;
#ifdef JTR_MODE
    mpz_init_set_si (chain_buf_new.ks_pos, 0);
    mpz_init_set_si (chain_buf_new.ks_cnt, 0);
#endif

    for (u32 chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
    {
      chain_gen_with_idx (&chain_buf_new, pw_len1, chains_idx);

      // make sure all the elements really exist

      int valid1 = chain_valid_with_db (&chain_buf_new, db_entries);

      if (valid1 == 0) continue;

      // boost by verify element count to be inside a specific range

      int valid2 = chain_valid_with_cnt_min (&chain_buf_new, elem_cnt_min);

      if (valid2 == 0) continue;

      int eff_elem_cnt_max;

      if (elem_cnt_max > 0)
      {
        eff_elem_cnt_max = elem_cnt_max;
      }
      else
      {
        eff_elem_cnt_max = pw_len + elem_cnt_max;

        if (eff_elem_cnt_max <= elem_cnt_min) continue;
      }

      int valid3 = chain_valid_with_cnt_max (&chain_buf_new, eff_elem_cnt_max);

      if (valid3 == 0) continue;

      // add chain to database

      check_realloc_chains (db_entry);

      chain_t *chain_buf = &db_entry->chains_buf[db_entry->chains_cnt];

      memcpy (chain_buf, &chain_buf_new, sizeof (chain_t));

      chain_buf->buf = malloc_tiny (pw_len);

      memcpy (chain_buf->buf, chain_buf_new.buf, pw_len);

      mpz_init_set_si (chain_buf->ks_cnt, 0);
      mpz_init_set_si (chain_buf->ks_pos, 0);

      db_entry->chains_cnt++;
    }

    memset (db_entry->cur_chain_ks_poses, 0, OUT_LEN_MAX * sizeof (u64));
  }

  /**
   * calculate password candidate output length distribution
   */

  if (wl_dist_len)
  {
#ifdef JTR_MODE
  log_event("Calculating output length distribution from wordlist file");
#endif
    for (int pw_len = IN_LEN_MIN; pw_len <= pw_max; pw_len++)
    {
      if (pw_len <= IN_LEN_MAX)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        wordlen_dist[pw_len] = db_entry->elems_cnt;
      }
      else
      {
        wordlen_dist[pw_len] = 1;
      }
    }
  }
  else
  {
#ifdef JTR_MODE
  log_event("- Using default output length distribution");
#endif
    for (int pw_len = IN_LEN_MIN; pw_len <= pw_max; pw_len++)
    {
      if (pw_len < DEF_WORDLEN_DIST_CNT)
      {
        wordlen_dist[pw_len] = DEF_WORDLEN_DIST[pw_len];
      }
      else
      {
        wordlen_dist[pw_len] = 1;
      }
    }
  }
#ifdef JTR_MODE
  status_init(get_progress, 0);

  rec_restore_mode(restore_state);
  rec_init(db, save_state);

  if (mpz_cmp_ui(rec_pos, 0))
  {
    mpz_set(skip, rec_pos);
  }

  log_event("Calculating keyspace");
  size_t tot_mem = (pw_max + 1) * (sizeof(db_entry_t) + sizeof(pw_order_t) + sizeof(u64));
#endif

  /**
   * Calculate keyspace stuff
   */

  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    int      chains_cnt = db_entry->chains_cnt;
    chain_t *chains_buf = db_entry->chains_buf;

#ifdef JTR_MODE
    tot_mem += db_entry->elems_alloc * sizeof(elem_t);
    tot_mem += db_entry->elems_cnt * pw_len;
    tot_mem += db_entry->chains_alloc * sizeof(chain_t);
#endif
    mpz_set_si (tmp, 0);

    for (int chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
    {
      chain_t *chain_buf = &chains_buf[chains_idx];

      chain_ks (chain_buf, db_entries, &chain_buf->ks_cnt);

      mpz_add (tmp, tmp, chain_buf->ks_cnt);
    }

    mpz_add (total_ks_cnt, total_ks_cnt, tmp);

    if (mpz_cmp_si (skip, 0))
    {
      mpz_init_set (pw_ks_cnt[pw_len], tmp);
    }
  }

#if FAKE_GMP
  if (total_ks_cnt == UINT128_MAX)
  {
    fprintf (stderr, "Warning: %d-bit keyspace saturated\n", FAKE_GMP);
  }
#endif

  if (keyspace)
  {
#ifndef JTR_MODE
    mpz_out_str (stdout, 10, total_ks_cnt);

    printf ("\n");

    return 0;
#else
    char l_msg[64];

    mpz_get_str(l_msg, 10, total_ks_cnt);
    fprintf(stderr, "Keyspace size %s (%d bits used)\n", l_msg,
            get_bits(&total_ks_cnt));
    exit(0);
#endif
  }
#ifdef JTR_MODE
  else
  {
    char l_msg[64];

    mpz_get_str(l_msg, 10, total_ks_cnt);
    log_event("- Keyspace size %s (%d bits used)", l_msg,
              get_bits(&total_ks_cnt));

    if (dupe_check)
      log_event("- Memory use for PRINCE: "Zu" bytes (peak "Zu" bytes)", tot_mem, uniq_mem + tot_mem);
    else
      log_event("- Memory use for PRINCE: "Zu" bytes", tot_mem);
  }

  mpf_set_z(count, total_ks_cnt);
  mpf_mul_ui(count, count, rule_count);

  crk_init(db, fix_state, NULL);

  if (dupe_check || rules) {
    int force = (dupe_check || (options.flags & FLG_STDOUT)) && options.suppressor_size;
    suppressor_init(SUPPRESSOR_UPDATE | (force ? SUPPRESSOR_FORCE : 0));
  }
#endif

  /**
   * sort chains by ks
   */

#ifdef JTR_MODE
  log_event("Sorting chains by keyspace");
#endif
  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    chain_t *chains_buf = db_entry->chains_buf;

    const int chains_cnt = db_entry->chains_cnt;

    qsort (chains_buf, chains_cnt, sizeof (chain_t), sort_by_ks);
  }
#ifdef JTR_MODE
  log_event("Sorting global order by password length counts");
#endif

  /**
   * sort global order by password length counts
   */

  for (int pw_len = pw_min, order_pos = 0; pw_len <= pw_max; pw_len++, order_pos++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    const u64 elems_cnt = db_entry->elems_cnt;

    pw_order_t *pw_order = &pw_orders[order_pos];

    pw_order->len = pw_len;
    pw_order->cnt = elems_cnt;
  }

  const int order_cnt = pw_max + 1 - pw_min;

  qsort (pw_orders, order_cnt, sizeof (pw_order_t), sort_by_cnt);

  /**
   * seek to some starting point
   */

  if (mpz_cmp_si (skip, 0))
  {
    if (mpz_cmp (skip, total_ks_cnt) >= 0)
    {
      fprintf (stderr, "Value of --skip must be smaller than total keyspace\n");

#ifndef JTR_MODE
      return (-1);
#else
      error();
#endif
    }
  }

  if (mpz_cmp_si (limit, 0))
  {
    if (mpz_cmp (limit, total_ks_cnt) > 0)
    {
      fprintf (stderr, "Value of --limit cannot be larger than total keyspace\n");

#ifndef JTR_MODE
      return (-1);
#else
      error();
#endif
    }

    mpz_add (tmp, skip, limit);

    if (mpz_cmp (tmp, total_ks_cnt) > 0)
    {
      fprintf (stderr, "Value of --skip + --limit cannot be larger than total keyspace\n");

#ifndef JTR_MODE
      return (-1);
#else
      error();
#endif
    }

    mpz_set (total_ks_cnt, tmp);
  }

  mpz_init_set (save, skip);

  /**
   * skip to the first main loop that will output a password
   */

  if (mpz_cmp_si (skip, 0))
  {
    mpz_t skip_left;  mpz_init_set (skip_left, skip);
    mpz_t main_loops; mpz_init (main_loops);

    u64 outs_per_main_loop = 0;

    for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
    {
      mpz_init_set_si (pw_ks_pos[pw_len], 0);

      outs_per_main_loop += wordlen_dist[pw_len];
    }

    // find pw_ks_pos[]

    while (1)
    {
      mpz_fdiv_q_ui (main_loops, skip_left, outs_per_main_loop);

      if (mpz_cmp_si (main_loops, 0) == 0)
      {
        break;
      }

      // increment the main loop "main_loops" times

      for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) < 0)
        {
          mpz_mul_ui (tmp, main_loops, wordlen_dist[pw_len]);

          mpz_add (pw_ks_pos[pw_len], pw_ks_pos[pw_len], tmp);

          mpz_sub (skip_left, skip_left, tmp);

          if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) > 0)
          {
            mpz_sub (tmp, pw_ks_pos[pw_len], pw_ks_cnt[pw_len]);

            mpz_add (skip_left, skip_left, tmp);
          }
        }
      }

      outs_per_main_loop = 0;

      for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) < 0)
        {
          outs_per_main_loop += wordlen_dist[pw_len];
        }
      }
    }

    mpz_sub (total_ks_pos, skip, skip_left);

    // set db_entries to pw_ks_pos[]

    for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
    {
      db_entry_t *db_entry = &db_entries[pw_len];

      int      chains_cnt = db_entry->chains_cnt;
      chain_t *chains_buf = db_entry->chains_buf;

      mpz_set (tmp, pw_ks_pos[pw_len]);

      for (int chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
      {
        chain_t *chain_buf = &chains_buf[chains_idx];

        if (mpz_cmp (tmp, chain_buf->ks_cnt) < 0)
        {
          mpz_set (chain_buf->ks_pos, tmp);

          set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);

          break;
        }

        mpz_sub (tmp, tmp, chain_buf->ks_cnt);

        db_entry->chains_pos++;
      }
    }

    // clean up

    for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
    {
      mpz_clear (pw_ks_cnt[pw_len]);
      mpz_clear (pw_ks_pos[pw_len]);
    }

    mpz_clear (skip_left);
    mpz_clear (main_loops);
  }

  /**
   * loop
   */

#ifdef JTR_MODE
  if (mpz_cmp_ui(skip, 0))
  {
    char l_msg[64];
    mpz_get_str(l_msg, 10, skip);
    log_event("- Skip %s", l_msg);
  }

  if (mpz_cmp_ui(limit, 0))
  {
    char l_msg[64];
    mpz_get_str(l_msg, 10, limit);
    log_event("- Limit %s", l_msg);
  }

  log_event("Starting candidate generation");

  int jtr_done = 0;
#endif
  while (mpz_cmp (total_ks_pos, total_ks_cnt) < 0)
  {
    for (int order_pos = 0; order_pos < order_cnt; order_pos++)
    {
      pw_order_t *pw_order = &pw_orders[order_pos];

      const int pw_len = pw_order->len;

      char pw_buf[BUFSIZ];

#ifndef JTR_MODE
      pw_buf[pw_len] = '\n';
#else
      pw_buf[pw_len] = '\0';
#endif

      db_entry_t *db_entry = &db_entries[pw_len];

      const u64 outs_cnt = wordlen_dist[pw_len];

      u64 outs_pos = 0;

      while (outs_pos < outs_cnt)
      {
        const int chains_cnt = db_entry->chains_cnt;
        const int chains_pos = db_entry->chains_pos;

        if (chains_pos == chains_cnt) break;

        chain_t *chains_buf = db_entry->chains_buf;

        chain_t *chain_buf = &chains_buf[chains_pos];

        mpz_sub (total_ks_left, total_ks_cnt, total_ks_pos);

        mpz_sub (iter_max, chain_buf->ks_cnt, chain_buf->ks_pos);

        if (mpz_cmp (total_ks_left, iter_max) < 0)
        {
          mpz_set (iter_max, total_ks_left);
        }

        const u64 outs_left = outs_cnt - outs_pos;

        mpz_set_ui (tmp, outs_left);

        if (mpz_cmp (tmp, iter_max) < 0)
        {
          mpz_set (iter_max, tmp);
        }

        const u64 iter_max_u64 = mpz_get_ui (iter_max);

        mpz_add (tmp, total_ks_pos, iter_max);

#ifdef JTR_MODE
        u32 for_node, node_skip = 0;
        if (options.node_count)
        {
          for_node = mpz_fdiv_ui(total_ks_pos,options.node_count) + 1;
          node_skip = for_node < options.node_min ||
                      for_node > options.node_max;
        }
        if (!node_skip && mpz_cmp (tmp, skip) > 0)
#else
        if (mpz_cmp (tmp, skip) > 0)
#endif
        {
          u64 iter_pos_u64 = 0;

          if (mpz_cmp (total_ks_pos, skip) < 0)
          {
            mpz_sub (tmp, skip, total_ks_pos);

            iter_pos_u64 = mpz_get_ui (tmp);

            mpz_add (tmp, chain_buf->ks_pos, tmp);

            set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);
          }

          chain_set_pwbuf_init (chain_buf, db_entries, db_entry->cur_chain_ks_poses, pw_buf);

          const u64 iter_pos_save = iter_max_u64 - iter_pos_u64;

          while (iter_pos_u64 < iter_max_u64)
          {
#ifndef JTR_MODE
            out_push (out, pw_buf, pw_len + 1);
#else
            char key_e[PLAINTEXT_BUFFER_SIZE];
            char *key;

            if (!rules) {
#if HAVE_REXGEN
              if (regex) {
                if ((jtr_done = do_regex_hybrid_crack(db, regex, pw_buf,
                                                      regex_case, regex_alpha)))
                  break;
                pp_hybrid_fix_state();
              } else
#endif
              if (f_new) {
                if ((jtr_done = do_external_hybrid_crack(db, pw_buf)))
                  break;
                pp_hybrid_fix_state();
              } else
              if (options.flags & FLG_MASK_CHK) {
                if ((jtr_done = do_mask_crack(pw_buf)))
                  break;
              } else
              {
                key = pw_buf;
                if (!f_filter || ext_filter_body(pw_buf, key = key_e))
                  if ((jtr_done = crk_process_key(key)))
                    break;
              }
            } else {
              struct list_entry *rule;

              if ((rule = rule_list->head))
              do {
                char *word;

                if ((word = rules_apply(pw_buf, rule->data, -1, last))) {
                  last = word;
#if HAVE_REXGEN
                  if (regex) {
                    if ((jtr_done = do_regex_hybrid_crack(db, regex, word,
                                                          regex_case,
                                                          regex_alpha)))
                      break;
                    pp_hybrid_fix_state();
                  } else
#endif
                  if (f_new) {
                    if (do_external_hybrid_crack(db, word))
                      break;
                    pp_hybrid_fix_state();
                  } else
                  if (options.flags & FLG_MASK_CHK) {
                    if ((jtr_done = do_mask_crack(word)))
                      break;
                  } else
                  {
                    key = word;
                    if (!f_filter || ext_filter_body(word, key = key_e))
                      if ((jtr_done = crk_process_key(key)))
                        break;
                  }
                }
              } while ((rule = rule->next));

              if (jtr_done || event_abort)
                break;
            }
#endif

            chain_set_pwbuf_increment (chain_buf, db_entries, db_entry->cur_chain_ks_poses, pw_buf);

            iter_pos_u64++;
          }

          mpz_add_ui (save, save, iter_pos_save);
#ifdef JTR_MODE
          if (jtr_done || event_abort)
            break;
#endif
        }
        else
        {
          mpz_add (tmp, chain_buf->ks_pos, iter_max);

          set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);
#ifdef JTR_MODE
          if (jtr_done || event_abort)
            break;
#endif
        }

        outs_pos += iter_max_u64;

        mpz_add (total_ks_pos, total_ks_pos, iter_max);

        mpz_add (chain_buf->ks_pos, chain_buf->ks_pos, iter_max);

        if (mpz_cmp (chain_buf->ks_pos, chain_buf->ks_cnt) == 0)
        {
          db_entry->chains_pos++;

          memset (db_entry->cur_chain_ks_poses, 0, OUT_LEN_MAX * sizeof (u64));
        }

        if (mpz_cmp (total_ks_pos, total_ks_cnt) == 0) break;
      }

      if (mpz_cmp (total_ks_pos, total_ks_cnt) == 0) break;
#ifdef JTR_MODE
      if (jtr_done || event_abort)
        break;
#endif
    }
#ifdef JTR_MODE
    if (jtr_done || event_abort)
      break;
#endif
  }

#ifndef JTR_MODE
  out_flush (out);

  if (save_pos)
  {
    catch_int (0);
  }
#endif

  /**
   * cleanup
   */

#ifdef JTR_MODE
  log_event("PRINCE done. Cleaning up.");

  if (!event_abort)
  {
    progress = 100.0;
    mpz_set(rec_pos, total_ks_cnt);
  }
#endif
  mpz_clear (iter_max);
  mpz_clear (total_ks_cnt);
  mpz_clear (total_ks_pos);
  mpz_clear (total_ks_left);
  mpz_clear (skip);
  mpz_clear (limit);
  mpz_clear (tmp);
  mpz_clear (save);

  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    if (db_entry->chains_buf)
    {
      int      chains_cnt = db_entry->chains_cnt;
      chain_t *chains_buf = db_entry->chains_buf;

      for (int chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
      {
        chain_t *chain_buf = &chains_buf[chains_idx];

        mpz_clear (chain_buf->ks_cnt);
        mpz_clear (chain_buf->ks_pos);
      }

      free (db_entry->chains_buf);
    }

    if (db_entry->elems_buf)  free (db_entry->elems_buf);
  }

#ifndef JTR_MODE
  free (out);
#endif
  free (wordlen_dist);
  free (pw_orders);
  free (db_entries);

#ifndef JTR_MODE
  return 0;
#else
#if defined(HAVE_MMAP)
  if (mem_map)
    munmap(mem_map, file_len);
#endif

  crk_done();
  rec_done(event_abort || (status.pass && db->salts));

  mpf_clear(count);
  rec_pos_destroyed = 1;
  mpz_clear(rec_pos);
#endif
}

#endif /* HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T */
