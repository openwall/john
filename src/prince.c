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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
#define HAVE_LIBGMP
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __USE_MINGW_ANSI_STDIO 1
#endif

#ifdef HAVE_LIBGMP

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
#include <getopt.h>
#if HAVE_GMP_GMP_H
#include <gmp/gmp.h>
#else
#include <gmp.h>
#endif

/**
 * Name........: princeprocessor (pp)
 * Description.: Standalone password candidate generator using the PRINCE algorithm
 * Version.....: 0.17
 * Autor.......: Jens Steube <jens.steube@gmail.com>
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
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "memory.h"
#include "unicode.h"
#include "prince.h"
#include "memdbg.h"

#define _STR_VALUE(arg) #arg
#define STR_MACRO(n)    _STR_VALUE(n)

#define calloc(a, b)    mem_calloc((a) * (b))
#endif

#define IN_LEN_MIN      1
#define IN_LEN_MAX      16
#define PW_MIN          IN_LEN_MIN
#define PW_MAX          IN_LEN_MAX
#define ELEM_CNT_MIN    1
#define ELEM_CNT_MAX    8
#define WL_DIST_LEN     0

#define VERSION_BIN     17

#define ALLOC_NEW_WORDS 0x40000
#define ALLOC_NEW_ELEMS 0x10

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

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
  u8  buf[IN_LEN_MAX];

} word_t;

typedef struct
{
  u8  buf[IN_LEN_MAX];
  int cnt;

  mpz_t ks_cnt;
  mpz_t ks_pos;

} elem_t;

typedef struct
{
  word_t *words_buf;
  u64     words_cnt;
  u64     words_alloc;

  elem_t *elems_buf;
  int     elems_cnt;
  int     elems_pos;
  int     elems_alloc;

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
static const char *USAGE_MINI[] =
{
  "Usage: %s [options] < wordlist",
  "",
  "Try --help for more help.",
  NULL
};

static const char *USAGE_BIG[] =
{
  "pp by atom, High-Performance word generator based on element permutations",
  "",
  "Usage: %s [options] < wordlist",
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
  "",
  "* Resources:",
  "",
  "  -s,  --skip=NUM            Start at specific position",
  "  -l,  --limit=NUM           Stop at specific position",
  "",
  "* Files:",
  "",
  "  -o,  --output-file=FILE    Output-file",
  "",
  NULL
};

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
#endif

static void check_realloc_words (db_entry_t *db_entry)
{
  if (db_entry->words_cnt == db_entry->words_alloc)
  {
    const u64 words_alloc = db_entry->words_alloc;

    const u64 words_alloc_new = words_alloc + ALLOC_NEW_WORDS;

    db_entry->words_buf = (word_t *) realloc (db_entry->words_buf, words_alloc_new * sizeof (word_t));

    if (db_entry->words_buf == NULL)
    {
      fprintf (stderr, "Out of memory!\n");

#ifndef JTR_MODE
      exit (-1);
#else
      error();
#endif
    }

    memset (&db_entry->words_buf[words_alloc], 0, ALLOC_NEW_WORDS * sizeof (word_t));

    db_entry->words_alloc = words_alloc_new;
  }
}

static void check_realloc_elems (db_entry_t *db_entry)
{
  if (db_entry->elems_cnt == db_entry->elems_alloc)
  {
    const u64 elems_alloc = db_entry->elems_alloc;

    const u64 elems_alloc_new = elems_alloc + ALLOC_NEW_ELEMS;

    db_entry->elems_buf = (elem_t *) realloc (db_entry->elems_buf, elems_alloc_new * sizeof (elem_t));

    if (db_entry->elems_buf == NULL)
    {
      fprintf (stderr, "Out of memory!\n");

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
  fwrite (out->buf, 1, out->len, out->fp);

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
  const elem_t *f1 = (const elem_t *) p1;
  const elem_t *f2 = (const elem_t *) p2;

  return mpz_cmp (f1->ks_cnt, f2->ks_cnt);
}

static int elem_valid_with_db (const elem_t *elem_buf, const db_entry_t *db_entries)
{
  const u8 *buf = elem_buf->buf;
  const int cnt = elem_buf->cnt;

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 elem_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[elem_key];

    if (db_entry->words_cnt == 0) return 0;
  }

  return 1;
}

static int elem_valid_with_cnt_min (const elem_t *elem_buf, const int elem_cnt_min)
{
  const int cnt = elem_buf->cnt;

  if (cnt < elem_cnt_min) return 0;

  return 1;
}

static int elem_valid_with_cnt_max (const elem_t *elem_buf, const int elem_cnt_max)
{
  const int cnt = elem_buf->cnt;

  if (cnt > elem_cnt_max) return 0;

  return 1;
}

static void elem_ks (const elem_t *elem_buf, const db_entry_t *db_entries, mpz_t ks_cnt)
{
  const u8 *buf = elem_buf->buf;
  const int cnt = elem_buf->cnt;

  mpz_init_set_si (ks_cnt, 1);

  for (int idx = 0; idx < cnt; idx++)
  {
    const u8 elem_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[elem_key];

    const u64 words_cnt = db_entry->words_cnt;

    mpz_mul_ui (ks_cnt, ks_cnt, words_cnt);
  }
}

static void elem_set_pwbuf (const elem_t *elem_buf, const db_entry_t *db_entries, mpz_t ks_pos, char *pw_buf)
{
  const u8 *buf = elem_buf->buf;

  const u32 cnt = elem_buf->cnt;

  for (u32 idx = 0; idx < cnt; idx++)
  {
    const u8 elem_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[elem_key];

    const u64 words_cnt = db_entry->words_cnt;

    const u64 words_idx = mpz_fdiv_ui (ks_pos, words_cnt);

    memcpy (pw_buf, &db_entry->words_buf[words_idx], elem_key);

    pw_buf += elem_key;

    mpz_div_ui (ks_pos, ks_pos, words_cnt);
  }
}

static void elem_gen_with_idx (elem_t *elem_buf, const int len1, const int elems_idx)
{
  elem_buf->cnt = 0;

  u8 elem_key = 1;

  for (int elems_shr = 0; elems_shr < len1; elems_shr++)
  {
    if ((elems_idx >> elems_shr) & 1)
    {
      elem_buf->buf[elem_buf->cnt] = elem_key;

      elem_buf->cnt++;

      elem_key = 1;
    }
    else
    {
      elem_key++;
    }
  }

  elem_buf->buf[elem_buf->cnt] = elem_key;

  elem_buf->cnt++;
}
#ifdef JTR_MODE

static FILE *word_file = NULL;
static double progress = -1;
static mpf_t count;
static mpf_t pos;

static void save_state(FILE *file)
{
  //fprintf(file, "%d\n" LLd "\n" LLd "\n",
  //        rec_rule, (long long)rec_pos, (long long)rec_line);
}

static int restore_state(FILE *file)
{
  return 0;
}

static void fix_state(void)
{
}

static double get_progress(void)
{
  mpf_t perc;

  mpf_init(perc);
  mpf_div(perc, pos, count);
  progress = 100.0 * mpf_get_d(perc);

  return progress;
}

void do_prince_crack(struct db_main *db, char *filename)
#else
int main (int argc, char *argv[])
#endif
{
  mpz_t iter_max;         mpz_init_set_si (iter_max,        0);
  mpz_t ks_pos;           mpz_init_set_si (ks_pos,          0);
  mpz_t ks_cnt;           mpz_init_set_si (ks_cnt,          0);
  mpz_t total_ks_cnt;     mpz_init_set_si (total_ks_cnt,    0);
  mpz_t total_ks_pos;     mpz_init_set_si (total_ks_pos,    0);
  mpz_t total_ks_left;    mpz_init_set_si (total_ks_left,   0);
  mpz_t total_words_cnt;  mpz_init_set_si (total_words_cnt, 0);
  mpz_t skip;             mpz_init_set_si (skip,            0);
  mpz_t limit;            mpz_init_set_si (limit,           0);

#ifndef JTR_MODE
  int     version       = 0;
  int     usage         = 0;
  int     keyspace      = 0;
#else
  mpf_init_set_ui(count, 1);
  mpf_init_set_ui(pos,   0);
#endif
  int     pw_min        = PW_MIN;
  int     pw_max        = PW_MAX;
  int     elem_cnt_min  = ELEM_CNT_MIN;
  int     elem_cnt_max  = ELEM_CNT_MAX;
  int     wl_dist_len   = WL_DIST_LEN;
#ifndef JTR_MODE
  char   *output_file   = NULL;
#endif

  #define IDX_VERSION       'V'
  #define IDX_USAGE         'h'
  #define IDX_PW_MIN        0x1000
  #define IDX_PW_MAX        0x2000
  #define IDX_ELEM_CNT_MIN  0x3000
  #define IDX_ELEM_CNT_MAX  0x4000
  #define IDX_KEYSPACE      0x5000
  #define IDX_WL_DIST_LEN   0x6000
  #define IDX_SKIP          's'
  #define IDX_LIMIT         'l'
  #define IDX_OUTPUT_FILE   'o'

#ifndef JTR_MODE
  struct option long_options[] =
  {
    {"version",       no_argument,       0, IDX_VERSION},
    {"help",          no_argument,       0, IDX_USAGE},
    {"keyspace",      no_argument,       0, IDX_KEYSPACE},
    {"pw-min",        required_argument, 0, IDX_PW_MIN},
    {"pw-max",        required_argument, 0, IDX_PW_MAX},
    {"elem-cnt-min",  required_argument, 0, IDX_ELEM_CNT_MIN},
    {"elem-cnt-max",  required_argument, 0, IDX_ELEM_CNT_MAX},
    {"wl-dist-len",   no_argument,       0, IDX_WL_DIST_LEN},
    {"skip",          required_argument, 0, IDX_SKIP},
    {"limit",         required_argument, 0, IDX_LIMIT},
    {"output-file",   required_argument, 0, IDX_OUTPUT_FILE},
    {0, 0, 0, 0}
  };

  int option_index = 0;

  int c;

  while ((c = getopt_long (argc, argv, "Vhs:l:o:", long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_VERSION:       version         = 1;              break;
      case IDX_USAGE:         usage           = 1;              break;
      case IDX_KEYSPACE:      keyspace        = 1;              break;
      case IDX_PW_MIN:        pw_min          = atoi (optarg);  break;
      case IDX_PW_MAX:        pw_max          = atoi (optarg);  break;
      case IDX_ELEM_CNT_MIN:  elem_cnt_min    = atoi (optarg);  break;
      case IDX_ELEM_CNT_MAX:  elem_cnt_max    = atoi (optarg);  break;
      case IDX_WL_DIST_LEN:   wl_dist_len     = 1;              break;
      case IDX_SKIP:          mpz_set_str (skip,  optarg, 10);  break;
      case IDX_LIMIT:         mpz_set_str (limit, optarg, 10);  break;
      case IDX_OUTPUT_FILE:   output_file     = optarg;         break;

      default: return (-1);
    }
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

  if (optind != argc)
  {
    usage_mini_print (argv[0]);

    return (-1);
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

  if (elem_cnt_max <= 0)
  {
    fprintf (stderr, "Value of --elem-cnt-max (%d) must be greater than %d\n", elem_cnt_max, 0);

    return (-1);
  }

  if (pw_min > pw_max)
  {
    fprintf (stderr, "Value of --pw-min (%d) must be smaller or equal than value of --pw-max (%d)\n", pw_min, pw_max);

    return (-1);
  }

  if (elem_cnt_min > elem_cnt_max)
  {
    fprintf (stderr, "Value of --elem-cnt-min (%d) must be smaller or equal than value of --elem-cnt-max (%d)\n", elem_cnt_min, elem_cnt_max);

    return (-1);
  }

  if (pw_min < IN_LEN_MIN)
  {
    fprintf (stderr, "Value of --pw-min (%d) must be greater or equal than %d\n", pw_min, IN_LEN_MIN);

    return (-1);
  }

  if (pw_max > IN_LEN_MAX)
  {
    fprintf (stderr, "Value of --pw-max (%d) must be smaller or equal than %d\n", pw_max, IN_LEN_MAX);

    return (-1);
  }

  /**
   * OS specific settings
   */

  #ifdef WINDOWS
  setmode (fileno (stdout), O_BINARY);
  #endif
#else
  log_event("Proceeding with PRINCE mode");

  pw_min = MAX(IN_LEN_MIN, options.force_minlength);
  pw_max = MIN(IN_LEN_MAX, db->format->params.plaintext_length);

  if (options.force_maxlength && options.force_maxlength < pw_max)
    pw_max = MIN(IN_LEN_MAX, options.force_maxlength);

  if (prince_elem_cnt_min)
    elem_cnt_min = prince_elem_cnt_min;
  if (prince_elem_cnt_max)
    elem_cnt_max = prince_elem_cnt_max;
  wl_dist_len = prince_wl_dist_len;

  if (elem_cnt_min > elem_cnt_max)
  {
    fprintf (stderr, "Error: --prince-elem-cnt-min (%d) must be smaller than or equal to\n--prince-elem-cnt-max (%d)\n", elem_cnt_min, elem_cnt_max);

    error();
  }

  /* If we did not give a name for wordlist mode,
     we use the "batch mode" one from john.conf */
  if (!filename)
  if (!(filename = cfg_get_param(SECTION_OPTIONS, NULL, "Wordlist")))
  if (!(filename = cfg_get_param(SECTION_OPTIONS, NULL, "Wordfile")))
    filename = options.wordlist = WORDLIST_NAME;

  log_event("- Wordlist file: %.100s", path_expand(filename));
  log_event("- Using candidates of length %d - %d", pw_min, pw_max);
  log_event("- Using chains with %d - %d elements", elem_cnt_min, elem_cnt_max);
  if (wl_dist_len)
    log_event("- Calculating length distribution from wordlist");
  else
    log_event("- Using default length distribution");

  status_init(get_progress, 0);

  rec_restore_mode(restore_state);
  rec_init(db, save_state);

  crk_init(db, fix_state, NULL);
#endif

  /**
   * alloc some space
   */

  db_entry_t *db_entries   = (db_entry_t *) calloc (IN_LEN_MAX + 1, sizeof (db_entry_t));
  pw_order_t *pw_orders    = (pw_order_t *) calloc (IN_LEN_MAX + 1, sizeof (pw_order_t));
  u64        *wordlen_dist = (u64 *)        calloc (IN_LEN_MAX + 1, sizeof (u64));

#ifndef JTR_MODE
  out_t *out = (out_t *) malloc (sizeof (out_t));

  out->fp  = stdout;
  out->len = 0;
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

  /**
   * load words from stdin
   */

  while (!feof (stdin))
  {
    char buf[BUFSIZ];

    char *input_buf = fgets (buf, sizeof (buf), stdin);
#else
    if (!(word_file = jtr_fopen(path_expand(filename), "rb")))
      pexit(STR_MACRO(jtr_fopen)": %s", path_expand(filename));
    log_event("- Input file: %.100s", path_expand(filename));

  log_event("Loading wordlist");

  while (!feof (word_file))
  {
    char buf[BUFSIZ];
    char *input_buf = fgets (buf, sizeof (buf), word_file);
#endif

    if (input_buf == NULL) continue;

#ifdef JTR_MODE
    if (!strncmp(input_buf, "#!comment", 9))
      continue;
#endif

    const int input_len = in_superchop (input_buf);

    if (input_len < IN_LEN_MIN) continue;
    if (input_len > IN_LEN_MAX) continue;

    db_entry_t *db_entry = &db_entries[input_len];

    check_realloc_words (db_entry);

    word_t *word_buf = &db_entry->words_buf[db_entry->words_cnt];

    memcpy (word_buf->buf, input_buf, input_len);

    db_entry->words_cnt++;
  }

  /**
   * init elems
   */

#ifdef JTR_MODE
  log_event("Init elements");
#endif
  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    const int pw_len1 = pw_len - 1;

    const int elems_cnt = 1 << pw_len1;

    elem_t elem_buf_new;

    for (int elems_idx = 0; elems_idx < elems_cnt; elems_idx++)
    {
      elem_gen_with_idx (&elem_buf_new, pw_len1, elems_idx);

      // make sure there are words of that specific length which is ued in the elemtal

      int valid1 = elem_valid_with_db (&elem_buf_new, db_entries);

      if (valid1 == 0) continue;

      // boost by reject elements to be inside a specific range

      int valid2 = elem_valid_with_cnt_min (&elem_buf_new, elem_cnt_min);

      if (valid2 == 0) continue;

      int valid3 = elem_valid_with_cnt_max (&elem_buf_new, elem_cnt_max);

      if (valid3 == 0) continue;

      // add element to database

      check_realloc_elems (db_entry);

      elem_t *elem_buf = &db_entry->elems_buf[db_entry->elems_cnt];

      memcpy (elem_buf, &elem_buf_new, sizeof (elem_t));

      mpz_init_set_si (elem_buf->ks_cnt, 0);
      mpz_init_set_si (elem_buf->ks_pos, 0);

      db_entry->elems_cnt++;
    }
  }

  /**
   * calculate password candidate output length distribution
   */

#ifdef JTR_MODE
  log_event("Calculate password candidate output length distribution");
#endif
  if (wl_dist_len)
  {
    for (int pw_len = IN_LEN_MIN; pw_len <= IN_LEN_MAX; pw_len++)
    {
      db_entry_t *db_entry = &db_entries[pw_len];

      wordlen_dist[pw_len] = db_entry->words_cnt;
    }
  }
  else
  {
    for (int pw_len = IN_LEN_MIN; pw_len <= IN_LEN_MAX; pw_len++)
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

  /**
   * Calculate keyspace stuff
   */

#ifdef JTR_MODE
  log_event("Calculate keyspace stuff");
#endif
  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    int     elems_cnt = db_entry->elems_cnt;
    elem_t *elems_buf = db_entry->elems_buf;

    for (int elems_idx = 0; elems_idx < elems_cnt; elems_idx++)
    {
      elem_t *elem_buf = &elems_buf[elems_idx];

      elem_ks (elem_buf, db_entries, ks_cnt);

      mpz_add (elem_buf->ks_cnt, elem_buf->ks_cnt, ks_cnt);

      mpz_add (total_ks_cnt, total_ks_cnt, ks_cnt);
    }

    const u64 words_cnt = db_entry->words_cnt;

    mpz_add_ui (total_words_cnt, total_words_cnt, words_cnt);
  }

#ifndef JTR_MODE
  if (keyspace)
  {
    mpz_out_str (stdout, 10, total_ks_cnt);

    printf ("\n");

    return 0;
  }
#else
  mpf_set_z(count, total_ks_cnt);
#endif

  /**
   * sort elems by ks
   */

#ifdef JTR_MODE
  log_event("Sort elements by keyspace");
#endif
  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    elem_t *elems_buf = db_entry->elems_buf;

    const int elems_cnt = db_entry->elems_cnt;

    qsort (elems_buf, elems_cnt, sizeof (elem_t), sort_by_ks);
  }

  /**
   * sort global order by pw length counts
   */

#ifdef JTR_MODE
  log_event("Sort elements by password length counts");
#endif
  for (int pw_len = pw_min, order_pos = 0; pw_len <= pw_max; pw_len++, order_pos++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    const u64 words_cnt = db_entry->words_cnt;

    pw_order_t *pw_order = &pw_orders[order_pos];

    pw_order->len = pw_len;
    pw_order->cnt = words_cnt;
  }

  const int order_cnt = pw_max + 1 - pw_min;

  qsort (pw_orders, order_cnt, sizeof (pw_order_t), sort_by_cnt);

  /**
   * seek to some starting point
   */

#ifdef JTR_MODE
  log_event("Seek to starting point");
#endif
  if (mpz_cmp_si (skip, 0))
  {
    if (mpz_cmp (skip, total_ks_cnt) > 0)
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
      fprintf (stderr, "Value of --limit must be smaller than total keyspace\n");

#ifndef JTR_MODE
      return (-1);
#else
      error();
#endif
    }

    mpz_t tmp;

    mpz_init (tmp);

    mpz_add (tmp, skip, limit);

    if (mpz_cmp (tmp, total_ks_cnt) > 0)
    {
      fprintf (stderr, "Value of --skip + --limit must be smaller than total keyspace\n");

#ifndef JTR_MODE
      return (-1);
#else
      error();
#endif
    }

    mpz_set (total_ks_cnt, tmp);

    mpz_clear (tmp);
  }

  /**
   * loop
   */

#ifdef JTR_MODE
  log_event("Starting candidate generation");
#endif
#ifndef JTR_MODE
  while (mpz_cmp (total_ks_pos, total_ks_cnt) < 0)
#else
  while (!event_abort && mpz_cmp (total_ks_pos, total_ks_cnt) < 0)
#endif
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

      const int elems_cnt = db_entry->elems_cnt;
      const int elems_pos = db_entry->elems_pos;

      if (elems_pos == elems_cnt) continue;

      elem_t *elems_buf = db_entry->elems_buf;

      elem_t *elem_buf = &elems_buf[elems_pos];

      mpz_sub (iter_max, elem_buf->ks_cnt, elem_buf->ks_pos);

      const u64 words_cnt = wordlen_dist[pw_len];

      if (mpz_cmp_ui (iter_max, words_cnt) > 0)
      {
        mpz_set_ui (iter_max, words_cnt);
      }

      mpz_sub (total_ks_left, total_ks_cnt, total_ks_pos);

      if (mpz_cmp (total_ks_left, iter_max) < 0)
      {
        mpz_set (iter_max, total_ks_left);
      }

      const u64 iter_max_u64 = mpz_get_ui (iter_max);

      for (u64 iter_pos_u64 = 0; iter_pos_u64 < iter_max_u64; iter_pos_u64++)
      {
        mpz_add_ui (ks_pos, elem_buf->ks_pos, iter_pos_u64);

        if (mpz_cmp (total_ks_pos, skip) >= 0)
        {
          elem_set_pwbuf (elem_buf, db_entries, ks_pos, pw_buf);

#ifndef JTR_MODE
          out_push (out, pw_buf, pw_len + 1);
#else
          if (ext_filter(pw_buf))
          if (crk_process_key(pw_buf))
            break;
#endif
        }

        mpz_add_ui (total_ks_pos, total_ks_pos, 1);
      }

#ifndef JTR_MODE
      out_flush (out);
#else
      mpf_set_z(pos, total_ks_pos);
#endif

      mpz_add (elem_buf->ks_pos, elem_buf->ks_pos, iter_max);

      if (mpz_cmp (elem_buf->ks_pos, elem_buf->ks_cnt) == 0)
      {
        mpz_set_si (elem_buf->ks_pos, 0);

        db_entry->elems_pos++;
      }

      if (mpz_cmp (total_ks_pos, total_ks_cnt) == 0) break;
    }
  }

  /**
   * cleanup
   */

#ifdef JTR_MODE
  log_event("PRINCE done. Cleaning up.");
#endif
  mpz_clear (iter_max);
  mpz_clear (ks_pos);
  mpz_clear (ks_cnt);
  mpz_clear (total_ks_cnt);
  mpz_clear (total_ks_pos);
  mpz_clear (total_ks_left);
  mpz_clear (total_words_cnt);
  mpz_clear (skip);
  mpz_clear (limit);

  for (int pw_len = pw_min; pw_len <= pw_max; pw_len++)
  {
    db_entry_t *db_entry = &db_entries[pw_len];

    if (db_entry->elems_buf) free (db_entry->elems_buf);
    if (db_entry->words_buf) free (db_entry->words_buf);
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
  crk_done();
  rec_done(event_abort || (status.pass && db->salts));
#endif
}

#endif /* HAVE_LIBGMP */
