#include "os.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>

#include "arch.h"
#include "int128.h"
#include "john.h"
#include "loader.h"
#include "cracker.h"
#include "options.h"
#include "config.h"
#include "logger.h"
#include "status.h"
#include "signals.h"
#include "external.h"
#include "recovery.h"
#include "mask.h"
#include "unicode.h"
#include "unicode_range.h"

#define MAX_CAND_LENGTH PLAINTEXT_BUFFER_SIZE
#define DEFAULT_MAX_LEN 16

#if JTR_HAVE_INT128
typedef uint128_t uint_big;
#define UINT_BIG_MAX UINT128_MAX
#else
typedef uint64_t uint_big;
#define UINT_BIG_MAX UINT64_MAX
#endif

int rain_cur_len;

static int rec_cur_len;
static char *charset;           

static UTF32 word[MAX_CAND_LENGTH+1];
static int charset_idx[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];//the first value should be req_maxlen-req_minlen
static int rec_charset_idx[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int maxlength;
static int minlength;
static int state_restored;
static uint64_t total;
static uint64_t subtotal;

static int loop;
static int rec_loop;

static int C;
static int rec_C;

static uint_big counter;//linear counter
static uint_big rec_counter;
static uint_big x;
static int l, c;

static int quick_conversion;
static int set, rec_set;

static double get_progress(void)
{
	emms();
	
	if (!total)
		return -1;
		
	if (rain_cur_len > maxlength)
		return 100;
	
	return (100.0 * x) / (total - subtotal);
}

static void fix_state(void)
{
	int i, j;
	
	rec_set = set;
	for (i = 0; i <= maxlength - minlength; ++i) {
		for(j = 0; j < maxlength; ++j)
			rec_charset_idx[i][j] = charset_idx[i][j];
	}
	rec_cur_len = rain_cur_len;
	rec_counter = x;
	rec_loop = l;
	rec_C = c;
}

static uint_big powi(uint32_t b, uint32_t p)
{
	uint_big res = 1;

	if (b == 0)
		return 0;

	while (p--) {
		uint_big temp = res * b;

		if (temp < res)
			return UINT_BIG_MAX;
		res = temp;
	}

	return res;
}

static void big2str(uint_big orig, char *str) {
	uint_big b = orig, total = 0;
	int c = 0;
	int x;
	
	do {
		str[c] = b%10 + '0';
		total += (b % 10) * powi(10, c);
		b /= 10;
		++c;
		
	} while(total < orig);
	
	char tmp[c/2];
	
	for(x=0; x<c; ++x) {
		if(x<c/2+c%2) {
			tmp[x] = str[x];
			str[x] = str[c-x-1];
		}
		else {
			str[x] = tmp[c-x-1];
		}
	}
	str[c] = '\0';	
}

static uint_big str2big(char *str) {
	int x;
	static uint_big num = 0;
	int c = 0;
	for(x=strlen(str)-1; x>=0; --x) {
		num += (str[x]-'0') * powi(10, c);
		c++;
	}
	return num;
}

static void save_state(FILE *file)
{
	int i, j;
	char str[40];
	memset(str, 0, 40);
	fprintf(file, "%d\n", rec_set);
	for (i = 0; i <= maxlength - minlength; ++i) {
		for(j = 0; j < maxlength; ++j)
			fprintf(file, "%d\n", rec_charset_idx[i][j]);
	}
	fprintf(file, "%d\n", rec_cur_len);
	big2str(rec_counter, str);
	fprintf(file, "%s\n", str);
	fprintf(file, "%d\n", rec_loop);
	fprintf(file, "%d\n", rec_C);
}
static int restore_state(FILE *file)
{
	int i, j, d;
	char str[41];
	
	if(fscanf(file, "%d\n", &d) == 1)
		set = d;
	else return 1;

	for (i = 0; i <= maxlength - minlength; ++i) {
		for(j = 0; j < maxlength; ++j)
			if(fscanf(file, "%d\n", &d) == 1)
				charset_idx[i][j] = d;
			else return 1;
	}
	if(fscanf(file, "%d\n", &d) == 1)
		rain_cur_len = d;
	else return 1;

	if(fscanf(file, "%s\n", str) == 1)
		counter = str2big(str);
	else return 1;
	
	if(fscanf(file, "%d\n", &d) == 1)
		loop = d;
	else return 1;
	
	if(fscanf(file, "%d\n", &d) == 1)
		C = d;
	else return 1;
	
	state_restored = 1;

	return 0;
}

/* Parse \U+HHHH and \U+HHHHH notation to characters, in place. */
static void parse_unicode(char *string)
{
	static int warned;
	unsigned char *s = (unsigned char*)string;
	unsigned char *d = s;

	if (!string || !*string)
		return;

	while (*s)
		if (*s == '\\' && s[1] != 'U') {
			*d++ = *s++;
			*d++ = *s++;
		} else if (*s == '\\' && s[1] == 'U' && s[2] == '+' &&
		           atoi16[s[3]] != 0x7f && atoi16[s[4]] != 0x7f &&
		           atoi16[s[5]] != 0x7f && atoi16[s[6]] != 0x7f &&
		           atoi16[s[7]] != 0x7f) {
			UTF32 wc[2];
			UTF8 conv[8];
			char *c = (char*)conv;

			wc[0] = (atoi16[s[3]] << 16) + (atoi16[s[4]] << 12) +
				(atoi16[s[5]] << 8) + (atoi16[s[6]] << 4) + atoi16[s[7]];
			wc[1] = 0;
			if (!wc[0] && !warned++ && john_main_process)
				fprintf(stderr,
				        "Warning: \\U+00000 in mask terminates the string\n");
			if (wc[0] == '\\')
				*d++ = '\\';

			utf32_to_enc(conv, sizeof(conv), wc);

			while (*c)
				*d++ = *c++;
			s += 8;
		} else if (*s == '\\' && s[1] == 'U' && s[2] == '+' &&
		           atoi16[s[3]] != 0x7f && atoi16[s[4]] != 0x7f &&
		           atoi16[s[5]] != 0x7f && atoi16[s[6]] != 0x7f) {
			UTF32 wc[2];
			UTF8 conv[8];
			char *c = (char*)conv;

			wc[0] = (atoi16[s[3]] << 12) + (atoi16[s[4]] << 8) +
				(atoi16[s[5]] << 4) + atoi16[s[6]];
			wc[1] = 0;
			if (!wc[0] && !warned++ && john_main_process)
				fprintf(stderr,
				        "Warning: \\U+0000 in mask terminates the string\n");
			if (wc[0] == '\\')
				*d++ = '\\';

			utf32_to_enc(conv, sizeof(conv), wc);

			while (*c)
				*d++ = *c++;
			s += 7;
		} else
			*d++ = *s++;

	*d = 0;
}

static int submit(UTF32 *word, int loop2)
{
	UTF8 out[4 * MAX_CAND_LENGTH];
	int i;

	/* Set current word */
	if (quick_conversion) {
		/* Quick conversion (only ASCII or ISO-8859-1) */
		for (i = 0; i < minlength + loop2; i++)
			out[i] = word[i];
		out[i] = 0;
	} else if (options.target_enc == UTF_8) {
		/* Nearly as quick conversion, from UTF-8-32[tm] to UTF-8 */
		word[minlength + loop2] = 0;
		utf8_32_to_utf8(out, word);
	} else {
		/* Slowest conversion, from real UTF-32 to sone legacy codepage */
		word[minlength + loop2] = 0;
		utf32_to_enc(out, sizeof(out), word);
	}
	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack((char*)out);
	else
		return crk_process_key((char*)out);
}

int do_rain_crack(struct db_main *db, char *req_charset)
{
	int i, j;
	int cp_max = 255;

	unsigned int charcount;
	int fmt_case = (db->format->params.flags & FMT_CASE);
	char *default_set;

	UTF32 *charset_utf32;

	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MAX(options.eff_minlength, 1);
	
	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;

	default_set = (char*)cfg_get_param("Rain", NULL, "DefaultCharset");
	if (!req_charset)
		req_charset = default_set;

	if (req_charset && *req_charset) {
		if (strlen(req_charset) == 1 && isdigit(req_charset[0])) {
			int cnum = atoi(req_charset);
			char pl[2] = { '0' + cnum, 0 };
			char *c = (char*)cfg_get_param("Rain", NULL, pl);

			if (c)
				req_charset = c;
		}
		/* Parse \U+HHHH notation */
		parse_unicode(req_charset);
		charset = req_charset;
	} else if (fmt_case)
		charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	else
		charset = "0123456789abcdefghijklmnopqrstuvwxyz !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

	charcount = strlen(charset);
	/* Convert charset to UTF-32 */
	if (!strcasecmp(charset, "full-unicode")) {
		charset_utf32 = mem_alloc(0x24000 * sizeof(UTF32));
		charcount = full_unicode_charset(charset_utf32);
	}
	else if (options.input_enc == UTF_8) {
		if (!valid_utf8((UTF8*)charset)) {
			if (john_main_process)
				fprintf(stderr, "Error in Unicode conversion. "
				        "Ensure --input-encoding is correct\n");
			error();
		} else {
			int charsize = strlen8((UTF8*)charset) + 1;

			charset_utf32 = mem_alloc(charsize * sizeof(UTF32));
			utf8_to_utf32(charset_utf32, charsize * sizeof(UTF32),
			              (UTF8*)charset, charcount);
		}
	}
	else {
		charset_utf32 = mem_alloc((charcount + 1) * sizeof(UTF32));
		enc_to_utf32(charset_utf32, (charcount + 1) * sizeof(UTF32),
		             (UTF8*)charset, charcount);
	}
	//Performance step: Use UTF-32-8 when applicable
	if (options.target_enc == UTF_8)
		utf32_to_utf8_32(charset_utf32);

	charcount = strlen32(charset_utf32);
	
	counter = 0;
	subtotal = 0;
	
	status_init(get_progress, 0);
	
	rec_restore_mode(restore_state);
	rec_init(db, save_state);
	
	if(john_main_process) {
		log_event("Proceeding with \"rain\" mode");
		log_event("- Charset: %s size %d", req_charset ? req_charset : charset,
		          charcount);
		log_event("- Lengths: %d-%d, max",
		          MAX(options.eff_minlength, 1), maxlength);
		if(rec_restored) {
			fprintf(stderr, "Proceeding with \"rain\"%s%s",
			        req_charset ? ": " : "",
			        req_charset ? req_charset : "");
			if (options.flags & FLG_MASK_CHK)
				fprintf(stderr, ", hybrid mask:%s", options.mask ?
				        options.mask : options.eff_mask);
			if (options.rule_stack)
				fprintf(stderr, ", rules-stack:%s", options.rule_stack);
			if (options.req_minlength >= 0 || options.req_maxlength)
				fprintf(stderr, ", lengths: %d-%d",
				        options.eff_minlength + mask_add_len,
				        options.eff_maxlength + mask_add_len);
			fprintf(stderr, "\n");
		}
	}
	if(!state_restored) {
		rain_cur_len = minlength;
		srand(time(NULL));
		loop = 0;
		counter = 0;
		C = 1;
		for(i = 0; i <= maxlength - minlength; i++) {
			for (j = 0; j < maxlength; j++)
				charset_idx[i][j] = 0;
		}
	}
	int mod = 2 - charcount % 2;
	crk_init(db, fix_state, NULL);
	
	for(l=loop; l <= maxlength-minlength; ++l) {
        if(event_abort) 
	        break;
	    uint_big total = powi(charcount, minlength+l);
        subtotal = 0;
        if(l > 0)
            subtotal = powi(charcount, minlength+l-1);
        for(x = counter; x < total-subtotal; ++x) {		         
            if(event_abort)
                break;
            int loop2;
            for(loop2 = l; loop2 <= maxlength-minlength; ++loop2) {	
                if(event_abort)
                    break;

                int skip = 0;

                if (state_restored)
                    state_restored = 0;
                else
                    set++;

                if (options.node_count) {
                    int for_node = set % options.node_count + 1;
                    skip = for_node < options.node_min ||
	                    for_node > options.node_max;
                }
                int mpl = minlength + loop2;
                if(!skip) {
                    quick_conversion = 1;
                    for(i=0; i<mpl; ++i) {
             			if((word[i] = charset_utf32[(charset_idx[loop2][i]+C)%charcount]) > cp_max)
	                        quick_conversion = 0;
                    }
                    submit(word, loop2);
                }
                for(i=0; i<mpl; ++i) {
                    if(++charset_idx[loop2][i] >= charcount) {
                        charset_idx[loop2][i] = 0;
                        break;
                    }
                }
                C+=mod;
                if(C > charcount) C = 1;
            }
        }
	}
	crk_done();
	rec_done(event_abort);
	MEM_FREE(charset_utf32);
	return 0;
}


