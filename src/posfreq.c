#include "os.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

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

static char word[MAX_CAND_LENGTH+1];

static int maxlength;
static int minlength;
static int state_restored;
static uint64_t total;
static uint64_t subtotal;

int posfreq_cur_len;
static int rec_cur_len;
static uint_big **step;
static uint_big **rec_step;
static int *cs;
static int *rec_cs;
static int set;
static int rec_set;
static int loop;
static int rec_loop;
static uint_big *counter;
static uint_big *rec_counter;

static double get_progress(void)
{
	emms();
	
	if (!total)
		return -1;
		
	if (posfreq_cur_len > maxlength)
		return 100;
	
	return (100.0 * counter[maxlength-posfreq_cur_len]) / (total - subtotal);
}

static void fix_state(void)
{
	int i, j;
	rec_set = set;
	for(i=0; i<=maxlength-minlength; i++) {
        for(j=0; j<minlength+i; j++) {
    	    rec_step[i][j] = step[i][j];
        }
        rec_counter[i] = counter[i];
	    rec_cs[i] = cs[i];
    }
	rec_cur_len = posfreq_cur_len;
	rec_loop = loop;
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
	char str[41];
	memset(str, 0, 41);
    fprintf(file, "%d\n", rec_set);
	for(i=0; i<=maxlength-minlength; i++) {
	    for(j=0; j<minlength+i; j++) {
		    big2str(rec_step[i][j], str);
	        fprintf(file, "%s\n", str);
            memset(str, 0, 41);
        }
        big2str(rec_counter[i], str);
        fprintf(file, "%s\n", str);
        memset(str, 0, 41);
        fprintf(file, "%d\n", rec_cs[i]);
    }
	fprintf(file, "%d\n", rec_cur_len);
	fprintf(file, "%d\n", rec_loop);
}

static int restore_state(FILE *file)
{
	int i, j, d;
	char str[41];
	memset(str, 0, 41);
	if(fscanf(file, "%d\n", &d) == 1)
		set = d;
	else return 1;

    for(i=0; i<=maxlength-minlength; i++) {
        for(j=0; j<minlength+i; j++) {
            if(fscanf(file, "%s\n", str) == 1)
                step[i][j] = str2big(str);
            else return 1;
            memset(str, 0, 41);    
        }
        if(fscanf(file, "%s\n", str) == 1)
            counter[i] = str2big(str);
        else return 1;
        memset(str, 0, 41);
        if(fscanf(file, "%d\n", &d) == 1)
            cs[i] = d;
        else return 1;
    }
	if(fscanf(file, "%d\n", &d) == 1)
		posfreq_cur_len = d;
	else return 1;

	if(fscanf(file, "%d\n", &d) == 1)
		loop = d;
	else return 1;

	state_restored = 1;

	return 0;
}

static int submit(char *word, int loop2)
{
	char out[4 * MAX_CAND_LENGTH];
	int i;

	/* Set current word */
	for (i = 0; i < minlength + loop2; i++)
		out[i] = word[i];
	out[i] = 0;

	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack(out);
	else
		return crk_process_key(out);
}

int do_posfreq_crack(struct db_main *db)
{
    static int i, j;
	unsigned int charcount;
	
	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MAX(options.eff_minlength, 1);

	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;

	charcount = 26;
    char **freq = (char **) mem_alloc(maxlength * sizeof(char *));
    for(i=0; i<maxlength; i++) {
        freq[i] = mem_alloc(charcount);
        switch(i) {
        case 0:
            strcpy(freq[i], "taoiswcbpfmhdrenlguvykxjqz");
            break;
        case 1:
            strcpy(freq[i], "hoeanirfutslpcmdybvwgxkjqz");
            break;
        case 2:
            strcpy(freq[i], "ertadsonilmcupvgwyfbhkxjqz");
            break;
        case 3:
            strcpy(freq[i], "etirnlsaodhcmupgywkvfbxjqz");
            break;
        case 4:
            strcpy(freq[i], "eritsnloaudchgmypvkbfwxjqz");
            break;
        case 5:
            strcpy(freq[i], "enrsitadlcogmyhuvpwfbkxjqz");
            break;
        case 6:
            strcpy(freq[i], "etsinarldogycmuhpfbvwkxjqz");
            break;
        }
        if(i > 6) {
            switch(maxlength - i) {
            case 6:
                strcpy(freq[i], "eraciostpnlmuhfdgbwvxqzjky");
                break;
            case 5:
                strcpy(freq[i], "ersaiotclncpumfhgbdvwyxkjqz");
                break;
            case 4:
                strcpy(freq[i], "etarioscnluwpmhgdfbvykxjqz");
                break;
            case 3:
                strcpy(freq[i], "tiarhoeslwnmcufdbpgvykxjqz");
                break;
            case 2:
                strcpy(freq[i], "itaeohnrnulswcdfbfvgpkxjqz");
                break;
            case 1:
                strcpy(freq[i], "enohaitrlscumgdbwvkxpfyjqz");
                break;
            case 0:
                strcpy(freq[i], "esdntyrfolgahmwcpibkuvxjqz");
                break;
            default:
                strcpy(freq[i], "etaoinsrhldcumfpgwxbvkxjqz");
                break;
            }
        }
    }
	posfreq_cur_len = minlength;
    
    step = (uint_big **) mem_alloc((maxlength-minlength+1) * sizeof(uint_big *));
    rec_step = (uint_big **) mem_alloc((maxlength-minlength+1) * sizeof(uint_big *));
    counter = (uint_big *) mem_alloc((maxlength-minlength+1) * sizeof(uint_big));
    rec_counter = (uint_big *) mem_alloc((maxlength-minlength+1) * sizeof(uint_big));
	cs = (int *) mem_alloc((maxlength-minlength+1) * sizeof(int));
    rec_cs = (int *) mem_alloc((maxlength-minlength+1) * sizeof(int));
    
    for(i = 0; i <= maxlength-minlength; i++) {
        step[i] = (uint_big *) mem_alloc((minlength+i) * sizeof(uint_big));
        rec_step[i] = (uint_big *) mem_alloc((minlength+i) * sizeof(uint_big));
        counter[i] = 0;
        cs[i] = 0;
        for(j = 0; j < minlength+i; j++)
            step[i][j] = 1;
    }

    char **chrsts = (char **) mem_alloc(maxlength * sizeof(char *));
    for(i=0; i<maxlength; i++) {
        chrsts[i] = (char *) mem_alloc((charcount + 1)* sizeof(char));
        for(j=0; j<charcount; j++) {
            chrsts[i][j] = freq[i][j];
            chrsts[i][j+1] = '\0';
        }
    }

    status_init(get_progress, 0);
    rec_restore_mode(restore_state);
    rec_init(db, save_state);

	if(john_main_process) {
		log_event("Proceeding with \"posfreq\" mode");
		log_event("- Lengths: %d-%d, max",
		          MAX(options.eff_minlength, 1), maxlength);
		if(rec_restored) {
			fprintf(stderr, "Proceeding with \"posfreq\" mode");
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

    crk_init(db, fix_state, NULL);
    for(; loop <= maxlength-minlength; loop++) {
        if(event_abort) break;
        uint_big total = powi(charcount, minlength+loop);
        for(; counter[loop] < total; ) {		         
    		if(event_abort) break;
    		int loop2;
    		for(loop2 = loop; loop2 <= maxlength-minlength; loop2++) {
                if(event_abort) break;
                int mpl = minlength + loop2;
        
           		int skip = 0;
                if (state_restored)
                    state_restored = 0;
                else
                	set++;

                if (options.node_count) {
                	int for_node = set % options.node_count + 1;
                	skip = for_node < options.node_min || for_node > options.node_max;
                }
                if(!skip) {
                	int pos;
                	for(pos=0; pos<mpl; ++pos) { 
                	    for(; step[loop2][pos] <= powi(charcount, pos+1); step[loop2][pos]++) { 
                            if(counter[loop2] < powi(charcount, mpl)/powi(charcount, pos+1) * step[loop2][pos]) {
                                cs[loop2] = (counter[loop2]*2-step[loop2][pos]+1) % charcount;
                                break;
                            }
                            if(step[loop2][pos] == powi(charcount, pos+1)) {
                                step[loop2][pos] = 1;
                                break;
                            }
                        }
                	    word[pos] = chrsts[pos][cs[loop2]];
                    }
            	    submit(word, loop2);
                }
                counter[loop2]++;
            }
        }
        posfreq_cur_len++;
    }
    crk_done();
	rec_done(event_abort);

	for(i=0; i<=maxlength-minlength; i++) {
        MEM_FREE(step[i]);
        MEM_FREE(rec_step[i]);
    }
	MEM_FREE(step);
    MEM_FREE(rec_step);
	MEM_FREE(counter);
	MEM_FREE(rec_counter);
	MEM_FREE(cs);
	MEM_FREE(rec_cs);
	for(i=0; i<maxlength; i++)
	    MEM_FREE(chrsts[i]);
	MEM_FREE(chrsts);
	
	return 0;
}


