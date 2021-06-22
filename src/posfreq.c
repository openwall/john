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
int posfreq_cur_len;
static int set;
static int rec_set;
static int rec_cur_len;
static uint_big *counter;
static uint_big *rec_counter;
static int **state;
static int **rec_state;
static int **cs;
static int **rec_cs;
static int loop;
static int rec_loop;
static char ***chrsts;
static int divi;

static double get_progress(void)
{
	emms();
	
	if (!total)
		return -1;
		
	if (posfreq_cur_len > maxlength)
		return 100;
	
	return (100.0 * counter[maxlength-posfreq_cur_len]) / total;
}

static void fix_state(void)
{
	int i, j;
	rec_set = set;
	for(i=0; i<=maxlength-minlength; i++) {
        for(j=0; j<minlength+i; j++) {
    	    rec_state[i][j] = state[i][j];    
    	    rec_cs[i][j] = cs[i][j];
        }
        rec_counter[i] = counter[i];
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
		    fprintf(file, "%d\n", rec_state[i][j]);
            fprintf(file, "%d\n", rec_cs[i][j]);
	    }
        big2str(rec_counter[i], str);
        fprintf(file, "%s\n", str);
        memset(str, 0, 41);
    }
    for(i=0; i<maxlength; i++) {
        for(j=0; j<divi; j++)
            fprintf(file, "%s\n", chrsts[i][j]);
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
            if(fscanf(file, "%d\n", &d) == 1)
                state[i][j] = d;
            else return 1;

            if(fscanf(file, "%d\n", &d) == 1)
                cs[i][j] = d;
            else return 1;
        }
        if(fscanf(file, "%s\n", str) == 1) {
            counter[i] = str2big(str);
            memset(str, 0, 41);
        }   
        else return 1;
    }
    for(i=0; i<maxlength; i++) {
        for(j=0; j<divi; j++) {
	        if(fscanf(file, "%s\n", str) == 1) {
                memset(chrsts[i][j], 0, strlen(chrsts[i][j]));
                strcpy(chrsts[i][j], str);
                memset(str, 0, 41);
            }
            else return 1;
	    }
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
	srand(time(NULL));
	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MAX(options.eff_minlength, 1);

	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;

	charcount = 26;
    char **freq = (char **) mem_alloc(maxlength * sizeof(char *));
    for(i=0; i<maxlength; i++) {
        freq[i] = mem_alloc(charcount+1);
        switch(i) {
        case 0:
            //strcpy(freq[i], "TtAa4Oo0Ii1Ss5WwCcBbPpFfMmHhDdRrEe3NnLlGgUuVvYyKkXxJjQqZz26789\0");
            strcpy(freq[i], "taoiswcbpfmhdrenlguvykxjqz\0");
            break;
        case 1:
            //strcpy(freq[i], "ho0e3a4ni1rfuts5lpcmdybvwgxkjqzHOEANIRFUTSLPCMDYBVWGXKJQZ26789\0");
            strcpy(freq[i], "hoeanirfutslpcmdybvwgxkjqz\0");
            break;
        case 2:
            //strcpy(freq[i], "e3rta4ds5o0ni1lmcupvgwyfbhkxjqzERTADSONILMCUPVGWYFBHKXJQZ26789\0");
            strcpy(freq[i], "ertadsonilmcupvgwyfbhkxjqz\0");
            break;
        case 3:
            //strcpy(freq[i], "e3ti1rnls5a4o0dhcmupgywkvfbxjqzETIRNLSAODHCMUPGYWKVFBXJQZ26789\0");
            strcpy(freq[i], "etirnlsaodhcmupgywkvfbxjqz\0");
            break;
        case 4:
            //strcpy(freq[i], "e3ri1ts5nlo0a4udchgmypvkbfwxjqzERITSNLOAUDCHGMYPVKBFWXJQZ26789\0");
            strcpy(freq[i], "eritsnloaudchgmypvkbfwxjqz\0");
            break;
        case 5:
            //strcpy(freq[i], "e3nrs5i1ta4dlco0gmyhuvpwfbkxjqzENRSITADLCOGMYHUVPWFBKXJQZ26789\0");
            strcpy(freq[i], "enrsitadlcogmyhuvpwfbkxjqz\0");
            break;
        case 6:
            //strcpy(freq[i], "e3ts5i1na4rldo0gycmuhpfbvwkxjqzETSINARLDOGYCMUHPFBVWKXJQZ26789\0");
            strcpy(freq[i], "etsinarldogycmuhpfbvwkxjqz\0");
            break;
        default:
            break;
        }
        if(i > 6) {
            switch(maxlength-i) {
            case 7:
                //strcpy(freq[i], "e3ra4ci1o0s5tpnlmuhfdgbwvxqzjkyERACIOSTPNLMUHFDGBWVXQZJKY26789\0");
                strcpy(freq[i], "eraciostpnlmuhfdgbwvxqzjky\0");
                break;
            case 6:
                //strcpy(freq[i], "e3rs5a4i1o0tclnpumfhgbdvwyxkjqzERSAIOTCLNPUMFHGBDVWYXKJQZ26789\0");
                strcpy(freq[i], "ersaiotclnpumfhgbdvwyxkjqz\0");
                break;
            case 5:
                //strcpy(freq[i], "e3ta4ri1o0s5cnluwpmhgdfbvykxjqzETARIOSCNLUWPMHGDFBVYKXJQZ26789\0");
                strcpy(freq[i], "etarioscnluwpmhgdfbvykxjqz\0");
                break;
            case 4:
                //strcpy(freq[i], "ti1a4rho0e3s5lwnmcufdbpgvykxjqzTIARHOESLWNMCUFDBPGVYKXJQZ26789\0");
                strcpy(freq[i], "tiarhoeslwnmcufdbpgvykxjqz\0");
                break;
            case 3:
                //strcpy(freq[i], "i1ta4e3o0hnruls5wcdfbmvgpykxjqzITAEOHNRMULSWCDFBMVGPKXJQZ26789\0");
                strcpy(freq[i], "itaeohnrulswcdfbmvgpykxjqz\0");
                break;
            case 2:
                //strcpy(freq[i], "e3no0ha4i1trls5cumgdbwvkxpfyjqzENOHAITRLSCUMGFBWVKXPFYJQZ26789\0");
                strcpy(freq[i], "enohaitrlscumgdbwvkxpfyjqz\0");
                break;
            case 1:
                //strcpy(freq[i], "e3s5dntyrfo0lga4hmwcpi1bkuvxjqzESDNTYRFOLGAHMWCPIBKUVXJQZ26789\0");
                strcpy(freq[i], "esdntyrfolgahmwcpibkuvxjqz\0");
                break;
            default:
                //strcpy(freq[i], "e3ta4o0i1ns5rhldcumfpgwybvkxjqzETAOINSRHLDCUMFPGWXBVKXJQZ26789\0");
                strcpy(freq[i], "etaoinsrhldcumfpgwybvkxjqz\0");
                break;
            }
        }
    }

	posfreq_cur_len = minlength;
 
    counter = (uint_big *) mem_alloc((maxlength-minlength+1) * sizeof(uint_big));
    rec_counter = (uint_big *) mem_alloc((maxlength-minlength+1) * sizeof(uint_big));
	state = (int **) mem_alloc((maxlength-minlength+1) * sizeof(int *));
    rec_state = (int **) mem_alloc((maxlength-minlength+1) * sizeof(int *));
    cs = (int **) mem_alloc((maxlength-minlength+1) * sizeof(int *));
	rec_cs = (int **) mem_alloc((maxlength-minlength+1) * sizeof(int *));

    for(i = 0; i <= maxlength-minlength; i++) {    
        counter[i] = 0;
        state[i] = (int *) mem_alloc((minlength+i) * sizeof(int));
        rec_state[i] = (int *) mem_alloc((minlength+i) * sizeof(int));
        cs[i] = (int *) mem_alloc((minlength+i) * sizeof(int));
        rec_cs[i] = (int *) mem_alloc((minlength+i) * sizeof(int));
        for(j = 0; j < minlength+i; j++) {
            state[i][j] = 0;
            cs[i][j] = 0;
        }
    }
    int x,y,z;
    chrsts = (char ***) mem_alloc(maxlength * sizeof(char **));
    divi = charcount/4;
    if(charcount % 4)
        divi++;
    
    for(x=0; x<maxlength; x++) {
        chrsts[x] = (char **) mem_alloc(divi * sizeof(char *));
        for(y=0; y<divi; y++) {
            chrsts[x][y] = (char *) mem_alloc(5 * sizeof(char));
            for(z=0; z<4; z++)
                chrsts[x][y][z] = 0;
        }
    }
    for(x=0; x<maxlength; x++) {
        int chain = 0, chain1 = 0, chain2 = 0, chain3 = 0;
        int chain4 = 0, chain5 = 0, chain6 = 0, chain7 = 0;
        for(y=0; y<divi; y++) {
            int Z = 4;
            if(y == divi-1)
                Z = charcount % 4;
            for(z=0; z<Z; z++) {
                char c = freq[x][rand()%((y+1)*4)];
                chrsts[x][y][z] = c;
                int again = 0;
                check:
                for(i=0; i<=y; i++) {
                    int Z2 = 4;
                    if((j == i) == divi-1)
                        Z2 = charcount % 4;
                    for(j=0; j<Z2; j++) {
                        if(z == j && i == y) continue;
                        if(chrsts[x][y][z] == chrsts[x][i][j]) {
                            again = 1;
                            break;
                        }
                    }
                    if(again)
                        break;
                }
                if(again) {
                    z--;
                    continue;
                }
                chrsts[x][y][z+1] = '\0';

                if(x > 0) {
                    if(chrsts[x-1][y][z-chain] == 't') {
                        if(chain < 4) {
                            chrsts[x][y][z] = "hieo"[chain];
                            chain++;
        
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain1] == 'h') { 
                        if(chain1 < 2) {
                            chrsts[x][y][z] = "ei"[chain1];
                            chain1++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain2] == 'i') {
                        if(chain2 < 5) {
                            chrsts[x][y][z] = "nstoc"[chain2];
                            chain2++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain3] == 'e') {
                        if(chain3 < 5) {
                            chrsts[x][y][z] = "rnsda"[chain3];
                            chain3++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain4] == 'a') {
                        if(chain4 < 5) {
                            chrsts[x][y][z] = "ntlrs"[chain4];
                            chain4++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain5] == 'r') {
                        if(chain5 < 3) {
                            chrsts[x][y][z] = "eia"[chain5];
                            chain5++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain6] == 'o') {
                        if(chain6 < 5) {
                            chrsts[x][y][z] = "nrfum"[chain6];
                            chain6++;
                            goto check;
                        }
                    }
                    if(chrsts[x-1][y][z-chain7] == 'n') {
                        if(chain7 < 4) {
                            chrsts[x][y][z] = "dtge"[chain7];
                            chain7++;
                            goto check;
                        }
                    }
                }
            }
            //printf("%s\n", chrsts[x][y]);
        }
    }

    status_init(get_progress, 0);
    rec_restore_mode(restore_state);
    rec_init(db, save_state);

   for(x=0; x<maxlength; x++)
        word[x] = chrsts[x][0][0];
    
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
        //int start = 0;
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
                	for(i=0; i<mpl; i++)
                	    word[i] = chrsts[i][cs[loop2][i]][state[loop2][i]];

            	    submit(word, loop2);
                }
                int pos = mpl - 1;
                while(pos >= 0 && ++state[loop2][pos] >= strlen(chrsts[pos][cs[loop2][pos]])) {
                    state[loop2][pos] = 0;  
                    pos--;
                }
                if(pos < 0) {
                    int pos2 = mpl - 1;
                    while(pos2 >= 0 && ++cs[loop2][pos2] >= divi) {
                        cs[loop2][pos2] = 0;
                        pos2--;
                    }
                }
                counter[loop2]++;
            }
        }
        posfreq_cur_len++;
    }

    crk_done();
	rec_done(event_abort);

	MEM_FREE(counter);
	MEM_FREE(rec_counter);

	for(i=0; i<=maxlength-minlength; i++) {
        MEM_FREE(state[i]);
        MEM_FREE(rec_state[i]);
        MEM_FREE(cs[i]);
        MEM_FREE(rec_cs[i]);
    }
	MEM_FREE(state);
    MEM_FREE(rec_state);
    MEM_FREE(cs);
    MEM_FREE(rec_cs);

	for(i=0; i<maxlength; i++) {
        for(j=0; j<divi; j++)
	        MEM_FREE(chrsts[i][j]);
	    MEM_FREE(chrsts[i]);
	}
	MEM_FREE(chrsts);

	return 0;
}


