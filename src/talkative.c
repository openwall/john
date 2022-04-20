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

#include "talkative.h"

#define MAX_CAND_LENGTH PLAINTEXT_BUFFER_SIZE
#define DEFAULT_MAX_LEN 16


#define CHAINS_MAX 95
#define DIVI_MAX 95
#define SET_MAX 95

#if JTR_HAVE_INT128
typedef uint128_t uint_big;
#define UINT_BIG_MAX UINT128_MAX
#else
typedef uint64_t uint_big;
#define UINT_BIG_MAX UINT64_MAX
#endif

static char word[MAX_CAND_LENGTH];
static int short maxlength;
static int short minlength;
static int short state_restored;
static uint_big total;
int talkative_cur_len;
static int set;
static int rec_set;
static int short rec_cur_len;
static uint_big counter[MAX_CAND_LENGTH-1];
static uint_big rec_counter[MAX_CAND_LENGTH-1];
static int short state[MAX_CAND_LENGTH-1][CHAINS_MAX][MAX_CAND_LENGTH];
static int short rec_state[MAX_CAND_LENGTH-1][CHAINS_MAX][MAX_CAND_LENGTH];
static int short loop;
static int short rec_loop;
static char chrsts[MAX_CAND_LENGTH-1][DIVI_MAX][SET_MAX];
static char rec_chrsts[MAX_CAND_LENGTH-1][DIVI_MAX][SET_MAX];
static char chrsts2[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX][SET_MAX];
static char rec_chrsts2[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX][SET_MAX];
static char chrsts3[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX][SET_MAX];
static char rec_chrsts3[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX][SET_MAX];
static char chainFreq[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX+1];
static char counterChainFreq[MAX_CAND_LENGTH-1][CHAINS_MAX][CHAINS_MAX];

static int short divi[MAX_CAND_LENGTH];
static int short rec_divi[MAX_CAND_LENGTH];
static int short divi1[MAX_CAND_LENGTH-1][CHAINS_MAX];
static int short rec_divi1[MAX_CAND_LENGTH-1][CHAINS_MAX];
static int short divi2[MAX_CAND_LENGTH-1][CHAINS_MAX];
static int short rec_divi2[MAX_CAND_LENGTH-1][CHAINS_MAX];

static int short state1[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];
static int short rec_state1[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];
static int short state2[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];
static int short rec_state2[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];

static int short cs[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int short cs1[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1][CHAINS_MAX];
static int short cs2[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1][CHAINS_MAX];//todo loop2
static int short rec_cs[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int short rec_cs2[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1][CHAINS_MAX];//todo loop2

static int short J[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];
static int short rec_J[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];

static int short top1[MAX_CAND_LENGTH-1][DIVI_MAX];
static int short top2[MAX_CAND_LENGTH-1][CHAINS_MAX][DIVI_MAX];
static int short top3[MAX_CAND_LENGTH-1][CHAINS_MAX][DIVI_MAX];
static uint_big chainCounter[MAX_CAND_LENGTH-1];
static uint_big counterChainCounter[MAX_CAND_LENGTH-1];
static uint_big chainCounterDone[MAX_CAND_LENGTH-1];


static int talk[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];
static int rec_talk[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];
static int c[MAX_CAND_LENGTH-1];
static int b[MAX_CAND_LENGTH-1];

static double get_progress(void)
{
	emms();
	
	if (!total)
		return -1;
		
	if (talkative_cur_len > maxlength)
		return 100;
	
	return (100.0 * counter[maxlength-talkative_cur_len]) / total;
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
	//revert the characters
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

static void fix_state(void)
{
	int i, j, k, l;
	rec_set = set;
	/*
	for(i=0; i<=maxlength-minlength; i++) {
        rec_counter[i] = counter[i];
        for(j=0; j<minlength+i; j++) {
            if(i == 0) {
                rec_inc[j] = inc[j];
                rec_J[loop2][j] = inc[j]; 
                rec_divi[j] = divi[j];
            }
            rec_cs[i][j] = cs[i][j];
            rec_counter1[i][j] = counter1[i][j];
        	for(k=0; k<7; k++) {
        	    for(l=0; l<8; l++) {
        	        if(k == 0) {
                        rec_cs2[i][j][l] = cs2[i][j][l];
                        if(i == 0 && j < minlength+i-1) {
                            rec_divi2[j][l] = divi2[j][l];
                            strcpy(rec_chrsts3[l][j][k], chrsts3[l][j][k]);
                            strcpy(rec_chainFreq[j][l], chainFreq[j][l]);  
                            rec_cs[i][j] = cs[i][j];
                        }
                        rec_state1[i][j][l] = state1[i][j][l];            	            
        	        }
        	        rec_state2[i][k][j][l] = state2[i][k][j][l];
        	        
        	    }
        	    strcpy(rec_chrsts[j][k], chrsts[j][k]);
    	        rec_state[i][k][j] = state[i][k][j];
    	    }
    	    
    	}
    }*/
	rec_cur_len = talkative_cur_len;
	rec_loop = loop;
}

/*
static void save_state(FILE *file)
{
	int i, j, k, l;
	char str[41];
	fprintf(file, "%d\n", rec_set);
    for(i=0; i<=maxlength-minlength; i++) {
        memset(str, 0, 41);
        big2str(rec_counter[i], str);
        fprintf(file, "%s\n", str);
        for(j=0; j<minlength+i; j++) {
            if(i == 0) {
                fprintf(file, "%d\n", rec_inc[j]);
                fprintf(file, "%d\n", rec_J[loop2][j]);
                fprintf(file, "%d\n", rec_divi[j]);
            }
            fprintf(file, "%d\n", rec_cs[i][j]);
            memset(str, 0, 41);
            big2str(rec_counter1[i][j], str);
            fprintf(file, "%s\n", str);
        	for(k=0; k<7; k++) {
        	    for(l=0; l<8; l++) {
        	        if(k == 0) {
            	        fprintf(file, "%d\n", rec_cs2[i][j][l]);
            	        if(i == 0 && j < minlength+i-1) {
            	            fprintf(file, "%d\n", rec_divi2[j][l]);
        	                fprintf(file, "%s\n", rec_chrsts3[l][j][k]);
        	                fprintf(file, "%s\n", rec_chainFreq[j][l]);
                            
                        }
            	        fprintf(file, "%d\n", rec_state1[i][j][l]);
            	    }
        	        fprintf(file, "%d\n", rec_state2[i][k][j][l]);
        	    }
        	    fprintf(file, "%s\n", rec_chrsts[j][k]);
    	        fprintf(file, "%d\n", rec_state[i][k][j]);
    	    }
    	    
    	}
    }
    fprintf(file, "%d\n", rec_cur_len);
	fprintf(file, "%d\n", rec_loop);
}

static int restore_state(FILE *file)
{
	int i, j, k, l, d;
	char str[41];
	memset(str, 0, 41);
	if(fscanf(file, "%d\n", &d) == 1)
		set = d;
	else return 1;

    for(i=0; i<=maxlength-minlength; i++) {
        if(fscanf(file, "%s\n", str) == 1) {
            counter[i] = str2big(str);
            memset(str, 0, 41);
        } 
        for(j=0; j<minlength+i; j++) {
            if(i == 0) {
                if(fscanf(file, "%d\n", &d) == 1)
                    inc[j] = d;
                else return 1;
                if(fscanf(file, "%d\n", &d) == 1)
                    J[loop2][j] = d;
                else return 1;
                if(fscanf(file, "%d\n", &d) == 1)
                    divi[j] = d;
                else return 1;
            }
            if(fscanf(file, "%d\n", &d) == 1)
                cs[i][j] = d;
            else return 1;
            if(fscanf(file, "%s\n", str) == 1)
                counter1[i][j] = str2big(str);
            else return 1;

            for(k=0; k<7; k++) {
                for(l=0; l<8; l++) {
                    if(k == 0 && j < minlength+i-1) {
                        if(fscanf(file, "%d\n", &d) == 1)
                            cs2[i][j][l] = d;
                        else return 1;
                        if(fscanf(file, "%s\n", str) == 1) {
                            strcpy(chrsts3[l][j][k], str);
                            memset(str, 0, 41);
                        }
                        else return 1;
                        if(fscanf(file, "%s\n", str) == 1) {
                            strcpy(chainFreq[j][l], str);
                            memset(str, 0, 41);
                        }
                        else return 1;
                        if(i == 0) {
                            if(fscanf(file, "%d\n", &d) == 1)
                                divi2[j][l] = d;
                            else return 1;
                        }
                        if(fscanf(file, "%d\n", &d) == 1)
                            state1[i][j][l] = d;
                        else return 1;
                    }
                    if(fscanf(file, "%d\n", &d) == 1)
                        state2[i][j][k][l] = d;
                    else return 1;
                }
                if(fscanf(file, "%d\n", &d) == 1)
                    state[i][j][k] = d;
                else return 1;

	            if(fscanf(file, "%s\n", str) == 1) {
                    strcpy(chrsts[i][j], str);
                    memset(str, 0, 41);
                }
                else return 1;
            }
        }
    }
	if(fscanf(file, "%d\n", &d) == 1)
	    talk[loop2]ative_cur_len = d;
	else return 1;

	if(fscanf(file, "%d\n", &d) == 1)
		loop = d;
	else return 1;

	state_restored = 1;

	return 0;
}
*/
static int submit(char *word, int loop2)
{
	char out[MAX_CAND_LENGTH+1];
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

int do_talkative_crack(struct db_main *db, int chunk_size)
{
	int i, j, k;
	srand(time(NULL));
	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MAX(options.eff_minlength, 1);
    if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;
    if (!options.chunk_size)
        chunk_size = 4;

    FILE *file = fopen("/home/i20/Documents/john/run/talkative.conf", "r");
	int file_size = 0;
	while(!feof(file)) {
	    char c = ' ';
	    file_size++;
	    fread(&c, 1, 1, file);
	}
	char *buff = mem_alloc(file_size+1);
	fseek(file, 0, SEEK_SET);

    fread(buff, file_size, 1, file);
    buff[file_size] = 0;
    
	char *length_supported = strtok(buff, "\n");
    int ls = strtoul(length_supported, NULL, 10);	
    int ls2 = ls;
    int *span = (int *) mem_alloc(sizeof(int) * ls2);
    char **freqs_buff = (char **) mem_alloc(ls2 * sizeof(char *));
	
    for(i=0; i<ls2; i++)
        span[i] = 0;
    i = strlen(length_supported)+1;
    int jump = 0;
    while(ls > 0) {
        if(strncmp(&buff[i], "\n", 1) == 0)
            ls--;
        else
            span[ls2-ls]++;
        i++;
    }
    int span_glob = 0;
    if(maxlength > ls2) {
        while(ls > -1) {
            if(strncmp(&buff[i], "\n", 1) == 0)
                ls--;
            else if(ls == -2)
                span_glob++;
            i++;
        }
    }
    char glob_freq[95];
    strncpy(glob_freq, &buff[i+1], 95);

	unsigned int charcount = 95;
	char **freq = (char **) mem_alloc(maxlength * sizeof(char *));
	i = strlen(length_supported) + 1;
	for(j=0; j<maxlength; j++) {
	    if(j >= ls2)
	        ;//use the global freq
	    else {
            freqs_buff[j] = (char *) mem_alloc(span[j]+1);
            strncpy(freqs_buff[j], &buff[i], span[j]);
            i+=span[j]+1;
            freqs_buff[j][span[j]] = 0;
            int line_size = strtoul(strtok(freqs_buff[j], ":"), NULL, 10) + 1; 
            freq[j] = mem_alloc(line_size);
            strncpy(freq[j], strtok(NULL, "\n"), line_size-1);
            freq[j][line_size-1] = 0;
        }
    }

    i = 0;
    //scroll to the chains
    ls = ls2;
    while(ls >= -2) {
        if(strncmp(&buff[i], "\n", 1) == 0)
            ls--;
        i++;
    }
	int chains_span = 0;
	char c2 = 0;
    int chains = 0, chains1 = 0;
    int lines = 0;
    int pos;
    while(i < file_size) {
        if(strncmp(&buff[i], "\n", 1) == 0) { 
            char tmpline[95];
	        int line_size;
            strncpy(tmpline, &buff[i-chains_span], chains_span);
            tmpline[chains_span] = 0;
	        if(lines % 2 == 0) {
	            char c = tmpline[0];
	            if(c == ':') {
                    pos = strtoul(strtok(&tmpline[1], ":"), NULL, 10);
                    line_size = strtoul(strtok(NULL, ":"), NULL, 10);
                }
                else {
                    strtok(tmpline, ":");
	                pos = strtoul(strtok(NULL, ":"), NULL, 10);
                    line_size = strtoul(strtok(NULL, ":"), NULL, 10);
	            }
	            chainFreq[pos-1][chains][0] = c;
	            strncpy(&chainFreq[pos-1][chains][1], strtok(NULL, "\n"), line_size);
	            chainFreq[pos-1][chains][line_size+1] = 0;
	            if(c2 != c) {
                    c2 = c;
                    chains++;
                }
	        }
	        else {
	            line_size = strtoul(strtok(tmpline, ":"), NULL, 10);
                strncpy(counterChainFreq[pos-1][chains-1], strtok(NULL, "\n"), line_size);
                counterChainFreq[pos-1][chains-1][line_size] = 0;
            }
            chains_span = 0;
            lines++;
        }
        else
            chains_span++;
        i++;
    }
    int rest;
	for(i=0; i<maxlength-1; i++) {
	    rest = 0;
        divi[i] = charcount/chunk_size;
		if(charcount % chunk_size) {
            divi[i]++;
            rest = 1;
        }
		for(j=0; j<divi[i]; j++)
        	if(j == divi[i] - 1 && rest)
        		top1[i][j] = charcount % chunk_size;
        	else
        		top1[i][j] = chunk_size;
	}
	for(i=0; i<maxlength-1; i++) {
	    for(j=0; j<chains; j++) {
	        rest = 0;
	        divi1[i][j] = (int) ((strlen(chainFreq[i][j]) - 1) / chunk_size);
	        if((strlen(chainFreq[i][j]) - 1) % chunk_size)
            {
                divi1[i][j]++;
                rest = 1;
            }
            for(k=0; k<divi1[i][j]; k++)
            	if(k == divi1[i][j] - 1 && rest)
        		    top2[i][j][k] = (strlen(chainFreq[i][j]) - 1) % chunk_size;
        		else top2[i][j][k] = chunk_size;
        }
    }
    for(i=0; i<maxlength-1; i++) {
        for(j=0; j<chains; j++) {
            rest = 0;
            divi2[i][j] = (int) (strlen(counterChainFreq[i][j]) / chunk_size);
	        if(strlen(counterChainFreq[i][j]) % chunk_size) {
                divi2[i][j]++;
                rest = 1;
            }
            for(k=0; k<divi2[i][j]; k++)
            	if(k == divi2[i][j] - 1 && rest)
                	top3[i][j][k] = strlen(counterChainFreq[i][j]) % chunk_size;
               	else
               		top3[i][j][k] = chunk_size;
        }
    }
	int x, y, z;
	crk_init(db, fix_state, NULL);
	if(!state_restored) {
        for(x=0; x<maxlength-1; x++) {
		    for(y=0; y<divi[x]; y++) {
			    int Z = chunk_size;
			    int min = 0;
			    if(y == divi[x]-1) {
				    Z = charcount % chunk_size;
				    min = chunk_size - Z;
			        if(Z == 0) {
			            Z = chunk_size;
			            min = 0;
			        }
			    }
			    for(z=0; z<Z; z++) {
				    int again;
				    chrsts[x][y][z] = freq[x][rand()%((y+1)*chunk_size-min)];
				    again = 0;
				    for(i=0; i<=y; i++) {
					    int Z2 = chunk_size;
					    if(i == divi[x]-1) {
						    Z2 = charcount % chunk_size;
						    min = chunk_size - Z2;
						    if(Z2 == 0) {
						        Z2 = chunk_size;
						        min = 0;
						    }
						}
					    for(j=0; j<Z2; j++) {
						    if(z == j && i == y)
							    continue;
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
			    }
			}
		}
	    int a;
	    for(x=0; x<maxlength-1; x++) {
	        for(a=0; a<chains; a++) {
		        for(y=0; y<divi1[x][a]; y++) {
                    int Z = chunk_size;
			        int min = 0;
			        if(y == divi1[x][a]-1) {
				        Z = (strlen(chainFreq[x][a])-1) % chunk_size;
				        min = chunk_size - Z;
			            if(Z == 0) {
		                    Z = chunk_size;
				            min = 0;
			            }
			        }
			        for(z=0; z<Z; z++) {
				        int again;
				        chrsts2[x][a][y][z] = chainFreq[x][a][rand()%((y+1)*chunk_size-min)+1];
				        again = 0;
				        for(i=0; i<=y; i++) {
					        int Z2 = chunk_size;
					        if(i == divi1[x][a]-1) {
						        Z2 = (strlen(chainFreq[x][a])-1) % chunk_size;
					            min = chunk_size - Z2;
					            if(Z2 == 0) {
		                            Z2 = chunk_size;
				                    min = 0;
			                    }
			                }
					        for(j=0; j<Z2; j++) {
						        if(z == j && i == y)
							        continue;
						        if(chrsts2[x][a][y][z] == chrsts2[x][a][i][j]) {
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
				        chrsts2[x][a][y][z+1] = '\0';
                    }
                }
            }
        }
        for(x=0; x<maxlength-1; x++) {
            for(a=0; a<chains; a++) {
	            for(y=0; y<divi2[x][a]; y++) {
                    int Z = chunk_size;
		            int min = 0;
		            if(y == divi2[x][a]-1) {
			            Z = strlen(counterChainFreq[x][a]) % chunk_size;
			            min = chunk_size - Z;
		                if(Z == 0) {
	                        Z = chunk_size;
			                min = 0;
		                }
		            }
		            for(z=0; z<Z; z++) {
			            int again;
			            chrsts3[x][a][y][z] = counterChainFreq[x][a][rand()%((y+1)*chunk_size-min)];
			            again = 0;
			            for(i=0; i<=y; i++) {
				            int Z2 = chunk_size;
				            if(i == divi2[x][a]-1) {
					            Z2 = strlen(counterChainFreq[x][a]) % chunk_size;
				                min = chunk_size - Z2;
				                if(Z2 == 0) {
	                                Z2 = chunk_size;
			                        min = 0;
		                        }
                            }
				            for(j=0; j<Z2; j++) {
					            if(z == j && i == y)
						            continue;
					            if(chrsts3[x][a][y][z] == chrsts3[x][a][i][j]) {
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
			            chrsts3[x][a][y][z+1] = '\0';
                    }
                }
            }
        }
	}
	talkative_cur_len = minlength;
	
	status_init(get_progress, 0);
	//rec_restore_mode(restore_state);
	//rec_init(db, save_state);
	
	if(john_main_process) {
		log_event("Proceeding with \"Talkative\" mode");
		log_event("- Lengths: %d-%d, max",
		          MAX(options.eff_minlength, 1), maxlength);
		if(rec_restored) {
			fprintf(stderr, "Proceeding with \"Talkative\" mode");
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
		        
		        if(options.node_count) {
		        	int for_node = set % options.node_count + 1;
		        	skip = for_node < options.node_min || for_node > options.node_max;
		        }

		        if(!skip) {
		            word[0] = freq[0][c[loop2]];
                    for(i=1; i<mpl; i++) {
                        if(!chainCounterDone[i-1]) 
                        {
	            	        for(j=0; j<chains; j++) {
                                if(word[i-1] == chainFreq[i-1][j][0]) {
                                    J[loop2][i-1] = j;
                                    if(chainCounter[i-1] < powi(charcount, mpl-i) && talk[loop2][i-1] != 2)
                                    {   talk[loop2][i-1] = 1;
                                        break; }
                                    chainCounterDone[i-1] = 1;
                                } else talk[loop2][i-1] = 0;
	                        }
	                    }
	        	        switch(talk[loop2][i-1]) {
        	            case 0:
	        	            word[i] = chrsts[i-1][cs[loop2][i-1]][state[loop2][cs[loop2][i-1]][i-1]];
					        break;
					    case 1:
					        word[i] = chrsts2[i-1][J[loop2][i-1]][cs1[i-1][loop2][J[loop2][i-1]]][state1[loop2][cs1[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1]];
						    break;
					    case 2:
						    word[i] = chrsts3[i-1][J[loop2][i-1]][cs2[i-1][loop2][J[loop2][i-1]]][state2[loop2][cs2[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1]];
						    break;
						}
					}
					submit(word, loop2);
				}
				int bail = 0;
				i = mpl-1;

                if(++c[loop2] >= charcount)
				    c[loop2] = 0;//the first character changes each word
				else
                while(i >= 1 && !bail) {
                    int a = 0;
                    chainCounterDone[i-1] = 0;
                    switch(talk[loop2][i-1]) {
				    case 0:
        				if(++state[loop2][cs[loop2][i-1]][i-1] >= top1[i-1][cs[loop2][i-1]]) {
		                    state[loop2][cs[loop2][i-1]][i-1] = 0;
		                    i--;
	                    } else bail = 1;
	                    break;
	                case 1:
	                    chainCounter[i-1]++;
	                    if(++state1[loop2][cs1[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1] >= top2[i-1][J[loop2][i-1]][cs1[i-1][loop2][J[loop2][i-1]]]) {
                            state1[loop2][cs1[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1] = 0;
                            i--;
	                    } else bail = 1;
	                    break;
		            case 2:
		                chainCounter[i-1]++;
                        if(++state2[loop2][cs2[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1] >= top3[i-1][J[loop2][i-1]][cs2[i-1][loop2][J[loop2][i-1]]]) {
                            state2[loop2][cs2[i-1][loop2][J[loop2][i-1]]][J[loop2][i-1]][i-1] = 0;
                            i--;
                        } else bail = 1;
				    }
				    if(i < 1) {
                        int i2 = mpl-1;
			            while(i2 >= 1) {
			                if(talk[loop2][i2-1] == 0) { 
	                            if(++cs[loop2][i2-1] >= divi[i2-1]) {
                                    cs[loop2][i2-1] = 0;
                                    i2--;
                                }
                                else break;
                            }
			                else if(talk[loop2][i2-1] == 1) { 
	                            if(++cs1[i2-1][loop2][J[loop2][i2-1]] >= divi1[i2-1][J[loop2][i2-1]]) {
                                    cs1[i2-1][loop2][J[loop2][i2-1]] = 0;
                                    i2--;
                                }
                                else break;
                            }
                            else if(talk[loop2][i2-1] == 2) { 
	                            if(++cs2[i2-1][loop2][J[loop2][i2-1]] >= divi2[i2-1][J[loop2][i2-1]]) {
                                    cs2[i2-1][loop2][J[loop2][i2-1]] = 0;
                                    i2--;
                                }
                                else break;
                            }
			            }
					}
			    }
				counter[loop2]++;
			}
		}
		talkative_cur_len++;
	}
	crk_done();
	rec_done(event_abort);
	for(i=0; i<maxlength; i++)
	    MEM_FREE(freqs_buff[i]);
	    
	MEM_FREE(freqs_buff);
	return 0;
}
