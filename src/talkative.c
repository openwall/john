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

#if JTR_HAVE_INT128
typedef uint128_t uint_big;
#define UINT_BIG_MAX UINT128_MAX
#else
typedef uint64_t uint_big;
#define UINT_BIG_MAX UINT64_MAX
#endif

#define CHAINS_MAX 95
#define DIVI_MAX 95

static char word[MAX_CAND_LENGTH+1];

static int maxlength;
static int minlength;
static int state_restored;
static uint64_t total;
int talkative_cur_len;
static int set;
static int rec_set;
static int rec_cur_len;
static uint_big counter[MAX_CAND_LENGTH-1];
static uint_big rec_counter[MAX_CAND_LENGTH-1];
static int state[MAX_CAND_LENGTH-1][CHAINS_MAX][MAX_CAND_LENGTH];
static int rec_state[MAX_CAND_LENGTH-1][CHAINS_MAX][MAX_CAND_LENGTH];
static int loop;
static int rec_loop;
static char ***chrsts;
static char ***rec_chrsts;
static char ***chrsts3;
static char ***rec_chrsts3;
static char **chainFreq;
static char **counterChainFreq;
static int divi[MAX_CAND_LENGTH];
static int rec_divi[MAX_CAND_LENGTH];

static int divi2[CHAINS_MAX];
static int rec_divi2[CHAINS_MAX];

static int state1[MAX_CAND_LENGTH-1][DIVI_MAX][MAX_CAND_LENGTH-1];
static int rec_state1[MAX_CAND_LENGTH-1][DIVI_MAX][MAX_CAND_LENGTH-1];
static int state2[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];
static int rec_state2[MAX_CAND_LENGTH-1][DIVI_MAX][CHAINS_MAX][MAX_CAND_LENGTH-1];

static int cs[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int cs2[MAX_CAND_LENGTH-1][CHAINS_MAX];//todo loop2
static int rec_cs[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int rec_cs2[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1][CHAINS_MAX];//todo loop2

static int J[MAX_CAND_LENGTH-1];
static int rec_J[MAX_CAND_LENGTH-1];
static uint_big freqCounter[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];
static uint_big freqCounter[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH-1];

static int talk[MAX_CAND_LENGTH-1];
static int rec_talk[MAX_CAND_LENGTH-1];

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
                rec_J[j] = inc[j]; 
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
                fprintf(file, "%d\n", rec_J[j]);
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
                    J[j] = d;
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
	    talkative_cur_len = d;
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
	        ;   
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
    int chains = 0;
    int i_save = i;
    while(i < file_size) {
        if(strncmp(&buff[i], "\n", 1) == 0)
            chains++;
        i++;
    }
    chainFreq = (char **) mem_alloc(chains / 2 * sizeof(char *));
	counterChainFreq = (char **) mem_alloc(chains / 2 * sizeof(char *));

	char **chains_buff = (char **) mem_alloc(chains * sizeof(char *));
	int *chains_span = (int *) mem_alloc(chains * sizeof(int));
	for(j=0; j<chains; j++)
	    chains_span[j] = 0;

	j = 0;
	i = i_save;
	while(i < file_size) {
	    if(strncmp(&buff[i], "\n", 1) == 0)
	        j++;
	    else
	        chains_span[j]++;
	    i++;
	}
	i = i_save;
	for(j=0; j<chains; j++) {
        chains_buff[j] = (char *) malloc(chains_span[j]+1);
	    strncpy(chains_buff[j], &buff[i], chains_span[j]);
	    chains_buff[j][chains_span[j]] = 0;
        i += chains_span[j]+1;
        int line_size;
        if(j % 2 == 0) {
	        char c = chains_buff[j][0];
            char *tmp_line;
            if(c == ':') {
                tmp_line = mem_alloc(charcount);
                strcpy(tmp_line, chains_buff[j]);
                line_size = strtoul(strtok(tmp_line, ":"), NULL, 10) + 2;
                chains_buff[j] = tmp_line;
            }
            else {
                strtok(chains_buff[j], ":");
	            line_size = strtoul(strtok(NULL, ":"), NULL, 10) + 2; 
	        }
	        chainFreq[j/2] = mem_alloc(line_size);
	        chainFreq[j/2][0] = c;
	        strncpy(&chainFreq[j/2][1], strtok(NULL, "\n"), line_size-2);
	        chainFreq[j/2][line_size-2] = 0;
	    }
	    else {
	        line_size = strtoul(strtok(chains_buff[j], ":"), NULL, 10) + 1; 
	        counterChainFreq[j/2] = mem_alloc(line_size);
            strncpy(counterChainFreq[j/2], strtok(NULL, "\n"), line_size-1);
            counterChainFreq[j/2][line_size-1] = 0;
	    }
	}
	for(j=1; j<chains/2; j++) {
	    divi2[j] = strlen(counterChainFreq[j]) / chunk_size;
        if(strlen(counterChainFreq[j]) % chunk_size) {
            divi2[j]++;  
        }
    }
    for(i=0; i<maxlength; i++) {
        divi[i] = charcount/chunk_size;
        if(charcount % chunk_size)
            divi[i]++;
	}
	chrsts = (char ***) mem_alloc(sizeof(char **) * maxlength);
	rec_chrsts = (char ***) mem_alloc(sizeof(char **) * maxlength);
	for(i=0; i<maxlength; i++) {
	    chrsts[i] = (char **) mem_alloc(sizeof(char *) * divi[i]);
        rec_chrsts[i] = (char **) mem_alloc(sizeof(char *) * divi[i]);
        for(j=0; j<divi[i]; j++) {
	        chrsts[i][j] = (char *) mem_alloc(chunk_size+1);
	        rec_chrsts[i][j] = (char *) mem_alloc(chunk_size+1);
	    }
    }
    chrsts3 = (char ***) mem_alloc(sizeof(char **) * chains / 2);
	rec_chrsts3 = (char ***) mem_alloc(sizeof(char **) * chains / 2);
    for(k=0; k<chains/2; k++) {
	    chrsts3[k] = (char **) mem_alloc(sizeof(char *) * divi2[k]);
        rec_chrsts3[k] = (char **) mem_alloc(sizeof(char *) * divi2[k]);
        for(j=0; j<divi2[k]; j++) {
            chrsts3[k][j] = (char *) mem_alloc(chunk_size+1);
            rec_chrsts3[k][j] = (char *) mem_alloc(chunk_size+1);
        }
	}
	int x, y, z;
	crk_init(db, fix_state, NULL);
	if(!state_restored) {
        for(x=0; x<maxlength; x++) {
		    for(y=0; y<divi[x]; y++) {
			    int Z = chunk_size;
			    int min = 0;
			    if(y == divi[x]-1) {
				    Z = charcount % chunk_size;
				    min = chunk_size - Z;
			    }
			    if(Z == 0) {
			        Z = chunk_size;
			        min = 0;
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
						}
						if(Z2 == 0) {
						    Z2 = chunk_size;
						    min = 0;
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
	    for(a=0; a<chains/2; a++) {
		    for(y=0; y<divi2[a]; y++) {
                int Z = chunk_size;
			    int min = 0;
			    if(y == divi2[a]-1) {
				    Z = strlen(counterChainFreq[a]) % chunk_size;
				    min = chunk_size - Z;
			    }
			    if(Z == 0) {
		            Z = chunk_size;
				    min = 0;
			    }
			    for(z=0; z<Z; z++) {
				    int again;
				    chrsts3[a][y][z] = counterChainFreq[a][rand()%((y+1)*chunk_size-min)];
				    again = 0;
				    for(i=0; i<=y; i++) {
					    int Z2 = chunk_size;
					    if(i == divi2[a]-1) {
						    Z2 = strlen(counterChainFreq[a]) % chunk_size;
					        min = chunk_size - Z2;
					    }
					    if(Z2 == 0) {
		                    Z2 = chunk_size;
				            min = 0;
			            }
					    for(j=0; j<Z2; j++) {
						    if(z == j && i == y)
							    continue;
						    if(chrsts3[a][y][z] == chrsts3[a][i][j]) {
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
				    chrsts3[a][y][z+1] = '\0';
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
		if(event_abort)
			break;
		uint_big total = powi(charcount, minlength+loop);
		for(; counter[loop] < total; ) {
			if(event_abort)
				break;
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
					word[0] = chrsts[0][cs[loop2][0]][state[loop2][cs[loop2][0]][0]];
		        	for(i=1; i<mpl; i++) {
					    for(j=0; j<chains/2; j++) {
						    if(chainFreq[j][0] == word[i-1]) {
                                J[i-1] = j;
                                uint_big total2;
                                if(talk[i-1] == 0 || talk[i-1] == 1)
                                    total2 = strlen(chainFreq[J[i-1]]) - 1;
                                else total2 = charcount;
                                for(k = i; k >= 1; k--)
                                    total2 *= charcount;
                                if(++freqCounter[loop2][i-1] < total2) {
                                    if(talk[i-1] == 1)
                                        talk[i-1] = 2;
                                    else
                                        talk[i-1] = 1;
                                }
                            }
						    else
						        talk[i-1] = 0;
						}
	        	        switch(0) {
						    case 0:
							    word[i] = chrsts[i][cs[loop2][i]][state[loop2][cs[loop2][i]][i]];
							    break;
						    case 1:
							    word[i] = chainFreq[J[i-1]][state1[loop2][J[i-1]][i-1]+1];
							    break;
						    case 2:
							    word[i] = chrsts3[J[i-1]][cs2[loop2][J[i-1]]][state2[loop2][cs2[loop2][J[i-1]]][J[i-1]][i-1]];
							    break;		
						}
					}
					submit(word, loop2);
				}
				i = mpl-1;
				int bail = 0;
				while(i >= 0 && !bail) {
				    int a = 0;
					if(i > 0) {
					    switch(0) {
            			    case 0:
                				if(++state[loop2][cs[loop2][i]][i] >= strlen(chrsts[i][cs[loop2][i]])) {
						            state[loop2][cs[loop2][i]][i] = 0;
						            i--;
					            }
					            else bail = 1;
                				break;
            			    case 1:
                	            if(++state1[loop2][J[i-1]][i-1] + 1 > strlen(chainFreq[J[i-1]])) {
						            i--;
				                    talk[i-1] = 2;
				                    state1[loop2][J[i-1]][i-1] = 0;
					            }
					            else bail = 1;
					            break;
				            case 2:
				                if(++state2[loop2][cs2[loop2][J[i-1]]][J[i-1]][i-1] >= strlen(chrsts3[J[i-1]][cs2[i-1][J[i-1]]])) {
					                talk[i-1] = 0;
					                state2[loop2][cs2[loop2][J[i-1]]][J[i-1]][i-1] = 0;
					                i--;
						        } 
					            else bail = 1;
				                break;
			            }
					}
					else {
                        if(++state[loop2][cs[loop2][0]][0] >= strlen(chrsts[0][cs[loop2][0]])) {
                            state[loop2][cs[loop2][0]][0] = 0;
							i--;
						    int i2 = mpl-1;
				            while(i2 >= 0) {
				                if(i2 > 0) {
				                    if(talk[i2-1] == 0) {
		                                if(++cs[loop2][i2] >= divi[i2]) {
	                                        cs[loop2][i2] = 0;
	                                        i2--;
                                        }
                                        else break;
				                    }
				                    else if(talk[i2-1] == 2) { 
			                            if(++cs2[loop2][J[i2-1]] >= divi2[J[i2-1]]) {
                                            cs2[loop2][J[i2-1]] = 0;
                                            i2--;
                                        }
                                    }
                                    else
                                        i2--;
				                }
				                else {
				                    if(++cs[loop2][0] >= divi[0]) {
				                        cs[loop2][0] = 0;
				                        i2--;   
				                    }
				                    else break;
				                }
				            }
					    }
						else break;
					}
				}
				counter[loop2]++;
			}
		}
		talkative_cur_len++;
	}
	crk_done();
	rec_done(event_abort);
	for(i=0; i<maxlength; i++) {
	    MEM_FREE(freqs_buff[i]);
	    for(j=0; j<divi[i]; j++)
	        MEM_FREE(chrsts[i][j]);
	    MEM_FREE(chrsts[i]);
	}
	MEM_FREE(freqs_buff);
	MEM_FREE(chrsts);
	for(i=0; i<chains/2; i++) {
    	MEM_FREE(chainFreq[i]);
    	MEM_FREE(counterChainFreq[i]);
        for(j=0; j<divi2[i]; j++)
	        MEM_FREE(chrsts3[i][j]);
        MEM_FREE(chrsts3[i]);
    }
    MEM_FREE(chainFreq);
    MEM_FREE(counterChainFreq);
    MEM_FREE(chrsts3);
    for(i=0; i<chains; i++)
        MEM_FREE(chains_buff[i]);
    MEM_FREE(span);
	MEM_FREE(chains_span);
	MEM_FREE(length_supported);
	MEM_FREE(chains_buff);	
	return 0;
}
