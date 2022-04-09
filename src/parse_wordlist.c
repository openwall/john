#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

struct freq {
    char c;
    int *posfreq;
    int freq;
    int nextfreq[95];
    char next[95];
};

int main(int argc, char *argv[]) {
    int full = 0;
    int ind = 1;
    if(strcmp(argv[1], "--full") == 0) {
        ind = 2;
        full = 1;
    }
    
    FILE *file = fopen(argv[ind], "r");
    int buff_size = 0;
    char c;
    while(!feof(file)) {
        fread(&c, 1, 1, file);
        buff_size++;
    }

    char buff[buff_size];
    fseek(file, 0, SEEK_SET);
    fread(buff, buff_size, 1, file);

    int i, wordcount = 0;
    for(i=0; i<buff_size; i++) {
        if(strncmp(&buff[i], "\n", 1) == 0)
            wordcount++;
    }
    int words_size[wordcount];
    for(i=0; i<wordcount; i++)
        words_size[i] = 0;

    int j = 0;
    for(i=0; i<buff_size; i++) {
        words_size[j]++;
        if(strncmp(&buff[i], "\n", 1) == 0) {
            j++;
        }
    }
    int max_len;
    for(i=0; i<wordcount; i++) {
        int set = 1;
        for(j=0; j<wordcount; j++) {
            if(words_size[j] > words_size[i]) {
                set = 0;
                break;
            }
        }
        if(set)
            max_len = words_size[i] - 1;
    }
    char **words;
    words = (char **) malloc(wordcount * sizeof(char*));
    for(i=0; i<wordcount; i++)
        words[i] = malloc(words_size[i]+1);
    
    fseek(file, 0, SEEK_SET);  
    for(i=0; i<wordcount; i++) {
        fread(words[i], words_size[i]-1, 1, file);
        fseek(file, 1, SEEK_CUR);//skip nl
        words[i][words_size[i]-1] = '\0';
    }
    struct freq chars[95];
    for(i=0; i<95; i++) {
        chars[i].c = ' ' + i;
        chars[i].freq = 0;
        chars[i].posfreq = (int *) malloc(sizeof(int) * max_len);
        for(j=0; j<max_len; j++)
            chars[i].posfreq[j] = 0;
    }
    int x;
    for(x=0; x<95; x++) {
        for(i=0; i<wordcount; i++) {
            for(j=0; j<words_size[i]; j++) {
                if(words[i][j] == chars[x].c) {
                    chars[x].posfreq[j]++;
                    chars[x].freq++;
                }
            }
        }
    }
    char freqs[max_len][96];
    int y;  

    for(i=0; i<max_len; i++)
        freqs[i][95] = 0;
    
    int used[max_len][95];
    int end;
    int t,p,q;
    for(j=0; j<max_len; j++) {
        for(p=0; p<max_len; p++)
            for(q=0; q<95; q++)
                used[p][q] = 0;
        end = 0;
        for(t=0; t<95; t++) {
            for(x=0; x<95; x++) {
                int set = 1;
                for(i=0; i<95; i++) {
                    if(chars[i].posfreq[j] > chars[x].posfreq[j] && !used[j][i] || (!chars[x].posfreq[j] && !full)) {
                        set = 0;
                        break;
                    }
                }
                if(set && !used[j][x]) { //test loop doesn't overpass original char
                    freqs[j][t] = chars[x].c;
                    used[j][x] = 1;
                    end++;
                    break;
                }
            }
        }
        freqs[j][end] = 0;
    }
    char glob_freq[95];//we will need this one for very long length for which we won't have datas
    
    int used2[95];
    for(q=0; q<95; q++)
        used2[q] = 0;
        
    end = 0;
    for(t=0; t<95; t++) {
        for(x=0; x<95; x++) {
            int set = 1;
            for(i=0; i<95; i++) {
                if(chars[i].freq > chars[x].freq && !used2[i] || (!chars[x].freq && !full)) {
                    set = 0;
                    break;
                }
            }
            if(set && !used2[x]) { //test loop doesn't overpass original char
                glob_freq[t] = chars[x].c;
                used2[x] = 1;
                end++;
                break;
            }
        }
    }
    glob_freq[end] = 0;

    FILE *output = fopen("talkative.conf", "w+");
    
    char max_lenout[256];
    sprintf(max_lenout, "%d\n", max_len); 
    fwrite(max_lenout, strlen(max_lenout), 1, output);
    for(i=0; i<max_len; i++) {
        if(strlen(freqs[i])) {
            char freqout[256];
            sprintf(freqout, "%d:%s\n", strlen(freqs[i]), freqs[i]);
            fwrite(freqout, strlen(freqout), 1, output);
        }
    }
    char glob_freqout[256];
    sprintf(glob_freqout, "\n%s\n\n", glob_freq);
    fwrite(glob_freqout, strlen(glob_freqout), 1, output);

    for(i=0; i<95; i++)
        for(j=0; j<95; j++)
            chars[i].nextfreq[j] = 0;

    for(i=0; i<wordcount; i++)
        for(j=1; j<words_size[i]; j++) {
            int bail = 0;
            for(t=0; t<95; t++) {
                for(y=0; y<95; y++) {
                    if(words[i][j] == chars[t].c && words[i][j-1] == chars[y].c) {
                        chars[t].nextfreq[y]++;
                        bail = 1;
                        break;
                    }
                }
                if(bail) break;
            }
        }

    for(i=0; i<95; i++) {
        for(j=0; j<95; j++)
            chars[i].next[j] = 0;
    }

  
    for(y=0; y<95; y++) {
        end = 0;
        for(j=0; j<95; j++)
            used2[j] = 0;
        int bail = 0;
        for(t=0; t<95; t++) {
            for(x=0; x<95; x++) {
                int set = 1;
                for(i=0; i<95; i++) {
                    if(chars[i].nextfreq[y] > chars[x].nextfreq[y] && !used2[i] || (!chars[x].nextfreq[y] && !full) ) {
                        set = 0;
                        break;
                    }
                }
                if(set && !used2[x]) { //test loop doesn't overpass original char
                    chars[y].next[t] = chars[x].c;
                    used2[x] = 1;
                    end++;
                    bail = 1;
                    break;
                }
            }
        }
    }

    for(t=0; t<95; t++) {
        if(strlen(chars[t].next)) {
            char nextout[256];
            sprintf(nextout, "%c:%d:%s\n", chars[t].c, strlen(chars[t].next), chars[t].next);
            fwrite(nextout, strlen(nextout), 1, output);
        }
    }
}
