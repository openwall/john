#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

struct freq {
    char c;
    int *posfreq;
};

int main(int argc, char *argv[]) {
    FILE *file = fopen(argv[1], "r");
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
            max_len = words_size[i];
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
        //printf("%s\n", words[i]);
    }
    struct freq chars[95];
    for(i=0; i<95; i++) {
        chars[i].c = ' ' + i;
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
                }
            }
        }
    }
    char freqs[max_len][96];
    int y;  
    for(i=0; i<95; i++) {
        //printf("%c:\t", chars[i].c);
        for(j=0; j<max_len; j++) {
            //printf("%d\t", chars[i].posfreq[j]);
            freqs[j][i] = 'a';
        }
        //printf("\n");
    }
    for(i=0; i<max_len; i++)
        freqs[i][95] = 0;
    
    int used[max_len][95];

    int p,q;
    for(j=0; j<max_len; j++) {
        int t;
        for(p=0; p<max_len; p++)
            for(q=0; q<95; q++)
                used[p][q] = 0;

        for(t=0; t<95; t++) {
            for(x=0; x<95; x++) {
                int set = 1;
                for(i=0; i<95; i++) {
                    if(chars[i].posfreq[j] > chars[x].posfreq[j] && !used[j][i]) {
                        set = 0;
                        break;
                    }    
                }
                if(set && !used[j][x]) { //test loop doesn't overpass original char
                    freqs[j][t] = chars[x].c;
                    used[j][x] = 1;
                    break;
                }
            }
        }
        freqs[j][95] = 0;
    }
    for(i=0; i<max_len; i++)
        printf("%s\n", freqs[i]);
}
