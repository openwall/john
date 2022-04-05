#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


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
    for(i=0; i<buff_size; ++i) {
        if(strncmp(&buff[i], "\n", 2) == 0)
            wordcount++;
    }

    int words_size[wordcount], j = 0;
    for(i=0; i<buff_size; ++i) {
        words_size[j]++;
        if(strncmp(&buff[i], "\n", 2) == 0)
            j++;
    }

    char **words;
    words = (char **) malloc(wordcount * sizeof(char*));
    for(i=0; i<wordcount; i++)
        words[i] = malloc(words_size[i]);
    
    fseek(file, 0, SEEK_SET);  
    for(i=0; i<wordcount; i++)
        fread(words[i], words_size[i]-2, 1, file);
        
    
    
}
