/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "mkvlib.h"
#include "path.h"
#include "memdbg.h"

unsigned char * proba1;
unsigned char * proba2;
unsigned long long * nbparts;
unsigned char * first;
unsigned char charsorted[256*256];

unsigned int gmax_level;
unsigned int gmax_len;
unsigned int gmin_level;
unsigned int gmin_len;
unsigned long long gidx;
unsigned long long gstart;
unsigned long long gend;

unsigned long long nb_parts(unsigned char lettre, unsigned int len, unsigned int level, unsigned int max_lvl, unsigned int max_len)
{
        int i;
        unsigned long long out=1;

        if(level>max_lvl)
                return 0;

        if(len==max_len)
        {
                nbparts[lettre + len*256 + level*256*max_len] = 1;
                return 1;
        }

        if(nbparts[lettre + (len)*256 + level*256*max_len] != 0)
                return nbparts[lettre + (len)*256 + level*256*max_len];

        for(i=1;i<256;i++)
                if(len==0)
                        out += nb_parts(i, len+1, proba1[i], max_lvl, max_len);
                else
                        out += nb_parts(i, len+1, level + proba2[lettre*256 + i], max_lvl, max_len);

        nbparts[lettre + (len)*256 + level*256*max_len] = out;
        return out;
}

void print_pwd(unsigned long long index, struct s_pwd * pwd, unsigned int max_lvl, unsigned int max_len)
{
	unsigned int len = 1;
	unsigned int level = 0;
	unsigned int lvl = 0;
	unsigned int i;
	unsigned int oldc = 0;

	if(index>nbparts[0])
		return;

	len = 1;
	while(index && (len<=max_len))
	{

		for(i=0;i<256;i++)
		{
			if(len==1)
				level = proba1[charsorted[256*0+i]];
			else
			{
				level = lvl + proba2[oldc*256 + charsorted[oldc*256+i]];
			}

			if( level > max_lvl )
			{
				i=256;
				break;
			}

			if(nbparts[charsorted[oldc*256+i] + len*256 + level*256*max_len]==0)
			{
				break;
			}

			if (index <= nbparts[charsorted[oldc*256+i] + len*256 + level*256*max_len])
				break;

			index -= nbparts[charsorted[oldc*256+i] + len*256 + level*256*max_len];
		}
		if(i==256)
			break;
		lvl = level;
		pwd->password[len-1] = charsorted[oldc*256+i];
		oldc = charsorted[oldc*256+i];
		len++;
	}
	pwd->password[len-1] = 0;
	pwd->index = index;
	pwd->level = lvl;
	pwd->len = len-1;
}


static void stupidsort(unsigned char * result, unsigned char * source, unsigned int size)
{
	unsigned char pivot;
	unsigned char more[256];
	unsigned char less[256];
	unsigned char piv[256];
	unsigned int i,m,l,p;

	if(size<=1)
		return;
	i=0;
	while( (i<size) && (source[result[i]]==UNK_STR))
		i++;
	if(i==size)
		return;
	pivot = result[i];
	if(size<=1)
		return;
	m=0;
	l=0;
	p=0;
	for(i=0;i<size;i++)
	{
		if(source[result[i]]==source[pivot])
		{
			piv[p] = result[i];
			p++;
		}
		else if(source[result[i]]<=source[pivot])
		{
			less[l] = result[i];
			l++;
		}
		else
		{
			more[m] = result[i];
			m++;
		}
	}
	stupidsort(less, source, l);
	stupidsort(more, source, m);
	memcpy(result, less, l);
	memcpy(result+l, piv, p);
	memcpy(result+l+p, more, m);
}

void init_probatables(char * filename)
{
	FILE * fichier;
	char * ligne;
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int nb_lignes;

	if (!(fichier = fopen(filename, "r")))
	{
		static char fpath[PATH_BUFFER_SIZE] = "$JOHN/";

		strcat(fpath, filename);
		filename = path_expand(fpath);
	}

	fichier = fopen(filename, "r");
	if(!fichier)
	{
		fprintf(stderr, "could not open %s\n", filename);
		error();
	}

	first = mem_alloc( sizeof(unsigned char) * 256 );
	ligne = mem_alloc(4096);
	proba2 = mem_alloc(sizeof(unsigned char) * 256 * 256);
	proba1 = mem_alloc(sizeof(unsigned char) * 256 );

	for(j=0;j<256*256;j++)
		proba2[j] = UNK_STR;
	for(j=0;j<256;j++)
		proba1[j] = UNK_STR;

	for(i=0;i<256;i++)
	{
		first[i] = 255;
		for(j=0;j<256;j++)
		{
			charsorted[i*256+j] = j;
		}
	}

	nb_lignes = 0;
	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
			continue;
		ligne[strlen(ligne)-1] = 0; // chop
		if( sscanf(ligne, "%d=proba1[%d]", &i, &j) == 2 )
		{
			if(i>UNK_STR)
				i = UNK_STR;
			proba1[j] = i;
		}
		if( sscanf(ligne, "%d=proba2[%d*256+%d]", &i, &j, &k) == 3 )
		{
			if(i>UNK_STR)
				i = UNK_STR;
			if( (first[j]>k) && (i<UNK_STR))
				first[j] = k;
			proba2[j*256+k] = i;

		}
		nb_lignes++;
	}
	MEM_FREE(ligne);
	fclose(fichier);

	stupidsort(charsorted, proba1, 256);
	for(i=1;i<256;i++)
		stupidsort(&(charsorted[i*256]), &(proba2[i*256]), 256);
}
