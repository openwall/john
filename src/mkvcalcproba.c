/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <stdlib.h>
#if !defined (_MSC_VER)
#include <unistd.h>
#else
#pragma warning ( disable : 4244 )
#endif
#include <string.h>

#if defined (__MINGW32__) || defined (_MSC_VER)
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
#define LLd "I64d"
#else
#define LLd "lld"
#endif

#define MAX_LVL_LEN 28
#define MAX_LEN 7

#include "params.h"
#include "mkvlib.h"
#include "memory.h"

#define C2I(c) ((unsigned int)(unsigned char)(c))

unsigned char * proba1;
unsigned char * proba2;
unsigned char * first;

int main(int argc, char * * argv)
{
	FILE * fichier;
	char * ligne;
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int l;
	unsigned long long index;
	unsigned char position[256];
	unsigned int charset;
	unsigned int nb_lignes;

	if(argc!=3)
	{
		printf("Usage: %s statfile pwdfile\n", argv[0]);
		return -1;
	}

	fichier = fopen(argv[1], "r");
	if(!fichier)
	{
		printf("could not open %s\n", argv[1]);
		return -1;
	}

	first = malloc( sizeof(unsigned char) * 256 );
	if(first == NULL)
	{
		perror("malloc first");
		return 3;
	}

	ligne = malloc(4096);
	if(ligne == NULL) { perror("malloc ligne"); return 3; }
	proba2 = malloc(sizeof(unsigned char) * 256 * 256);
	if(proba2 == NULL) { perror("malloc proba2"); return 3; }
	proba1 = malloc(sizeof(unsigned char) * 256 );
	if(proba1 == NULL) { perror("malloc proba1"); return 3; }
	for(i=0;i<256*256;i++)
		proba2[i] = UNK_STR;
	for(i=0;i<256;i++)
		proba1[i] = UNK_STR;

	for(i=0;i<256;i++)
	{
		first[i] = 255;
		position[i] = 255;
	}

	nb_lignes = 0;
	charset = 0;
	fprintf(stderr, "reading stats ... [%p]\n", fichier);
	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
		{
			fprintf(stderr, "empty line?\n");
			continue;
		}
		ligne[strlen(ligne)-1] = 0; // chop
		if( sscanf(ligne, "%d=proba1[%d]", &i, &j) == 2 )
		{
			if( j>255 )
			{
				fprintf(stderr, "invalid line %s\n", ligne);
				continue;
			}
			proba1[j] = i;
			if(position[j] == 255)
			{
				position[j] = charset;
				charset++;
			}
		}
		else if( sscanf(ligne, "%d=proba2[%d*256+%d]", &i, &j, &k) == 3 )
		{
			if( (j>255) || (k>255) )
			{
				fprintf(stderr, "invalid line %s\n", ligne);
				continue;
			}
			if( (first[j]>k) && (i<UNK_STR))
				first[j] = k;
			proba2[j*256+k] = i;
			if(position[k] == 255)
			{
				position[k] = charset;
				charset++;
			}
		}
		else
			fprintf(stderr, "invalid line %s\n", ligne);
		nb_lignes++;
	}
	fprintf(stderr, "%d lines parsed [%p]\n", nb_lignes, fichier);
	fclose(fichier);

	fichier = fopen(argv[2], "r");
	if(!fichier)
	{
		printf("could not open %s\n", argv[2]);
		return -1;
	}

	fprintf(stderr, "scanning password file ...\n");
	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
			continue;
		ligne[strlen(ligne)-1] = 0; // chop
		i=1; j=0; k=0;
		j = C2I(ligne[0]);
		k = proba1[j];
		if(ligne[0]==0)
			k = 0;
		printf("%s\t%d", ligne, k);
		l = 0;
		index = position[j];
		if(position[j]==255)
			index = 8.1E18;
		while(ligne[i])
		{
			if(index<8E18)
				index = (index*charset)+position[C2I(ligne[i])];
			if(position[C2I(ligne[i])]==255)
				index = 8.1E18;
			printf("+%d", proba2[j*256+C2I(ligne[i])]);
			k+=proba2[j*256+C2I(ligne[i])];
			if(l)
				l+=proba2[j*256+C2I(ligne[i])];
			if(i==2)
				l=proba1[C2I(ligne[i])];
			j = C2I(ligne[i]);
			i++;
		}
		if(index<8E18)
			printf("\t%d\t%d\t%"LLd"\t%d\n",k,i,index,l);
		else
			printf("\t%d\t%d\t-\t%d\n",k,i,l);
	}
	fprintf(stderr, "freeing stuff ...\n");

	fclose(fichier);

	MEM_FREE(proba1);
	MEM_FREE(proba2);

	MEM_FREE(first);

	MEM_FREE(ligne);

	fprintf(stderr, "charsetsize = %d\n", charset);

	return 0;
}
