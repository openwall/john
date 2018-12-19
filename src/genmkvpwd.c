/*
 * This software is Copyright (c) 2007 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <math.h>
#include <string.h>

#include "jumbo.h"
#include "params.h"
#include "memory.h"
#include "mkvlib.h"

static void show_pwd_rnbs(struct s_pwd * pwd)
{
	uint64_t i;
	unsigned int k;
	unsigned long lvl;

	k=0;
	i = nbparts[pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len];
	pwd->len++;
	lvl = pwd->level;
	pwd->password[pwd->len] = 0;
	while(i>1)
	{
		pwd->password[pwd->len-1] = charsorted[ pwd->password[pwd->len-2]*256 + k ];
		pwd->level = lvl + proba2[ pwd->password[pwd->len-2]*256 + pwd->password[pwd->len-1] ];
		i -= nbparts[ pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len ];
		if (pwd->len<=gmax_len)
		{
			show_pwd_rnbs(pwd);
		}
		printf("%s\n", pwd->password);
		gidx++;
		k++;
		if (gidx>gend)
			return;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
}

static void show_pwd_r(struct s_pwd * pwd, unsigned int bs)
{
	uint64_t i;
	unsigned int k;
	unsigned long lvl;
	unsigned char curchar;

	k=0;
	i = nbparts[pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len];
	pwd->len++;
	lvl = pwd->level;
	if (bs)
	{
		while( (curchar=charsorted[ pwd->password[pwd->len-2]*256 + k ]) != pwd->password[pwd->len-1] )
		{
			i -= nbparts[ curchar + pwd->len*256 + (pwd->level + proba2[ pwd->password[pwd->len-2]*256 + curchar ])*256*gmax_len  ];
			k++;
		}
		pwd->level += proba2[ pwd->password[pwd->len-2]*256 + pwd->password[pwd->len-1] ];
		if (pwd->password[pwd->len]!=0)
			show_pwd_r(pwd, 1);
		i -= nbparts[ pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len ];
		printf("%s\n", pwd->password);
		gidx++;
		k++;
	}
	pwd->password[pwd->len] = 0;
	while(i>1)
	{
		pwd->password[pwd->len-1] = charsorted[ pwd->password[pwd->len-2]*256 + k ];
		pwd->level = lvl + proba2[ pwd->password[pwd->len-2]*256 + pwd->password[pwd->len-1] ];
		i -= nbparts[ pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len ];
		if (pwd->len<=gmax_len)
		{
			show_pwd_r(pwd, 0);
		}
		printf("%s\n", pwd->password);
		gidx++;
		k++;
		if (gidx>gend)
			return;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
}

static void show_pwd(uint64_t start, uint64_t end, unsigned int max_level, unsigned int max_len)
{
	struct s_pwd pwd;
	unsigned int i;
	unsigned int bs;

	gmax_level = max_level;
	gmax_len = max_len;
	gend = end;
	gidx = start;
	i=0;
	bs = 0;
	if (start>0)
		bs = 1;
	if (bs)
	{
		print_pwd(start, &pwd, max_level, max_len);
		while(charsorted[i] != pwd.password[0])
			i++;
		pwd.len = 1;
		pwd.level = proba1[pwd.password[0]];
		show_pwd_r(&pwd, 1);
		printf("%s\n", pwd.password);
		i++;
	}
	while(proba1[charsorted[i]]<=max_level)
	{
		if (gidx>gend)
			return;
		pwd.len = 1;
		pwd.password[0] = charsorted[i];
		pwd.level = proba1[pwd.password[0]];
		pwd.password[1] = 0;
		show_pwd_rnbs(&pwd);
		printf("%s\n", pwd.password);
		gidx++;
		i++;
	}
}

#if 0
static void stupidsort(unsigned char * result, unsigned int * source, unsigned int size)
{
	unsigned char pivot;
	unsigned char more[256];
	unsigned char less[256];
	unsigned char piv[256];
	unsigned int i,m,l,p;

	if (size<=1)
		return;
	i=0;
	while( (source[result[i]]==1000) && (i<size))
		i++;
	if (i==size)
		return;
	pivot = result[i];
	if (size<=1)
		return;
	m=0;
	l=0;
	p=0;
	for (i=0;i<size;i++)
	{
		if (source[result[i]]==source[pivot])
		{
			piv[p] = result[i];
			p++;
		}
		else if (source[result[i]]<=source[pivot])
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
#endif

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return 0;
}
#endif

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char * * argv)
#else
int main(int argc, char * * argv)
#endif
{
	struct s_pwd pwd;
	struct s_pwd pwd2;

	unsigned int max_lvl = 0, max_len;
	uint64_t start, end;

	max_len = 0;
	start = 0;
	end = 0;

	if ((argc<3) || (argc>6))
	{
		printf("Usage: %s statfile max_lvl [max_len] [start] [end]\n", argv[0]);
		return -1;
	}

	max_lvl = atoi(argv[2]);

	if (argc>3)
		max_len = atoi(argv[3]);
	if (argc>4)
		start = atoll(argv[4]);
	if (argc>5)
		end = atoll(argv[5]);

	init_probatables(argv[1]);

	if (max_len == 0)
	{
		for (max_len=6;max_len<20;max_len++)
		{
			nbparts = mem_alloc(256*(max_lvl+1)*sizeof(long long)*(max_len+1));
			printf("len=%u (%lu KB for nbparts) ", max_len, (unsigned long)(256UL*(max_lvl+1)*(max_len+1)*sizeof(long long)/1024));
			memset(nbparts, 0, 256*(max_lvl+1)*(max_len+1)*sizeof(long long));
			nb_parts(0, 0, 0, max_lvl, max_len);
			if (nbparts[0] > 1000000000)
				printf("%"PRIu64" G possible passwords (%"PRIu64")\n", nbparts[0] / 1000000000, nbparts[0]);
			else if (nbparts[0] > 10000000)
				printf("%"PRIu64" M possible passwords (%"PRIu64")\n", nbparts[0] / 1000000, nbparts[0]);
			else if (nbparts[0] > 10000)
				printf("%"PRIu64" K possible passwords (%"PRIu64")\n", nbparts[0] / 1000, nbparts[0]);
			else
				printf("%"PRIu64" possible passwords\n", nbparts[0] );
			MEM_FREE(nbparts);
		}
		goto fin;
	}

	if (max_lvl == 0)
	{
		for (max_lvl=100;max_lvl<=MAX_MKV_LVL;max_lvl++)
		{
			nbparts = mem_alloc(256*(max_lvl+1)*sizeof(long long)*(max_len+1));
			printf("lvl=%u (%lu KB for nbparts) ", max_lvl, (unsigned long)(256UL*(max_lvl+1)*(max_len+1)*sizeof(long long)/1024));
			memset(nbparts, 0, 256*(max_lvl+1)*(max_len+1)*sizeof(long long));
			nb_parts(0, 0, 0, max_lvl, max_len);
			if (nbparts[0] > 1000000000)
				printf("%"PRIu64" G possible passwords (%"PRIu64")\n", nbparts[0] / 1000000000, nbparts[0]);
			else if (nbparts[0] > 10000000)
				printf("%"PRIu64" M possible passwords (%"PRIu64")\n", nbparts[0] / 1000000, nbparts[0]);
			else if (nbparts[0] > 10000)
				printf("%"PRIu64" K possible passwords (%"PRIu64")\n", nbparts[0] / 1000, nbparts[0]);
			else
				printf("%"PRIu64" possible passwords\n", nbparts[0] );
			MEM_FREE(nbparts);
		}
		goto fin;
	}
	if (max_lvl>MAX_MKV_LVL) {
		fprintf(stderr, "Warning: Level = %d is too large (max = %d)\n", max_lvl, MAX_MKV_LVL);
		max_lvl = MAX_MKV_LVL;
	}

	nbparts = mem_alloc(256*(max_lvl+1)*sizeof(long long)*(max_len+1));
	fprintf(stderr, "allocated %lu KB for nbparts\n", (unsigned long)(256UL*(max_lvl+1)*(max_len+1)*sizeof(long long)/1024));
	memset(nbparts, 0, 256*(max_lvl+1)*(max_len+1)*sizeof(long long));

	nb_parts(0, 0, 0, max_lvl, max_len);
	if (nbparts[0] > 1000000000)
		fprintf(stderr, "%"PRIu64" G possible passwords (%"PRIu64")\n", nbparts[0] / 1000000000, nbparts[0]);
	else if (nbparts[0] > 10000000)
		fprintf(stderr, "%"PRIu64" M possible passwords (%"PRIu64")\n", nbparts[0] / 1000000, nbparts[0]);
	else if (nbparts[0] > 10000)
		fprintf(stderr, "%"PRIu64" K possible passwords (%"PRIu64")\n", nbparts[0] / 1000, nbparts[0]);
	else
		fprintf(stderr, "%"PRIu64" possible passwords\n", nbparts[0] );

	if (end == 0)
		end = nbparts[0];

	pwd.level = 0;
	pwd.len = 0;
	pwd.index = 0;
	memset(pwd.password, 0, max_len+1);

	print_pwd(start, &pwd, max_lvl, max_len);
	print_pwd(start, &pwd2, max_lvl, max_len);

	fprintf(stderr, "starting with %s (%"PRIu64" to %"PRIu64", %f%% of the scope)\n", pwd.password, start, end, 100*((float) end-start)/((float) nbparts[0]) );

	show_pwd(start, end, max_lvl, max_len);

	MEM_FREE(nbparts);
fin:
	MEM_FREE(proba1);
	MEM_FREE(proba2);
	MEM_FREE(first);
	return 0;
}
