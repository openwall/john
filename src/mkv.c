/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "config.h"
#include "charset.h"
#include "external.h"
#include "cracker.h"

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "mkv.h"

#if defined (__MINGW32__) || defined (_MSC_VER)
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
// MinGW is 'same', since it uses msvcrt.dll
#define LLd "%I64d"
#else
#define LLd "%lld"
#endif

extern struct fmt_main fmt_LM;

static long long tidx;

static void save_state(FILE *file)
{
	fprintf(file, LLd"\n", tidx);
}

static int restore_state(FILE *file)
{
	if (fscanf(file, LLd"\n", &gidx) != 1) return 1;

	return 0;
}

static void fix_state(void)
{
	tidx = gidx;
}

static int show_pwd_rnbs(struct s_pwd * pwd)
{
	unsigned long long i;
	unsigned int k;
	unsigned long lvl;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char * pass;

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
		if(pwd->len<=gmax_len)
		{
			if(show_pwd_rnbs(pwd))
				return 1;
		}
		if( (pwd->len >= gmin_len) && (pwd->level >= gmin_level) )
		{
			pass = (char*) pwd->password;
			if (!f_filter || ext_filter_body((char*) pwd->password, pass = pass_filtered))
				if(crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
		if(gidx>gend)
			return 1;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
	return 0;
}

static int show_pwd_r(struct s_pwd * pwd, unsigned int bs)
{
	unsigned long long i;
	unsigned int k;
	unsigned long lvl;
	unsigned char curchar;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char * pass;

	k=0;
	i = nbparts[pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len];
	pwd->len++;
	lvl = pwd->level;
	if(bs)
	{
		while( (curchar=charsorted[ pwd->password[pwd->len-2]*256 + k ]) != pwd->password[pwd->len-1] )
		{
			i -= nbparts[ curchar + pwd->len*256 + (pwd->level + proba2[ pwd->password[pwd->len-2]*256 + curchar ])*256*gmax_len  ];
			k++;
		}
		pwd->level += proba2[ pwd->password[pwd->len-2]*256 + pwd->password[pwd->len-1] ];
		if(pwd->password[pwd->len]!=0)
			if(show_pwd_r(pwd, 1))
				return 1;
		i -= nbparts[ pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len ];
		if( (pwd->len >= gmin_len) && (pwd->level >= gmin_level) )
		{
			pass = (char*) pwd->password;
			if (!f_filter || ext_filter_body((char*)pwd->password, pass = pass_filtered))
				if(crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
	}
	pwd->password[pwd->len] = 0;
	while(i>1)
	{
		pwd->password[pwd->len-1] = charsorted[ pwd->password[pwd->len-2]*256 + k ];
		pwd->level = lvl + proba2[ pwd->password[pwd->len-2]*256 + pwd->password[pwd->len-1] ];
		i -= nbparts[ pwd->password[pwd->len-1] + pwd->len*256 + pwd->level*256*gmax_len ];
		if(pwd->len<=gmax_len)
		{
			if(show_pwd_r(pwd, 0))
				return 1;
		}
		if( (pwd->len >= gmin_len) && (pwd->level >= gmin_level) )
		{
			pass = (char*) pwd->password;
			if (!f_filter || ext_filter_body((char*)pwd->password, pass = pass_filtered))
				if(crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
		if(gidx>gend)
			return 1;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
	return 0;
}

static int show_pwd(unsigned long long start)
{
	struct s_pwd pwd;
	unsigned int i;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char * pass;

	if(gidx==0)
		gidx = start;
	i=0;

	if(gidx>0)
	{
		print_pwd(gidx, &pwd, gmax_level, gmax_len);
		while(charsorted[i] != pwd.password[0])
			i++;
		pwd.len = 1;
		pwd.level = proba1[pwd.password[0]];
		if(show_pwd_r(&pwd, 1))
			return 1;

		if( (pwd.len >= gmin_len) && (pwd.level >= gmin_level) )
		{
			pass = (char*) pwd.password;
			if (!f_filter || ext_filter_body((char*)pwd.password, pass = pass_filtered))
				if(crk_process_key(pass))
					return 1;
		}
		gidx++;
		i++;
	}
	while(proba1[charsorted[i]]<=gmax_level)
	{
		if(gidx>gend)
			return 1;
		pwd.len = 1;
		pwd.password[0] = charsorted[i];
		pwd.level = proba1[pwd.password[0]];
		pwd.password[1] = 0;
		if(show_pwd_rnbs(&pwd))
			return 1;
		if( (pwd.len >= gmin_len) && (pwd.level >= gmin_level) )
		{
			pass = (char*) pwd.password;
			if (!f_filter || ext_filter_body((char*)pwd.password, pass = pass_filtered))
				if(crk_process_key(pass))
					return 1;
		}
		gidx++;
		i++;
	}
	return 0;
}

static int get_progress(int *hundth_perc)
{
	unsigned long long lltmp;
	unsigned hun;
	int per;

	if(gend == 0)
		return 0;

	lltmp = gidx;
	lltmp -= gstart;
	lltmp *= 10000;
	lltmp /= (gend-gstart);

	hun = (unsigned)lltmp;
	per = (int)(hun/100);
	*hundth_perc = (int)(hun-(per*100));
	return per;
}


void do_markov_crack(struct db_main *db, unsigned int mkv_level, unsigned long long mkv_start, unsigned long long mkv_end, unsigned int mkv_maxlen, unsigned int mkv_minlevel, unsigned int mkv_minlen)
{
	char * statfile;

#ifdef HAVE_MPI
	unsigned long long mkv_size;
#endif
	if(mkv_level == 0)
		if( (mkv_level = cfg_get_int("Options", SUBSECTION_MARKOV, "MkvLvl")) == -1 )
		{
			log_event("no markov level defined!");
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "no markov level defined!\n");
			error();
		}

	if(mkv_maxlen == 0)
		if( (mkv_maxlen = cfg_get_int("Options", SUBSECTION_MARKOV, "MkvMaxLen")) == -1 )
		{
			log_event("no markov max length defined!");
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "no markov max length defined!\n");
			error();
		}

	statfile = cfg_get_param("Options", SUBSECTION_MARKOV, "Statsfile");
	if(statfile == NULL)
	{
		log_event("statfile not defined");
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Statfile not defined\n");
		error();
	}

	if (mkv_maxlen > db->format->params.plaintext_length) {
		log_event("! MaxLen = %d is too large for this hash type",
			mkv_maxlen);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: "
			"MaxLen = %d is too large for the current hash type, "
			"reduced to %d\n",
			mkv_maxlen, db->format->params.plaintext_length);
		mkv_maxlen = db->format->params.plaintext_length;
	}

	if (mkv_maxlen > MAX_MKV_LEN) {
		log_event("! MaxLen = %d is too large (max=%d)", mkv_maxlen, MAX_MKV_LEN);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: Maxlen = %d is too large (max = %d)\n", mkv_maxlen, MAX_MKV_LEN);
		mkv_maxlen = MAX_MKV_LEN;
	}

	if (mkv_level > MAX_MKV_LVL) {
		log_event("! Level = %d is too large (max=%d)", mkv_level, MAX_MKV_LVL);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: Level = %d is too large (max = %d)\n", mkv_level, MAX_MKV_LVL);
		mkv_level = MAX_MKV_LVL;
	}

	gidx = 0;
	status_init(get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	init_probatables(path_expand(statfile));

	crk_init(db, fix_state, NULL);

	gmax_level = mkv_level;
	gmax_len = mkv_maxlen;
	gmin_level = mkv_minlevel;
	gmin_len = mkv_minlen;

	nbparts = mem_alloc(256*(mkv_level+1)*sizeof(long long)*(mkv_maxlen+1));
	memset(nbparts, 0, 256*(mkv_level+1)*(mkv_maxlen+1)*sizeof(long long));

	nb_parts(0, 0, 0, mkv_level, mkv_maxlen);

	if(mkv_end==0)
		mkv_end = nbparts[0];

	if(mkv_end>nbparts[0])
	{
		log_event("! End = "LLd" is too large (max="LLd")", mkv_end, nbparts[0]);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: End = "LLd" is too large (max = "LLd")\n", mkv_end, nbparts[0]);
		mkv_end = nbparts[0];
	}

	if(mkv_start>mkv_end)
	{
		log_event("! MKV start > end ("LLd" > "LLd")", mkv_start, mkv_end);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Error: MKV start > end ("LLd" > "LLd")\n", mkv_start, mkv_end);
		error();
	}

#ifdef HAVE_MPI
	if (mpi_id == 0) {
		fprintf(stderr, "MKV start (lvl=");
		if(mkv_minlevel>0) fprintf(stderr, "%d-", mkv_minlevel);
		fprintf(stderr, "%d len=", mkv_level);
		if(mkv_minlen>0) fprintf(stderr, "%d-", mkv_minlen);
		fprintf(stderr, "%d pwd="LLd"%s)\n", mkv_maxlen, mkv_end-mkv_start,
		mpi_p > 1 ? " split over MPI nodes" : "");
	}

	if (mpi_p > 1) {
		mkv_size = mkv_end - mkv_start + 1;
		if (mpi_id != (mpi_p - 1))
			mkv_end = mkv_start + (mkv_size / mpi_p) * (mpi_id + 1) - 1;
		mkv_start = mkv_start + (mkv_size / mpi_p) * mpi_id;
	}
#endif
	gstart = mkv_start;
	gend = mkv_end + 10; /* omg !! */

#ifndef HAVE_MPI
	fprintf(stderr, "MKV start (lvl=");
	if(mkv_minlevel>0) fprintf(stderr, "%d-", mkv_minlevel);
	fprintf(stderr, "%d len=", mkv_level);
	if(mkv_minlen>0) fprintf(stderr, "%d-", mkv_minlen);
	fprintf(stderr, "%d pwd="LLd")\n", mkv_maxlen, mkv_end-mkv_start);
#endif

	show_pwd(mkv_start);

	if (!event_abort)
		gidx = gend; // For reporting DONE properly

	crk_done();
	rec_done(event_abort);

	MEM_FREE(nbparts);
	MEM_FREE(proba1);
	MEM_FREE(proba2);
	MEM_FREE(first);
}
