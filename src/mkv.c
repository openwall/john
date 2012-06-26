/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Added --markov=MODE[:<options>] support and other minor adjustments, 2012, Frank Dittrich
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

#define SUBSECTION_DEFAULT	"Default"

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

void get_markov_options(struct db_main *db,
                        char *mkv_param,
                        unsigned int *mkv_minlevel, unsigned int *mkv_level,
                        char **start_token, char **end_token,
                        unsigned int *mkv_minlen, unsigned int *mkv_maxlen,
                        char **statfile)
{
	char * mode = NULL;
	char *lvl_token = NULL;
	char *len_token = NULL;
	char *dummy_token = NULL;

	int minlevel, level, minlen, maxlen;

	*start_token = NULL;
	*end_token = NULL;

	minlevel = -1;
	level = -1;
	minlen = -1;
	maxlen = -1;

/*
 * FIXME: strsep() is not portable enough!
 *        I would prefer it over strtok(), to allow something like
 *        --markov=mode:0:0:0:10-15
 *        or
 *        --markov=mode::0:10000000
 *        --markov=mode::10000000:20000000
 *        --markov=mode::20000000:30000000
 *        instead of
 *        --markov=mode:0:0:10000000
 *        --markov=mode:0:10000000:20000000
 *        --markov=mode:0:20000000:30000000
 *
 *        For now, live with strtok(), may be later I need a replacement
 *        for strsep().
 */
	if (mkv_param)
	{
		int i;
		lvl_token = strtok(mkv_param, ":");
		/*
		 * If the first token contains anything else than digits
		 * (for the Markov level) or '-' (for a level interval),
		 * then treat it as a section name, and use the next token
		 * as the Markov level (or level interval)
		 */
		for(i = 0; mode == NULL && lvl_token[i] != '\0'; i++)
		{
			if((lvl_token[i] < '0' || lvl_token[i] > '9') && lvl_token[i] != '-')
			{
				mode = lvl_token;
				lvl_token = strtok(NULL, ":");
			}

		}
		*start_token = strtok(NULL, ":");
		*end_token = strtok(NULL, ":");
		len_token = strtok(NULL, ":");

		dummy_token = strtok(NULL, ":");
		if(dummy_token)
		{
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr,
			        "Too many markov parameters specified: %s\n",
				dummy_token);
			error();
		}
	}

	if(mode == NULL)
		mode = SUBSECTION_DEFAULT;

	if(cfg_get_section(SECTION_MARKOV, mode) == NULL)
	{
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr,
		        "Section [" SECTION_MARKOV "%s] not found\n",
		        mode);
		error();
	}

	*statfile = cfg_get_param(SECTION_MARKOV, mode, "Statsfile");
	if(*statfile == NULL)
	{
		log_event("Statsfile not defined");
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr,
		        "Statsfile not defined in section ["
		        SECTION_MARKOV "%s]\n", mode);
		error();
	}

	if(lvl_token != NULL)
	{
		if(sscanf(lvl_token, "%d-%d", &minlevel, &level) != 2)
		{
			if (sscanf(lvl_token, "%d", &level) != 1)
			{
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf(stderr, "Could not parse markov level\n");
				error();
			}
			if(level == 0)
				/* get min. and max. level from markov section */
				minlevel = -1;
			else
				minlevel = 0;

		}
	}
	if( (len_token != NULL) && (sscanf(len_token, "%d-%d", &minlen, &maxlen)!=2) )
	{
		sscanf(len_token, "%d", &maxlen);
		if(maxlen == 0)
			/* get min. and max. length from markov section */
			minlen = -1;
		else
			minlen = 0;
	}

	if(level <= 0)
		if( (level = cfg_get_int(SECTION_MARKOV, mode, "MkvLvl")) == -1 )
		{
			log_event("no markov level defined!");
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr,
			        "no markov level defined in section [" SECTION_MARKOV "%s]\n",
				mode);
			error();
		}

	if (level > MAX_MKV_LVL) {
		log_event("! Level = %d is too large (max=%d)", level, MAX_MKV_LVL);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: Level = %d is too large (max = %d)\n", level, MAX_MKV_LVL);
		level = MAX_MKV_LVL;
	}

	if(minlevel < 0)
		if( (minlevel = cfg_get_int(SECTION_MARKOV, mode, "MkvMinLvl")) == -1 )
			minlevel = 0;

	if(level<minlevel)
	{
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: max level(%d) < min level(%d), min level set to %d\n", level, minlevel, level);
		minlevel = level;
	}

	if(maxlen <= 0)
		if( (maxlen = cfg_get_int(SECTION_MARKOV, mode, "MkvMaxLen")) == -1 )
		{
			log_event("no markov max length defined!");
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr,
			        "no markov max length defined in section [" SECTION_MARKOV "%s]\n",
			        mode);
			error();
		}

	if (db->format->params.plaintext_length <= MAX_MKV_LEN &&
	    maxlen > db->format->params.plaintext_length)
	{
		log_event("! MaxLen = %d is too large for this hash type",
			maxlen);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: "
			"MaxLen = %d is too large for the current hash type, "
			"reduced to %d\n",
			maxlen, db->format->params.plaintext_length);
		maxlen = db->format->params.plaintext_length;
	}
	else
	if (maxlen > MAX_MKV_LEN)
	{
		log_event("! MaxLen = %d is too large (max=%d)", maxlen, MAX_MKV_LEN);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: Maxlen = %d is too large (max = %d)\n", maxlen, MAX_MKV_LEN);
		maxlen = MAX_MKV_LEN;
	}

	if(minlen < 0)
		if( (minlen = cfg_get_int(SECTION_MARKOV, mode, "MkvMinLen")) == -1 )
			minlen = 0;

	if(minlen > maxlen)
	{
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: minimum length(%d) > maximum length(%d), minimum length set to %d\n", minlen, maxlen, maxlen);
		minlen = maxlen;
	}

	*mkv_minlen = minlen;
	*mkv_maxlen = maxlen;
	*mkv_minlevel = minlevel;
	*mkv_level = level;
}
void get_markov_start_end(char *start_token, char *end_token,
                          unsigned long long mkv_max,
                          unsigned long long *mkv_start, unsigned long long *mkv_end)
{
	*mkv_start = 0;
	*mkv_end = 0;

	if((start_token != NULL) && (sscanf(start_token, LLd, mkv_start)==1) )
	{
		if((end_token != NULL) && (sscanf(end_token, LLd, mkv_end)==1) )
		{
		}
		else if(end_token != NULL)
		{
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr,
			        "invalid end: %s\n", end_token);
			error();
		}
	}
	/*
	 * Currently I see no use case for MkvStart and MkvEnd as variables
	 * in a [Markov:mode] section.
	 * If that changes, I'll need
	 * start_token = cfg_get_param(SECTION_MARKOV, mode, "MkvStart")
	 * and
	 * sscanf(start_token, LLd, start)
	 * because the values could be too large for integers
	 */
	else if(start_token != NULL)
	{
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr,
		        "invalid start: %s\n", start_token);
		error();
	}

	if (start_token != NULL && start_token[strlen(start_token)-1] == '%') {
		if (*mkv_start >= 100) {
			log_event("! Start = %s is too large (max < 100%%)", end_token);
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Error: Start = %s is too large (max < 100%%)\n", start_token);
				exit(1);
		} else if (*mkv_start > 0) {
			*mkv_start *= mkv_max / 100;
			log_event("- Start: %s converted to "LLd, start_token, *mkv_start);
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Start: %s converted to "LLd"\n", start_token, *mkv_start);
		}
	}
	if (end_token != NULL && end_token[strlen(end_token)-1] == '%') {
		if (*mkv_end >= 100) {
			if (*mkv_end > 100) {
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf(stderr, "Warning: End = %s is too large (max = 100%%)\n", end_token);
			}
			*mkv_end = 0;
		} else if (*mkv_end > 0) {
			*mkv_end *= mkv_max / 100;
			log_event("- End: %s converted to "LLd"", end_token, *mkv_end);
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "End: %s converted to "LLd"\n", end_token, *mkv_end);
		}
	}
	if(*mkv_end == 0)
		*mkv_end = mkv_max;

	if(*mkv_end > mkv_max)
	{
		log_event("! End = "LLd" is too large (max="LLd")", *mkv_end, mkv_max);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: End = "LLd" is too large (max = "LLd")\n", *mkv_end, mkv_max);
		*mkv_end = mkv_max;
	}

	if(*mkv_start > *mkv_end)
	{
		log_event("! MKV start > end ("LLd" > "LLd")", *mkv_start, *mkv_end);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Error: MKV start > end ("LLd" > "LLd")\n", *mkv_start, *mkv_end);
		error();
	}
}

void do_markov_crack(struct db_main *db, char *mkv_param)
{
	char *statfile = NULL;
	char *start_token = NULL;
	char *end_token = NULL;
	char *param = NULL;
	unsigned int mkv_minlevel, mkv_level,  mkv_maxlen, mkv_minlen;
	unsigned long long mkv_start, mkv_end;

#ifdef HAVE_MPI
	unsigned long long mkv_size;
#endif

	if(mkv_param != NULL)
	{
		param = str_alloc_copy(mkv_param);
		if(param == NULL)
			param = mkv_param;
	}

	get_markov_options(db,
	                   mkv_param,
	                   &mkv_minlevel, &mkv_level, &start_token, &end_token,
	                   &mkv_minlen, &mkv_maxlen, &statfile);

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

	get_markov_start_end(start_token, end_token, nbparts[0], &mkv_start, &mkv_end);

#ifdef HAVE_MPI
	if (mpi_id == 0) {
		fprintf(stderr, "MKV start (stats=%s, lvl=", statfile);
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
	fprintf(stderr, "MKV start (stats=%s, lvl=", statfile);
	if(mkv_minlevel>0) fprintf(stderr, "%d-", mkv_minlevel);
	fprintf(stderr, "%d len=", mkv_level);
	if(mkv_minlen>0) fprintf(stderr, "%d-", mkv_minlen);
	fprintf(stderr, "%d pwd="LLd")\n", mkv_maxlen, mkv_end-mkv_start);
#endif

	if(param)
		log_event("Proceeding with Markov mode %s", param);
	else
		log_event("Proceeding with Markov mode");

	log_event("- Statsfile: %s", statfile);
	log_event("- Markov level: %d - %d", mkv_minlevel, mkv_level);
	log_event("- Length: %d - %d", mkv_minlen, mkv_maxlen);
	log_event("- Start-End: "LLd" - "LLd, mkv_start, mkv_end);

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
