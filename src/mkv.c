/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
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
#include "os.h"                 /* Needed for signals.h */
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
#include "options.h"
#include "john.h"
#include "mkv.h"
#include "mask.h"
#include "regex.h"

#define SUBSECTION_DEFAULT  "Default"

extern struct fmt_main fmt_LM;

static int64_t tidx, hybrid_tidx;
#if HAVE_REXGEN
static char *regex_alpha;
static int regex_case;
static char *regex;
#endif

static void save_state(FILE *file)
{
	fprintf(file, "%"PRId64 "\n", tidx);
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%"PRId64 "\n", &gidx) != 1)
		return 1;

	return 0;
}

static void fix_state(void)
{
	if (hybrid_tidx) {
		tidx = hybrid_tidx;
		hybrid_tidx = 0;
	} else
		tidx = gidx;
}

void mkv_hybrid_fix_state(void)
{
	hybrid_tidx = gidx;
}

static int show_pwd_rnbs(struct db_main *db, struct s_pwd *pwd)
{
	uint64_t i;
	unsigned int k;
	unsigned long lvl;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char *pass;

	k = 0;
	i = nbparts[pwd->password[pwd->len - 1] + pwd->len * 256 +
	            pwd->level * 256 * gmax_len];
	pwd->len++;
	lvl = pwd->level;
	pwd->password[pwd->len] = 0;
	while (i > 1) {
		pwd->password[pwd->len - 1] =
		    charsorted[pwd->password[pwd->len - 2] * 256 + k];
		pwd->level =
		    lvl + proba2[pwd->password[pwd->len - 2] * 256 +
		                 pwd->password[pwd->len - 1]];
		i -= nbparts[pwd->password[pwd->len - 1] + pwd->len * 256 +
		             pwd->level * 256 * gmax_len];
		if (pwd->len <= gmax_len) {
			if (show_pwd_rnbs(db, pwd))
				return 1;
		}
		if ((pwd->len >= gmin_len) && (pwd->level >= gmin_level)) {
			pass = (char *)pwd->password;
#if HAVE_REXGEN
			if (regex) {
				if (do_regex_hybrid_crack(db, regex, pass,
				                          regex_case, regex_alpha))
					return 1;
				mkv_hybrid_fix_state();
			} else
#endif
			if (f_new) {
				if (do_external_hybrid_crack(db, pass))
					return 1;
				mkv_hybrid_fix_state();
			} else
			if (options.flags & FLG_MASK_CHK) {
				if (do_mask_crack(pass))
					return 1;
			} else
			if (!f_filter ||
			    ext_filter_body((char *)pwd->password, pass = pass_filtered))
				if (crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
		if (gidx > gend)
			return 1;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
	return 0;
}

static int show_pwd_r(struct db_main *db, struct s_pwd *pwd, unsigned int bs)
{
	uint64_t i;
	unsigned int k;
	unsigned long lvl;
	unsigned char curchar;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char *pass;

	k = 0;
	i = nbparts[pwd->password[pwd->len - 1] + pwd->len * 256 +
	            pwd->level * 256 * gmax_len];
	pwd->len++;
	lvl = pwd->level;
	if (bs) {
		while ((curchar =
		            charsorted[pwd->password[pwd->len - 2] * 256 + k]) !=
		        pwd->password[pwd->len - 1]) {
			i -= nbparts[curchar + pwd->len * 256 + (pwd->level +
			             proba2[pwd->password[pwd->len - 2] * 256 +
			                    curchar]) * 256 * gmax_len];
			k++;
		}
		pwd->level +=
		    proba2[pwd->password[pwd->len - 2] * 256 + pwd->password[pwd->len -
		            1]];
		if (pwd->password[pwd->len] != 0)
			if (show_pwd_r(db, pwd, 1))
				return 1;
		i -= nbparts[pwd->password[pwd->len - 1] + pwd->len * 256 +
		             pwd->level * 256 * gmax_len];
		if ((pwd->len >= gmin_len) && (pwd->level >= gmin_level)) {
			pass = (char *)pwd->password;
#if HAVE_REXGEN
			if (regex) {
				if (do_regex_hybrid_crack(db, regex, pass,
				                          regex_case, regex_alpha))
					return 1;
				mkv_hybrid_fix_state();
			} else
#endif
			if (f_new) {
				if (do_external_hybrid_crack(db, pass))
					return 1;
				mkv_hybrid_fix_state();
			} else
			if (options.flags & FLG_MASK_CHK) {
				if (do_mask_crack(pass))
					return 1;
			} else
			if (!f_filter ||
			    ext_filter_body((char *)pwd->password, pass = pass_filtered))
				if (crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
	}
	pwd->password[pwd->len] = 0;
	while (i > 1) {
		pwd->password[pwd->len - 1] =
		    charsorted[pwd->password[pwd->len - 2] * 256 + k];
		pwd->level =
		    lvl + proba2[pwd->password[pwd->len - 2] * 256 +
		                 pwd->password[pwd->len - 1]];
		i -= nbparts[pwd->password[pwd->len - 1] + pwd->len * 256 +
		             pwd->level * 256 * gmax_len];
		if (pwd->len <= gmax_len) {
			if (show_pwd_r(db, pwd, 0))
				return 1;
		}
		if ((pwd->len >= gmin_len) && (pwd->level >= gmin_level)) {
			pass = (char *)pwd->password;
#if HAVE_REXGEN
			if (regex) {
				if (do_regex_hybrid_crack(db, regex, pass,
				                          regex_case, regex_alpha))
					return 1;
				mkv_hybrid_fix_state();
			} else
#endif
			if (f_new) {
				if (do_external_hybrid_crack(db, pass))
					return 1;
				mkv_hybrid_fix_state();
			} else
			if (options.flags & FLG_MASK_CHK) {
				if (do_mask_crack(pass))
					return 1;
			} else
			if (!f_filter ||
			    ext_filter_body((char *)pwd->password, pass = pass_filtered))
				if (crk_process_key(pass))
					return 1;
		}
		gidx++;
		k++;
		if (gidx > gend)
			return 1;
	}
	pwd->len--;
	pwd->password[pwd->len] = 0;
	pwd->level = lvl;
	return 0;
}

static int show_pwd(struct db_main *db, uint64_t start)
{
	struct s_pwd pwd;
	unsigned int i;
	char pass_filtered[PLAINTEXT_BUFFER_SIZE];
	char *pass;

	if (gidx == 0)
		gidx = start;
	i = 0;

	if (gidx > 0) {
		print_pwd(gidx, &pwd, gmax_level, gmax_len);
		while (charsorted[i] != pwd.password[0])
			i++;
		pwd.len = 1;
		pwd.level = proba1[pwd.password[0]];
		if (pwd.level <= gmax_level) {
			if (show_pwd_r(db, &pwd, 1))
				return 1;

			if ((pwd.len >= gmin_len) && (pwd.level >= gmin_level)) {
				pass = (char *)pwd.password;
#if HAVE_REXGEN
				if (regex) {
					if (do_regex_hybrid_crack(db, regex, pass,
					                          regex_case, regex_alpha))
						return 1;
					mkv_hybrid_fix_state();
				} else
#endif
				if (f_new) {
					if (do_external_hybrid_crack(db, pass))
						return 1;
					mkv_hybrid_fix_state();
				} else
				if (options.flags & FLG_MASK_CHK) {
					if (do_mask_crack(pass))
						return 1;
				} else
				if (!f_filter ||
				    ext_filter_body((char *)pwd.password, pass = pass_filtered))
					if (crk_process_key(pass))
						return 1;
			}
		}
		gidx++;
		i++;
	}
	while (proba1[charsorted[i]] <= gmax_level) {
		if (gidx > gend)
			return 1;
		pwd.len = 1;
		pwd.password[0] = charsorted[i];
		pwd.level = proba1[pwd.password[0]];
		pwd.password[1] = 0;
		if (show_pwd_rnbs(db, &pwd))
			return 1;
		if ((pwd.len >= gmin_len) && (pwd.level >= gmin_level)) {
			pass = (char *)pwd.password;
#if HAVE_REXGEN
			if (regex) {
				if (do_regex_hybrid_crack(db, regex, pass,
				                          regex_case, regex_alpha))
					return 1;
				mkv_hybrid_fix_state();
			} else
#endif
			if (f_new) {
				if (do_external_hybrid_crack(db, pass))
					return 1;
				mkv_hybrid_fix_state();
			} else
			if (options.flags & FLG_MASK_CHK) {
				if (do_mask_crack(pass))
					return 1;
			} else
			if (!f_filter ||
			    ext_filter_body((char *)pwd.password, pass = pass_filtered))
				if (crk_process_key(pass))
					return 1;
		}
		gidx++;
		i++;
	}
	return 0;
}

static double get_progress(void)
{
	uint64_t mask_mult = mask_tot_cand ? mask_tot_cand : 1;
	uint64_t factors = crk_stacked_rule_count * mask_mult;
	uint64_t keyspace = (gend - gstart) * factors;
	uint64_t pos = status.cands;

	emms();

	if (keyspace == 0)
		return 0;

	/* Less accurate because we don't know all details needed */
	if (f_filter || f_new || options.eff_minlength || gmin_level)
		pos = ((rules_stacked_number - 1) * keyspace) +
			(gidx - gstart) * factors;

	return 100.0 * pos / keyspace;
}

void get_markov_options(struct db_main *db,
                        char *mkv_param,
                        unsigned int *mkv_minlevel, unsigned int *mkv_level,
                        char **start_token, char **end_token,
                        unsigned int *mkv_minlen, unsigned int *mkv_maxlen, char **statfile)
{
	char *mode = NULL;
	char *lvl_token = NULL;
	char *len_token = NULL;
	char *dummy_token = NULL;

	int minlevel, level, minlen, maxlen;
	int our_fmt_len = options.eff_maxlength;

	*start_token = NULL;
	*end_token = NULL;

	minlevel = -1;
	level = -1;
	minlen = -1;
	maxlen = -1;

	if (mkv_param) {
		int i;

		if (*mkv_param == ':')
			++mkv_param;
		lvl_token = strtokm(mkv_param, ":");
		/*
		 * If the first token contains anything else than digits
		 * (for the Markov level) or '-' (for a level interval),
		 * then treat it as a section name, and use the next token
		 * as the Markov level (or level interval)
		 */
		for (i = 0; mode == NULL && lvl_token[i] != '\0'; i++) {
			if ((lvl_token[i] < '0' || lvl_token[i] > '9') &&
			        lvl_token[i] != '-') {
				mode = lvl_token;
				lvl_token = strtokm(NULL, ":");
			}

		}
		*start_token = strtokm(NULL, ":");
		*end_token = strtokm(NULL, ":");
		len_token = strtokm(NULL, ":");

		dummy_token = strtokm(NULL, ":");
		if (dummy_token) {
			if (john_main_process)
				fprintf(stderr,
				        "Too many markov parameters specified:"
				        " %s\n", dummy_token);
			error();
		}
	}

	if (mode == NULL)
		mode = SUBSECTION_DEFAULT;

	if (cfg_get_section(SECTION_MARKOV, mode) == NULL) {
		if (john_main_process)
			fprintf(stderr,
			        "Section [" SECTION_MARKOV "%s] not found\n", mode);
		error();
	}

	if (options.mkv_stats == NULL)
		*statfile = (char*)cfg_get_param(SECTION_MARKOV, mode, "Statsfile");
	else
		*statfile = options.mkv_stats;

	if (*statfile == NULL) {
		log_event("Statsfile not defined");
		if (john_main_process)
			fprintf(stderr,
			        "Statsfile not defined in section ["
			        SECTION_MARKOV "%s]\n", mode);
		error();
	}
	/* treat 'empty' level token same as NULL, i.e. pull in from config */
	if (NULL != lvl_token && !strlen(lvl_token))
		lvl_token = 0;
	if (lvl_token != NULL) {
		if (sscanf(lvl_token, "%d-%d", &minlevel, &level) != 2) {
			if (sscanf(lvl_token, "%d", &level) != 1) {
				if (john_main_process)
					fprintf(stderr, "Could not parse markov" " level\n");
				error();
			}
			if (level == 0)
				/* get min. and max. level from markov section */
				minlevel = -1;
			else
				minlevel = 0;

		}
	}
	if ((len_token != NULL) &&
	        (sscanf(len_token, "%d-%d", &minlen, &maxlen) != 2)) {
		sscanf(len_token, "%d", &maxlen);
		if (maxlen == 0)
			/* get min. and max. length from markov section */
			minlen = -1;
		else
			minlen = 0;
	}

	if (level <= 0)
		if ((level = cfg_get_int(SECTION_MARKOV, mode, "MkvLvl")) == -1) {
			log_event("no markov level defined!");
			if (john_main_process)
				fprintf(stderr,
				        "no markov level defined in section ["
				        SECTION_MARKOV "%s]\n", mode);
			error();
		}

	if (level > MAX_MKV_LVL) {
		log_event("! Level = %d is too large (max=%d)", level, MAX_MKV_LVL);
		if (john_main_process)
			fprintf(stderr, "Warning: Level = %d is too large "
			        "(max = %d)\n", level, MAX_MKV_LVL);
		level = MAX_MKV_LVL;
	}

	if (minlevel < 0)
		if ((minlevel = cfg_get_int(SECTION_MARKOV, mode, "MkvMinLvl")) == -1)
			minlevel = 0;

	if (level < minlevel) {
		if (john_main_process)
			fprintf(stderr, "Warning: max level(%d) < min level(%d)"
			        ", min level set to %d\n", level, minlevel, level);
		minlevel = level;
	}

	/*
	 * Command-line --min-length and --max-length, or a format's min length,
	 * can over-ride lengths from config file. This may clash with the
	 * len_token stuff, or rather it will over-ride that too.
	 */
	if (options.eff_minlength > minlen)
		minlen = options.eff_minlength;
	if (options.req_maxlength)
		maxlen = options.eff_maxlength;

	if (maxlen <= 0) {
		if ((maxlen = cfg_get_int(SECTION_MARKOV, mode, "MkvMaxLen")) == -1) {
			log_event("no markov max length defined!");
			if (john_main_process)
				fprintf(stderr,
				        "no markov max length defined in "
				        "section [" SECTION_MARKOV "%s]\n", mode);
			error();
		} else {
			maxlen -= mask_add_len;
			if (mask_num_qw > 1)
				maxlen /= mask_num_qw;
		}
	}

	if (our_fmt_len <= MAX_MKV_LEN && maxlen > our_fmt_len) {
		log_event("! MaxLen = %d is too large for this hash type", maxlen);
		if (john_main_process)
			fprintf(stderr, "Warning: "
			        "MaxLen = %d is too large for the current hash"
			        " type, reduced to %d\n", maxlen, our_fmt_len);
		maxlen = our_fmt_len;
	} else if (maxlen > MAX_MKV_LEN) {
		log_event("! MaxLen = %d is too large (max=%d)", maxlen, MAX_MKV_LEN);
		if (john_main_process)
			fprintf(stderr, "Warning: Maxlen = %d is too large (max"
			        " = %d)\n", maxlen, MAX_MKV_LEN);
		maxlen = MAX_MKV_LEN;
	}

	if (minlen < 0) {
		if ((minlen = cfg_get_int(SECTION_MARKOV, mode, "MkvMinLen")) == -1)
			minlen = 0;
		else {
			minlen -= mask_add_len;
			if (mask_num_qw > 1)
				minlen /= mask_num_qw;
		}
	}

	if (minlen > maxlen) {
		if (john_main_process)
			fprintf(stderr, "Warning: minimum length(%d) > maximum"
			        " length(%d), minimum length set to %d\n",
			        minlen, maxlen, maxlen);
		minlen = maxlen;
	}

	*mkv_minlen = minlen;
	*mkv_maxlen = maxlen;
	*mkv_minlevel = minlevel;
	*mkv_level = level;

	/* Save some stuff we might have got from john.conf so we can
	   resume even if it changes */
	if (!mkv_param) {
		int len = strlen(mode) + 1 + 4 * 4 + 1;

		options.mkv_param = mem_alloc_tiny(len, MEM_ALIGN_NONE);
		sprintf(options.mkv_param, "%s:%d-%d:%d-%d", mode,
		        minlevel, level, minlen, maxlen);
	}

	if (!options.mkv_stats)
		options.mkv_stats = *statfile;
}

void get_markov_start_end(char *start_token, char *end_token,
                          uint64_t mkv_max,
                          uint64_t *mkv_start, uint64_t *mkv_end)
{
	*mkv_start = 0;
	*mkv_end = 0;

	if ((start_token != NULL) && (sscanf(start_token, "%"PRIu64, mkv_start) == 1)) {
		if ((end_token != NULL) && (sscanf(end_token, "%"PRIu64, mkv_end) == 1)) {
		}
		/* NOTE, end_token can be an empty string. Treat "" and mkv_max as equal */
		else if (end_token != NULL && *end_token) {
			if (john_main_process)
				fprintf(stderr, "invalid end: %s\n", end_token);
			error();
		}
	}
	/*
	 * Currently I see no use case for MkvStart and MkvEnd as variables
	 * in a [Markov:mode] section.
	 * If that changes, I'll need
	 * start_token = cfg_get_param(SECTION_MARKOV, mode, "MkvStart")
	 * and
	 * sscanf(start_token, "%"PRId64, start)
	 * because the values could be too large for integers
	 */
	/* NOTE, start_token can be an empty string. Treat "" and "0" equal */
	else if (start_token != NULL && *start_token) {
		if (john_main_process)
			fprintf(stderr, "invalid start: %s\n", start_token);
		error();
	}

	if (start_token != NULL && strlen(start_token) &&
	        start_token[strlen(start_token) - 1] == '%') {
		if (*mkv_start >= 100) {
			log_event("! Start = %s is too large (max < 100%%)", end_token);
			if (john_main_process)
				fprintf(stderr, "Error: Start = %s is too large"
				        " (max < 100%%)\n", start_token);
			exit(1);
		} else if (*mkv_start > 0) {
			*mkv_start *= mkv_max / 100;
			log_event("- Start: %s converted to %" PRId64, start_token,
			          *mkv_start);
			if (john_main_process)
				fprintf(stderr, "Start: %s converted to %" PRId64
				        "\n", start_token, *mkv_start);
		}
	}
	if (end_token != NULL && strlen(end_token) &&
	        end_token[strlen(end_token) - 1] == '%') {
		if (*mkv_end >= 100) {
			if (*mkv_end > 100) {
				if (john_main_process)
					fprintf(stderr, "Warning: End = %s is "
					        "too large (max = 100%%)\n", end_token);
			}
			*mkv_end = 0;
		} else if (*mkv_end > 0) {
			*mkv_end *= mkv_max / 100;
			log_event("- End: %s converted to %" PRId64 "", end_token, *mkv_end);
			if (john_main_process)
				fprintf(stderr, "End: %s converted to %" PRId64
				        "\n", end_token, *mkv_end);
		}
	}
	if (*mkv_end == 0)
		*mkv_end = mkv_max;

	if (*mkv_end > mkv_max) {
		log_event("! End = %" PRId64 " is too large (max=%" PRId64 ")", *mkv_end,
		          mkv_max);
		if (john_main_process)
			fprintf(stderr, "Warning: End = %" PRId64 " is too large "
			        "(max = %" PRId64 ")\n", *mkv_end, mkv_max);
		*mkv_end = mkv_max;
	}

	if (*mkv_start > *mkv_end) {
		log_event("! MKV start > end (%" PRId64 " > %" PRId64 ")", *mkv_start,
		          *mkv_end);
		if (john_main_process)
			fprintf(stderr, "Error: MKV start > end (%" PRId64 " > %" PRId64
			        ")\n", *mkv_start, *mkv_end);
		error();
	}
}

void do_markov_crack(struct db_main *db, char *mkv_param)
{
	char *statfile = NULL;
	char *start_token = NULL;
	char *end_token = NULL;
	char *param = NULL;
	unsigned int mkv_minlevel, mkv_level, mkv_maxlen, mkv_minlen;
	uint64_t mkv_start, mkv_end;

	if (mkv_param != NULL) {
		param = str_alloc_copy(mkv_param);
		if (param == NULL)
			param = mkv_param;
	}

	get_markov_options(db,
	                   mkv_param,
	                   &mkv_minlevel, &mkv_level, &start_token, &end_token,
	                   &mkv_minlen, &mkv_maxlen, &statfile);

#if HAVE_REXGEN
	if ((regex = prepare_regex(options.regex, &regex_case, &regex_alpha))) {
		if (mkv_minlen)
			mkv_minlen--;
		if (mkv_maxlen)
			mkv_maxlen--;
	}
#endif

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

	nbparts =
	    mem_alloc(256 * (mkv_level + 1) * sizeof(int64_t) * (mkv_maxlen +
	              1));
	memset(nbparts, 0,
	       256 * (mkv_level + 1) * (mkv_maxlen + 1) * sizeof(int64_t));

	nb_parts(0, 0, 0, mkv_level, mkv_maxlen);

	get_markov_start_end(start_token, end_token, nbparts[0], &mkv_start,
	                     &mkv_end);

	if (john_main_process) {
		fprintf(stderr, "MKV start (stats=%s, lvl=", statfile);
		if (mkv_minlevel > 0)
			fprintf(stderr, "%d-", mkv_minlevel);
		fprintf(stderr, "%d len=", mkv_level);
		if (mkv_minlen > 0)
			fprintf(stderr, "%d-", mkv_minlen);
		fprintf(stderr, "%d pwd=%" PRIu64 "%s)\n", mkv_maxlen, mkv_end - mkv_start,
		        options.node_count > 1 ? " split over nodes" : "");
	}

	if (options.node_count > 1) {
		uint64_t mkv_size;

		mkv_size = mkv_end - mkv_start + 1;
		if (options.node_max != options.node_count)
			mkv_end =
			    mkv_start + mkv_size / options.node_count * options.node_max -
			    1;
		mkv_start += mkv_size / options.node_count * (options.node_min - 1);
	}

	gstart = mkv_start;
	gend = mkv_end + 10;        /* omg !! */

	log_event("Proceeding with Markov mode%s%s",
	          param ? " " : "", param ? param : "");
	log_event("- Statsfile: %s", statfile);
	log_event("- Markov level: %d - %d", mkv_minlevel, mkv_level);
	log_event("- Length: %d - %d", mkv_minlen, mkv_maxlen);
	log_event("- Start-End: %" PRIu64 " - %" PRIu64, mkv_start, mkv_end);

	if (rec_restored && john_main_process) {
		fprintf(stderr, "Proceeding with Markov%s%s",
		        param ? " " : "", param ? param : "");
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

	show_pwd(db, mkv_start);

	if (!event_abort)
		gidx = gend;            // For reporting DONE properly

	crk_done();
	rec_done(event_abort);

	MEM_FREE(nbparts);
	MEM_FREE(proba1);
	MEM_FREE(proba2);
	MEM_FREE(first);
}
