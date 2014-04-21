/* Compile: gcc uaf2john.c uaf_hash.c -o ../run/uaf2john
 *
 * Convert a OpenVMS SYSUAF file to a unix-style password file (7
 * colon-delimited printable fields).  The password string is 29 characters
 * of the form:
 *
 *    $V$hhhhhhhhhhhhuuuuuuuuuuuuuu
 *
 * where:
 *    $V$	    Tags field as VMS SYSUAF format.
 *    hhhhhhhhhhhhh (12 characters) Encodes the 64-bit password hash and 8-bit
 *                  algorithm code (e.g. PURDY_V) in 12 characters (6-bit/char).
 *    uuuuuuuuuuuuu (14 characters) Encodes 16-bit salt value and 12 character
 *		    username (stored as RAD-50) and 4 flags bits:
 *                     <0>  If set, mixed case password in use.
 *
 * The username is an implicit 'salt' for the VMS password hash algorithms so
 * that information must be carried along in the password string.
 *
 * Encoding is 6 bits per character:
 *
 *    0000000000111111111122222222223333333333444444444455555555556666
 *    0123456789012345678901234567890123456789012345678901234567890123
 *    -ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789abcedfghijklmnopqrstuvwxyz+
 *
 * Usage:
 *    (OpenVMS) uaf2john [input-file|$|~user|./raw-file] [output-file]
 *
 *    (Unix) uaf2john raw-file [output-file]
 *
 * Arguments:
 *    raw-file      Binary file containing 1412 byte data records converted
 *                  from SYSUAF.DAT with OpenVMS convert utility.
 *
 *    input-file    File containing output of "mcr authorize list/brief"
 *		    command (SYSUAF.LIS).
 *
 *       $          Generates SYSUAF.LIS file by spawning authorize command,
 *                  then uses that file as input file.
 *
 *    ~username     Creates an input file for a single username, may be
 *                  used by non-privileged users to get their own password
 *		    hash.
 *
 *    output-file   Generated passwd file, defaults to stdout.  Output fields,
 *                  separated by colons, are:
 *			username[.n]    Suffix present if multiple passwords.
 *                      password        Encoded as described above.
 *                      group           UIC group in decimal (i.e. 010-> 8).
 *                      user            UIC user in decimal.
 *                      owner           UAF owner field (Gecos).
 *                      flags-summary   Fake homedir of form:
 *                                       /[Users|USERS][/Disuser|/Expired]/priv
 *                                      Mixed case "Users" indicate mixed case
 *					paswords.  priv is keyword "Normal" or
 *					"All".
 *                      CLI             Command line interpreter (DCL).
 *
 * Author: David Jones
 * Date:   7-JUL-2009
 * Revised:11-JUL-2009
 * Revised:19-JUL-2009		! add secondary password records.
 * Revised:17-AUG-2009		! add explicit uaf_init() call.
 * Revised:18-OCT-2009		! add /disuser or /expired to path.
 * Revised:21-AUG-2011		! augment header comments.
 * Revised:23-SEP-2011		! Support raw_file format.
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>, and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifdef VMS
#include <descrip.h>
#include <jpidef.h>
#include <starlet.h>
#include <lib$routines.h>
#include <uaidef.h>
#endif
#ifndef UAI$M_PWDMIX
#define UAI$M_PWDMIX 0
#endif

#include "uaf_encode.h"
#include "uaf_raw.h"
#include "memdbg.h"

/*
 * Define function, primarily used on non-VMS systems, to extract UAF data
 * from raw record.  If error status (0) is returned, acct_status has detail.
 */
int uaf_extract_from_raw(void *rec_vp, int rec_len,
    struct uaf_hash_info *pwd,
    struct uaf_hash_info *pwd2,
    struct uaf_account_info *acct, char **acct_status, char **priv_summary)
{
	struct uaf_rec *rec;
	int i, len, devlen;
	/*
	 * Do sanity checks on input record.
	 */
	*acct_status = "";
	rec = rec_vp;
	if (rec_len < UAF_RAW_REC_MIN_LENGTH) {
		*acct_status = "record length too short";
		return 0;
	}
	if (rec->rtype != UAF_RECTYPE_USER) {
		*acct_status = "invalid record type";
		return 0;
	}
	if (rec->usrdatoff != 0) {
		if (rec->usrdatoff < UAF_REC_MIN_USRDATOFF) {
			*acct_status = "user data out of range (short)";
			return 0;
		}
		if (rec->usrdatoff > UAF_REC_SIZE) {
			*acct_status = "user data out of range";
			return 0;
		}
	}
	/*
	 * Fill in acct struct.
	 */
	for (i = 0; (i < 31) && (rec->username[i] != ' '); i++) {
		acct->username[i] = toupper(rec->username[i]);
	}
	acct->username[i] = '\0';
	if (i > 12) {
		*acct_status = "username too long (>12)";
		return 0;
	}
	acct->uic[0] = rec->uic.mem;
	acct->uic[1] = rec->uic.grp;

	len = rec->owner.len;
	if (len > sizeof(rec->owner.s)) {
		*acct_status = "invalid owner length";
		return 0;
	}
	for (i = 0; i < len; i++)
		acct->owner[i] = rec->owner.s[i];
	acct->owner[len] = '\0';

	len = rec->defcli.len;
	if (len > sizeof(rec->defcli.s)) {
		*acct_status = "invalid defcli length";
		return 0;
	}
	for (i = 0; i < len; i++)
		acct->shell[i] = rec->defcli.s[i];
	acct->shell[len] = '\0';

	len = rec->defdev.len;
	if (len > sizeof(rec->defdev.s)) {
		*acct_status = "invalid defdev length";
		return 0;
	}
	for (i = 0; i < len; i++)
		acct->home_dir[i] = rec->defdev.s[i];
	devlen = i;
	len = rec->defdir.len;
	for (i = 0; i < len; i++)
		acct->home_dir[i + devlen] = rec->defdir.s[i];
	acct->home_dir[len + devlen] = '\0';
	/*
	 * Fill in password data.
	 */
	memcpy(pwd, rec->pwd, 8);	/* assume hash is first member */
	pwd->flags = rec->flagbits;
	if ((pwd->flags & UAI$M_PWDMIX) && !rec->flags.pwdmix)
		printf("Bugcheck, pwdmix bitfield definition wrong: %d\n",
		    rec->flags.pwdmix);
	if (rec->flags.pwdmix)
		pwd->flags |= UAI$M_PWDMIX;
	pwd->salt = rec->salt;
	pwd->alg = rec->encrypt;
	pwd->opt = rec->flags.pwdmix;
	strcpy(pwd->username.s, acct->username);
	uaf_packed_convert(&pwd->username, 1);

	memcpy(pwd2, rec->pwd2, 8);	/* assume hash is first member */
	pwd2->flags = 0;
	if (rec->flags.pwdmix)
		pwd2->flags |= UAI$M_PWDMIX;
	pwd2->salt = rec->salt;
	pwd2->alg = rec->encrypt;
	pwd2->opt = rec->flags.pwdmix;
	strcpy(pwd2->username.s, acct->username);
	uaf_packed_convert(&pwd2->username, 1);
	/*
	 * Determine special account status as best we can.
	 */
	if (rec->flags.disacnt)
		*acct_status = "Disuser";
	else if (rec->expiration[0] || rec->expiration[1]) {
		long long expiration;
		memcpy(&expiration, rec->expiration, 8);
	}
	if (priv_summary) {
		static struct {
			char *summary;
			uafrec_qword mask;
		} priv_category[9] = {
			{
				"All", {
			0x344040a7, 0x000b}}, {
				"Objects", {
			0x02220040, 0x010}}, {
				"System", {
			0xc0053000, 0x060}}, {
				"Devour", {
			0x09880e18, 0x000}}, {
				"Group", {
			0x00000100, 0x004}}, {
				"Normal", {
			0x00108000, 0}}, {
				"None", {
			0, 0}}
		};
		for (i = 0; priv_category[i].mask[0]; i++) {
			if ((priv_category[i].mask[0] & rec->priv[0]) ||
			    (priv_category[i].mask[1] & rec->priv[1]))
				break;
		}
		*priv_summary = priv_category[i].summary;
	}
	return 1;
}

/*
 * Replace colon characters in string with periods.
 */
static char *colon_blow(char *field)
{
	int i;
	for (i = 0; field[i]; i++)
		if (field[i] == ':')
			field[i] = '.';
	return field;
}

/*
 * Spawn authorize command that will generate SYSUAF.LIS file.
 */
#ifdef VMS
static void spawn_authorize(char *expected_file)
{
	static $DESCRIPTOR(cmd_dx, "MCR SYS$SYSTEM:AUTHORIZE list/brief *");
	int status, flags;

	printf("Spawning authorize command...\n");
	flags = 2 + 8;		/* noclisym + nokeypad */
	status = LIB$SPAWN(&cmd_dx, 0, 0, &flags, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	if ((status & 1) == 0) {
		printf("Error spawning spawn\n");
		exit(status);
	}
}

/*
 * Generate a 1-line dummy SYSUAF listing for a particular user.
 */
static void single_user(char *infile, char *username)
{
	FILE *outf;

	outf = fopen(infile, "w");
	/*   0123456789012345678901 */
	fprintf(outf, "[Dummy placeholder21]%s            \n", username);
	fclose(outf);
}
#endif
/****************************************************************************/

static void process_file(char *infile)
{
	int i, status, lnum, is_raw;
	FILE *listf, *rawf;
	char line[4096], *lf, *username, *suffix, *directory, *prefix;
	char encoded[UAF_ENCODE_SIZE], *result;

	struct uaf_hash_info pwd, pwd2;
	struct uaf_account_info acct;
	struct uaf_rec rec;	/* raw record */
	uaf_qword null_hash;

	is_raw = 1;
#ifdef VMS
	if (strcmp(infile, "$") == 0) {
		is_raw = 0;
		infile = "SYSUAF.LIS";
		spawn_authorize(infile);
	} else if (infile[0] == '~') {
		is_raw = 0;
		infile = "useruaf.lis";
		single_user(infile, &argv[1][1]);
	} else if ((infile[0] != '/') && (0 != strncmp(infile, "./", 2))) {
		is_raw = 0;
	}
#endif
	if (is_raw) {
		rawf = fopen(infile, "rb");
		listf = (FILE *) 0;
	} else {
		listf = fopen(infile, "r");
		rawf = (FILE *) 0;
	}
	if (!listf && !rawf) {
		fprintf(stderr, "File open failue on '%s'\n", infile);
		return;
	}

	/*
	 * Convert each input line to a corresponding passwd file line.
	 */
	uaf_init();
	UAF_QW_SET(null_hash, 0);
	lnum = 0;
	while (1) {
		char *priv_summary;
		if (is_raw) {
			/*
			 * Input file is raw UAF file records, call function in uaf_encode
			 * module to extract passwword and other information.
			 */
			if (1 != fread(&rec, sizeof(rec), 1, rawf))
				break;
			status =
			    uaf_extract_from_raw(&rec, sizeof(rec), &pwd,
			    &pwd2, &acct, &prefix, &priv_summary);
		} else {
			/*
			 * Input is a authorize utility brief listing, trim carriage control.
			 */
			if (!fgets(line, sizeof(line), listf))
				break;
			lf = strchr(line, '\n');
			if (lf)
				*lf = '\0';
			lnum++;
			if (strlen(line) < 21)
				continue;	/* line too short, ignore */
			/*
			 * Extract summary data and username from line.
			 */
			prefix = "";
			if (strlen(line) > 69) {
				directory = &line[69];
				if (strcmp(directory, "Disuser") == 0)
					prefix = "/disuser";
				if (strcmp(directory, "Expired") == 0)
					prefix = "/expired";
			}
			if (strlen(line) > 59) {
				priv_summary = &line[59];
				for (i = 0; priv_summary[i]; i++) {
					if (priv_summary[i] == ' ') {
						priv_summary[i] = '\0';
						break;
					}
				}
			} else {
				priv_summary = "unknown";
			}
			username = &line[21];
			for (i = 0; username[i]; i++) {
				if (username[i] == ' ') {
					username[i] = '\0';
					break;
				}
			}
			/*
			 * Use $GETUAI to get info needed to populate fields of passwd file
			 * line.  Be lazy and use dummy string for home_dir (to avoid dealing
			 * with colon in VMS file specification).
			 */
			if (strcmp(username, "Username") == 0)
				continue;	/* header line */
			status = uaf_getuai_info(username, &pwd, &pwd2, &acct);
		}
		if (status & 1) {
			/*
			 * Output user data as passwd-like text line.
			 */
			if (UAF_QW_EQL(pwd2.hash, null_hash))
				suffix = "";
			else
				suffix = ".1";	/* flag as primary of 2 */

			result = uaf_hash_encode(&pwd, encoded);

			fprintf(stdout, "%s%s:%s:%d:%d:%s:/%s%s%s/%s:%s\n",
			    colon_blow(pwd.username.s), suffix,
			    result,
			    acct.uic[0],
			    acct.uic[1],
			    colon_blow(acct.owner),
			    (pwd.flags & UAI$M_PWDMIX) ? "Users" : "USERS",
			    prefix[0] ? "/" : "", prefix, priv_summary,
			    colon_blow(acct.shell));
			if (suffix[0] == '.') {
				/*
				 * secondary password present.
				 */
				result = uaf_hash_encode(&pwd2, encoded);
				fprintf(stdout,
				    "%s%s:%s:%d:%d:%s:/%s%s%s/%s:%s\n",
				    colon_blow(pwd.username.s), suffix, result,
				    acct.uic[0], acct.uic[1],
				    colon_blow(acct.owner),
				    (pwd.
					flags & UAI$M_PWDMIX) ? "Users" :
				    "USERS", prefix[0] ? "/" : "", prefix,
				    priv_summary, colon_blow(acct.shell));
			}
		} else {
			fprintf(stderr, "Error fetching UAF information, %s\n", prefix);
			return;
		}
	}

	if (is_raw)
		fclose(rawf);
	else
		fclose(listf);

}

int main(int argc, char **argv)
{
	int i;

	/* Process command line arguments and open input/output files. */
	if (argc < 2) {
#ifdef VMS
		printf("Usage: uaf_to_passwd [sysuaf-brief-list|$|~user]\n");
		printf("($ spawns authorize to make SYSUAF.LIS file)\n");
#else
		printf("Usage: uaf_to_passwd uaf_file\n");
#endif
		return 0;
	}

	for (i = 1; i < argc; i++) {
		process_file(argv[i]);
	}

	return 0;
}
