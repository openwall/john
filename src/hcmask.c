/*
 * This software was written by JimF jfoug AT cox dot net
 * in 2016. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2016 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * JtR native support for Hashcat's .hcmask files. This 'mode' is
 * driven by option --hc_mask_file=hashfile.  The logic added to JtR
 * is just like HC.  No JtR extensions (like the ?w or using the
 * [Mask] placeholder is used.  The only minor difference is that the
 * ?b mask handles characters from \x1 to \xff while hashcat handles
 * chars from \x0 to \xff.
 */
#include "arch.h"
#include "misc.h"
#include "mask.h"
#include "hcmask.h"
#include "memory.h"
#include "options.h"
#include "recovery.h"

static int linenum=1;

// examples:
// ?d?l,test?1?1?1
//   test[0-9a-z][0-9a-z][0-9a-z]
// abcdef,0123,ABC,789,?3?3?3?1?1?1?1?2?2?4?4?4?4
//   [ABC][ABC][ABC][abcdef][abcdef][abcdef][abcdef][0123][0123][789][789][789][789]
// company?d?d?d?d?d
//   company?d?d?d?d?d
// ?l?l?l?l?d?d?d?d?d?d
//   ?l?l?l?l?d?d?d?d?d?d
// \#ab-c\,0123,ABC,?1?2?1?2password
//   [#ab\-c,0123][ABC][#ab\-c,0123][ABC]password


static char *hcmask_producemask(char *out, int outlen, char *inmask) {
	char *cp, *cp1, *cp2;
	int i = 0;

	// handle comment or blank lines
	if (*inmask == 0 || *inmask == '#') {
		*out = 0;
		return out;
	}
	// clear out any prior custom_mask data.
	for (i = 0; i < MAX_NUM_CUST_PLHDR; ++i)
		options.custom_mask[i] = NULL;
	// handle lines starting with \#
	if (*inmask == '\\' && inmask[1] == '#')
		++inmask;
	// search for first custom mask (?1).  NOTE, there may be
	// embedded commas in there, and they must be kept (they are \,)
	cp = strchr(inmask, ',');
	while (cp && cp[-1] == '\\')
		cp = strchr(&cp[1], ',');
	cp1 = inmask;
	i = 0;
	// cp is used to walk the commas (params)
	// cp1 is used to walk the masks (and ends up as the 'main' mask value.
	// cp2 is used to convert \, back into plain , characters.
	while (cp) {
		char mask_param[512];
		int len;
		if (cp-cp1 > sizeof(mask_param))
			len = sizeof(mask_param)-1;
		else
			len = cp-cp1;
		strnzcpy(mask_param, cp1, len+1);
		// we have to eat any escaped commas
		cp2 = strstr(mask_param, "\\,");
		while (cp2) {
			memmove (cp2, cp2+1, strlen(cp2));
			cp2 = strstr(cp2, "\\,");
		}
		// ok, now set this param up into the proper custom_mask value.
		options.custom_mask[i++] = str_alloc_copy(mask_param);
		// move cp1 to the next mask_parm, OR the real mask.
		cp1 = cp+1;
		// find the next param if there is one.
		cp = strchr(cp1, ',');
		while (cp && cp[-1] == '\\')
			cp = strchr(&cp[1], ',');
	}
	// Ok, now cp1 should point to the real mask.
	// simply eat any escaped commas
	strnzcpy(out, cp1, outlen);
	cp2 = strstr(out, "\\,");
	while (cp2) {
		memmove (cp2, cp2+1, strlen(cp2));
		cp2 = strstr(cp2, "\\,");
	}
	return out;
}

void hcmask_hybrid_fix_state()
{
//	fprintf(stderr, "hcmask_hybrid_fix_state() linenum=%d local_linenum=%d\n", linenum, local_linenum);
//	linenum = local_linenum;

//	fprintf(stderr, "hcmask_hybrid_fix_state() linenum=%d\n", linenum);
}

int hcmask_restore_state_hybrid(const char *sig, FILE *fp) {
	if (!strncmp(sig, "HC-v1", 5)) {
		fscanf(fp, "%d\n", &linenum);
//		fprintf(stderr, "hcmask_restore_state_hybrid() linenum=%d\n", linenum);
	}
	return 0;
}

static void hc_save_mode(FILE *fp) {
//	fprintf(stderr, "hc_save_mode() linenum=%d\n", linenum);
	if (linenum)
		fprintf(fp, "HC-v1\n%d\n", linenum-1);
}

// this is like a do_crack.  yes, it needs a lot of work, but this is
// a PoC that gets the water warmed up.
void do_hcmask_crack(struct db_main *database, const char *fname) {
	FILE *in = fopen(fname, "r");
	char hBuf[512], linebuf[512];
	int i;
	if (!in) {
		fprintf (stderr, "Error opening hc-mask file %s\n", fname);
		exit(0);
	}
	rec_init_hybrid(hc_save_mode);
	mask_crk_init(database);
	for (i = 1; i < linenum; ++i)
		fgetl(linebuf, sizeof(linebuf)-1, in);
	fgetl(linebuf, sizeof(linebuf)-1, in);
	++linenum;
	while (!feof(in)) {
		hcmask_producemask(hBuf, sizeof(hBuf), linebuf);
		if (*hBuf == 0) {
			fgetl(linebuf, sizeof(linebuf)-1, in);
			continue;
		}
		mask_init(database, hBuf);
		mask_reset();
		if (do_mask_crack(NULL))
			break;
		fgetl(linebuf, sizeof(linebuf)-1, in);
		++linenum;
	}
}

#ifdef TEST
int main() {
	char outb[256];
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "x"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?d?l,test?1?1?1"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "abcdef,0123,ABC,789,?3?3?3?1?1?1?1?2?2?4?4?4?4"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "company?d?d?d?d?d"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?l?l?l?l?d?d?d?d?d?d"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?l?d\\,,?1?1"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?l?d\\,ab,?d,?1?2"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?l?d\\,xyz,?d,?1\\,with_comma\\,?2"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "?l-?l\\,g,?d,?1\\,wi-th_comma\\,?2"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "#?l-?l\\,g,?d,?1\\,wi-th_comma\\,?2"));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), ""));
	printf ("Mask = %s\n", hcmask_producemask(outb, sizeof(outb), "\\#?l-?l\\,g,?d,?1\\,wi-th_comma\\,?2"));
}
#endif
