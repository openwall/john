#include "arch.h"
#include "misc.h"
#include "mask.h"
#include "memory.h"
#include "options.h"

// examples:
// ?d?l,test?1?1?1
//   test[0-9a-z][0-9a-z][0-9a-z]
// abcdef,0123,ABC,789,?3?3?3?1?1?1?1?2?2?4?4?4?4
//   [ABC][ABC][ABC][abcdef][abcdef][abcdef][abcdef][0123][0123][789][789][789][789]
// company?d?d?d?d?d
//   company?d?d?d?d?d
// ?l?l?l?l?d?d?d?d?d?d
//   ?l?l?l?l?d?d?d?d?d?d
static char *hcmask_producemask(char *out, int outlen, char *inmask) {
	char *cp, *cp1, *cp2;
	int i = 0;

	if (*inmask == 0 || *inmask == '#') {  // handle comment or blank lines
		*out = 0;
		return out;
	}
	for (i = 0; i < MAX_NUM_CUST_PLHDR; ++i)
		options.custom_mask[i] = NULL;
	if (*inmask == '\\' && inmask[1] == '#')  // handle lines starting with \#
		++inmask;
	cp = strchr(inmask, ',');
	while (cp && cp[-1] == '\\')
		cp = strchr(&cp[1], ',');
	cp1 = inmask;
	i = 0;
	while (cp) {
		char tmp_mask[512];
		int len;
		if (cp-cp1 > sizeof(tmp_mask))
			len = sizeof(tmp_mask)-1;
		else
			len = cp-cp1;
		strnzcpy(tmp_mask, cp1, len+1);
		// we have to eat any escaped commas
		cp2 = strstr(tmp_mask, "\\,");
		while (cp2) {
			memmove (cp2, cp2+1, strlen(cp2));
			cp2 = strstr(cp2, "\\,");
		}
		options.custom_mask[i++] = str_alloc_copy(tmp_mask);
		cp1 = cp+1;
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

// required a reset in mask.c to run multiple masks in a single run.
extern void reset_old_keylen();

// this is like a do_crack.  yes, it needs a lot of work, but this is
// a PoC that gets the water warmed up.
void do_hcmas_crack(struct db_main *database, const char *fname) {
	FILE *in = fopen(fname, "r");
	char hBuf[512], linebuf[512];
	int bFirst = 1;
	if (!in) {
		fprintf (stderr, "Error opening hc-mask file %s\n", fname);
		exit(0);
	}
	fgetl(linebuf, sizeof(linebuf)-1, in);
	while (!feof(in)) {
		hcmask_producemask(hBuf, sizeof(hBuf), linebuf);
		if (*hBuf == 0) {
			fgetl(linebuf, sizeof(linebuf)-1, in);
			continue;
		}
		mask_init(database, hBuf);
		if (bFirst)
			mask_crk_init(database);
		bFirst = 0;
		reset_old_keylen();
		do_mask_crack(NULL);
		fgetl(linebuf, sizeof(linebuf)-1, in);
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
