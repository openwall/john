#include "arch.h"
#include "misc.h"
#include "mask.h"
#include "options.h"

static void convert_to_sub(char *out, int len, const char *in);

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
	char Vars[4][512], *cp, *cp1, *cpo=out;
	int nVars[4], i = 0;

	if (*inmask == 0 || *inmask == '#')  // handle comment or blank lines
		return "";
	if (*inmask == '\\' && inmask[1] == '#')  // handle lines starting with \#
		++inmask;
	cp = strchr(inmask, ',');
	while (cp && cp[-1] == '\\')
		cp = strchr(&cp[1], ',');
	cp1 = inmask;
	while (cp) {
		char tmp_mask[256];
		int len;
		if (cp-cp1 > sizeof(tmp_mask))
			len = sizeof(tmp_mask)-1;
		else
			len = cp-cp1;
		strnzcpy(tmp_mask, cp1, len+1);
		convert_to_sub(Vars[i], sizeof(Vars[i]), tmp_mask);
		nVars[i] = strlen(Vars[i]);
		++i;
		cp1 = cp+1;
		cp = strchr(cp1, ',');
		while (cp && cp[-1] == '\\')
			cp = strchr(&cp[1], ',');
	}
	// Ok, now cp1 should point to the real mask.  Now we just have to replace ?1,?2,?3,?4 with proper values and return.
	i = 0;
	while (*cp1 && i < outlen-1) {
		if (*cp1 != '?') {
			if (*cp1 == '\\' && cp1[1] == ',')
				++cp1;
			*cpo++ = *cp1++;
			++i;
		} else {
			if (cp1[1] >= '1' && cp1[1] <= '4') {
				int which = cp1[1] - '0' -1;
				if (i < outlen-1-nVars[which]) {
					strcpy(cpo, Vars[which]);
					cpo += nVars[which];
					i += nVars[which];
				}
			} else if (i < outlen-3) {
				memcpy(cpo, cp1, 2);
				cpo += 2;
			}
			cp1 += 2;
		}
	}
	*cpo = 0;
	return out;
}

// This converts one of the first 4 comma separated items into a jtr mask
// compatible range string.
static void convert_to_sub(char *out, int len, const char *in) {
	char *cp = out;
	int used = 0;
	*cp++ = '['; ++used;
	while (*in && used < len-2)
	switch (*in) {
		case 0:
			break;
		case '?':
		{
			++in;
			switch(*in++) {
				case 'd':
					if (used > len-5)
						break;
					strcpy(cp, "0-9"); cp += 3; used += 3;
					break;
				case 'l':
					if (used > len-5)
						break;
					strcpy(cp, "a-z"); cp += 3; used += 3;
					break;
				case 'U':
					if (used > len-5)
						break;
					strcpy(cp, "A-Z"); cp += 3; used += 3;
					break;
				case 'a':
					if (used > len-5)
						break;
					strcpy(cp, " -~"); cp += 3; used += 3;
					break;
				case 's':
					if (used > len-38)
						break;
					strcpy(cp, " !\"#$%&'()*+,\\-./:;<=>?@\\[\\]^_`{}|\\~"); cp += 36; used += 36;
					break;
				case 'b':
					if (used > len-3)
						break;
					// hashcat includes null.  JTR can not do that.
					strcpy(cp, "\x01-\xff"); cp += 3; used += 3;
					break;
			}
			break;
		}
		default:
		{
			if (*in == '-')
				*cp++ = '\\';
			else if (*in == '\\' && in[1] == ',')
				++in;
			*cp++ = *in++;
			++used;
		}

	}
	*cp++ = ']';
	*cp = 0;
	return;
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
