// common type source to test functions:
//	misc.c		(mostly done)
//	common.c	(done)
//	jumbo.c		(todo)
//	list.c		(??)
//	mask.c		(??)
//	mask_ext.c	(??)
//	memory.c    (??)
//	unicode.c	(??)
//	unicode_range.c (??)
//	simd-intrinsics.c (??)
//
//  Likely could add tests for all hash types (or many).  Things like md2/4/5
//	sha/1/224/..512  sha3, etc, etc. These would be very fast set of known
//	test vectors.  Make sure the functions return proper results, and
//	simply list pass/fail. NOTE< sha-2 added, with input files from the
//	NESSIE project. There are more which we can use from NESSIE, and
//	easily add things like some of the sph* hashes to the TS, or some
//	other internal hash functions.
//
//	base64_convert.c(may have it's own ST code already)
//	compiler.c	(Possible unit test by building test suite of config
//		files, then spawning john to test them)
//	external.c	(Possible unit test by building test suite of config
//		files, then spawning john to test them)
//
//	loader.c	(Not unit testable)
//	logger.c	(Not unit testable)
//	fuzz.c		(Not unit testable)
//	inc.c		(Not unit testable)


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>
#include <inttypes.h>
#include <limits.h>
#include "../misc.h"
#include "../memory.h"
#include "../common.h"

#include "../sha2.h"

char *_fgetl_pad = NULL;
#define _FGETL_PAD_SIZE 19000
#define _ISHEX_CNT 260
// if we miss a line(s), only show 1 error. This variable is used to adjust
// the linecount since we don't have the expected line count (we missed
// a line or lines). Without this 'fudge' variable, every line after a
// missed line would be an error.  NOT what we want at all.
int _fgetl_fudge = 0;
char *_hex_even_lower[_ISHEX_CNT];
char *_hex_even_upper[_ISHEX_CNT];
char *_hex_even_mixed[_ISHEX_CNT];
char *_hex_even_digits[_ISHEX_CNT];
char *_hex_odd_lower[_ISHEX_CNT];
char *_hex_odd_upper[_ISHEX_CNT];
char *_hex_odd_mixed[_ISHEX_CNT];
char *_hex_odd_digits[_ISHEX_CNT];

/*
 * code for statistics
 */
int nFuncs = 0;
int failed;
int any_failure = 0;
clock_t start_of_run;
struct {
	char test_name[128];
	unsigned tests;
	unsigned fails;
	clock_t tStart, tStop;
} Results;
void set_unit_test_source(const char *fname) {
	printf("\n**** Performing unit tests for functions from [%s] ****\n", fname);
}
void start_test(const char *fn) {
	Results.tests = Results.fails = 0;
	Results.tStart = Results.tStop = clock();
	strcpy(Results.test_name, fn);
}
inline void inc_test() {
	Results.tests++;
}
void inc_failed_test() {
	if (failed)
		return;  // failed already logged for this test.
	Results.fails++;
	any_failure = failed = 1;
}
void end_test() {
	int n;
	double seconds;

	Results.tStop = clock();
	n = printf("  test %01d %s", ++nFuncs, Results.test_name);
	while (++n < 35) printf(" ");
	if (!Results.tests)
		printf("-  Unit tests not yet written for this function\n");
	else {
		seconds = Results.tStop - Results.tStart;
		seconds /= CLOCKS_PER_SEC;
		printf("-  Performed %8d tests", Results.tests);
		if (Results.fails)
			printf(" WITH %d FAILURES!!!", Results.fails);
		printf(" %.2f seconds used\n", seconds);
	}
}
void dump_stats() {
	double secs = clock() - start_of_run;
	secs /= CLOCKS_PER_SEC;
	printf("Performed testing on %d total functions.\n", nFuncs);
	printf("Total time taken : %.02f\n\n", secs);
}
/*
 * end of code for statistics
 */

/*
 *  Misc utility functions
 */
// gets hex string of some bytes
char *hex(const void *_p, int n) {
	static char Buf[1000*1000];
	char *op = Buf;
	const unsigned char *p = (const unsigned char *)_p;
	int i;

	for (i = 0; i < n; ++i) {
		if (i) op += sprintf(op, " ");
		op += sprintf(op, "%02X", p[i]);
	}
	return Buf;
}

char *packedhex(const void *_p, int n) {
	static char Buf[4096];
	char *op = Buf;
	const unsigned char *p = (const unsigned char *)_p;
	int i;

	for (i = 0; i < n; ++i)
		op += sprintf(op, "%02X", p[i]);
	return Buf;
}
int Random(int m) {
	unsigned r = rand();
	r = (((uint64_t)r) * m) / ((uint64_t)RAND_MAX+1);
	return r;
}
// base-36 atoi for a single digit
#if !_MSC_VER
char *strupr(char *_p) {
	unsigned char *p = (unsigned char*)_p;

	while (*p) {
		if (*p >= 'a' && *p <= 'z')
			*p ^= 0x20;
		++p;
	}
	return _p;
}
char *strlwr(char *_p) {
	unsigned char *p = (unsigned char*)_p;

	while (*p) {
		if (*p >= 'A' && *p <= 'Z')
			*p ^= 0x20;
		++p;
	}
	return _p;
}
#endif
int digit_val(char c)
{
	if (c >= '0' && c <= '9')
		return (int)c - '0';
	else if (c >= 'a' && c <= 'z')
		return (int)c - 'a' + 10;
	// force failure in the calling function, because 666 is > 36 which is the max base.
	return 666;
}
// Here is our atoi-with base conversion, and error checking functions
// (one function for unsigned, one for signed)
uint64_t toDeci_ull(char *s, int base)
{
	// unsigned int atoi with base handling from 2 to 26
	int i, len = strlen(s);
	uint64_t power = 1, num = 0;

	failed = 0;
	for (i = len - 1; i >= 0; i--) {
		int d = digit_val(s[i]);
		// an invalid character will be > base. Also, a 'valid' digit,
		// but one that is too large for the base is a failure!
		if (d >= base) {
			inc_failed_test();
			printf("%s failed:  %s base %d\n", Results.test_name, s, base);
			return -1;
		}
		num += d * power;
		power *= base;
	}
	return num;
}
int64_t toDeci_ll(char *s, int base)
{
	// signed atoi with base handling from 2 to 26
	int sign = 1;
	int i, len = strlen(s);
	uint64_t power = 1, num = 0;

	failed = 0;
	if (*s == '-') {
		// set sign to -1, and skip the '-' character
		++s;
		sign = -1;
		--len;
	}
	for (i = len - 1; i >= 0; i--) {
		int d = digit_val(s[i]);
		// an invalid character will be > base. Also, a 'valid' digit,
		// but one that is too large for the base is a failure!
		if (d >= base) {
			inc_failed_test();
			printf("%s failed:  %s base %d\n", Results.test_name, s, base);
			return -1;
		}
		num += d * power;
		power *= base;
	}
	return num*sign;
}
/*
*  End of Misc utility functions
*/

char *_tst_1_strnzcatn(char *head, char *tail, int cnt) {
	static char dest[13 + 6];  // the 13 is the size of the buffer. The '+6 is to later validate we have not blown buffer.
	char dest_orig[17];
	static char ex_crap[4096];
	char *cpex = ex_crap;
	char *ret;
	int n;
	int over = 0;

	*ex_crap = 0;
	memset(dest, 'X', sizeof(dest));
	memcpy(dest, head, 12);
	dest[12] = 0;
	memcpy(dest_orig, dest, 17);
	ret = strnzcatn(dest, 13, tail, cnt);
	for (n = 13; n < sizeof(dest); ++n) {
		if (dest[n] != 'X') {
			if (!over)
				cpex += sprintf(cpex, "BUFFER OVERFLOW in strnzcatn(%s, %d, %s, %d) ", dest, 13, tail, cnt);
			cpex += sprintf(cpex, " [%d]=(0x%02X)", n, dest[n]);
			inc_failed_test();
		}
	}
	if (!ret) {
		sprintf(ex_crap, "strnzcatn(%s, %d, %s, %d) returned NULL pointer\n", dest, 13, tail, cnt);
		inc_failed_test();
		return ex_crap;
	}
	if (*ex_crap)
		strcat(ex_crap, "\n");
	if (strcmp(ret, "1234567890AB") || *ex_crap) {
		// validate if this is OK or not.  NOTE, things 'can' be OK.
		// however, we still return at least the ex_crap string, so that
		// if there were any buffer overwrites, we are informed of them.
		static char tmp[5000];

		if (!strcmp(ret, "1234567890AB"))
			// got right results, but it looks like there was overflow or something.
			return ex_crap;

		if (strlen(ret) > 12 || strncmp(ret, "1234567890AB", strlen(ret))) {
			if (!ex_crap[0])
				strcpy(ex_crap, "\n");
			sprintf(tmp, "%s  (something is wrong, not expected string value).  prep=[%s] tail=[%s] cnt=%d %s", ret, head, tail, cnt, ex_crap);
			return tmp;
		}

		// put prep and tail together (say they are shorter than 12 bytes)
		// if they match what was returned, then all is OK.
		sprintf(tmp, "%s%s", head, tail);
		if (!strcmp(tmp, ret) && strlen(ret) < 12)
			return ex_crap;

		// OK, put prep and tail together, BUT chop tail down based upon the cnt passed in
		// if things are the same, all is OK.
		sprintf(tmp, "%s%*.*s", head, cnt, cnt, tail);
		if (!strcmp(tmp, ret) && strlen(ret) < 12)
			return ex_crap;

		// If we get here, there is something wrong, the strnzcatn did NOT properly work.
		// return information to the calling program.
		if (!ex_crap[0])
			strcpy(ex_crap, "\n");
		if (cnt > 2000)
			cnt = 2000;
		sprintf(tmp, "%s  (something is wrong).  prep=[%s] tail=[%s] cnt=%d %s", ret, head, tail, cnt, ex_crap);
		return tmp;
	}
	// show nothing. This was successful!  Use the Unix philosophy of be quiet on success.
	return ex_crap;
}

// perform a COMPREHESIVE test.  this will test every way (and a few extra for 'longer than strings) of
// of producing "", "1", "12", "123" ... "1234567890AB" concatenating 2 strings.  The test() function
// will make sure that the destination data can hold 13 bytes, and that there are never more than
// 12 'valid' bytes in it, even if we pass in more than 12 bytes here.  NOTE, the way the strnzcatn() is
// written, you could pass in a string of more than 12+1 bytes (say 64), but list it as being 12 bytes of
// significant data. The function 'will' work, and will simply put a null byte into offset [12], and never
// append anything.  The 'test' function does not do this.  We do this as a last step here in main.
int _tst_strnzcatn() {
	// note tail array is allocated to proper size, so that ASAN will catch any
	// read PAST end of valid buffer
	char head[48], *tail[14], *data = "1234567890ABCDEFGHIJKLMNOPQRS";
	int i, j, k;

	memset(head, 0, sizeof(head));

	for (j = 0; j < 14; ++j)
		tail[j] = (char*)mem_alloc(j + 1); // allocate for proper sized ASCIIZ string.
	for (i = 0; i < 14; ++i) {
		sprintf(head, "%*.*s", i, i, data);
		for (j = 0; j < 14; ++j) {
			sprintf(tail[j], "%*.*s", j, j, data + i);
			for (k = 0; k < 14; ++k) {
				// perform the actual test across ALL lengths (0 to 14)
				printf("%s", _tst_1_strnzcatn(head, tail[j], k));
				inc_test();
			}
		}
	}
	// OK, perform test where we have a buffer LONGER than dst_max+1, and see that
	// it properly returns a NULL terminated string of dst_max bytes long, but it
	// can concatenate nothing in this case.
	inc_test();
	sprintf(head, "%s", data);	// head is now 48 byte buffer, with 30 bytes of 'data'
	strnzcatn(head, 12, "CDEFGHIJ", 20);
	// head should now be just 12 bytes long, simply truncated, and nothing from the 'tail' src added to it.
	if (strcmp(head, "1234567890AB"))
		printf("Final test did not truncate the 'overlong' buffer properly\n");

	for (j = 0; j < 14; ++j)
		free(tail[j]);


	return 0;
}

/*
  test_cpy_func handles 3 'types' of functions.
    The first 3 params are function pointers. Only 1 should be set and the
    other 2 should be NULL.  NOTE, the first non-null pointer is used.
    cfn tests    copy functions returning char*
    nfn tests    copy functions returning length (int)
    pfn tests    copy functions that 'pad'

    case_type    0 for no case change, 1 for tolower,    2 for toupper
    append_null  0 always append       1 append if fits  2 never null terminate
    pad          the byte to pad with (only used for pfn function calls
*/
#define CPI "012345ABCd99900AbC0"
void _test_cpy_func(char *(cfn)(char *, const char *, int),
                    int   (nfn)(char *, const char *, int),
                    void *(pfn)(void *, const void *, size_t, uint8_t),
                    int case_type, int append_null, uint8_t pad) {
	int i;
	char pad_chk[50];
	int input_len = strlen(CPI);

	// build 'padded' buffer, it is "012345ABCd99900AbC0xxxx...x\0" (pad of 'x')
	if (pfn) {
		memset(pad_chk, 'x', sizeof(pad_chk));
		pad_chk[sizeof(pad_chk) - 1] = 0;
		memcpy(pad_chk, CPI, input_len); // NOT the null byte!
	}
	for (i = -3; i < 24; ++i) {
		inc_test();
		if (i < 1) {
			if (cfn)
				cfn("", "test", i);
			else if (pfn)
				pfn("", "test", i, pad);
			else
				if (nfn("", "test", i) != 0)
					inc_failed_test();
		}
		else {
			// Allocate EXACTLY the right size, so that ASAN will
			// catch any over/under reads or writes.
			char *buf = mem_alloc(i);
			int check_len = i - 1;
			int null_check = i - 1 > input_len ? input_len : i - 1;

			failed = 0;
			if (append_null == 2) {
				++check_len;
				null_check = 0;
			} else if (append_null == 1) {
				if (i <= input_len) {
					null_check = 0;
					++check_len;
				}
			}
			if (cfn) {
				char *cp = cfn(buf, CPI, i);
				if (cp != buf)
					inc_failed_test();
			} else if (pfn) {
				char *cp = (char*) pfn(buf, CPI, i, pad);
				if (cp != buf)
					inc_failed_test();
			} else {
				int n = nfn(buf, CPI, i);
				if (n != strlen(buf))
					inc_failed_test();
			}
			if (!case_type) {
				if (strncmp(buf, CPI, check_len)) {
					if (pfn && !strncmp(buf, pad_chk, check_len))
						; // OK
					else
						inc_failed_test();
				}
			} else {
				if (strncasecmp(buf, CPI, check_len))
					inc_failed_test();
				if (case_type == 1 && i > 7 && !strncmp(buf, CPI, check_len))
					inc_failed_test();
				if (case_type == 2 && i > 10 && !strncmp(buf, CPI, check_len))
					inc_failed_test();
			}
			if (null_check &&  buf[null_check])
				inc_failed_test();
			if (failed)
				printf("Failed! Function: %s(buf,\"%s\", %d); data: %s\n",
					Results.test_name, CPI, i, hex(buf, i));
			free(buf);
		}
	}
}

/*
 * The trim() functions change the input buffer, so we must have one test for
 * each funcion call
 */
int _tst_trim() {
	// note tail array is allocated to proper size, so that ASAN will catch any
	// read PAST end of valid buffer
	char *data = "1234567890ABCDEFGHIJKLMNOPQRS";
	char *p, *string, buffer[56], expected[56];
	int i, j, len;

	string = (char *) mem_alloc(strlen(data) + 1); // allocate for proper sized ASCIIZ string.

	// Test lTrim()
	for (len = 0; len < strlen(data); ++len) {
		for (j = 0; j < 14; ++j) {
			for (i = 0; i < 14; ++i) {
				// The string I'm going to test
				strncpy(string, data, len);
				string[len] = '\0';

				// Add spaces to the string
				sprintf(buffer, "%*s%s%*s", i, "", string, j, "");

				// Run the test
				inc_test();
				p = ltrim(buffer);

				// What data is expected after trim (skip zero length)
				strncpy(expected, string, sizeof(expected));
				expected[len + j] = '\0';

				if (len)
					memset(expected + len, ' ', j);

				// Test
				if (strcmp(p, expected)) {
					inc_failed_test();
					printf("\tltrim() failed for [%d,%d,%d] |%s||%s|\n",
						len, j, i, expected, p);
				}
			}
		}
	}

	// Test rTrim()
	for (len = 0; len < strlen(data); ++len) {
		for (j = 0; j < 14; ++j) {
			for (i = 0; i < 14; ++i) {
				// The string I'm going to test
				strncpy(string, data, len);
				string[len] = '\0';

				// Add spaces to the string
				sprintf(buffer, "%*s%s%*s", i, "", string, j, "");

				// Run the test
				inc_test();
				p = rtrim(buffer);

				// What data is expected after trim (skip zero length)
				strncpy(expected + i, string, sizeof(expected) - i);
				expected[len + i] = '\0';

				if (len)
					memset(expected, ' ', i);

				// Test
				if (strcmp(p, expected)) {
					inc_failed_test();
					printf("\trtrim() failed for [%d,%d,%d] |%s||%s|\n",
						len, j, i, expected, p);
				}
			}
		}
	}

	// Test both lTrim() and rTrim(), in that order
	for (len = 0; len < strlen(data); ++len) {
		for (j = 0; j < 14; ++j) {
			for (i = 0; i < 14; ++i) {
				// The string I'm going to test
				strncpy(string, data, len);
				string[len] = '\0';

				// Add spaces to the string
				sprintf(buffer, "%*s%s%*s", i, "", string, j, "");

				// Run the test
				inc_test();
				p = ltrim(rtrim(buffer));

				// What data is expected after trim
				strncpy(expected, string, sizeof(expected));

				// Test
				if (strcmp(p, expected)) {
					inc_failed_test();
					printf("\tltrim(rtrim()) failed for [%d,%d,%d] |%s||%s|\n",
						len, j, i, expected, p);
				}
			}
		}
	}

	// Test both rTrim() and lTrim(), in that order
	for (len = 0; len < strlen(data); ++len) {
		for (j = 0; j < 14; ++j) {
			for (i = 0; i < 14; ++i) {
				// The string I'm going to test
				strncpy(string, data, len);
				string[len] = '\0';

				// Add spaces to the string
				sprintf(buffer, "%*s%s%*s", i, "", string, j, "");

				// Run the test
				inc_test();
				p = rtrim(ltrim(buffer));

				// What data is expected after trim
				strncpy(expected, string, sizeof(expected));

				// Test
				if (strcmp(p, expected)) {
					inc_failed_test();
					printf("\trtrim(ltrim()) failed for [%d,%d,%d] |%s||%s|\n",
						len, j, i, expected, p);
				}
			}
		}
	}
	free(string);
	return 0;
}

/*
 * this function writes 'special' files. The files have each line be fully
 * self describing. lines ALL start with  "line %04d  ", where the number is
 * the line number. Then there will be some line which have the string [NULL]\0
 * added after that signature. These test a known NULL bug (where the following
 * line was skipped.  Lines that do not have the 'NULL\n' will instead have a
 * space.  Then there is a ':' followed by a rotating set of characters. The
 * length of each line is random, from 24 to 18999 bytes long. This will make
 * sure that there are tests where we get a 'full' line (i.e. the size of our
 * buffer is smaller than the length of data, BUT it also assures that we
 * get data which is LONGER than our buffer.  This will test both fgetl and
 * fgetll, which handle things differently. in fgetl, we truncate the line
 * returned, to fit the buffer, throw away the remainder, and the next read
 * MUST be at the start of the next line.  For fgetll, we instead allocate
 * a different buffer, larger than the input buffer, read the whole line.
 * the only case fgetll will return a truncated line, is if there is a NULL
 * byte in the line.  We test 6000 lines, this allows the testing function
 * to test 3 different buffer length (normal, small, huge), which will also
 * help make sure there are enough buffer large enough, and buffer too small
 * lines to test things well.  Each file will be 6000 lines long.
 *
 *  NOTE, one thing not tested, is files > 2gb and files > 4gb. This testing
 *  was left out on purpose.  These unit tests are written to be run on the
 *  CI's, and not knowing the limits on the CI's, I did not want to have
 *  13+GB of test file data written. The tests will test everything other
 *  than 64 bit file seeking, and 64 bit file telling.  However, seek/tell
 *  is not part of fgetl or fgetll.
 */
void _nontest_gen_fgetl_files(int generate) {
	int i, x, rlen;
	FILE *fp, *fp1, *fp2;

	if (!generate) {
		// if !generate, then delete
		unlink("/tmp/jnk.txt");
		unlink("/tmp/jnkd.txt");
		unlink("/tmp/jnkfu.txt");
		return;
	}
	/* first, setup the fgetl 'pad' data (moved from main() function. */
	_fgetl_pad = (char*)mem_alloc(_FGETL_PAD_SIZE + 1);
	for (i = 0; i <= _FGETL_PAD_SIZE; ++i)
		_fgetl_pad[i] = (i % 95) + ' ';
	_fgetl_pad[_FGETL_PAD_SIZE] = 0;

	start_test(__FUNCTION__); inc_test(); inc_test(); inc_test();
	fp = fopen("/tmp/jnk.txt", "wb");
	fp1 = fopen("/tmp/jnkd.txt", "wb");
	fp2 = fopen("/tmp/jnkfu.txt", "wb");
	for (i = 0; i < 5999; ++i) {
		char *is_null = "";
		char null_or_space = ' ';
		char *cr = "";

		if (i % 13 == 12) {
			// this line will contain a NULL byte
			is_null = "[NULL]";
			null_or_space = 0;
		}
		if (i % 32 > 15 && i % 32 < 20)
			// add a bogus \r on these lines, to file 3
			cr = "\r";
		rlen = Random(_FGETL_PAD_SIZE-24)+24;
		// place a couple blocks in the file with specific lengths
		if (i > 50 && i < 150)
			// block of very short lines.
			rlen = 24;
		else if (i > 250 && i < 450)
			// block of alternate short / very long lines
			rlen = (i & 1) ? 24 : _FGETL_PAD_SIZE;
		else if (i > 650 && i < 750)
			// block of very long lines.
			rlen = _FGETL_PAD_SIZE;
		x =
		fprintf(fp,  "line %04d  %s%c:", i, is_null, null_or_space);
		fprintf(fp1, "line %04d  %s%c:", i, is_null, null_or_space);
		fprintf(fp2, "line %04d  %s%c:", i, is_null, null_or_space);
		fprintf(fp,  "%*.*s\n", rlen - x, rlen - x, &_fgetl_pad[x]);
		fprintf(fp1, "%*.*s\r\n", rlen - x, rlen - x, &_fgetl_pad[x]);
		fprintf(fp2, "%*.*s%s\n", rlen - x, rlen - x, &_fgetl_pad[x], cr);
	}
	// make sure LAST line contains no \r or \r\n.
	rlen = 888;
	x = fprintf(fp, "line 5999  [NULL]%c:", 0);
	fprintf(fp1, "line 5999  [NULL]%c:", 0);
	fprintf(fp2, "line 5999  [NULL]%c:", 0);
	fprintf(fp,  "%*.*s", rlen - x, rlen - x, &_fgetl_pad[x]);
	fprintf(fp1, "%*.*s", rlen - x, rlen - x, &_fgetl_pad[x]);
	fprintf(fp2, "%*.*s", rlen - x, rlen - x, &_fgetl_pad[x]);

	fclose(fp2);
	fclose(fp1);
	fclose(fp);
	end_test();
}
void _validate_line(const char *line, int n, int len) {
	int i, j;
	char line_head[48];
	int len_seen = strlen(line);

	if (strstr(line, "[NULL]")) {
		sprintf(line_head, "line %04d  [NULL]", n + _fgetl_fudge);
		if (strcmp(line_head, line)) {
			inc_failed_test();
			// we have to 'fix' the _fgetl_fudge variable, so this
			// line and not EVERY line to end of file gets counted
			// as an error. Each line 'documents' it's own line
			// number. SO we simply read that number, and then
			// make an 'adjustment' so the next line read should
			// be read without an error.  n is what we 'thought'
			// the line was, we compute j from the line (which
			// is what the line REALLY is), then figure how far
			// off we are.
			sscanf(line, "line %04d  ", &j);
			_fgetl_fudge = j - n;
		}
		return;
	}
	if (len_seen > len)
		inc_failed_test();
	i = sprintf(line_head, "line %04d   :", n + _fgetl_fudge);

	if (strncmp(line_head, line, i)) {
		inc_failed_test();
		// adjust _fgetl_fudge var (as documented above)
		sscanf(line, "line %04d  ", &j);
		_fgetl_fudge = j - n;
	}
	if (memcmp(&_fgetl_pad[i], &line[i], len_seen-i))
		inc_failed_test();
}
void _tst_fget_l_ll(const char *fname, int tst_l)
{
	int i;
	char Buf[256], Bufs[18], Bufh[16384], *cp;
	FILE *in = fopen(fname, "r");

	/* tests fgetl AND fgetll.  Which function is called set by tst_l */
	_fgetl_fudge = 0;
	for (i = 0; i < 2000; ++i) {
		/* read this line using 'normal' sized buffer */
		inc_test(); failed = 0;
		if (tst_l) {
			cp = fgetl(Buf, sizeof(Buf), in);
			_validate_line(Buf, i * 3, sizeof(Buf) - 1);
			if (cp != Buf)
				inc_failed_test();
		} else {
			cp = fgetll(Buf, sizeof(Buf), in);
			_validate_line(cp, i * 3, strlen(cp));
			if (cp && cp != Buf)
				MEM_FREE(cp);
		}

		/* read this line using 'tiny' sized buffer */
		inc_test(); failed = 0;
		if (tst_l) {
			cp = fgetl(Bufs, sizeof(Bufs), in);
			_validate_line(Bufs, i * 3 + 1, sizeof(Bufs) - 1);
			if (cp != Bufs)
				inc_failed_test();
		} else {
			cp = fgetll(Bufs, sizeof(Bufs), in);
			_validate_line(cp, i * 3 + 1, strlen(cp));
			if (cp && cp != Bufs)
				MEM_FREE(cp);
		}

		/* read this line using 'huge' sized buffer */
		/* but buffer not ALWAYS large enough       */
		inc_test(); failed = 0;
		if (tst_l) {
			cp = fgetl(Bufh, sizeof(Bufh), in);
			_validate_line(Bufh, i * 3 + 2, sizeof(Bufh) - 1);
			if (cp != Bufh)
				inc_failed_test();
		}
		else {
			cp = fgetll(Bufh, sizeof(Bufh), in);
			_validate_line(cp, i * 3 + 2, strlen(cp));
			if (cp && cp != Bufh)
				MEM_FREE(cp);
		}
	}

	inc_test(); failed = 0;
	if (tst_l)
		cp = fgetl(Bufh, sizeof(Bufh), in);
	else
		cp = fgetll(Bufh, sizeof(Bufh), in);
	if (cp)
		inc_failed_test();
}
// char *fgetl(char *s, int size, FILE *stream)
void test_fgetl() {
	start_test(__FUNCTION__);

	_fgetl_fudge = 0;
	_tst_fget_l_ll("/tmp/jnk.txt", 1);
	_tst_fget_l_ll("/tmp/jnkd.txt", 1);
	_tst_fget_l_ll("/tmp/jnkfu.txt", 1);
	end_test();
}
// char *fgetll(char *s, size_t size, FILE *stream)
void test_fgetll() {
	start_test(__FUNCTION__);
	_tst_fget_l_ll("/tmp/jnk.txt", 0);
	_tst_fget_l_ll("/tmp/jnkd.txt", 0);
	_tst_fget_l_ll("/tmp/jnkfu.txt", 0);
	end_test();
}
// void *strncpy_pad(void *dst, const void *src, size_t size, uint8_t pad)
void test_strncpy_pad() {
	start_test(__FUNCTION__);
	_test_cpy_func(NULL, NULL, strncpy_pad, 0, 2, 'x');
	end_test();
}
// char *strnfcpy(char *dst, const char *src, int size)
void test_strnfcpy() {
	start_test(__FUNCTION__);
	_test_cpy_func(strnfcpy, NULL, NULL, 0, 1, 0);
	end_test();
}
// char *strnzcpy(char *dst, const char *src, int size)
void test_strnzcpy() {
	start_test(__FUNCTION__);
	_test_cpy_func(strnzcpy, NULL, NULL, 0, 0, 0);
	end_test();
}
// char *strnzcpylwr(char *dst, const char *src, int size)
void test_strnzcpylwr() {
	start_test(__FUNCTION__);
	_test_cpy_func(strnzcpylwr, NULL, NULL, 1, 0, 0);
	end_test();
}
// int strnzcpyn(char *dst, const char *src, int size)
void test_strnzcpyn() {
	start_test(__FUNCTION__);
	_test_cpy_func(NULL, strnzcpyn, NULL, 0, 0, 0);
	end_test();
}
// int strnzcpylwrn(char *dst, const char *src, int size)
void test_strnzcpylwrn() {
	start_test(__FUNCTION__);
	_test_cpy_func(NULL, strnzcpylwrn, NULL, 1, 0, 0);
	end_test();
}
// fills a string with random text, specific length
void _fill_str(char *p, int len) {
	int i;

	for (i = 0; i < len; ++i) {
		p[i] = Random(254) + 1;
	}
	p[len] = 0;
}
// char *strnzcat(char *dst, const char *src, int size)
void test_strnzcat() {
	// we do strcpy(buf[i], buf1) then strnzcat(buf[i], buf2, i+1)
	// buf[i] is allocated to be EXACTLY (and only) i+1 bytes long
	// so that any ASAN overflow (r/w) will be caught.
	char *buf[512*2], *buf1[512], *buf2[512];
	int i, j;

	start_test(__FUNCTION__);
	for (i = 0; i < 512 * 2; ++i)
		buf[i] = mem_alloc(i + 1);
	for (i = 0; i < 512; ++i) {
		buf1[i] = mem_alloc(i + 1);
		buf2[i] = mem_alloc(i + 1);
		_fill_str(buf1[i], i); // fill random string data here.
		_fill_str(buf2[i], i); // the fill is exactly i bytes long.
	}
	// now perform the actual tests
	for (i = 0; i < 512; ++i) {
		for (j = 0; j < 512; ++j) {
			inc_test(); failed = 0;
			strcpy(buf[i + j], buf1[i]);
			strnzcat(buf[i + j], buf2[j], i+j+1);
			if (strlen(buf[i+j]) != i+j)
				inc_failed_test();
			if (strncmp(buf[i + j], buf1[i], i))
				inc_failed_test();
			if (strncmp(&((buf[i + j])[i]), buf2[j], j))
				inc_failed_test();
			// perform a SHORT strnzcat
			if (j && j < 511) {
				inc_test(); failed = 0;
				strcpy(buf[i + j], buf1[i]);
				// the [j+1] buffer will be 1 byte too long
				// and SHOULD handle this with no overflow
				// and the first j bytes written should match.
				// we DO provide proper size of buffer i+j+1
				strnzcat(buf[i + j], buf2[j+1], i + j + 1);
				if (strlen(buf[i + j]) != i + j)
					inc_failed_test();
				if (strncmp(buf[i + j], buf1[i], i))
					inc_failed_test();
				if (strncmp(&((buf[i + j])[i]), buf2[j+1], j))
					inc_failed_test();
			}
		}
	}

	// clean stuff up.
	for (i = 0; i < 512; ++i) {
		free(buf1[i]);
		free(buf2[i]);
	}
	for (i = 0; i < 512*2; ++i)
		free(buf[i]);
	end_test();
}
// char *strnzcatn(char *dst, int size, const char *src, int src_max)
void test_strnzcatn() {
	start_test(__FUNCTION__);
	_tst_strnzcatn();
	end_test();
}
void _test_strtokm(char *delims, int cnt, ...) {
	int n, i;
	char *buf, *items[24], big[4096], *cp = big;
	va_list args;
	int dlen = strlen(delims);

	*cp = 0;
	va_start(args, cnt);
	for (i = 0; i < cnt - 1; ++i) {
		items[i] = va_arg(args, char*);
		cp += sprintf(cp, "%s", items[i]);
		*cp++ = delims[Random(dlen)];
	}
	if (cnt) {
		items[i] = va_arg(args, char*);
		cp += sprintf(cp, "%s", items[i]);
	}
	*cp = 0;
	va_end(args);

	buf = strdup(big);

	cp = strtokm(buf, delims);
	inc_test(); failed = 0;
	for (n = 0; n < cnt; ++n) {
		if (strcmp(items[n], cp))
			inc_failed_test();
		cp = strtokm(NULL, delims);
		inc_test(); failed = 0;
	}
	if (cp)
		inc_failed_test();
	free(buf);

}
// char *strtokm(char *s1, const char *delims)
void test_strtokm() {
	start_test(__FUNCTION__);
	// Not quite sure how to comprehensively test this beast.  I guess I
	// will build strings, and also build the 'expected' data for each one
	// then see that they properly match, and that there are no ASAN's

	_test_strtokm(" ", 10, "", "", "test", "8", "halloc", "", "boom", "8", "9", "10");
	_test_strtokm(" 67kB", 10, "", "", "test", "8", "halloc", "", "boom", "8", "9", "10");
	_test_strtokm(" \t\r\n", 5, "1", "2", "3", "4", "5");
	_test_strtokm(" \t\r\n", 9, "1", "2", "", "", "", "", "3", "4", "5");
	_test_strtokm("  *", 9, "11", "22", "3", "", "6", "", "33", "44", "55");
	end_test();
}
// unsigned int atou(const char *src)
void test_atou() {
	unsigned u;

	start_test(__FUNCTION__);
	for (u = (unsigned)-100005; u < 100005 || u >= (unsigned)-100005; ++u) {
		char buf[24];

		sprintf(buf, "%u", u);
		inc_test();
		if (atou(buf) != u) {
			failed = 0;
			inc_failed_test();
			printf("test_atou failed for %u\n", u);
		}
	}
	end_test();
}
// const char *jtr_ulltoa(uint64_t val, char *result, int rlen, int base)
void test_jtr_ulltoa() {
	uint64_t u;
	int base, x,y;
	char buf[128], jnk[4];
	const char *cp;

	start_test(__FUNCTION__);
	memset(buf, 1, sizeof(buf)); // for overflow checking
	for (u = (uint64_t)-100005; u < 100005 || u >= (uint64_t)-100005; ++u) {
		failed = 0;
		for (base = -2; base < 2; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_ulltoa(u, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_ulltoa fail %"PRIu64"/%d\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
		}
		for (base = 2; base <= 36; ++base) {
			inc_test();
			cp = jtr_ulltoa(u, buf, sizeof(buf), base);
			if (cp != buf || toDeci_ull(buf, base) != u) {
				failed = 0;
				inc_failed_test();
				printf("jtr_ulltoa fail %"PRIu64"/%d\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
			x = strlen(buf);
			for (y = 1; y < 8; ++y) {
				if (buf[x + y] != 1) {
					failed = 0;
					inc_failed_test();
					printf("jtr_ulltoa failed BUFFER OVERFLOW %"PRIu64"/%d - %s\n", u, base, hex(buf, x+8));
					memset(buf, 1, sizeof(buf));
				}
			}
			memset(buf, 1, x + 1);
		}
		for (base = 37; base < 40; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_ulltoa(u, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_ulltoa failed %"PRIu64"/%d)\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
		}
	}
	end_test();
}
// const char *jtr_itoa(int val, char *result, int rlen, int base)
void test_jtr_itoa() {
	int d;
	int base, x, y;
	char buf[128], jnk[4];
	const char *cp;

	start_test(__FUNCTION__);
	memset(buf, 1, sizeof(buf)); // for overflow checking
	for (d = -100005; d < 100005; ++d) {
		failed = 0;
		for (base = -2; base < 2; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_itoa(d, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_itoa failed %d/%d)\n", d, base);
				memset(buf, 1, sizeof(buf));
			}
		}
		for (base = 2; base <= 36; ++base) {
			inc_test();
			cp = jtr_itoa(d, buf, sizeof(buf), base);
			if (cp != buf || toDeci_ll(buf, base) != d) {
				failed = 0;
				inc_failed_test();
				printf("jtr_itoa failed %d/%d\n", d, base);
				memset(buf, 1, sizeof(buf));
			}
			x = strlen(buf);
			for (y = 1; y < 8; ++y) {
				if (buf[x + y] != 1) {
					failed = 0;
					inc_failed_test();
					printf("jtr_itoa failed BUFFER OVERFLOW %d/%d - %s\n", d, base, hex(buf, x + 8));
					memset(buf, 1, sizeof(buf));
				}
			}
			memset(buf, 1, x + 1);
		}
		for (base = 37; base < 40; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_itoa(d, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_itoa failed %d/%d)\n", d, base);
				memset(buf, 1, sizeof(buf));
			}
		}
	}
	end_test();
}
// const char *jtr_utoa(unsigned int val, char *result, int rlen, int base)
void test_jtr_utoa() {
	unsigned int u;
	int base, x, y;
	char buf[128], jnk[4];
	const char *cp;

	start_test(__FUNCTION__);
	memset(buf, 1, sizeof(buf)); // for overflow checking
	for (u = (unsigned int) -100005; u < 100005 || u >= (unsigned int) - 100005; ++u) {
		failed = 0;
		for (base = -2; base < 2; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_utoa(u, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_utoa failed %u/%d)\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
		}
		for (base = 2; base <= 36; ++base) {
			inc_test();
			cp = jtr_utoa(u, buf, sizeof(buf), base);
			if (cp != buf || toDeci_ull(buf, base) != u) {
				failed = 0;
				inc_failed_test();
				printf("jtr_utoa failed %u/%d)\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
			x = strlen(buf);
			for (y = 1; y < 8; ++y) {
				if (buf[x + y] != 1) {
					failed = 0;
					inc_failed_test();
					printf("test__utoa failed BUFFER OVERFLOW %u/%d  %s\n", u, base, hex(buf, x + 8));
					memset(buf, 1, sizeof(buf));
				}
			}
			memset(buf, 1, x + 1);
		}
		for (base = 37; base < 40; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_utoa(u, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_utoa failed %u/%d)\n", u, base);
				memset(buf, 1, sizeof(buf));
			}
		}
	}
	end_test();
}
// const char *jtr_lltoa(int64_t val, char *result, int rlen, int base)
void test_jtr_lltoa() {
	int64_t ll;
	int base, x, y;
	char buf[128], jnk[4];
	const char *cp;

	start_test(__FUNCTION__);
	memset(buf, 1, sizeof(buf)); // for overflow checking
	for (ll = -100005; ll < 100005; ++ll) {
		failed = 0;
		for (base = -2; base < 2; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_lltoa(ll, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_lltoa failed %"PRId64"/%d\n", ll, base);
				memset(buf, 1, sizeof(buf));
			}
		}
		for (base = 2; base <= 36; ++base) {
			inc_test();
			cp = jtr_lltoa(ll, buf, sizeof(buf), base);
			if (cp != buf || toDeci_ll(buf, base) != ll) {
				failed = 0;
				inc_failed_test();
				printf("jtr_lltoa failed %"PRId64"/%d\n", ll, base);
				memset(buf, 1, sizeof(buf));
			}
			x = strlen(buf);
			for (y = 1; y < 8; ++y) {
				if (buf[x + y] != 1) {
					failed = 0;
					inc_failed_test();
					printf("jtr_lltoa failed BUFFER OVERFLOW %"PRId64"%d - %s\n", ll, base, hex(buf, x + 8));
					memset(buf, 1, sizeof(buf));
				}
			}
			memset(buf, 1, x + 1);
		}
		for (base = 37; base < 40; ++base) {
			inc_test();
			strcpy(jnk, "jnk");
			cp = jtr_lltoa(ll, jnk, sizeof(jnk), base);
			if (cp != jnk || memcmp(jnk, "\0nk", 4)) {
				failed = 0;
				inc_failed_test();
				printf("jtr_lltoa failed %"PRId64"/%d\n", ll, base);
				memset(buf, 1, sizeof(buf));
			}
		}
	}
	end_test();
}
// char *human_prefix(uint64_t num)
void test_human_prefix() {
	start_test(__FUNCTION__);
	end_test();
}

// char *[l/r]trim(char *str)
void test_trim() {
	start_test(__FUNCTION__);
	_tst_trim();
	end_test();
}

//stuff in common.c

// generate a 100% assured mixed case hex string of a specific length
void _fill_hEx(char *p, int len, int digitsonly) {
	int i;
	const char *hEx = "0123456789ABCDEFabcdef";
	const char *Hex = "ABCDEF";
	const char *hex = "abcdef";

	if (digitsonly) {
		const char *hex0 = "0123456789";
		for (i = 0; i < len; ++i)
			p[i] = hex0[Random(10)];
		p[len] = 0;
		return;
	}
	if (len < 4) {
		p[0] = Hex[Random(6)];
		p[1] = hex[Random(6)];
		if (len == 2)
			p[2] = 0;
		else {
			p[2] = hEx[Random(22)];
			p[3] = 0;
		}
		return;
	}
	p[0] = hEx[Random(22)];
	p[1] = Hex[Random(6)];
	p[2] = hex[Random(6)];
	for (i = 3; i < len; ++i) {
		p[i] = hEx[Random(22)];
	}
	p[len] = 0;
}
void _gen_hex_len_data() {
	int i;
	for (i = 1; i < _ISHEX_CNT; ++i) {
		// each line is 2*i or 2*i+1 length.  The "", and 1 byte hex strings
		// are handled by special code, NOT by the normal generic loop code.
		_hex_even_lower[i] = mem_alloc(i * 2 + 1);
		_hex_even_upper[i] = mem_alloc(i * 2 + 1);
		_hex_even_mixed[i] = mem_alloc(i * 2 + 1);
		_hex_even_digits[i] = mem_alloc(i * 2 + 1);
		_hex_odd_lower[i] = mem_alloc(i * 2 + 2);
		_hex_odd_upper[i] = mem_alloc(i * 2 + 2);
		_hex_odd_mixed[i] = mem_alloc(i * 2 + 2);
		_hex_odd_digits[i] = mem_alloc(i * 2 + 2);
		// fill our 2 mIXed case hex strings.
		_fill_hEx(_hex_even_mixed[i], i * 2, 0);
		_fill_hEx(_hex_odd_mixed[i], i * 2 + 1, 0);
		_fill_hEx(_hex_even_digits[i], i * 2, 1);
		_fill_hEx(_hex_odd_digits[i], i * 2 + 1, 1);
		// copy them to the lc and uc strings, then make them proper case.
		strcpy(_hex_even_lower[i], _hex_even_mixed[i]);
		strcpy(_hex_even_upper[i], _hex_even_mixed[i]);
		strcpy(_hex_odd_lower[i], _hex_odd_mixed[i]);
		strcpy(_hex_odd_upper[i], _hex_odd_mixed[i]);
		strlwr(_hex_even_lower[i]);
		strupr(_hex_even_upper[i]);
		strlwr(_hex_odd_lower[i]);
		strupr(_hex_odd_upper[i]);
	}
}
void _free_hex_len_data() {
	int i;
	for (i = 1; i < _ISHEX_CNT; ++i) {
		free(_hex_odd_digits[i]);
		free(_hex_odd_mixed[i]);
		free(_hex_odd_upper[i]);
		free(_hex_odd_lower[i]);
		free(_hex_even_digits[i]);
		free(_hex_even_mixed[i]);
		free(_hex_even_upper[i]);
		free(_hex_even_lower[i]);
	}
}
void _test_one_ishex(int (fn)(const char *), int uc, int lc, int odd) {
	int v, i;
	char _1c[2], *Line;
	// we test one of the ishex*() functions.  We are passed in whether this
	// function can handle lc, or uc, OR a mixed case. Also whether the
	// function calls an odd length hex string as a hex string (some only
	// say an even length string is hex.  We run the function against all
	// 255 strings created in each of 6 flavors, and detect whether a function
	// improperly detects a string as hex when it should not, OR if it says
	// a string is NOT hex, when it should pass.  All text lengths from 0
	// to 512 are tested, in all 3 casing flavors.

	Line = mem_alloc(_ISHEX_CNT * 2 + 1);
	inc_test(); failed = 0; v = fn(NULL); if (v) inc_failed_test();
	// this tests all the 3 even[0] strings, they are all ""
	inc_test(); failed = 0; v = fn(""); if (v) inc_failed_test();

	// this tests all the 3 odd[0] strings, they are all 1 byte long. We simply
	// test all digits, then all lower, then all upper independently.
	_1c[1] = 0;
	for (i = 0; i < 10; ++i) {
		_1c[0] = '0' + i;
		inc_test(); failed = 0;
		v = fn(_1c);  // same checks as _hex_odd_digits
		if (v && !odd)
			inc_failed_test();
		else if (!v && odd)
			inc_failed_test();

		if (i < 6) {
			// handle each lc digit, then each uc digit
			_1c[0] = 'a' + i;
			inc_test(); failed = 0;
			v = fn(_1c);  // same checks as _hex_odd_lower
			if (v && (!lc || !odd || (!lc && uc)))
				inc_failed_test();
			else if (!v && lc && odd)
				inc_failed_test();
			_1c[0] = 'A' + i;

			inc_test(); failed = 0;
			v = fn(_1c); // same checks as _hex_odd_upper
			if (v && (!uc || !odd || (lc && !uc)))
				inc_failed_test();
			else if (!v && uc && odd)
				inc_failed_test();
		}
	}

	for (i = 1; i < _ISHEX_CNT; ++i) {
		inc_test(); failed = 0;
		v = fn(_hex_odd_mixed[i]);
		if (v && (!uc || !lc || !odd))
			inc_failed_test();
		else if (!v && uc && lc && odd)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_odd_upper[i]);
		if (v && (!uc || !odd || (lc && !uc)))
			inc_failed_test();
		else if (!v && uc && odd)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_odd_lower[i]);
		if (v && (!lc || !odd || (!lc && uc)))
			inc_failed_test();
		else if (!v && lc && odd)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_odd_digits[i]);
		if (v && !odd)
			inc_failed_test();
		else if (!v && odd)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_even_mixed[i]);
		if (v && (!lc || !uc))
			inc_failed_test();
		else if (!v && lc && uc)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_even_upper[i]);
		if (v && (!uc || (lc && !uc)))
			inc_failed_test();
		else if (!v && uc)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_even_lower[i]);
		if (v && (!lc || (!lc && uc)))
			inc_failed_test();
		else if (!v && lc)
			inc_failed_test();

		inc_test(); failed = 0;
		v = fn(_hex_even_digits[i]);
		// note, this should ALWAYS succeed!
		if (!v)
			inc_failed_test();
	}
	// test known garbage strings.  For this we use the pure digit string
	// which we 'known' should pass all tests
	strcpy(Line, _hex_even_digits[_ISHEX_CNT-1]);
	for (i = 0; i < (_ISHEX_CNT-1)*2; ++i) {
		int j;
		char keep;

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
		}
		Line[i] = keep;
	}
	free(Line);
}
void test_ishex() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishex, 1, 1, 0);
	end_test();
}
void test_ishex_oddOK() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishex_oddOK, 1, 1, 1);
	end_test();
}
void test_ishexuc() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishexuc, 1, 0, 0);
	end_test();
}
void test_ishexlc() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishexlc, 0, 1, 0);
	end_test();
}
void test_ishexuc_oddOK() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishexuc_oddOK, 1, 0, 1);
	end_test();
}
void test_ishexlc_oddOK() {
	start_test(__FUNCTION__);
	_test_one_ishex(ishexlc_oddOK, 0, 1, 1);
	end_test();
}
void _test_one_ishexn(int (fn)(const char *, int), int uc, int lc) {
	char Line[_ISHEX_CNT*2 + 5 + 1];
	int i, j, v;
	char keep;

	// test known garbage strings.

	// First, we use the pure digit string
	// which we 'known' should pass all tests
	strcpy(Line, _hex_even_digits[_ISHEX_CNT - 1]);
	// since we pass > than length _ISHEX_CNT*2 at times.
	strcat(Line, "55555");

	for (i = 0; i < (_ISHEX_CNT - 1) * 2; ++i) {

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line, i);
			// note, this should ALWAYS succeed
			if (!v)
				inc_failed_test();
			v = fn(Line, i+1);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
			v = fn(Line, i + 35);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
		}
		Line[i] = keep;
	}

	// Next, we use the uc case string
	// all lc only tests should fail every time
	strcpy(Line, _hex_even_upper[_ISHEX_CNT - 1]);
	// since we pass > than length _ISHEX_CNT*2 at times.
	strcat(Line, "55555");

	for (i = 4; i < (_ISHEX_CNT - 1) * 2; ++i) {

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line, i);
			// succeed only for uc version, or all case version
			if ((!v && uc) || (v && lc && !(uc&&lc)))
				inc_failed_test();
			v = fn(Line, i + 1);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
			v = fn(Line, i + 35);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
		}
		Line[i] = keep;
	}

	// Next, we use the lc case string
	// all uc only tests should fail every time
	strcpy(Line, _hex_even_lower[_ISHEX_CNT - 1]);
	// since we pass > than length _ISHEX_CNT*2 at times.
	strcat(Line, "55555");

	for (i = 4; i < (_ISHEX_CNT - 1) * 2; ++i) {

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line, i);
			// succeed only for lc version, or all case version
			if ((!v && lc) || (v && uc && !(uc && lc)))
				inc_failed_test();
			v = fn(Line, i + 1);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
			v = fn(Line, i + 35);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
		}
		Line[i] = keep;
	}

	// finally, we use the mixed case string
	// all lc/uc only tests should fail every time
	strcpy(Line, _hex_even_mixed[_ISHEX_CNT - 1]);
	// since we pass > than length _ISHEX_CNT*2 at times.
	strcat(Line, "55555");

	for (i = 4; i < (_ISHEX_CNT - 1) * 2; ++i) {

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line, i);
			// succeed, only for all-case version
			if ((!v && lc && uc) || (v && !(uc && lc)))
				inc_failed_test();
			v = fn(Line, i + 1);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
			v = fn(Line, i + 35);
			// note, this should ALWAYS fail!
			if (v)
				inc_failed_test();
		}
		Line[i] = keep;
	}
}
void test_ishexn() {
	start_test(__FUNCTION__);
	_test_one_ishexn(ishexn, 1, 1);
	end_test();
}
void test_ishexucn() {
	start_test(__FUNCTION__);
	_test_one_ishexn(ishexucn, 1, 0);
	end_test();
}
void test_ishexlcn() {
	start_test(__FUNCTION__);
	_test_one_ishexn(ishexlcn, 0, 1);
	end_test();
}
void _test_one_hexlen(size_t (fn)(const char *, int *), int uc, int lc) {
	char *Line;
	int j, n;
	size_t i, v;
	char keep;
	int line_len;

	Line = malloc((_ISHEX_CNT - 8) * 2 + 1);
	// test known garbage strings.

	// First, we use the pure digit string
	// which we 'known' should pass all tests
	strcpy(Line, _hex_even_digits[_ISHEX_CNT - 8]);
	line_len = strlen(Line);

	for (i = 0; i < line_len; ++i) {

		keep = Line[i];
		for (j = 1; j < 256; ++j) {
			if (j >= '0' && j <= '9') continue;
			if (j >= 'a' && j <= 'f') continue;
			if (j >= 'A' && j <= 'F') continue;
			Line[i] = j;
			inc_test(); failed = 0;
			v = fn(Line, &n);
			// note, this should ALWAYS succeed
			if ( (i&(~1)) != v)
				inc_failed_test();
			if (n && line_len <= v)
				inc_failed_test();

		}
		Line[i] = keep;
	}
	// here we test the cases.
	// If a test has low case letter in it, and lc is not set, we simply
	// skip that test. Same for the upper cased letters and uc is not set.

	if (uc && lc) {
		// Next, we use the mixed case string
		// We only test if both uc and lc are set
		strcpy(Line, _hex_even_mixed[_ISHEX_CNT - 8]);
		line_len = strlen(Line);

		for (i = 0; i < line_len; ++i) {

			keep = Line[i];
			for (j = 1; j < 256; ++j) {
				if (j >= '0' && j <= '9') continue;
				if (j >= 'a' && j <= 'f') continue;
				if (j >= 'A' && j <= 'F') continue;
				Line[i] = j;
				inc_test(); failed = 0;
				v = fn(Line, &n);
				// note, this should ALWAYS succeed
				if ((i&(~1)) != v)
					inc_failed_test();
				if (n && line_len <= v)
					inc_failed_test();

			}
			Line[i] = keep;
		}
	}
	if (uc) {
		// Next, we use the upper case string
		// We only test if uc is set
		strcpy(Line, _hex_even_upper[_ISHEX_CNT - 8]);
		line_len = strlen(Line);

		for (i = 0; i < line_len; ++i) {

			keep = Line[i];
			for (j = 1; j < 256; ++j) {
				if (j >= '0' && j <= '9') continue;
				if (lc && j >= 'a' && j <= 'f') continue;
				if (j >= 'A' && j <= 'F') continue;
				Line[i] = j;
				inc_test(); failed = 0;
				v = fn(Line, &n);
				// note, this should ALWAYS succeed
				if ((i&(~1)) != v)
					inc_failed_test();
				if (n && line_len <= v)
					inc_failed_test();

			}
			Line[i] = keep;
		}
	}
	if (lc) {
		// Next, we use the lower case string
		// We only test if lc is set
		strcpy(Line, _hex_even_lower[_ISHEX_CNT - 8]);
		line_len = strlen(Line);

		for (i = 0; i < line_len; ++i) {

			keep = Line[i];
			for (j = 1; j < 256; ++j) {
				if (j >= '0' && j <= '9') continue;
				if (j >= 'a' && j <= 'f') continue;
				if (uc && j >= 'A' && j <= 'F') continue;
				Line[i] = j;
				inc_test(); failed = 0;
				v = fn(Line, &n);
				// note, this should ALWAYS succeed
				if ((i&(~1)) != v)
					inc_failed_test();
				if (n && line_len <= v)
					inc_failed_test();

			}
			Line[i] = keep;
		}
	}
	free(Line);
}
void test_hexlen() {
	start_test(__FUNCTION__);
	_test_one_hexlen(hexlen, 1, 1);
	end_test();
}
void test_hexlenl() {
	start_test(__FUNCTION__);
	_test_one_hexlen(hexlenl, 0, 1);
	end_test();
}
void test_hexlenu() {
	start_test(__FUNCTION__);
	_test_one_hexlen(hexlenu, 1, 0);
	end_test();
}
void _is_dec_tester(int (fn)(const char *), int neg, int uns) {
	unsigned u, i, j;
	uint64_t U;
	char Fmt[8], buf[16];

	if (neg)
		sprintf(Fmt, "%s", "%-d");
	else if (uns)
		sprintf(Fmt, "%s", "%u");
	else
		sprintf(Fmt, "%s", "%d");

	for (u = 0; u < 1000005; ++u) {
		sprintf(buf, Fmt, u);
		inc_test();
		if (fn(buf) == 0) {
			failed = 0;
			inc_failed_test();
		}
	}
	for (u = 0x7FFF0000; u < 0x80000000; ++u) {
		sprintf(buf, Fmt, u);
		inc_test();
		if (fn(buf) == 0) {
			failed = 0;
			inc_failed_test();
		}
	}
	if (neg || uns) {
		for (u = 0x7FFFFFFF; u < 0x80010000; ++u) {
			sprintf(buf, Fmt, u);
			inc_test();
			if (fn(buf) == 0) {
				failed = 0;
				inc_failed_test();
			}
		}
		for (u = 0xFFF0FFFF; u < 0xFFFFFFFF; ++u) {
			sprintf(buf, Fmt, u);
			inc_test();
			if (fn(buf) == 0) {
				failed = 0;
				inc_failed_test();
			}
		}
	}
	if (!uns) {
		// make sure that numbers > 0x7fffffff fail.
		for (u = 0x80000000; u < 0x80010000; ++u) {
			sprintf(buf, "%u", u);
			inc_test();
			if (fn(buf) != 0) {
				failed = 0;
					inc_failed_test();
			}
		}
	} else {
		// make sure that just over numbers > 0x7fffffff work.
		for (u = 0x80000000; u < 0x80010000; ++u) {
			sprintf(buf, "%u", u);
			inc_test();
			if (fn(buf) == 0) {
				failed = 0;
				inc_failed_test();
			}
		}
		// make sure number > 0xffffffff fail
		for (U = 0x100000000; U < 0x100010000; ++U) {
			sprintf(buf, "%"PRIu64, U);
			inc_test();
			if (fn(buf) != 0) {
				failed = 0;
				inc_failed_test();
			}
		}
	}
	// additional tests
	for (u = 1; u < 12; ++u) {
		// add a bad byte into all places. NONE of these should work.
		for (j = 0; j < u; ++j)
			buf[j] = '6';
		buf[j] = 0;
		for (j = 0; j < u; ++j) {
			for (i = 1; i < 256; ++i) {
				if ((i >= '0' && i <= '9') || (j == 0 && neg && i == '-'))
					; // skip this one. it's a digit, or valid '-'
				else {
					buf[j] = i;
					if (fn(buf) != 0) {
						failed = 0;
						inc_failed_test();
					}
				}
			}
			buf[j] = '6';
		}
	}

}
void test_isdec() {
	start_test(__FUNCTION__);
	_is_dec_tester(isdec, 0, 0);
	end_test();
}
void test_isdec_negok() {
	start_test(__FUNCTION__);
	_is_dec_tester(isdec_negok, 1, 0);
	end_test();
}
void test_isdecu() {
	start_test(__FUNCTION__);
	_is_dec_tester(isdecu, 0, 1);
	end_test();
}


// Test code for internal JTR hash code, i.e. MD2, MD4, MD5, SHA/1/2... etc
//   do not worry about testing things like OpenSSL hashes!. Waste of time.
//  I use a lot of vectors from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
//  they have a standard file layout, so are easy to auto-test.

typedef struct {
	unsigned char *test_data;
	char *message;
	uint64_t test_bits;
	// result hash (UC hex). 512 bit hash fits (128+1 byte hex string)
	char hash[129], *cur;
	int iterations;
} Hash_Tests;
Hash_Tests *HTst;
int nHTst;

void _Reset_test_hash_data() {
	int n;
	for (n = 0; n < nHTst; ++n) {
		free(HTst[n].test_data);
		free(HTst[n].message);
	}
	free(HTst);
	nHTst = 0;
	HTst = NULL;
}

/**********************************************************************
 * parsing the NESSIE files are a bit nasty, but once it is done and
 * working, we can easily toss more files into the unit-tests easily.
 **********************************************************************/

/* this function pre-parses, but only to get the bit count for each message */
uint64_t _parse_NESSIE_bits(const char *cp) {
	const char *cp2;
	long long bits, b;
	unsigned u;
	char c;

	if (*cp == '\"') {
		// literal string
		++cp;
		cp2 = strchr(cp, '\"');
		if (strstr(cp, "...") == 0)
			return (cp2 - cp) * 8;
		// there are ranges. Compute how many 'real' byte counts once
		// ranges are handled.  In the end, the len is bits+8*b
		// the ranges get put into bits.  The 'literal' data gets
		// put into b. NOTE, we subtract from bits for each range,
		// since there is literal 'data', but we do NOT use it for
		// each range.
		bits = 0;
		for (b = 0; &cp[b] < cp2; ++b) {
			if (cp[b] != '.' && !strncmp(&cp[b + 1], "...", 3)) {
				char f = cp[b];
				char t = cp[b + 4];
				// ok, we move b forward 5, so remove 40 bits
				b += 4;  // Note ++b in the for statement ;)
				bits -= (5 * 8);
				// this computes bits properly.
				for (; f <= t; ++f)
					bits += 8;
			}
		}
		return b * 8 + bits;
	}
	if (sscanf(cp, "%u million times %c", &u, &c) == 2 && c == '\"') {
		cp = strchr(cp, '\"') + 1;
		return (strlen(cp) - 1) * 8ULL * u * 1000000;

	}
	if (sscanf(cp, "%u times %c", &u, &c) == 2 && c == '\"') {
		cp = strchr(cp, '\"') + 1;
		return (strlen(cp) - 1) * 8ULL * u;

	}
	// # zero bits
	//	NOTE, we only handle, bits==0 mod(8), BUT read all from file
	//	in case at some later date, we want to test 1 bit, 2 bit, etc.
	if (sscanf(cp, "%llu zero %c", &bits, &c) == 2 && c == 'b')
		return bits;
	// 512-bit string: x*00,hex,y*00
	// these  are all cases of 512 bits with 511 0 and 1 bit set.
	if (sscanf(cp, "%u-bit string:%c", &u, &c) == 2 && u == 512 && c == ' ')
		return 512;

	if (!strcmp(cp, "message=256 zero bits"))
		return 256;

	printf("Un-handled %s\n", cp);
	return 0;
}
/* this function allocates a buffer, and parses the message properly. */
unsigned char *_parse_NESSIE(const char *cp, uint64_t bits) {
	unsigned char *p, *pRet;
	const char *cp2;
	long long b;
	uint64_t bytes;
	unsigned u;
	char c;

	bytes = (bits + 7) / 8;
	p = bytes ? calloc(1, bytes) : calloc (1,1);
	pRet = p;

	if (*cp == '\"') {
		// literal string
		++cp;
		cp2 = strchr(cp, '\"');
		if (strstr(cp, "...") == 0) {
			memcpy(p, cp, bytes);
			return p;
		}
		// there are ranges. Handle them (and any literals
		for (b = 0; &cp[b] < cp2; ++b) {
			if (cp[b] != '.' && !strncmp(&cp[b + 1], "...", 3)) {
				char f = cp[b];
				char t = cp[b + 4];
				// ok, we move b forward 5, so remove 5*8 from bits
				b += 4;  // Note ++b in the for statement ;)
				bits -= (5 * 8);
				for (; f <= t; ++f)
					*p++ = f;
			} else
				*p++ = cp[b];
		}
		return pRet;
	}
	// message=1 million times "a"
	if (sscanf(cp, "%u million times %c", &u, &c) == 2 && c == '\"') {
		uint64_t n, Til;
		uint32_t j, jTil;

		cp = strchr(cp, '\"') + 1;
		Til = u;
		Til *= 1000000;
		jTil = strlen(cp) - 1;
		for (n = 0; n < Til; ++n) {
			for (j = 0; j < jTil; ++j) {
				*p++ = cp[j];
			}
		}
		return pRet;
	}
	//  message=8 times "1234567890"
	if (sscanf(cp, "%u times %c", &u, &c) == 2 && c == '\"') {
		uint32_t j, n, jTil;

		cp = strchr(cp, '\"') + 1;
		jTil = strlen(cp) - 1;
		for (n = 0; n < u; ++n) {
			for (j = 0; j < jTil; ++j) {
				*p++ = cp[j];
			}
		}
		return pRet;
	}
	// message=8 zero bits
	if (sscanf(cp, "%llu zero %c", &b, &c) == 2 && c == 'b') {
		return pRet;
	}
	// 512-bit string: x*00,hex,y*00
	// these  are all cases of 512 bits with 511 0 and 1 bit set.
	if (sscanf(cp, "%u-bit string:%c", &u, &c) == 2 && u == 512 && c == ' ') {
		unsigned n, x, z;

		if (sscanf(cp, "512-bit string:  %u*00,%x,%u*00", &n, &x, &z) != 3)
			fprintf(stderr, "Error, parsing message format:  %s\n", cp);
		p[n] = (char)((unsigned char)x);
		return pRet;
	}

	if (!strcmp(cp, "message=256 zero bits"))
		return pRet;

	printf("Un-handled %s\n", cp);

	return pRet;
}

/*
 * this function will load a NESSIE file, containing precomputed hash values
 * and the message which generated this hash. These are known correct HASH
 * data, pre-built to test hashing functions (such as MD5/SHA1, etc).
 * NESSIE files:  https://www.cosic.esat.kuleuven.be/nessie/testvectors/
 *
 *  NOTE, here are other sources of pre-built test input data files:
 *  AESAVS, KAT, MCT tests from the NIST CAVP (Note, NIST shut down
 *  temporarily due to US govt fake shutdown).
 *     http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf
 *     https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/
 */
void _Load_NESSIE_hash_file(const char *fname) {
	// currently only handles NESSIE files.
	FILE *in = fopen(fname, "r");
	char LineBuf[512], *cp, *cpLB;
	int n;
	int in_hash;

	_Reset_test_hash_data();
	if (!in) {
		fprintf(stderr, "Error, could not open file %s\n", fname);
		return;
	}
	// first read file, counting # of entries
	cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	while (!feof(in)) {
		if (strstr(cpLB, "vector#"))
			++nHTst;
		else if (strstr(cpLB, "iterated "))
			++nHTst;
		if (cpLB != LineBuf)
			MEM_FREE(cpLB);
		cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	}
	fclose(in);

	if (!nHTst) {
		fprintf(stderr, "Error, no hash test data found in %s\n", fname);
		return;
	}
	// Now allocate
	HTst = (Hash_Tests*)calloc(nHTst, sizeof(Hash_Tests));

	// Now, re-read the file, and load the hash tests.
	in = fopen(fname, "r");
	cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	n = 0;
	in_hash = 0;
	while (!feof(in)) {
		if (strstr(cpLB, "Test vectors")) {
			if (in_hash)
				++n;
			in_hash = 0;
		}
		else if (strstr(cpLB, "vector#")) {
			if (in_hash)
				++n;
			in_hash = 1;
		}
		else if (strstr(cpLB, "End of test vectors")) {
			in_hash = 0;
		}
		else if (in_hash) {
			if ((cp = strstr(cpLB, "message=")) != NULL) {
				cp += 8;
				strtok(cp, "\r\n");
				HTst[n].message = strdup(cp);
				HTst[n].test_bits = _parse_NESSIE_bits(cp);
				HTst[n].test_data = _parse_NESSIE(cp, HTst[n].test_bits);
				HTst[n].cur = HTst[n].hash;
				if (cpLB != LineBuf)
					MEM_FREE(cpLB);
				cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
				continue;
			}
			if ((cp = strstr(cpLB, "iterated ")) != NULL) {
				char c;
				int x;
				// take the last message, perform hash on its
				// data, BUT also re-run the hash on the raw
				// output buffer iterated (-1) times, and
				// compare to the expected hash.
				++n;
				// replicate last message
				// but append iterated x times message.
				HTst[n].message = mem_alloc(strlen(HTst[n - 1].message) + strlen(cp) + 4);
				sprintf(HTst[n].message, "%s - %s", HTst[n - 1].message, cp);
				// test bits and data are SAME.
				HTst[n].test_bits = HTst[n - 1].test_bits;
				HTst[n].test_data = calloc(1, (HTst[n].test_bits + 7) / 8);
				// The hash we will read from the file, starting
				// with THIS line.
				HTst[n].cur = HTst[n].hash;
				//   the test data does this (perl code)
				//      #!/usr/bin/perl
				//      using Digest::hash  qw{hash};
				//      my $s = hash($test_data);
				//      my $n;
				//      for ($n = 1; $n < $iterations; ++$n) {
				//         $s = hash($s);
			        //      }
				//      print unpack("H*", $s);
				x = sscanf(cpLB, " iterated %u times%c", &HTst[n].iterations, &c);
				if (x != 2 && c != '=') {
					fprintf(stderr, "Invalid iteration line  %s\n", cpLB);
				}
				// since this iterations line contains the
				// 'first' line of hash data, we need to
				// make a fake message line, and then simply
				// read the file forward.
				cp = strchr(cpLB, '=');
				sprintf(cpLB, "    hash");
				// Note, cp is IN LineBuf/cpLB, so be careful.
				memmove(&cpLB[strlen(cpLB)], cp, strlen(cp) + 1);
			}
			if ((cp=strstr(cpLB, "hash=")) != NULL) {
				// ok, this is the start of a hash line.
				cp += 5;
				strtok(cp, "\r\n");
				strcpy(HTst[n].cur, cp);
				HTst[n].cur += strlen(cp);
			}
			else if (strlen(cpLB) > 10) {
				// if we have a line with > 10 bytes (actually
				// if it is more than 2), and it was not caught
				// by any of the above IF statements, then it
				// is simply the continuation of the hash data
				// so append it to the growing hash.
				cp = cpLB;
				while (*cp == ' ') ++cp;
				strtok(cp, "\r\n");
				strcpy(HTst[n].cur, cp);
				HTst[n].cur += strlen(cp);
			}
		}
		if (cpLB != LineBuf)
			MEM_FREE(cpLB);
		cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	}
	fclose(in);
}

void ParseHex(unsigned char *po, const char *_pi, int b) {
	int i;
	const unsigned char *pi = (const unsigned char*)_pi;

	for (i = 0; i < b && *pi; ++i) {
		*po++ = (atoi16[pi[0]] << 4) | atoi16[pi[1]];
		pi += 2;
	}
}
/*
 * This file format is MUCH easier to parse than NESSIE.  In this format there
 * are no parsing of the message.  The message is simply a hex string (simple
 * to parse). Also, the MD is all on 1 line, which also makes it trivial to
 * parse.  The biggest thing is to have large enough line buffers to properly
 * read the file.  There are multiple file types, however, making it more
 * of a process to parse.
 *
 *   type:  1 == XX[Short][Long]Msg.rsp  (simple strings, simply hashed)
 *   type:  2 == XXMonte.rsp             This contains the 100 values for the
 *                                       monte-carlo tests. There is ONLY 1
 *                                       input data (the seed).  All result
 *                                       values are from re-running using the
 *                                       last 'runs' output.
 */
void _Load_CAVS_hash_file(const char *fname, int type) {
	// this format is MUCH easier to parse than NESSIE.  In this format
	// there are no parsing of the message.  The message is simply a
	// hex string (simple to parse). Also, the MD is all on 1 line,
	// which also makes it trivial to parse.  The biggest thing is to
	// have large enough line buffers to properly read the file.
	char LineBuf[1024], *cpLB;
	FILE *in;
	int n;

	in = fopen(fname, "r");
	if (!in) {
		fprintf(stderr, "Unable to open testing file %s\n", fname);
		return;
	}
	_Reset_test_hash_data();
	if (type == 2) {
		int len=64;
		// handle monte-carlo
		// here, we simply read the seed, and the expected hash values.
		nHTst = 100;
		HTst = calloc(nHTst, sizeof(HTst[0]));

		// handle getting the seed, AND hashes from the file
		// we put the seed into HTst[0].test_data
		// We only put the expected hashes into HTst[n].hash
		cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
		n = 0;
		while (!feof(in)) {
			strtok(cpLB, "\r\n");
			if (!strncmp(cpLB, "[L = ", 5)) {
				sscanf(cpLB, "[L = %d]", &len);
			} else if (!strncmp(cpLB, "Seed = ", 7)) {
				HTst[0].test_bits = len * 8;
				HTst[0].test_data = calloc(1, HTst[0].test_bits / 8);
				ParseHex(HTst[0].test_data, &cpLB[7], HTst[0].test_bits / 8);
			} else if (!strncmp(cpLB, "MD = ", 5)) {
				strcpy(HTst[n].hash, &cpLB[5]);
				strupr(HTst[n].hash);
				++n;
			}
			if (cpLB != LineBuf)
				MEM_FREE(cpLB);
			cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
		}
		fclose(in);
		return;
	}
	// handle a short/long 'flat' file
	cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	while (!feof(in)) {
		if (!strncmp(cpLB, "Len = ", 6))
			++nHTst;
		if (cpLB != LineBuf)
			MEM_FREE(cpLB);
		cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	}
	// Ok, now we know how many variables we have
	HTst = calloc(nHTst, sizeof(HTst[0]));

	// start over in the file.
	fseek(in, 0, SEEK_SET);
	cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	n = -1;	// note set to -1, since the first thing Len= read does is do ++n;
	while (!feof(in)) {
		strtok(cpLB, "\r\n");
		if (!strncmp(cpLB, "Len = ", 6)) {
			++n;
			sscanf(cpLB, "Len = %"PRIu64, &HTst[n].test_bits);
			if (HTst[n].test_bits)
				HTst[n].test_data = calloc(1, HTst[n].test_bits / 8);
		} else if (!strncmp(cpLB, "Msg = ", 6)) {
			HTst[n].message = strdup(cpLB);
			ParseHex(HTst[n].test_data, &cpLB[6], HTst[n].test_bits / 8);
		} else if (!strncmp(cpLB, "MD = ", 5)) {
			strcpy(HTst[n].hash, &cpLB[5]);
			strupr(HTst[n].hash);
		}
		if (cpLB != LineBuf)
			MEM_FREE(cpLB);
		cpLB = fgetll(LineBuf, sizeof(LineBuf), in);
	}
	fclose(in);
}
void _hash_error(const char *T, int n, unsigned char *buf, int len) {
	char *m = HTst[n].message;
	unsigned mlen = HTst[n].test_bits / 8;
	printf("%s test %d failed.\n", T, n + 1);
	printf("   input    : %s [%s]\n", m, hex(m, mlen));
	printf("   Expected : %s\n", HTst[n].hash);
	printf("   Computed : %s\n", packedhex(buf, len));
}
/*
 * this macro will handle all oSSL CTX model hashes.
 * usage:  ossl_CTX_FLAT_HASH(hash_type, hash_bytes, buffer_width)
 * note, some hashes like SHA224/SHA384 may have different hash_bytes
 * vs buffer_width.
*/
#define ossl_CTX_FLAT_HASH(T,t,B,b)					\
void _Perform_FLAT_tests_##T ()	{					\
	int n, j;							\
	for (n = 0; n < nHTst; ++n) {					\
		t##_CTX c;						\
		unsigned char buf[b];					\
									\
		if (HTst[n].test_bits % 8)				\
			continue;  /* only handle full byte data */	\
		inc_test();						\
		T##_Init(&c);						\
		T##_Update(&c, HTst[n].test_data, HTst[n].test_bits/8);	\
		T##_Final(buf, &c);					\
		if (HTst[n].iterations > 1) {				\
			for (j = 1; j < HTst[n].iterations; ++j) {	\
				T##_Init(&c);				\
				T##_Update(&c, buf, B);			\
				T##_Final(buf, &c);			\
			}						\
		}							\
		if (strcmp(packedhex(buf, B), HTst[n].hash)) {		\
			failed = 0;					\
			inc_failed_test();				\
			_hash_error(#T, n, buf, B);			\
		}							\
	}								\
}

/*
 * this macro will handles the FIPS CAVS 'Monte-Carlo' algorithm.
 * That algorithm starts with a 'seed'. It builds a buffer with
 * that seed replicated 3 times.  It then repeatedly drops off the
 * first part of that input stream, and appends the results of the
 * last hash.  1000 iterations are performed, resulting in a value.
 * that value is checked against provided data.  THEN that value is
 * used as the starting seed to the next round (again 1000 iterations)
 * This is done in total of 100 times. At the end of each inner loop
 * there is a value (should be 100 of them).  ANY failure will cascade
 * and all of the data following will be smashed and not match.
 * this implementation is not super well written, BUT it does fully
 * implement the algorithm, and the results can be trusted. NOTE, the
 * 'b' variable is only used in the s[] array, since that is where the
 * hash will write to. All other lengths used are the 'B' variable,
 * which is the actual usable bytes of the hash, which can be shorter
 * than 'b' (hashes such as SHA224 or SHA384)
 */
#define ossl_CTX_CAVS_MONTE_HASH(T,t,B,b)				\
void _Perform_CAVS_MONTE_tests_##T() {					\
	int i, j;							\
	/* the 'only' thing needing to be 'b' bytes is the s array */	\
	unsigned char S[3][B], seed[B], t[B * 3], s[b];			\
	memcpy(seed, HTst[0].test_data, B);				\
	for (j = 0; j < 100; ++j) {					\
		memcpy(S[0], seed, B);					\
		memcpy(S[1], seed, B);					\
		memcpy(S[2], seed, B);					\
		for (i = 0; i < 1000; ++i) {				\
			t##_CTX c;					\
			memcpy(t, S[0], B);				\
			memcpy(&t[B], S[1], B);				\
			memcpy(&t[B * 2], S[2], B);			\
			T##_Init(&c);					\
			T##_Update(&c, t, B * 3);			\
			T##_Final(s, &c);				\
			memcpy(S[0], S[1], B);				\
			memcpy(S[1], S[2], B);				\
			memcpy(S[2], s, B);				\
		}							\
		if (strcmp(packedhex(s, B), HTst[j].hash)) {		\
			failed = 0;					\
			inc_failed_test();				\
			_hash_error(#T"-NIST_Monte", j, s, B);		\
		}							\
		memcpy(seed, s, B);					\
	}								\
}

ossl_CTX_FLAT_HASH(SHA224, SHA256, 28, 32)
ossl_CTX_FLAT_HASH(SHA256, SHA256, 32, 32)
ossl_CTX_FLAT_HASH(SHA384, SHA512, 48, 64)
ossl_CTX_FLAT_HASH(SHA512, SHA512, 64, 64)

ossl_CTX_CAVS_MONTE_HASH(SHA224, SHA256, 28, 32)
ossl_CTX_CAVS_MONTE_HASH(SHA256, SHA256, 32, 32)
ossl_CTX_CAVS_MONTE_HASH(SHA384, SHA512, 48, 64)
ossl_CTX_CAVS_MONTE_HASH(SHA512, SHA512, 64, 64)

void _perform_hash_test(const char *fname, int type, void(fn)()) {
	if (type == 0)
		_Load_NESSIE_hash_file(fname);
	else
		_Load_CAVS_hash_file(fname, type);
	fn();
}

/*
* Here is the perl code to handle the monte carlo tests for sha256.  Very
* simple stuff, once we understand it ;)

#!/usr/bin/perl
use Digest::SHA qw{sha256};
# seed read from the SHA256Monte.rsp file.  It is the ONLY input data.
$seed=pack("H*", "6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691");
# there are 100 'tests', which use their starting input from seed OR prior test
for($j = 0; $j < 100; ++$j) {
	my @S = ();
	push(@S, $seed); push(@S, $seed); push(@S, $seed);
	for($i=0;$i<1000;++$i){
		$t = $S[0].$S[1].$S[2];
		#printx($t);  # 1st 5 loops seen in SHA256Monte.txt
		$s=sha256($t);
		#printx($s);  # 1st 5 loops seen in SHA256Monte.txt
		shift(@S);
		push(@S, $s);
	}
	$shex=unpack("H*",$s);
	print "$j - $shex\n";
	$seed = $s;	# use this test result as seed for next run.
}
*/
void test_sha2_c() {
	// test using NESSIE and NIST/CAVS input data files

	start_test("test_sha224");
	// no NESSIE data for sha224 :(
	_perform_hash_test("tests/NIST_CAVS/SHA224ShortMsg.rsp", 1, _Perform_FLAT_tests_SHA224);
	_perform_hash_test("tests/NIST_CAVS/SHA224LongMsg.rsp", 1, _Perform_FLAT_tests_SHA224);
	_perform_hash_test("tests/NIST_CAVS/SHA224Monte.rsp", 2, _Perform_CAVS_MONTE_tests_SHA224);
	end_test();

	start_test("test_sha256");
	_perform_hash_test("tests/NESSIE/Sha-2-256.unverified.test-vectors.txt", 0, _Perform_FLAT_tests_SHA256);
	_perform_hash_test("tests/NIST_CAVS/SHA256ShortMsg.rsp", 1, _Perform_FLAT_tests_SHA256);
	_perform_hash_test("tests/NIST_CAVS/SHA256LongMsg.rsp", 1, _Perform_FLAT_tests_SHA256);
	_perform_hash_test("tests/NIST_CAVS/SHA256Monte.rsp", 2, _Perform_CAVS_MONTE_tests_SHA256);
	end_test();

	start_test("test_sha384");
	_perform_hash_test("tests/NESSIE/Sha-2-384.unverified.test-vectors.txt", 0, _Perform_FLAT_tests_SHA384);
	_perform_hash_test("tests/NIST_CAVS/SHA384ShortMsg.rsp", 1, _Perform_FLAT_tests_SHA384);
	_perform_hash_test("tests/NIST_CAVS/SHA384LongMsg.rsp", 1, _Perform_FLAT_tests_SHA384);
	_perform_hash_test("tests/NIST_CAVS/SHA384Monte.rsp", 2, _Perform_CAVS_MONTE_tests_SHA384);
	end_test();

	start_test("test_sha512");
	_perform_hash_test("tests/NESSIE/Sha-2-512.unverified.test-vectors.txt", 0, _Perform_FLAT_tests_SHA512);
	_perform_hash_test("tests/NIST_CAVS/SHA512ShortMsg.rsp", 1, _Perform_FLAT_tests_SHA512);
	_perform_hash_test("tests/NIST_CAVS/SHA512LongMsg.rsp", 1, _Perform_FLAT_tests_SHA512);
	_perform_hash_test("tests/NIST_CAVS/SHA512Monte.rsp", 2, _Perform_CAVS_MONTE_tests_SHA512);
	end_test();
}

int main() {
	start_of_run = clock();

	common_init();

	set_unit_test_source("misc.c");
	// when the function gets 'done' tab it out.
	/* not testing */ //test_real_error();	// void real_error(char *file, int line)
	/* not testing */ //test_real_error_msg();	// void real_error_msg(char *file, int line, char *format, ...)
	/* not testing */ //test_real_pexit();	// void real_pexit(char *file, int line, char *format, ...)
	/* not testing */ //test_write_loop();	// int write_loop(int fd, const char *buffer, int count)
	_nontest_gen_fgetl_files(1);	// creates the 3 files
	test_fgetl();		// char *fgetl(char *s, int size, FILE *stream)
	test_fgetll();		// char *fgetll(char *s, size_t size, FILE *stream)
	_nontest_gen_fgetl_files(0);	// deletes the 3 files
	test_strncpy_pad();	// void *strncpy_pad(void *dst, const void *src, size_t size, uint8_t pad)
	test_strnfcpy();	// char *strnfcpy(char *dst, const char *src, int size)
	test_strnzcpy();	// char *strnzcpy(char *dst, const char *src, int size)
	test_strnzcpylwr();	// char *strnzcpylwr(char *dst, const char *src, int size)
	test_strnzcpyn();	// int strnzcpyn(char *dst, const char *src, int size)
	test_strnzcpylwrn();	// int strnzcpylwrn(char *dst, const char *src, int size)
	test_strnzcat();	// char *strnzcat(char *dst, const char *src, int size)
	test_strnzcatn();	// char *strnzcatn(char *dst, int size, const char *src, int src_max)
	test_strtokm();		// char *strtokm(char *s1, const char *delims)
	test_atou();		// unsigned int atou(const char *src)
	test_jtr_itoa();	// const char *jtr_itoa(int val, char *result, int rlen, int base)
	test_jtr_utoa();	// const char *jtr_utoa(unsigned int val, char *result, int rlen, int base)
	test_jtr_lltoa();	// const char *jtr_lltoa(int64_t val, char *result, int rlen, int base)
	test_jtr_ulltoa();	// const char *jtr_ulltoa(uint64_t val, char *result, int rlen, int base)
//test_human_prefix();	// char *human_prefix(uint64_t num)
	test_trim();            // char *[l/r]trim(char *str)

	set_unit_test_source("common.c");
	_gen_hex_len_data();
	test_ishex();		// int ishex(const char *q);
	test_ishex_oddOK();	// int ishex_oddOK(const char *q);
	test_ishexuc();		// int ishexuc(const char *q);
	test_ishexlc();		// int ishexlc(const char *q);
	test_ishexuc_oddOK();	// int ishexuc_oddOK(const char *q);
	test_ishexlc_oddOK();	// int ishexlc_oddOK(const char *q);
	test_ishexn();		// int ishexn(const char *q, int n);
	test_ishexucn();	// int ishexucn(const char *q, int n);
	test_ishexlcn();	// int ishexlcn(const char *q, int n);
	test_hexlen();		// size_t hexlen(const char *q, int *extra_chars);
	test_hexlenl();		// size_t hexlenl(const char *q, int *extra_chars);
	test_hexlenu();		// size_t hexlenu(const char *q, int *extra_chars);
	test_isdec();		// int isdec(const char *q);
	test_isdec_negok();	// int isdec_negok(const char *q);
	test_isdecu();		// int isdecu(const char *q);


	set_unit_test_source("sha2.c");
	test_sha2_c();

	// perform dump listing of all processed functions.
	dump_stats();

	/* do all cleanups. Make SURE ASAN if fully happy, and reports NO issues */
	_Reset_test_hash_data();
	_free_hex_len_data();
	free(_fgetl_pad);
	cleanup_tiny_memory();

	return any_failure;
}
