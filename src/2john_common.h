/*
 * Shared helpers used by the family of *2john converters (zip2john,
 * rar2john, dmg2john, keepass2john, ...). See:
 *   https://github.com/openwall/john/issues/4051
 *
 * Many of these converters embed the encrypted blob from the input archive
 * directly into the JtR hash line they print to stdout. For large archives
 * (encrypted disk images, password-protected RARs, KeePass databases with
 * sizeable key files) the resulting hash line can run into hundreds of
 * megabytes or more, which routinely surprises new users into thinking the
 * tool has malfunctioned. The helpers here let each *2john print a single
 * one-shot stderr note up front when the input is large enough that a big
 * stdout output is expected.
 */

#ifndef _JOHN_2JOHN_COMMON_H
#define _JOHN_2JOHN_COMMON_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Default threshold (in bytes) above which a *2john tool should print the
 * "output may be very large" stderr note. Roughly 1 MiB matches the
 * suggestion in https://github.com/openwall/john/issues/4051. Each tool can
 * override this if its output is more (or less) bloated relative to the
 * input.
 */
#define LARGE_OUTPUT_THRESHOLD_BYTES (1L << 20)

/*
 * Print a one-shot stderr explanation that the output may be very large.
 * The note is suppressed after the first call within a process so users
 * who feed in many archives don't see it once per file.
 */
static inline void large_output_note(const char *progname)
{
	static int announced;

	if (announced)
		return;
	announced = 1;

	fprintf(stderr,
		"Note: %s output can be very large for large inputs (often 2x the\n"
		"input size or more, since the encrypted blob is hex-encoded into the\n"
		"hash line). This is normal — redirect the output into a file with\n"
		"'%s <archive> > hashes.txt'.\n",
		progname, progname);
}

/*
 * Stat path and call large_output_note() iff the file is at least
 * threshold bytes. Errors from stat() are silently ignored — the note is a
 * best-effort UX hint, not a correctness check.
 */
static inline void large_output_note_if_input_large(const char *progname,
						    const char *path,
						    off_t threshold)
{
	struct stat st;

	if (path == NULL)
		return;
	if (stat(path, &st) != 0)
		return;
	if (st.st_size >= threshold)
		large_output_note(progname);
}

#endif /* _JOHN_2JOHN_COMMON_H */
