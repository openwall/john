/*
 * This is extern set of 'main' functions. It is used to allow the
 * -Wmissing-declarations to properly see and not warn about these
 * functions.  NOTE, these are similar to a C main() function, but
 * within john's main(), if john detects that it is running from
 * certain symlink named files, it will instead call the 'main'
 * function from the proper file (thus making that functionality work).
 *
 * Coded Winter 2019 by JimF.  Code placed in public domain.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * Please note that although this main john.c file is under the cut-down BSD
 * license above (so that you may reuse sufficiently generic pieces of code
 * from this file under these relaxed terms), some other source files that it
 * uses are under GPLv2.  For licensing terms for John the Ripper as a whole,
 * see doc/LICENSE.
 */
 
#if !defined(__EXTERN_MAINS_H__)
#define __EXTERN_MAINS_H__

extern int base64conv(int argc, char **argv);
extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int unique(int argc, char **argv);
extern int undrop(int argc, char **argv);
extern int zip2john(int argc, char **argv);
extern int gpg2john(int argc, char **argv);
extern int rar2john(int argc, char **argv);

#endif