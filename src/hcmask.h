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

extern void do_hcmask_crack(struct db_main *database, const char *fname);
extern int hcmask_restore_state_hybrid(const char *sig, FILE *fp);
extern void hcmask_hybrid_fix_state();
