 /*
 * This software was written by JimF jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Salt finder. This will allow JtR to process a few salted type
 * hashes, if the original salt has been lost.  The only 2 types
 * done at this time, are PHPS (VB), and osCommerce. PHPS is dynamic_6
 * which is md5(md5($p).$s) with a 3 byte salt.  osCommerce is dynamic_4
 * of md5($s.$p) with a 2 type salt.
 *
 * this was made 'generic' now, so it will work for dynamic salted formats
 * in 'general'.
 *

Data needed for --regen_salts:

--regen_salts=#  (deprecated.  valid values are 1, 2, 3, 4, 5, 6 and will get 'converted' into proper regen_salts= value)
or
--regen_salts=type:hash_len:mask

--regen_salts=1  == --regen_salts=dynamic_6:32:?y?y?y
--regen_salts=2  == --regen_salts=dynamic_4:32:?y?y
--regen_salts=3  == --regen_salts=dynamic_9:32:?d?d?d-
--regen_salts=4  == --regen_salts=dynamic_9:32:?d?d?d?d-
--regen_salts=5  == --regen_salts=dynamic_9:32:?d?d?d?d?d-
--regen_salts=6  == --regen_salts=dynamic_61:64:?d?d

Options:

options.regen_lost_salts   (now only 0 or 1)

?d = 0123456789
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?s = !@#$%^&*()`~-_=+\|[]{};:'",.<>/?
?h = 0123456789abcdef
?y = all
?a = a-zA-Z
[?d?l] = 0123456789abcdefghijklmnopqrstuvwxyz
?z = \x1-\x255

From jtr rules.  Using ! instead of ? means 'optional' character.  So ?d?d?d?d- is 1 to 4 digit characters with a '-' char always being appended (like media wiki)

 */

extern char *regen_salts_options;
extern int regen_salts_count;

extern int regen_lost_salt_parse_options();
extern char *load_regen_lost_salt_Prepare(char *split_fields1);
extern void crk_guess_fixup_salt(char *source, char *salt);
extern void ldr_pot_possible_fixup_salt(char *source, char *ciphertext);
extern void build_fake_salts_for_regen_lost(struct db_main *);
