/*
 * Copyright (c) 2012, 2013 Frank Dittrich and magnum
 *
 * This software is hereby released to the general public under the following
 * terms:  Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _JOHN_LISTCONF_H
#define _JOHN_LISTCONF_H

/* Suboptions that can be used before full initialization, like --list=help */
void listconf_parse_early(void);

/* Suboptions that depend on full initialization, like --list=externals */
void listconf_parse_late(void);

#endif
