/*
 * This software is Copyright (c) 2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#ifndef _ZTEX_SN_H
#define _ZTEX_SN_H

// includes '\0' terminator
#define ZTEX_SNSTRING_LEN 11
#define ZTEX_SNSTRING_MIN_LEN 5


// checks if given string is a valid Serial Number.
// 3rd party firmware may have SN of different format.
int ztex_sn_is_valid(char *sn);

// Initialize [List.ZTEX:Devices] configuration section,
// verify syntax correctness
void ztex_sn_init_conf_devices(void);

// Check if given alias string has valid syntax
int ztex_sn_alias_is_valid(char *alias);

// Check if alias exists (SN is specified in [List.ZTEX:Devices])
int ztex_sn_check_alias(char *alias);

// Given original SN reported by the board, return SN
// for display in the application.
char *ztex_sn_get_by_sn_orig(char *sn_orig);

#endif
