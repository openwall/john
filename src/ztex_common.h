/*
 * This software is Copyright (c) 2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#ifndef _ZTEX_COMMON_H_
#define _ZTEX_COMMON_H_

/*
 * List of boards detected at initialization.
 * --dev command-line option applies.
 */
extern struct list_main *ztex_detected_list;

/*
 * List of boards for use in current fork.
 */
extern struct list_main *ztex_use_list;

extern int ztex_devices_per_fork;
extern int ztex_fork_num;

/*
 * The function is to be called on the access to ZTEX formats.
 * On the 1st call, initializes libusb, detects boards,
 * uploads firmware where required.
 * Populates ztex_detected_list.
 */
void ztex_init();

#endif
