/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libusb-1.0/libusb.h>

#include "../memory.h"

#include "ztex.h"
#include "inouttraffic.h"
#include "device.h"
#include "task.h"
#include "jtr_device.h"
#include "jtr_mask.h"

#include "pkt_comm/pkt_comm.h"
#include "pkt_comm/word_list.h"
#include "pkt_comm/word_gen.h"
#include "pkt_comm/cmp_config.h"
#include "pkt_comm/inpkt.h"


void jtr_device_error(const char *s, ...) {
	va_list ap;
	va_start(ap, s);
	vfprintf(stderr, s, ap);
	va_end(ap);
}


struct jtr_device *jtr_device_new(
		struct jtr_device_list *jtr_device_list,
		struct device *device,
		struct pkt_comm *comm)
{
	struct jtr_device *self = mem_alloc(sizeof(struct jtr_device));

	self->next = jtr_device_list->device;
	jtr_device_list->device = self;
	self->device = device;
	self->comm = comm;
	
	self->cmp_config_id = -1;
	self->task_id_next = 1;

	return self;
}


struct jtr_device_list *jtr_device_list_new(struct device_list *device_list)
{
	struct jtr_device_list *self = mem_alloc(sizeof(struct jtr_device_list));
	self->device = NULL;
	
	// Create 1 JtR device for each fpga
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int i;
		for (i = 0; i < device->num_of_fpgas; i++) {
			struct fpga *fpga = &device->fpga[i];
			//struct jtr_device *jtr_device = 
			jtr_device_new(self, device, fpga->comm);
			//printf("jtr_device_new(%d,%d,%d)\n",self, device, fpga->comm);
		}
	}
	
	return self;
}


//////////////////////////////////////////////////////////////////////////////

int libusb_initialized;

// Global inouttraffic device list
struct device_list *device_list;

// Global jtr_device_list
struct jtr_device_list *jtr_device_list;


struct jtr_device_list *jtr_device_list_init()
{
	int result;
	
	if (!libusb_initialized) {
		result = libusb_init(NULL);
		if (result < 0) {
			fprintf(stderr, "libusb_init() returns %d: %s\n",
					result, libusb_error_name(result));
			return NULL;
		}
		libusb_initialized = 1;
	}
//ZTEX_DEBUG=1;
//DEBUG = 2;

	// devices aren't initialized
	if (!device_list) {
		device_list = device_init_scan(jtr_bitstream);
		
		int device_count = device_list_count(device_list);
		
		if (device_count) {
			fprintf(stderr, "%d device(s) ZTEX 1.15y ready\n", device_count);
			ztex_dev_list_print(device_list->ztex_dev_list);
		} else {
			fprintf(stderr, "no valid ZTEX devices found\n");
			return NULL;
		}

	// devices already initialized
	// - upload bitstream of proper type if necessary
	// - soft reset, initialize fpgas
	} else {
		device_list_init(device_list, jtr_bitstream);
		int device_count = device_list_count(device_list);
		if (!device_count) {
			fprintf(stderr, "no valid ZTEX devices found\n");
			return NULL;
		}
	}

	// Create jtr_devices from inouttraffic devices
	// TODO: remove old jtr_device's if any
	jtr_device_list = jtr_device_list_new(device_list);
	return jtr_device_list;
}


int jtr_device_list_count()
{
	if (!jtr_device_list)
		return 0;
	
	int count = 0;
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next)
		count++;
	
	return count;
}


void jtr_device_list_merge(
		struct jtr_device_list *jtr_device_list,
		struct jtr_device_list *jtr_device_list_1)
{
	if (!jtr_device_list || !jtr_device_list_1) {
		fprintf(stderr, "jtr_device_list_merge: invalid args\n");
		exit(-1);
	}
	
	struct jtr_device *dev, *dev_next;
	for (dev = jtr_device_list_1->device; dev; dev = dev_next) {
		dev_next = dev->next;
		dev->next = jtr_device_list->device;
		jtr_device_list->device = dev;
	}
	MEM_FREE(jtr_device_list_1);
}


void jtr_device_delete(
		struct jtr_device_list *jtr_device_list,
		struct jtr_device *jtr_device)
{
	if (!jtr_device_list->device)
		return;
		
	if (jtr_device_list->device == jtr_device) {
		jtr_device_list->device = jtr_device->next;
		MEM_FREE(jtr_device);
		return;
	}
	
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next) {
		if (dev->next == jtr_device) {
			struct jtr_device *next_device = jtr_device->next;
			MEM_FREE(jtr_device);
			dev->next = next_device;
			return;
		}
	}
}


struct jtr_device *jtr_device_by_device(
		struct jtr_device_list *jtr_device_list,
		struct device *device)
{
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next)
		if (dev->device == device)
			return dev;
	return NULL;
}


int jtr_device_list_rw(struct task_list *task_list)
{
	// timely scan for new devices
	struct device_list *device_list_1
			= device_timely_scan(device_list, jtr_bitstream);
	int found_devices_num = device_list_count(device_list_1);
	if (found_devices_num) {
		fprintf(stderr, "Found %d device(s) ZTEX 1.15y\n", found_devices_num);
		ztex_dev_list_print(device_list_1->ztex_dev_list);

		// found devices - merge into global device list
		struct jtr_device_list *jtr_device_list_1
				= jtr_device_list_new(device_list_1);
		jtr_device_list_merge(jtr_device_list, jtr_device_list_1);
		device_list_merge(device_list, device_list_1);
	}
	else {
		free(device_list_1);
	}
	
	int data_transfer = 0;
	int device_count = 0;
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int result = device_pkt_rw(device);
		if (result > 0)
			data_transfer = 1;
		if (result >= 0) {
			device_count ++;
			continue;
		}
		
		fprintf(stderr, "SN %s error %d doing r/w of FPGAs (%s)\n",
			device->ztex_device->snString, result, libusb_error_name(result) );

		// Physical device I/O error.
		device_stop(device, task_list, NULL);

	} // for (device_list)
	
	return !device_count ? -1 : data_transfer;
}


int device_stop(
		struct device *device,
		struct task_list *task_list,
		char *error_msg)
{
	// jtr_devices for this physical device might have assigned tasks.
	// - deassign tasks
	// - remove jtr_devices for failed physical device
	//
	int num_deassigned = 0;
	for (;;) {
		struct jtr_device *jtr_dev;
		jtr_dev = jtr_device_by_device(jtr_device_list, device);
		if (!jtr_dev)
			break;
		num_deassigned += tasks_deassign(task_list, jtr_dev);
		jtr_device_delete(jtr_device_list, jtr_dev);
	}
	
	if (error_msg)
		fprintf(stderr, "SN %s: %s\n",
				device->ztex_device->snString, error_msg);
	
	// Device is excluded from operation, becomes subject for device_*_scan().
	// TODO: maybe perform hardware reset?
	//
	device_invalidate(device);
fprintf(stderr, "Deassigned: %d\n",num_deassigned);
	return num_deassigned;
}


// TODO: more effort on proper error handling
void jtr_device_list_process_inpkt(struct task_list *task_list)
{
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next) {
		//int do_break = 0;
	
		// Fetch input packets from pkt_comm_queue
		struct pkt *inpkt;
		while ( (inpkt = pkt_queue_fetch(dev->comm->input_queue) ) ) {

			unsigned int pkt_id = pkt_get_id(inpkt);
			struct task *task = task_find(task_list, dev, pkt_id);
			if (!task) {
				fprintf(stderr, "pkt_type=%d, pkt_id=%d: no task\n",
						inpkt->type, pkt_id);
				pkt_delete(inpkt);
				continue;
			}
			if (task->status != TASK_ASSIGNED) {
				fprintf(stderr, "pkt_type=%d, pkt_id=%d: task not assigned\n",
						inpkt->type, pkt_id);
				pkt_delete(inpkt);
				continue;
			}
			
			// Comparator found equality
			if (inpkt->type == PKT_TYPE_CMP_EQUAL) {
				
				struct pkt_equal *pkt_equal = pkt_equal_new(inpkt);
				if (pkt_equal->word_id >= task->num_keys) {
					fprintf(stderr, "CMP_EQUAL: word_id=%d, num_keys=%d\n",
							pkt_equal->word_id, task->num_keys);
				}
				if (pkt_equal->gen_id >= mask_num_cand()) {
					fprintf(stderr, "CMP_EQUAL: gen_id=%lu, mask_num_cand=%d\n",
							pkt_equal->gen_id, mask_num_cand());
				}
				if (pkt_equal->hash_num >= cmp_config.num_hashes) {
					fprintf(stderr, "CMP_EQUAL: hash_num=%d, num_hashes=%d\n",
							pkt_equal->hash_num, cmp_config.num_hashes);
				}
				
				//fprintf(stderr,"equality w:%d g:%lu h:%d\n", pkt_equal->word_id,
				//		pkt_equal->gen_id, pkt_equal->hash_num);
				task_result_new(task, task->keys
					+ pkt_equal->word_id * jtr_fmt_params->plaintext_length,
					!task->range_info ? NULL :
					task->range_info + pkt_equal->word_id * MASK_FMT_INT_PLHDR,
					pkt_equal->gen_id,
					cmp_config.pw[pkt_equal->hash_num]);

				free(pkt_equal);
			
			// Processing of an input packet done
			// (task processing is complete) 	
			} else if (inpkt->type == PKT_TYPE_PROCESSING_DONE) {
				
				struct pkt_done *pkt_done = pkt_done_new(inpkt);
				if (pkt_done->num_processed
						!= task->num_keys * mask_num_cand()) {
					fprintf(stderr, "PROCESSING_DONE: keys=%d, %lu/%u\n",
							task->num_keys, pkt_done->num_processed,
							task->num_keys * mask_num_cand());
				}
				task->status = TASK_COMPLETE;
				task_update_mtime(task);
				
				free(pkt_done);
			
			} else {
				fprintf(stderr, "Unknown packet type=0x%02x len=%d\n",
						inpkt->type, inpkt->data_len);
				pkt_delete(inpkt);
				break;
			}
		}
	
		//if (do_break)
		//	break;
	} // for (jtr_device_list)
	
}


	//libusb_exit(NULL);


