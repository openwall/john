/*
 * This software is Copyright (c) 2016-2018 Denis Burykin
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
#include <assert.h>

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
		struct device *device, int fpga_num,
		struct pkt_comm *comm)
{
	struct jtr_device *self = mem_alloc(sizeof(struct jtr_device));

	self->next = jtr_device_list->device;
	jtr_device_list->device = self;
	self->device = device;
	self->fpga_num = fpga_num;
	self->comm = comm;

	self->cmp_config_id = -1;
	self->task_id_next = 1;

	return self;
}


struct jtr_device_list *jtr_device_list_new(struct device_list *device_list)
{
	struct jtr_device_list *self = mem_alloc(sizeof(struct jtr_device_list));
	self->device = NULL;

	assert(device_list != NULL);

	// Create 1 JtR device for each fpga
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int i;
		for (i = 0; i < device->num_of_fpgas; i++) {
			struct fpga *fpga = &device->fpga[i];
			jtr_device_new(self, device, i, fpga->comm);
			//printf("jtr_device_new(%d,%d,%d,%d)\n",self, device, i, fpga->comm);
		}
	}

	return self;
}


char *jtr_device_id(struct jtr_device *dev)
{
	static char device_id[32];
	if (!dev)
		return "";
	sprintf(device_id, "%s #%d", dev->device->ztex_device->snString,
		dev->fpga_num + 1);
	return device_id;
}

//////////////////////////////////////////////////////////////////////////////

int libusb_initialized;

// Global inouttraffic device list
struct device_list *device_list;

// Global jtr_device_list
struct jtr_device_list *jtr_device_list;

int PKT_DEBUG = 1;


//////////////////////////////////////////////////////////////////////////////

struct jtr_device_list *jtr_device_list_init()
{
	if (!libusb_initialized) {
		int result = libusb_init(NULL);
		if (result < 0) {
			fprintf(stderr, "libusb_init() returns %d: %s\n",
					result, libusb_error_name(result));
			return NULL;
		}
		libusb_initialized = 1;
	}
//ZTEX_DEBUG=1;
//DEBUG = 1; // print I/O function calls
//DEBUG = 2; // print all I/O data in hex
PKT_DEBUG = 1; // print erroneous packets recieved from devices
//PKT_DEBUG = 2; // print all application packets recieved from devices

	// devices aren't initialized
	if (!device_list) {
		device_list = device_init_scan(jtr_bitstream);

	// devices already initialized
	// - upload bitstream of proper type if necessary
	// - soft reset, initialize fpgas
	// This happens when "format" changes (--test).
	} else {
		device_list_init(device_list, jtr_bitstream);
	}

	// Create jtr_devices from inouttraffic devices
	// TODO: remove old jtr_device's if any
	jtr_device_list = jtr_device_list_new(device_list);
	return jtr_device_list;
}


void jtr_device_list_print()
{
	device_list_print(device_list);
}


void jtr_device_list_print_count()
{
	int device_count = device_list_count(device_list);
	fprintf(stderr, "%d device(s) ZTEX 1.15y ready\n", device_count);
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
		error();
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


int jtr_device_list_check()
{
	// timely scan for new devices
	struct device_list *device_list_1
			= device_timely_scan(device_list, jtr_bitstream);
	int found_devices_num = device_list_count(device_list_1);
	if (found_devices_num) {
		//fprintf(stderr, "Found %d device(s) ZTEX 1.15y\n", found_devices_num);
		//ztex_dev_list_print(device_list_1->ztex_dev_list);

		// found devices - merge into global device list
		struct jtr_device_list *jtr_device_list_1
				= jtr_device_list_new(device_list_1);
		jtr_device_list_merge(jtr_device_list, jtr_device_list_1);
		device_list_merge(device_list, device_list_1);
	}
	else {
		free(device_list_1->ztex_dev_list);
		free(device_list_1);
	}
	return found_devices_num;
}


int jtr_device_list_set_app_mode(unsigned char mode)
{
	return device_list_set_app_mode(device_list, mode);
}


int jtr_device_list_rw(struct task_list *task_list)
{
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

	//fprintf(stderr, "Deassigned: %d\n",num_deassigned);
	return num_deassigned;
}


///////////////////////////////////////////////////////////////////////
//
//
//  Handling of input application-level data packets
//
//
///////////////////////////////////////////////////////////////////////


// Find task that matches given input packet
// Return NULL if no match
static struct task *inpkt_check_task(struct pkt *inpkt,
		struct jtr_device *dev, struct task_list *task_list)
{
	unsigned int pkt_id = pkt_get_id(inpkt);
	struct task *task = task_find(task_list, dev, pkt_id);
	if (!task) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: no task\n",
				jtr_device_id(dev), inpkt_type_name(inpkt->type), pkt_id);
		return NULL;
	}

	if (task->status == TASK_COMPLETE) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: task already completed\n",
				jtr_device_id(dev), inpkt_type_name(inpkt->type), pkt_id);

	} else if (task->status != TASK_ASSIGNED) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: task not assigned\n",
				jtr_device_id(dev), inpkt_type_name(inpkt->type), pkt_id);
		return NULL;
	}
	return task;
}


// Check if word_id,gen_id,hash_num from CMP_* packet are valid
// Return false if data isn't valid
static int inpkt_check_cmp(struct jtr_device *jtr_dev,
		struct pkt *inpkt, struct task *task,
		int word_id, unsigned int gen_id, int hash_num)
{
	if (word_id >= task->num_keys) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: word_id=%d, num_keys=%d\n",
				jtr_device_id(jtr_dev), inpkt_type_name(inpkt->type),
				inpkt->id, word_id, task->num_keys);
		return 0;
	}
	if (gen_id >= mask_num_cand()) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: gen_id=%u, mask_num_cand=%d\n",
				jtr_device_id(jtr_dev), inpkt_type_name(inpkt->type),
				inpkt->id, gen_id, mask_num_cand());
		return 0;
	}
	if (hash_num >= cmp_config.num_hashes) {
		if (PKT_DEBUG >= 1)
			fprintf(stderr, "%s %s id=%d: hash_num=%d, num_hashes=%d\n",
				jtr_device_id(jtr_dev), inpkt_type_name(inpkt->type),
				inpkt->id, hash_num, cmp_config.num_hashes);
		return 0;
	}
	return 1;
}


struct jtr_device *jtr_device_list_process_inpkt(
		struct task_list *task_list)
{
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next) {
		int bad_input = 0;

		// Fetch input packets from pkt_comm_queue
		struct pkt *inpkt;
		while ( (inpkt = pkt_queue_fetch(dev->comm->input_queue) ) ) {

			struct task *task = inpkt_check_task(inpkt, dev, task_list);
			if (!task) {
				// Bad packet from the device.
				pkt_delete(inpkt);
				bad_input = 1;
				break;
			}

			// Computed result received
			if (inpkt->type == PKT_TYPE_RESULT1) {

				struct pkt_result *pkt_result = pkt_result_new(inpkt);

				if (PKT_DEBUG >= 2)
					fprintf(stderr,"%s RESULT1 id=%d: w:%d g:%u\n",
						jtr_device_id(dev), pkt_result->id,
						pkt_result->word_id, pkt_result->gen_id);

				if (!inpkt_check_cmp(dev, inpkt, task, pkt_result->word_id,
						pkt_result->gen_id, -1)) {
					pkt_result_delete(pkt_result);
					bad_input = 1;
					break;
				}

				struct task_result *task_result = task_result_new(
					task, task->keys
					+ pkt_result->word_id * jtr_fmt_params->plaintext_length,
					!task->range_info ? NULL :
					task->range_info + pkt_result->word_id * MASK_FMT_INT_PLHDR,
					pkt_result->gen_id, NULL
				);

				task_result->binary = mem_alloc(pkt_result->result_len);
				memcpy(task_result->binary, pkt_result->result,
						pkt_result->result_len);

				pkt_result_delete(pkt_result);

				int expected_total = task->num_keys * mask_num_cand();
				task->num_processed ++;
				if (task->num_processed > expected_total) {
					fprintf(stderr, "%s RESULT1: keys=%d, "
						"mask=%d, processed=%u (must be %u)\n",
						jtr_device_id(dev), task->num_keys, mask_num_cand(),
						task->num_processed, expected_total);
					bad_input = 1;
					break;
				}
				else if (task->num_processed == expected_total) {
					task->status = TASK_COMPLETE;
				}
				task_update_mtime(task);

			// Comparator found equality & it sends computed result
			} else if (inpkt->type == PKT_TYPE_CMP_RESULT) {

				struct pkt_cmp_result *pkt_cmp_result
						= pkt_cmp_result_new(inpkt);

				if (PKT_DEBUG >= 2)
					fprintf(stderr,"%s CMP_RESULT id=%d: w:%d g:%u h:%d\n",
						jtr_device_id(dev),
						pkt_cmp_result->id, pkt_cmp_result->word_id,
						pkt_cmp_result->gen_id, pkt_cmp_result->hash_num);

				if (!inpkt_check_cmp(dev, inpkt, task,
						pkt_cmp_result->word_id, pkt_cmp_result->gen_id,
						pkt_cmp_result->hash_num)) {
					pkt_cmp_result_delete(pkt_cmp_result);
					bad_input = 1;
					break;
				}

				struct task_result *task_result = task_result_new(
					task, task->keys
					+ pkt_cmp_result->word_id * jtr_fmt_params->plaintext_length,
					!task->range_info ? NULL :
					task->range_info + pkt_cmp_result->word_id * MASK_FMT_INT_PLHDR,
					pkt_cmp_result->gen_id,
					cmp_config.pw[pkt_cmp_result->hash_num]
				);

				task_result->binary = mem_alloc(pkt_cmp_result->result_len);
				memcpy(task_result->binary, pkt_cmp_result->result,
						pkt_cmp_result->result_len);

				pkt_cmp_result_delete(pkt_cmp_result);


			// Comparator found equality
			} else if (inpkt->type == PKT_TYPE_CMP_EQUAL) {

				struct pkt_equal *pkt_equal = pkt_equal_new(inpkt);

				if (PKT_DEBUG >= 2)
					fprintf(stderr,"%s CMP_EQUAL id=%d: w:%d g:%u h:%d\n",
						jtr_device_id(dev),
						pkt_equal->id, pkt_equal->word_id,
						pkt_equal->gen_id, pkt_equal->hash_num);

				if (!inpkt_check_cmp(dev, inpkt, task,
						pkt_equal->word_id, pkt_equal->gen_id,
						pkt_equal->hash_num)) {
					free(pkt_equal);
					bad_input = 1;
					break;
				}

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

				// In a design with several onboard generators/arbiters,
				// each one sends PKT_DONE
				int expected_total = task->num_keys * mask_num_cand();

				if (PKT_DEBUG >= 2)
					fprintf(stderr, "%s PROCESSING_DONE id=%d: %u(+%d) of %d\n",
						jtr_device_id(dev), pkt_done->id,
						pkt_done->num_processed, task->num_processed,
						expected_total);

				task->num_processed += pkt_done->num_processed;
				free(pkt_done);

				if (task->num_processed > expected_total) {
					fprintf(stderr, "%s PROCESSING_DONE: keys=%d, "
						"mask=%d, processed=%u (must be %u)\n",
						jtr_device_id(dev), task->num_keys, mask_num_cand(),
						task->num_processed, expected_total);
					bad_input = 1;
					break;
				}
				else if (task->num_processed == expected_total) {
					task->status = TASK_COMPLETE;
					task_update_mtime(task);
				}

			// Unknown packet type
			} else {
				if (PKT_DEBUG >= 1)
					fprintf(stderr, "%s %s type=0x%02x id=%d: len=%d\n",
						jtr_device_id(dev), inpkt_type_name(inpkt->type),
						inpkt->type, inpkt->id, inpkt->data_len);
				pkt_delete(inpkt);
				bad_input = 1;
				break;
			}
		} // while (input packets)

		if (bad_input)
			// Incorrect packets received from jtr_device.
			return dev;

	} // for (jtr_device_list)

	return NULL;
}


	//libusb_exit(NULL);
