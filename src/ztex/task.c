/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../memory.h"

#include "task.h"
#include "jtr_device.h"
#include "jtr_mask.h"

#include "pkt_comm/pkt_comm.h"
#include "pkt_comm/word_list.h"
#include "pkt_comm/word_gen.h"
#include "pkt_comm/cmp_config.h"



static void task_result_list_init(struct task_result_list *list)
{
	list->count = 0;
	list->result_list = NULL;
	list->index = NULL;
}


static void task_result_list_add(struct task_result_list *list,
		struct task_result *task_result)
{
	task_result->next = list->result_list;
	list->result_list = task_result;
	list->count++;
	//MEM_FREE(list->index);
}


static void task_result_list_create_index(struct task_result_list *list)
{
	MEM_FREE(list->index);
	if (!list->count)
		return;

	list->index = mem_alloc(list->count * sizeof(struct task_result *));

	struct task_result *result;
	int i = 0;
	for (result = list->result_list; result; result = result->next)
		list->index[i++] = result;
}


struct task_result *task_result_new(struct task *task,
		char *key, unsigned char *range_info,
		unsigned int gen_id, struct db_password *pw)
{
	struct task_result *result = mem_alloc(sizeof(struct task_result));

	int plaintext_len = jtr_fmt_params->plaintext_length;
	result->key = mem_alloc(plaintext_len + 1);
	result->key[plaintext_len] = 0;
	memcpy(result->key, key, plaintext_len);

	if (range_info)
		mask_reconstruct_plaintext(result->key, range_info, gen_id);

	result->pw = pw;
	result->binary = NULL;

	task_result_list_add(&task->result_list, result);
	return result;
}


static int task_result_count(struct task *task)
{
	return task->result_list.count;
}


static void task_result_list_clear(struct task_result_list *list)
{
	if (!list) {
		fprintf(stderr,"task_result_list_clear: NULL\n");
		return;
	}
	if (!list->result_list) {
		if (list->count)
			fprintf(stderr,"task_result_list_clear: result_list=NULL,"
				" count=%d\n", list->count);
		return;
	}

	struct task_result *result = list->result_list;
	while (1) {
		struct task_result *next = result->next;
		MEM_FREE(result->key);
		MEM_FREE(result->binary);
		MEM_FREE(result);
		if (!next)
			break;
		result = next;
	}
	list->count = 0;
	MEM_FREE(list->index);
	list->result_list = NULL;
}


struct task *task_new(struct task_list *task_list,
		int num_keys, char *keys,
		unsigned char *range_info)
{
	struct task *task = mem_alloc(sizeof(struct task));

	task->next = task_list->task;
	task_list->task = task;

	task->status = TASK_NONE;
	task->num_keys = num_keys;
	task->keys = keys;
	task->range_info = range_info;
	task_result_list_init(&task->result_list);
	task->jtr_device = NULL;
	task->id = 0;

	static struct timeval zero_time = { 0, 0 };
	task->mtime = zero_time;

	task->num_processed = 0;
	return task;
}


void task_assign(struct task *task, struct jtr_device *jtr_device)
{
	task->jtr_device = jtr_device;
	task->id = jtr_device->task_id_next++; // TODO: move 3 lines to jtr_device.c
	if (jtr_device->task_id_next == 65536)
		jtr_device->task_id_next = 1;
	task->status = TASK_ASSIGNED;
	task_update_mtime(task);
	task_create_output_pkt_comm(task);
}


void task_delete(struct task *task)
{
	task_result_list_clear(&task->result_list);
	MEM_FREE(task);
}


struct task_list *task_list_create(int num_keys,
		char *keys, unsigned char *range_info)
{
	// distribute keys equally among devices
	int num_devices = jtr_device_list_count();
	if (!num_devices)
		return NULL;

	struct task_list *task_list = mem_alloc(sizeof(struct task_list));
	task_list->task = NULL;

	if (!num_keys) {
		fprintf(stderr, "task_list_create: num_keys=0\n");
		error();
	}

	int keys_per_device = num_keys / num_devices;
	int num_extra_keys = num_keys % num_devices;

	int keys_buffer_offset = 0;
	int range_info_offset = 0;
	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next) {

		int device_num_keys = keys_per_device;
		if (num_extra_keys) {
			device_num_keys++;
			num_extra_keys--;
		}

		// No more keys for this device and remaining ones
		if (!device_num_keys)
			break;

		// Number of keys in word_list/template_list is 16 bit value.
		// There's also a limit on packet's data length.
		// Create several tasks if necessary.
		while (device_num_keys) {
			// TODO: maybe create tasks of equal size
			int task_num_keys = device_num_keys;
			if (task_num_keys * jtr_fmt_params->plaintext_length
					> PKT_MAX_DATA_LEN)
				task_num_keys = PKT_MAX_DATA_LEN
					/ jtr_fmt_params->plaintext_length;
			if (task_num_keys > 65535)
				task_num_keys = 65535;
			device_num_keys -= task_num_keys;

			struct task *task = task_new(task_list, task_num_keys,
					keys + keys_buffer_offset,
					range_info ? range_info + range_info_offset : NULL);
			task_assign(task, dev);

			keys_buffer_offset += task_num_keys * jtr_fmt_params->plaintext_length;
			if (range_info)
				range_info_offset += task_num_keys * MASK_FMT_INT_PLHDR;
		}
	}

	return task_list;
}


void tasks_assign(struct task_list *task_list,
		struct jtr_device_list *jtr_device_list)
{
	int num_tasks = task_list_count_by_status(task_list, TASK_UNASSIGNED);
	if (!num_tasks)
		return;

	int jtr_device_count = jtr_device_list_count();
	if (!jtr_device_count)
		return;

	int min_tasks_per_device = num_tasks / jtr_device_count;
	int extra_tasks = num_tasks % jtr_device_count;

	struct jtr_device *dev;
	for (dev = jtr_device_list->device; dev; dev = dev->next) {
		int i;
		for (i = 0; i < min_tasks_per_device; i++) {
			struct task *task = task_find_by_status(task_list, TASK_UNASSIGNED);
			if (!task) {
				fprintf(stderr, "Error: task not found 1!\n");
				break;
			}
			task_assign(task, dev);
		}
		if (extra_tasks) {
			struct task *task = task_find_by_status(task_list, TASK_UNASSIGNED);
			if (!task) {
				fprintf(stderr, "Error: task not found 2!\n");
				break;
			}
			task_assign(task, dev);
			extra_tasks--;
		}
	}

}


void task_deassign(struct task *task)
{
	task_result_list_clear(&task->result_list);
	task->num_processed = 0;
	task->status = TASK_UNASSIGNED;
	task_update_mtime(task);
	task->jtr_device = NULL;
}


int tasks_deassign(struct task_list *task_list, struct jtr_device *jtr_device)
{
	int count = 0;
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		if (task->status == TASK_ASSIGNED && task->jtr_device == jtr_device) {
			task_deassign(task);
			count++;
		}
	}
	return count;
}


struct task *task_find(struct task_list *task_list,
		struct jtr_device *jtr_device, int id)
{
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		if (task->id == id && task->jtr_device == jtr_device)
			return task;
	}
	return NULL;
}


struct task *task_find_by_status(struct task_list *task_list,
		enum task_status status)
{
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		if (task->status == status)
			return task;
	}
	return NULL;
}


struct task *task_find_by_mtime(struct task_list *task_list, int tv_sec)
{
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		if (task->status == TASK_ASSIGNED && task->mtime.tv_sec < tv_sec)
			return task;
	}
	return NULL;
}


void task_create_output_pkt_comm(struct task *task)
{
	struct jtr_device *dev = task->jtr_device;
	if (!dev || task->status != TASK_ASSIGNED) {
		fprintf(stderr, "task_list_create_output_pkt_comm: unassigned task\n");
		error();
	}
	if (!task->num_keys || !task->keys) {
		fprintf(stderr, "task_list_create_output_pkt_comm: task contains nothing\n");
		error();
	}
//fprintf(stderr,"task_create_output_pkt_comm\n");

	// TODO: check if input queues are not full

	// If on-device comparator is unconfigured or its configuration changes
	//
	// Issue. While sequential_id doesn't change, the content can change
	// (hash removed). For now, re-create and resend cmp_config every time.
	//
	//if (dev->cmp_config_id == -1 || dev->cmp_config_id != cmp_config.id) {
	if (1) {
		struct pkt *pkt_cmp_config = pkt_cmp_config_new(&cmp_config);
		if (!pkt_cmp_config) {
			// some wrong input / internal error
			fprintf(stderr, "task_list_create_output_pkt_comm: pkt_cmp_config_new\n");
			exit(-1);
		}
		pkt_queue_push(dev->comm->output_queue, pkt_cmp_config);
		dev->cmp_config_id = cmp_config.id;
		//fprintf(stderr, "dev: %s cmp_config_id: %d num_hashes:%d\n",
		//		dev->device->ztex_device->snString, dev->cmp_config_id,
		//		cmp_config.num_hashes );
	}

	// Create and enqueue word generator configuration
	//
	struct pkt *pkt_word_gen = pkt_word_gen_new(mask_convert_to_word_gen());
	pkt_word_gen->id = task->id;
	pkt_queue_push(dev->comm->output_queue, pkt_word_gen);


	// Create and enqueue template_list or word_list
	//
	struct pkt *pkt_list;
	if (task->range_info)
		pkt_list = pkt_template_list_new(task->keys, task->num_keys,
				jtr_fmt_params->plaintext_length,
				task->range_info, MASK_FMT_INT_PLHDR);
	else
		pkt_list = pkt_word_list_new(task->keys, task->num_keys,
				jtr_fmt_params->plaintext_length);

	pkt_queue_push(dev->comm->output_queue, pkt_list);
}


int task_list_count_by_status(struct task_list *task_list,
		enum task_status status)
{
	int count = 0;
	struct task *task;
	for (task = task_list->task; task; task = task->next)
		if (task->status == status)
			count++;
	return count;
}


int task_list_all_completed(struct task_list *task_list)
{
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		if (task->status != TASK_COMPLETE)
			return 0;
	}
	return 1;
}


int task_list_result_count(struct task_list *task_list)
{
	int count = 0;
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		count += task_result_count(task);
	}
	return count;
}


void task_result_execute(struct task_list *task_list,
		void (*func)(struct task_result *result))
{
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		struct task_result *result;
		for (result = task->result_list.result_list; result;
				result = result->next)
			func(result);
	}
}


void task_list_create_index(struct task_list *task_list)
{
	struct task *task;
	for (task = task_list->task; task; task = task->next)
		task_result_list_create_index(&task->result_list);
}


struct task_result *task_result_by_index(struct task_list *task_list, int index)
{
	int count = 0;
	struct task *task;
	for (task = task_list->task; task; task = task->next) {
		int cur_task_count = task_result_count(task);
		if (!cur_task_count)
			continue;
		if (count + cur_task_count <= index) {
			count += cur_task_count;
			continue;
		}
/*
		struct task_result *result;
		for (result = task->result_list.result_list; result;
				result = result->next) {
			if (count == index)
				return result;
			count++;
		}
*/

		if (!task->result_list.index) {
			fprintf(stderr,"task_result_by_index: index not created\n");
			return NULL;
		}
		//fprintf(stderr,"task_result_by_index: i:%d c:%d\n",index, count);
		return task->result_list.index[index - count];
	}
	return NULL;
}


void task_list_delete(struct task_list *task_list)
{
	if (!task_list)
		return;
	struct task *task = task_list->task;
	if (!task)
		return;

	while (1) {
		struct task *next = task->next;
		task_delete(task);
		if (!next)
			break;
		task = next;
	}
	MEM_FREE(task_list);
}
