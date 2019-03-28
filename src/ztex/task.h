/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _TASK_H_
#define _TASK_H_

#include <sys/time.h>

#include "../loader.h"
#include "../mask_ext.h"
#include "../formats.h"

/*
 * Task.
 * - includes all the data required to perform computation
 * - is assigned to some device (part of the device) independent from
 * other devices from the point of view from JtR's core
 * - processed task (status == TASK_COMPLETE) can include the result.
 * - task.id is used by pkt_comm for pkt_id field
 */

enum task_status {
	TASK_NONE, TASK_UNASSIGNED, TASK_ASSIGNED, TASK_COMPLETE
};

struct task_result {
	struct task_result *next;
	char *key;	// "plaintext" or template key
	unsigned char *binary;
	struct db_password *pw;
};

struct task_result_list {
	int count;
	struct task_result *result_list;
	struct task_result **index;
};

struct task {
	struct task *next;
	enum task_status status;

	// for now, all tasks have same comparator configuration
	//int cmp_config_id;
	// Global cmp_config
	//struct cmp_config *cmp_config;

	int num_keys;
	char *keys;
	unsigned char *range_info; // NULL if no mask

	struct task_result_list result_list;
	struct jtr_device *jtr_device;
	int id; // ID is 16-bit, unique within jtr_device

	struct timeval mtime; // status modification time
	int num_processed;
};

struct task_list {
	struct task *task;
};

// Forward declarations
struct jtr_device_list;


// Adds newly created 'struct task_result' to task_result_list
// Copies 'key' inside 'struct task_result', if mask was used
// then it reconstructs plaintext.
struct task_result *task_result_new(struct task *task,
		char *key, unsigned char *range_info,
		unsigned int gen_id, struct db_password *pw);

// inserts newly created 'struct task' into 'task_list'
struct task *task_new(struct task_list *task_list,
		int num_keys, char *keys,
		unsigned char *range_info);

// Create output packet communication data out of task content
// and place that into output queue of device associated with task
void task_create_output_pkt_comm(struct task *task);

// Assign task to the device, call task_create_output_pkt_comm().
void task_assign(struct task *task, struct jtr_device *jtr_device);

// Deassign task.
void task_deassign(struct task *task);

// Update status change time
inline static void task_update_mtime(struct task *task)
{
	gettimeofday(&task->mtime, NULL);
}

// ! does not update task_list
void task_delete(struct task *task);

// create 1 task for each jtr_device
// equally distribute load among tasks assuming all devices are equal
// assign tasks to jtr_devices
struct task_list *task_list_create(int num_keys,
		char *keys, unsigned char *range_info);

// find task by ID and jtr_device *
struct task *task_find(struct task_list *task_list,
		struct jtr_device *jtr_device, int id);

// find 1st task in a list with given task_status
struct task *task_find_by_status(struct task_list *task_list,
		enum task_status status);

// find 1st assigned task with status change time less than given seconds
struct task *task_find_by_mtime(struct task_list *task_list, int tv_sec);

// assign unassigned tasks, equally distribute among jtr_devices
void tasks_assign(struct task_list *task_list,
		struct jtr_device_list *jtr_device_list);

// for tasks assigned to given jtr_device -
// remove association with the device, set status TASK_UNASSIGNED
// if tasks already have some results - remove results
// returns number of affected tasks
int tasks_deassign(struct task_list *task_list, struct jtr_device *jtr_device);

// count tasks that have specified status
int task_list_count_by_status(struct task_list *task_list,
		enum task_status status);

// Returns true if all tasks have TASK_COMPLETE status
int task_list_all_completed(struct task_list *task_list);

// Returns total count of task_result's in a task_list
int task_list_result_count(struct task_list *task_list);

// execute given function for each task_result
void task_result_execute(struct task_list *task_list,
		void (*func)(struct task_result *result));

// Creates index, required by task_result_by_index()
void task_list_create_index(struct task_list *task_list);

// Returns task_result at given index (NULL if none)
struct task_result *task_result_by_index(struct task_list *task_list, int index);

void task_list_delete(struct task_list *task_list);


#endif
