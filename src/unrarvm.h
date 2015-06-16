/*
 * Extract RAR archives
 *
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 * Copyright (C) 2005-2006 trog@uncon.org
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */


#ifndef _RAR_VM_
#define _RAR_VM_

#include "unrarcmd.h"

#define RARVM_MEMSIZE	0x40000
#define RARVM_MEMMASK	(RARVM_MEMSIZE-1)

#define VM_GLOBALMEMADDR            0x3C000
#define VM_GLOBALMEMSIZE             0x2000
#define VM_FIXEDGLOBALSIZE               64

typedef enum rarvm_commands
{
  VM_MOV,  VM_CMP,  VM_ADD,  VM_SUB,  VM_JZ,   VM_JNZ,  VM_INC,  VM_DEC,
  VM_JMP,  VM_XOR,  VM_AND,  VM_OR,   VM_TEST, VM_JS,   VM_JNS,  VM_JB,
  VM_JBE,  VM_JA,   VM_JAE,  VM_PUSH, VM_POP,  VM_CALL, VM_RET,  VM_NOT,
  VM_SHL,  VM_SHR,  VM_SAR,  VM_NEG,  VM_PUSHA,VM_POPA, VM_PUSHF,VM_POPF,
  VM_MOVZX,VM_MOVSX,VM_XCHG, VM_MUL,  VM_DIV,  VM_ADC,  VM_SBB,  VM_PRINT,
  VM_MOVB, VM_MOVD, VM_CMPB, VM_CMPD, VM_ADDB, VM_ADDD, VM_SUBB, VM_SUBD,
  VM_INCB, VM_INCD, VM_DECB, VM_DECD, VM_NEGB, VM_NEGD, VM_STANDARD
} rarvm_commands_t;

typedef enum rarvm_standard_filters {
  VMSF_NONE, VMSF_E8, VMSF_E8E9, VMSF_ITANIUM, VMSF_RGB, VMSF_AUDIO,
  VMSF_DELTA, VMSF_UPCASE
} rarvm_standard_filters_t;

enum VM_Flags {
	VM_FC=1,
	VM_FZ=2,
	VM_FS=0x80000000
};

enum rarvm_op_type {
	VM_OPREG,
	VM_OPINT,
	VM_OPREGMEM,
	VM_OPNONE
};

struct rarvm_prepared_operand {
	unsigned int *addr;
	enum rarvm_op_type type;
	unsigned int data;
	unsigned int base;
};

struct rarvm_prepared_command {
	rarvm_commands_t op_code;
	int byte_mode;
	struct rarvm_prepared_operand op1, op2;
};

struct rarvm_prepared_program {
	rar_cmd_array_t cmd;
	struct rarvm_prepared_command *alt_cmd;
	unsigned char *global_data;
	unsigned char *static_data;
	unsigned char *filtered_data;
	long global_size, static_size;
	int cmd_count;
	unsigned int init_r[7];
	unsigned int filtered_data_size;
};

typedef struct rarvm_input_tag {
	unsigned char *in_buf;
	int buf_size;
	int in_addr;
	int in_bit;
} rarvm_input_t;

typedef struct rarvm_data_tag {
	unsigned char *mem;
	unsigned int R[8];
	unsigned int Flags;
} rarvm_data_t;

unsigned int rarvm_getbits(rarvm_input_t *rarvm_input);
void rarvm_addbits(rarvm_input_t *rarvm_input, int bits);
int rarvm_init(rarvm_data_t *rarvm_data);
void rarvm_free(rarvm_data_t *rarvm_data);
int rarvm_prepare(rarvm_data_t *rarvm_data, rarvm_input_t *rarvm_input, unsigned char *code,
		int code_size, struct rarvm_prepared_program *prg);
void rarvm_set_memory(rarvm_data_t *rarvm_data, unsigned int pos, unsigned char *data, unsigned int data_size);
int rarvm_execute(rarvm_data_t *rarvm_data, struct rarvm_prepared_program *prg);
void rarvm_set_value(int byte_mode, unsigned int *addr, unsigned int value);
unsigned int rarvm_read_data(rarvm_input_t *rarvm_input);
unsigned int rar_crc(unsigned int start_crc, void *addr, unsigned int size);
#endif
