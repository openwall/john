/*
 *  Extract RAR archives
 *
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *  Patches added by Sourcefire, Inc. Copyright (C) 2007-2013
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "arch.h"

#include <stdio.h>
#include <string.h>
#include "aes.h"

#include "unrar.h"
#include "unrarvm.h"
#include "unrarcmd.h"
#include "common.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
//static void rar_dbgmsg(const char* fmt,...){(void)fmt;}
#endif

#define VMCF_OP0             0
#define VMCF_OP1             1
#define VMCF_OP2             2
#define VMCF_OPMASK          3
#define VMCF_BYTEMODE        4
#define VMCF_JUMP            8
#define VMCF_PROC           16
#define VMCF_USEFLAGS       32
#define VMCF_CHFLAGS        64

#define UINT32(x)  (sizeof(unsigned int)==4 ? (unsigned int)(x):((x)&0xffffffff))

#if ARCH_LITTLE_ENDIAN
#define GET_VALUE(byte_mode,addr) ((byte_mode) ? (*(unsigned char *)(addr)) : UINT32((*(unsigned int *)(addr))))
#else
#define GET_VALUE(byte_mode,addr) ((byte_mode) ? (*(unsigned char *)(addr)) : (((unsigned char *)addr)[0] | ((unsigned char *)addr)[1]<<8 | ((unsigned char *)addr)[2]<<16 | ((unsigned char *)addr)[3]<<24))
#endif

#if ARCH_LITTLE_ENDIAN
#define SET_VALUE(byte_mode,addr,value) (void)(((byte_mode) ? (*(unsigned char *)(addr)=(value)):(*(unsigned int *)(addr)=((unsigned int)(value)))))
#else
#define SET_VALUE(byte_mode,addr,value) rarvm_set_value(byte_mode, (unsigned int *)addr, value);
#endif

#define SET_IP(IP)                      \
  if ((IP)>=(unsigned int)code_size)                   \
    return 1;                       \
  if (--max_ops<=0)                  \
    return 0;                      \
  cmd=prepared_code+(IP);

static unsigned char vm_cmdflags[]=
{
  /* VM_MOV   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_CMP   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_ADD   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SUB   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JZ    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JNZ   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_INC   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_DEC   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JMP   */ VMCF_OP1 | VMCF_JUMP                                    ,
  /* VM_XOR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_AND   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_OR    */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_TEST  */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_JS    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JNS   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JB    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JBE   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JA    */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_JAE   */ VMCF_OP1 | VMCF_JUMP | VMCF_USEFLAGS                    ,
  /* VM_PUSH  */ VMCF_OP1                                                ,
  /* VM_POP   */ VMCF_OP1                                                ,
  /* VM_CALL  */ VMCF_OP1 | VMCF_PROC                                    ,
  /* VM_RET   */ VMCF_OP0 | VMCF_PROC                                    ,
  /* VM_NOT   */ VMCF_OP1 | VMCF_BYTEMODE                                ,
  /* VM_SHL   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SHR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_SAR   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_NEG   */ VMCF_OP1 | VMCF_BYTEMODE | VMCF_CHFLAGS                 ,
  /* VM_PUSHA */ VMCF_OP0                                                ,
  /* VM_POPA  */ VMCF_OP0                                                ,
  /* VM_PUSHF */ VMCF_OP0 | VMCF_USEFLAGS                                ,
  /* VM_POPF  */ VMCF_OP0 | VMCF_CHFLAGS                                 ,
  /* VM_MOVZX */ VMCF_OP2                                                ,
  /* VM_MOVSX */ VMCF_OP2                                                ,
  /* VM_XCHG  */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_MUL   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_DIV   */ VMCF_OP2 | VMCF_BYTEMODE                                ,
  /* VM_ADC   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_USEFLAGS | VMCF_CHFLAGS ,
  /* VM_SBB   */ VMCF_OP2 | VMCF_BYTEMODE | VMCF_USEFLAGS | VMCF_CHFLAGS ,
  /* VM_PRINT */ VMCF_OP0
};

const unsigned int crc_tab[256]={
	0x0,        0x77073096, 0xee0e612c, 0x990951ba, 0x76dc419,  0x706af48f, 0xe963a535, 0x9e6495a3,
	0xedb8832,  0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x9b64c2b,  0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x1db7106,  0x98d220bc, 0xefd5102a, 0x71b18589, 0x6b6b51f,  0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0xf00f934,  0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x86d3d2d,  0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x3b6e20c,  0x74b1d29a, 0xead54739, 0x9dd277af, 0x4db2615,  0x73dc1683,
	0xe3630b12, 0x94643b84, 0xd6d6a3e,  0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0xa00ae27,  0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x26d930a,  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x5005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0xcb61b38,  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0xbdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

void rarvm_set_value(int byte_mode, unsigned int *addr, unsigned int value)
{
	if (byte_mode) {
		*(unsigned char *)addr=value;
	} else {
#if ARCH_LITTLE_ENDIAN
		*(unsigned int *)addr = value;
#else
		((unsigned char *)addr)[0]=(unsigned char)value;
		((unsigned char *)addr)[1]=(unsigned char)(value>>8);
		((unsigned char *)addr)[2]=(unsigned char)(value>>16);
		((unsigned char *)addr)[3]=(unsigned char)(value>>24);
#endif
	}
}

unsigned int rar_crc(unsigned int start_crc, void *addr, unsigned int size)
{
	unsigned char *data;
	size_t i;

	data = addr;
#if ARCH_LITTLE_ENDIAN
	while (size > 0 && ((size_t)data & 7))
	{
		start_crc = crc_tab[(unsigned char)(start_crc^data[0])]^(start_crc>>8);
		size--;
		data++;
	}
	while (size >= 8)
	{
		start_crc ^= *(unsigned int *) data;
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc ^= *(unsigned int *)(data+4);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		start_crc = crc_tab[(unsigned char)start_crc] ^ (start_crc>>8);
		data += 8;
		size -= 8;
	}
#endif
	for (i=0 ; i < size ; i++) {
		start_crc = crc_tab[(unsigned char)(start_crc^data[i])]^(start_crc >> 8);
	}
	return start_crc;
}

int rarvm_init(rarvm_data_t *rarvm_data)
{
	rarvm_data->mem = (unsigned char *) rar_malloc(RARVM_MEMSIZE+4);
	if (!rarvm_data->mem) {
		return 0;
	}
	return 1;
}

void rarvm_free(rarvm_data_t *rarvm_data)
{
	if (rarvm_data && rarvm_data->mem) {
		MEM_FREE(rarvm_data->mem);
		rarvm_data->mem = NULL;
	}
}

void rarvm_addbits(rarvm_input_t *rarvm_input, int bits)
{
	bits += rarvm_input->in_bit;
	rarvm_input->in_addr += bits >> 3;
	rarvm_input->in_bit = bits & 7;
}

unsigned int rarvm_getbits(rarvm_input_t *rarvm_input)
{
	unsigned int bit_field = 0;

	if (rarvm_input->in_addr < rarvm_input->buf_size) {
		bit_field = (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr] << 16;
		if (rarvm_input->in_addr+1 < rarvm_input->buf_size) {
			bit_field |= (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr+1] << 8;
			if (rarvm_input->in_addr+2 < rarvm_input->buf_size) {
				bit_field |= (unsigned int) rarvm_input->in_buf[rarvm_input->in_addr+2];
			}
		}
	}
	bit_field >>= (8-rarvm_input->in_bit);

	return (bit_field & 0xffff);
}

unsigned int rarvm_read_data(rarvm_input_t *rarvm_input)
{
	unsigned int data;

	data = rarvm_getbits(rarvm_input);
	//rar_dbgmsg("rarvm_read_data getbits=%u\n", data);
	switch (data & 0xc000) {
	case 0:
		rarvm_addbits(rarvm_input,6);
		//rar_dbgmsg("rarvm_read_data=%u\n", ((data>>10)&0x0f));
		return ((data>>10)&0x0f);
	case 0x4000:
		if ((data & 0x3c00) == 0) {
			data = 0xffffff00 | ((data>>2) & 0xff);
			rarvm_addbits(rarvm_input,14);
		} else {
			data = (data >> 6) &0xff;
			rarvm_addbits(rarvm_input,10);
		}
		//rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	case 0x8000:
		rarvm_addbits(rarvm_input,2);
		data = rarvm_getbits(rarvm_input);
		rarvm_addbits(rarvm_input,16);
		//rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	default:
		rarvm_addbits(rarvm_input,2);
		data = (rarvm_getbits(rarvm_input) << 16);
		rarvm_addbits(rarvm_input,16);
		data |= rarvm_getbits(rarvm_input);
		rarvm_addbits(rarvm_input,16);
		//rar_dbgmsg("rarvm_read_data=%u\n", data);
		return data;
	}
}

static rarvm_standard_filters_t is_standard_filter(unsigned char *code, int code_size)
{
	unsigned int code_crc;
	size_t i;

	struct standard_filter_signature
	{
		int length;
		unsigned int crc;
		rarvm_standard_filters_t type;
	} std_filt_list[] = {
		{53,  0xad576887, VMSF_E8},
		{57,  0x3cd7e57e, VMSF_E8E9},
		{120, 0x3769893f, VMSF_ITANIUM},
		{29,  0x0e06077d, VMSF_DELTA},
		{149, 0x1c2c5dc8, VMSF_RGB},
		{216, 0xbc85e701, VMSF_AUDIO},
		{40,  0x46b9c560, VMSF_UPCASE}
	};

	code_crc = rar_crc(0xffffffff, code, code_size)^0xffffffff;
	//rar_dbgmsg("code_crc=%u\n", code_crc);
	for (i=0 ; i<sizeof(std_filt_list)/sizeof(std_filt_list[0]) ; i++) {
		if (std_filt_list[i].crc == code_crc && std_filt_list[i].length == code_size) {
			return std_filt_list[i].type;
		}
	}
	return VMSF_NONE;
}

void rarvm_set_memory(rarvm_data_t *rarvm_data, unsigned int pos, unsigned char *data, unsigned int data_size)
{
	if (pos<RARVM_MEMSIZE && data!=rarvm_data->mem+pos) {
		memmove(rarvm_data->mem+pos, data, MIN(data_size, RARVM_MEMSIZE-pos));
	}
}

static unsigned int *rarvm_get_operand(rarvm_data_t *rarvm_data,
				struct rarvm_prepared_operand *cmd_op)
{
	if (cmd_op->type == VM_OPREGMEM) {
		return ((unsigned int *)&rarvm_data->mem[(*cmd_op->addr+cmd_op->base) & RARVM_MEMMASK]);
	} else {
		return cmd_op->addr;
	}
}

static unsigned int filter_itanium_getbits(unsigned char *data, unsigned int bit_pos, unsigned int bit_count)
{
	unsigned int in_addr=bit_pos/8;
	unsigned int in_bit=bit_pos&7;
	unsigned int bit_field=(unsigned int)data[in_addr++];
	bit_field|=(unsigned int)data[in_addr++] << 8;
	bit_field|=(unsigned int)data[in_addr++] << 16;
	bit_field|=(unsigned int)data[in_addr] << 24;
	bit_field >>= in_bit;
	return(bit_field & (0xffffffff>>(32-bit_count)));
}

static void filter_itanium_setbits(unsigned char *data, unsigned int bit_field, unsigned int bit_pos, unsigned int bit_count)
{
	unsigned int i, in_addr=bit_pos/8;
	unsigned int in_bit=bit_pos&7;
	unsigned int and_mask=0xffffffff>>(32-bit_count);
	and_mask=~(and_mask<<in_bit);

	bit_field<<=in_bit;

	for (i=0 ; i<4 ; i++) {
		data[in_addr+i]&=and_mask;
		data[in_addr+i]|=bit_field;
		and_mask=(and_mask>>8)|0xff000000;
		bit_field>>=8;
	}
}

static void execute_standard_filter(rarvm_data_t *rarvm_data, rarvm_standard_filters_t filter_type)
{
	unsigned char *data, cmp_byte2, cur_byte, *src_data, *dest_data;
	unsigned int i, j, data_size, channels, src_pos, dest_pos, border, width, PosR;
	unsigned int op_type, cur_channel, byte_count, start_pos;
	int pa, pb, pc;
	unsigned int file_offset, cur_pos, predicted;
	uint32_t offset, addr;
	const unsigned int file_size=0x1000000;

	switch(filter_type) {
	case VMSF_E8:
	case VMSF_E8E9:
		data=rarvm_data->mem;
		data_size = rarvm_data->R[4];
		file_offset = rarvm_data->R[6];

		if ((data_size > VM_GLOBALMEMADDR) || (data_size < 4)) {
			break;
		}

		cmp_byte2 = filter_type==VMSF_E8E9 ? 0xe9:0xe8;
		for (cur_pos = 0 ; cur_pos < data_size-4 ; ) {
			cur_byte = *(data++);
			cur_pos++;
			if (cur_byte==0xe8 || cur_byte==cmp_byte2) {
				offset = cur_pos+file_offset;
				addr = GET_VALUE(0, data);
				// We check 0x80000000 bit instead of '< 0' comparison
				// not assuming int32 presence or uint size and endianness.
				if ((addr & 0x80000000)!=0) {              // addr<0
					if (((addr+offset) & 0x80000000)==0) {   // addr+offset>=0
						SET_VALUE(0, data, addr+file_size);
					}
				} else {
					if (((addr-file_size) & 0x80000000)!=0) { // addr<file_size
						SET_VALUE(0, data, addr-offset);
					}
				}
				data += 4;
				cur_pos += 4;
			}
		}
		break;
	case VMSF_ITANIUM:
		data=rarvm_data->mem;
		data_size = rarvm_data->R[4];
		file_offset = rarvm_data->R[6];

		if ((data_size > VM_GLOBALMEMADDR) || (data_size < 21)) {
			break;
		}

		cur_pos = 0;

		file_offset>>=4;

		while (cur_pos < data_size-21) {
			int Byte = (data[0] & 0x1f) - 0x10;
			if (Byte >= 0) {
				static unsigned char masks[16]={4,4,6,6,0,0,7,7,4,4,0,0,4,4,0,0};
				unsigned char cmd_mask = masks[Byte];

				if (cmd_mask != 0) {
					for (i=0 ; i <= 2 ; i++) {
						if (cmd_mask & (1<<i)) {
							start_pos = i*41+5;
							op_type = filter_itanium_getbits(data,
									start_pos+37, 4);
							if (op_type == 5) {
								offset = filter_itanium_getbits(data,
										start_pos+13, 20);
								filter_itanium_setbits(data,
									(offset-file_offset)
									&0xfffff,start_pos+13,20);
							}
						}
					}
				}
			}
			data += 16;
			cur_pos += 16;
			file_offset++;
		}
		break;
	case VMSF_DELTA:
		data_size = rarvm_data->R[4];
		channels = rarvm_data->R[0];
		src_pos = 0;
		border = data_size*2;

		SET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		if (data_size > VM_GLOBALMEMADDR/2 || channels > 1024 || channels == 0) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels ; cur_channel++) {
			unsigned char prev_byte = 0;
			for (dest_pos=data_size+cur_channel ; dest_pos<border ; dest_pos+=channels) {
				rarvm_data->mem[dest_pos] = (prev_byte -= rarvm_data->mem[src_pos++]);
			}
		}
		break;
	case VMSF_RGB: {
		const unsigned int channels=3;
		data_size = rarvm_data->R[4];
		width = rarvm_data->R[0] - 3;
		PosR = rarvm_data->R[1];
		src_data = rarvm_data->mem;
		dest_data = src_data + data_size;

		SET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		if (data_size > VM_GLOBALMEMADDR/2 || data_size < 3 || width > data_size || PosR > 2) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels; cur_channel++) {
			unsigned int prev_byte = 0;
			for (i=cur_channel ; i<data_size ; i+=channels) {
				if (i >= width+3) {
					unsigned char *upper_data = dest_data+i-width;
					unsigned int upper_byte = *upper_data;
					unsigned int upper_left_byte = *(upper_data-3);
					predicted = prev_byte+upper_byte-upper_left_byte;
					pa = abs((int)(predicted-prev_byte));
					pb = abs((int)(predicted-upper_byte));
					pc = abs((int)(predicted-upper_left_byte));
					if (pa <= pb && pa <= pc) {
						predicted = prev_byte;
					} else {
						if (pb <= pc) {
							predicted = upper_byte;
						} else {
							predicted = upper_left_byte;
						}
					}
				} else {
					predicted = prev_byte;
				}
				dest_data[i] = prev_byte = (unsigned char)(predicted-*(src_data++));
			}
		}
		for (i=PosR,border=data_size-2 ; i < border ; i+=3) {
			unsigned char g=dest_data[i+1];
			dest_data[i] += g;
			dest_data[i+2] += g;
		}
		break;
	}
	case VMSF_AUDIO: {
		unsigned int channels=rarvm_data->R[0];
		data_size = rarvm_data->R[4];
		src_data = rarvm_data->mem;
		dest_data = src_data + data_size;

		SET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		// In fact, audio channels never exceed 4.
		if (data_size > VM_GLOBALMEMADDR/2 || channels > 4 || channels == 0) {
			break;
		}
		for (cur_channel=0 ; cur_channel < channels ; cur_channel++) {
			unsigned int prev_byte = 0, prev_delta=0, Dif[7];
			int D, D1=0, D2=0, D3=0, K1=0, K2=0, K3=0;

			memset(Dif, 0, sizeof(Dif));

			for (i=cur_channel, byte_count=0 ; i<data_size ; i+=channels, byte_count++) {
				D3=D2;
				D2 = prev_delta-D1;
				D1 = prev_delta;

				predicted = 8*prev_byte+K1*D1+K2*D2+K3*D3;
				predicted = (predicted>>3) & 0xff;

				cur_byte = *(src_data++);

				predicted -= cur_byte;
				dest_data[i] = predicted;
				prev_delta = (signed char)(predicted-prev_byte);
				prev_byte = predicted;

				D=((signed char)cur_byte) << 3;

				Dif[0] += abs(D);
				Dif[1] += abs(D-D1);
				Dif[2] += abs(D+D1);
				Dif[3] += abs(D-D2);
				Dif[4] += abs(D+D2);
				Dif[5] += abs(D-D3);
				Dif[6] += abs(D+D3);

				if ((byte_count & 0x1f) == 0) {
					unsigned int min_dif=Dif[0], num_min_dif=0;
					Dif[0]=0;
					for (j=1 ; j<sizeof(Dif)/sizeof(Dif[0]) ; j++) {
						if (Dif[j] < min_dif) {
							min_dif = Dif[j];
							num_min_dif = j;
						}
						Dif[j]=0;
					}
					switch(num_min_dif) {
					case 1: if (K1>=-16) K1--; break;
					case 2: if (K1 < 16) K1++; break;
					case 3: if (K2>=-16) K2--; break;
					case 4: if (K2 < 16) K2++; break;
					case 5: if (K3>=-16) K3--; break;
					case 6: if (K3 < 16) K3++; break;
					}
				}
			}
		}
		break;
	}
	case VMSF_UPCASE:
		data_size = rarvm_data->R[4];
		src_pos = 0;
		dest_pos = data_size;
		if (data_size > VM_GLOBALMEMADDR/2) {
			break;
		}
		while (src_pos < data_size) {
			cur_byte = rarvm_data->mem[src_pos++];
			if (cur_byte==2 && (cur_byte=rarvm_data->mem[src_pos++]) != 2) {
				cur_byte -= 32;
			}
			rarvm_data->mem[dest_pos++]=cur_byte;
		}
		SET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x1c], dest_pos-data_size);
		SET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20], data_size);
		break;
	default: /* make gcc happy */
		break;
	}
}

static int rarvm_execute_code(rarvm_data_t *rarvm_data,
		struct rarvm_prepared_command *prepared_code, int code_size)
{
	int max_ops=25000000, i, SP;
	struct rarvm_prepared_command *cmd;
	unsigned int value1, value2, result, divider, FC, *op1, *op2;
	const int reg_count=sizeof(rarvm_data->R)/sizeof(rarvm_data->R[0]);

	//rar_dbgmsg("in rarvm_execute_code\n");
	cmd = prepared_code;
	while (1) {
		if (cmd > (prepared_code + code_size)) {
			//rar_dbgmsg("RAR: code overrun detected\n");
			return 0;
		}
		if (cmd < prepared_code) {
			//rar_dbgmsg("RAR: code underrun detected\n");
			return 0;
		}
		op1 = rarvm_get_operand(rarvm_data, &cmd->op1);
		op2 = rarvm_get_operand(rarvm_data, &cmd->op2);
		//rar_dbgmsg("op(%d) op_code: %d, op1=%u, op2=%u\n", 25000000-max_ops,
		//			cmd->op_code, op1, op2);
		switch(cmd->op_code) {
		case VM_MOV:
			SET_VALUE(cmd->byte_mode, op1, GET_VALUE(cmd->byte_mode, op2));
			break;
		case VM_MOVB:
			SET_VALUE(1, op1, GET_VALUE(1, op2));
			break;
		case VM_MOVD:
			SET_VALUE(0, op1, GET_VALUE(0, op2));
			break;
		case VM_CMP:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 - GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_CMPB:
			value1 = GET_VALUE(1, op1);
			result = UINT32(value1 - GET_VALUE(1, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_CMPD:
			value1 = GET_VALUE(0, op1);
			result = UINT32(value1 - GET_VALUE(0, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			break;
		case VM_ADD:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 + GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result<value1)|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_ADDB:
			SET_VALUE(1, op1, GET_VALUE(1, op1)+GET_VALUE(1, op2));
			break;
		case VM_ADDD:
			SET_VALUE(0, op1, GET_VALUE(0, op1)+GET_VALUE(0, op2));
			break;
		case VM_SUB:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 - GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : (result>value1)|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SUBB:
			SET_VALUE(1, op1, GET_VALUE(1, op1)-GET_VALUE(1, op2));
			break;
		case VM_SUBD:
			SET_VALUE(0, op1, GET_VALUE(0, op1)-GET_VALUE(0, op2));
			break;
		case VM_JZ:
			if ((rarvm_data->Flags & VM_FZ) != 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JNZ:
			if ((rarvm_data->Flags & VM_FZ) == 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_INC:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)+1);
			SET_VALUE(cmd->byte_mode, op1, result);
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_INCB:
			SET_VALUE(1, op1, GET_VALUE(1, op1)+1);
			break;
		case VM_INCD:
			SET_VALUE(0, op1, GET_VALUE(0, op1)+1);
			break;
		case VM_DEC:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)-1);
			SET_VALUE(cmd->byte_mode, op1, result);
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_DECB:
			SET_VALUE(1, op1, GET_VALUE(1, op1)-1);
			break;
		case VM_DECD:
			SET_VALUE(0, op1, GET_VALUE(0, op1)-1);
			break;
		case VM_JMP:
			SET_IP(GET_VALUE(0, op1));
			continue;
		case VM_XOR:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)^GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_AND:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)&GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_OR:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)|GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_TEST:
			result = UINT32(GET_VALUE(cmd->byte_mode, op1)&GET_VALUE(cmd->byte_mode, op2));
			rarvm_data->Flags = result==0 ? VM_FZ : result&VM_FS;
			break;
		case VM_JS:
			if ((rarvm_data->Flags & VM_FS) != 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JNS:
			if ((rarvm_data->Flags & VM_FS) == 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JB:
			if ((rarvm_data->Flags & VM_FC) != 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JBE:
			if ((rarvm_data->Flags & (VM_FC|VM_FZ)) != 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JA:
			if ((rarvm_data->Flags & (VM_FC|VM_FZ)) == 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_JAE:
			if ((rarvm_data->Flags & VM_FC) == 0) {
				SET_IP(GET_VALUE(0, op1));
				continue;
			}
			break;
		case VM_PUSH:
			rarvm_data->R[7] -= 4;
			SET_VALUE(0, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
				RARVM_MEMMASK],	GET_VALUE(0, op1));
			break;
		case VM_POP:
			SET_VALUE(0, op1, GET_VALUE(0,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK]));
			rarvm_data->R[7] += 4;
			break;
		case VM_CALL:
			rarvm_data->R[7] -= 4;
			SET_VALUE(0, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
					RARVM_MEMMASK], cmd-prepared_code+1);
			SET_IP(GET_VALUE(0, op1));
			continue;
		case VM_NOT:
			SET_VALUE(cmd->byte_mode, op1, ~GET_VALUE(cmd->byte_mode, op1));
			break;
		case VM_SHL:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 << value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 << (value2-1))&0x80000000 ? VM_FC:0);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SHR:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(value1 >> value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 >> (value2-1)) & VM_FC);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SAR:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			value2 = GET_VALUE(cmd->byte_mode, op1);
			result = UINT32(((int)value1) >> value2);
			rarvm_data->Flags = (result==0 ? VM_FZ : (result&VM_FS))|
				((value1 >> (value2-1)) & VM_FC);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_NEG:
			result = UINT32(-GET_VALUE(cmd->byte_mode, op1));
			rarvm_data->Flags = result==0 ? VM_FZ:VM_FC|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_NEGB:
			SET_VALUE(1, op1, -GET_VALUE(1, op1));
			break;
		case VM_NEGD:
			SET_VALUE(0, op1, -GET_VALUE(0, op1));
			break;
		case VM_PUSHA:
			for (i=0, SP=rarvm_data->R[7]-4 ; i<reg_count ; i++, SP-=4) {
				SET_VALUE(0,
					(unsigned int *)&rarvm_data->mem[SP & RARVM_MEMMASK],
					rarvm_data->R[i]);
			}
			rarvm_data->R[7] -= reg_count*4;
			break;
		case VM_POPA:
			for (i=0,SP=rarvm_data->R[7] ; i<reg_count ; i++, SP+=4) {
				rarvm_data->R[7-i] = GET_VALUE(0,
					(unsigned int *)&rarvm_data->mem[SP & RARVM_MEMMASK]);
			}
			break;
		case VM_PUSHF:
			rarvm_data->R[7] -= 4;
			SET_VALUE(0,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK],
				rarvm_data->Flags);
			break;
		case VM_POPF:
			rarvm_data->Flags = GET_VALUE(0,
				(unsigned int *)&rarvm_data->mem[rarvm_data->R[7] & RARVM_MEMMASK]);
			rarvm_data->R[7] += 4;
			break;
		case VM_MOVZX:
			SET_VALUE(0, op1, GET_VALUE(1, op2));
			break;
		case VM_MOVSX:
			SET_VALUE(0, op1, (signed char)GET_VALUE(1, op2));
			break;
		case VM_XCHG:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			SET_VALUE(cmd->byte_mode, op1, GET_VALUE(cmd->byte_mode, op2));
			SET_VALUE(cmd->byte_mode, op2, value1);
			break;
		case VM_MUL:
			result = GET_VALUE(cmd->byte_mode, op1) * GET_VALUE(cmd->byte_mode, op2);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_DIV:
			divider = GET_VALUE(cmd->byte_mode, op2);
			if (divider != 0) {
				result = GET_VALUE(cmd->byte_mode, op1) / divider;
				SET_VALUE(cmd->byte_mode, op1, result);
			}
			break;
		case VM_ADC:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			FC = (rarvm_data->Flags & VM_FC);
			result = UINT32(value1+GET_VALUE(cmd->byte_mode, op2)+FC);
			rarvm_data->Flags = result==0 ? VM_FZ:(result<value1 ||
				(result==value1 && FC))|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_SBB:
			value1 = GET_VALUE(cmd->byte_mode, op1);
			FC = (rarvm_data->Flags & VM_FC);
			result = UINT32(value1-GET_VALUE(cmd->byte_mode, op2)-FC);
			rarvm_data->Flags = result==0 ? VM_FZ:(result>value1 ||
				(result==value1 && FC))|(result&VM_FS);
			SET_VALUE(cmd->byte_mode, op1, result);
			break;
		case VM_RET:
			if (rarvm_data->R[7] >= RARVM_MEMSIZE) {
				return 1;
			}
			SET_IP(GET_VALUE(0, (unsigned int *)&rarvm_data->mem[rarvm_data->R[7] &
				RARVM_MEMMASK]));
			rarvm_data->R[7] += 4;
			continue;
		case VM_STANDARD:
			execute_standard_filter(rarvm_data,
					(rarvm_standard_filters_t)cmd->op1.data);
			break;
		case VM_PRINT:
			/* DEBUG */
			break;
		}
		cmd++;
		--max_ops;
	}
}

int rarvm_execute(rarvm_data_t *rarvm_data, struct rarvm_prepared_program *prg)
{
	unsigned int global_size, static_size, new_pos, new_size, data_size;
	struct rarvm_prepared_command *prepared_code;

	//rar_dbgmsg("in rarvm_execute\n");
	memcpy(rarvm_data->R, prg->init_r, sizeof(prg->init_r));
	global_size = MIN(prg->global_size, VM_GLOBALMEMSIZE);
	if (global_size) {
		memcpy(rarvm_data->mem+VM_GLOBALMEMADDR, &prg->global_data[0], global_size);
	}
	static_size = MIN(prg->static_size, VM_GLOBALMEMSIZE-global_size);
	if (static_size) {
		memcpy(rarvm_data->mem+VM_GLOBALMEMADDR+global_size,
				&prg->static_data[0], static_size);
	}

	rarvm_data->R[7] = RARVM_MEMSIZE;
	rarvm_data->Flags = 0;

	prepared_code=prg->alt_cmd ? prg->alt_cmd : &prg->cmd.array[0];
	if (!prepared_code) {
	    //rar_dbgmsg("unrar: rarvm_execute: prepared_code == NULL\n");
	    return 0;
	}
	if (!rarvm_execute_code(rarvm_data, prepared_code, prg->cmd_count)) {
		prepared_code[0].op_code = VM_RET;
	}
	new_pos = GET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x20])&RARVM_MEMMASK;
	new_size = GET_VALUE(0, &rarvm_data->mem[VM_GLOBALMEMADDR+0x1c])&RARVM_MEMMASK;
	if (new_pos+new_size >= RARVM_MEMSIZE) {
		new_pos = new_size = 0;
	}
	prg->filtered_data = rarvm_data->mem + new_pos;
	prg->filtered_data_size = new_size;

	if (prg->global_data) {
		MEM_FREE(prg->global_data);
		prg->global_data = NULL;
		prg->global_size = 0;
	}
	data_size = MIN(GET_VALUE(0,
		(unsigned int *)&rarvm_data->mem[VM_GLOBALMEMADDR+0x30]),VM_GLOBALMEMSIZE);
	if (data_size != 0) {
		prg->global_size += data_size+VM_FIXEDGLOBALSIZE;
		prg->global_data = rar_realloc2(prg->global_data, prg->global_size);
		if (!prg->global_data) {
		    //rar_dbgmsg("unrar: rarvm_execute: rar_realloc2 failed for prg->global_data\n");
		    return 0;
		}
		memcpy(prg->global_data, &rarvm_data->mem[VM_GLOBALMEMADDR],
				data_size+VM_FIXEDGLOBALSIZE);
	}

	return 1;
}

static void rarvm_decode_arg(rarvm_data_t *rarvm_data, rarvm_input_t *rarvm_input,
		struct rarvm_prepared_operand *op, int byte_mode)
{
	unsigned short data;

	data = rarvm_getbits(rarvm_input);
	if (data & 0x8000) {
		op->type = VM_OPREG;
		op->data = (data >> 12) & 7;
		op->addr = &rarvm_data->R[op->data];
		rarvm_addbits(rarvm_input,4);
	} else if ((data & 0xc000) == 0) {
		op->type = VM_OPINT;
		if (byte_mode) {
			op->data = (data>>6) & 0xff;
			rarvm_addbits(rarvm_input,10);
		} else {
			rarvm_addbits(rarvm_input,2);
			op->data = rarvm_read_data(rarvm_input);
		}
	} else {
		op->type = VM_OPREGMEM;
		if ((data & 0x2000) == 0) {
			op->data = (data >> 10) & 7;
			op->addr = &rarvm_data->R[op->data];
			op->base = 0;
			rarvm_addbits(rarvm_input,6);
		} else {
			if ((data & 0x1000) == 0) {
				op->data = (data >> 9) & 7;
				op->addr = &rarvm_data->R[op->data];
				rarvm_addbits(rarvm_input,7);
			} else {
				op->data = 0;
				rarvm_addbits(rarvm_input,4);
			}
			op->base = rarvm_read_data(rarvm_input);
		}
	}
}

static void rarvm_optimize(struct rarvm_prepared_program *prg)
{
	struct rarvm_prepared_command *code, *cmd;
	int code_size, i, flags_required, j, flags;

	code = prg->cmd.array;
	code_size = prg->cmd_count;

	for (i=0 ; i < code_size ; i++) {
		cmd = &code[i];
		switch(cmd->op_code) {
			case VM_MOV:
				cmd->op_code = cmd->byte_mode ? VM_MOVB:VM_MOVD;
				continue;
			case VM_CMP:
				cmd->op_code = cmd->byte_mode ? VM_CMPB:VM_CMPD;
				continue;
			default: /* make gcc happy */
				break;
		}
		if (cmd->op_code > VM_PRINT) {
			continue; /* don't re-optimize, unlikely anyway */
		}
		if ((vm_cmdflags[cmd->op_code] & VMCF_CHFLAGS) == 0) {
			continue;
		}
		flags_required = 0;
		for (j=i+1 ; j < code_size ; j++) {
			flags = vm_cmdflags[code[j].op_code];
			if (flags & (VMCF_JUMP|VMCF_PROC|VMCF_USEFLAGS)) {
				flags_required=1;
				break;
			}
			if (flags & VMCF_CHFLAGS) {
				break;
			}
		}
		if (flags_required) {
			continue;
		}
		switch(cmd->op_code) {
			case VM_ADD:
				cmd->op_code = cmd->byte_mode ? VM_ADDB:VM_ADDD;
				continue;
			case VM_SUB:
				cmd->op_code = cmd->byte_mode ? VM_SUBB:VM_SUBD;
				continue;
			case VM_INC:
				cmd->op_code = cmd->byte_mode ? VM_INCB:VM_INCD;
				continue;
			case VM_DEC:
				cmd->op_code = cmd->byte_mode ? VM_DECB:VM_DECD;
				continue;
			case VM_NEG:
				cmd->op_code = cmd->byte_mode ? VM_NEGB:VM_NEGD;
				continue;
			default: /* make gcc happy */
				break;
		}
	}
}

int rarvm_prepare(rarvm_data_t *rarvm_data, rarvm_input_t *rarvm_input, unsigned char *code,
		int code_size, struct rarvm_prepared_program *prg)
{
	unsigned char xor_sum;
	int i, op_num, distance;
	rarvm_standard_filters_t filter_type;
	struct rarvm_prepared_command *cur_cmd;
	unsigned int data_flag, data;
	struct rarvm_prepared_command *cmd;

	//rar_dbgmsg("in rarvm_prepare code_size=%d\n", code_size);
	rarvm_input->in_addr = rarvm_input->in_bit = 0;
	memcpy(rarvm_input->in_buf, code, MIN(code_size, 0x8000));
	xor_sum = 0;
	for (i=1 ; i<code_size; i++) {
		//rar_dbgmsg("code[%d]=%d\n", i, code[i]);
		xor_sum ^= code[i];
	}
	//rar_dbgmsg("xor_sum=%d\n", xor_sum);
	rarvm_addbits(rarvm_input,8);

	prg->cmd_count = 0;
	if (xor_sum == code[0]) {
		filter_type = is_standard_filter(code, code_size);
		//rar_dbgmsg("filter_type=%d\n", filter_type);
		if (filter_type != VMSF_NONE) {
			rar_cmd_array_add(&prg->cmd, 1);
			cur_cmd = &prg->cmd.array[prg->cmd_count++];
			cur_cmd->op_code = VM_STANDARD;
			cur_cmd->op1.data = filter_type;
			cur_cmd->op1.addr = &cur_cmd->op1.data;
			cur_cmd->op2.addr = &cur_cmd->op2.data;
			cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;
			code_size = 0;
		}

		data_flag = rarvm_getbits(rarvm_input);
		//rar_dbgmsg("data_flag=%u\n", data_flag);
		rarvm_addbits(rarvm_input, 1);
		if (data_flag & 0x8000) {
			int data_size = rarvm_read_data(rarvm_input)+1;
			//rar_dbgmsg("data_size=%d\n", data_size);
			prg->static_data = rar_malloc(data_size);
			if (!prg->static_data) {
			    //rar_dbgmsg("unrar: rarvm_prepare: rar_malloc failed for prg->static_data\n");
			    return 0;
			}
			for (i=0 ; rarvm_input->in_addr < code_size && i < data_size ; i++) {
				prg->static_size++;
				prg->static_data = rar_realloc2(prg->static_data, prg->static_size);
				if (!prg->static_data) {
				    //rar_dbgmsg("unrar: rarvm_prepare: rar_realloc2 failed for prg->static_data\n");
				    return 0;
				}
				prg->static_data[i] = rarvm_getbits(rarvm_input) >> 8;
				rarvm_addbits(rarvm_input, 8);
			}
		}
		while (rarvm_input->in_addr < code_size) {
			rar_cmd_array_add(&prg->cmd, 1);
			cur_cmd = &prg->cmd.array[prg->cmd_count];
			data = rarvm_getbits(rarvm_input);
			//rar_dbgmsg("data: %u\n", data);
			if ((data & 0x8000) == 0) {
				cur_cmd->op_code = (rarvm_commands_t) (data>>12);
				rarvm_addbits(rarvm_input, 4);
			} else {
				cur_cmd->op_code = (rarvm_commands_t) ((data>>10)-24);
				rarvm_addbits(rarvm_input, 6);
			}
			if (vm_cmdflags[cur_cmd->op_code] & VMCF_BYTEMODE) {
				cur_cmd->byte_mode = rarvm_getbits(rarvm_input) >> 15;
				rarvm_addbits(rarvm_input, 1);
			} else {
				cur_cmd->byte_mode = 0;
			}
			cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;
			op_num = (vm_cmdflags[cur_cmd->op_code] & VMCF_OPMASK);
			//rar_dbgmsg("op_num: %d\n", op_num);
			cur_cmd->op1.addr = cur_cmd->op2.addr = NULL;
			if (op_num > 0) {
				rarvm_decode_arg(rarvm_data, rarvm_input,
					&cur_cmd->op1, cur_cmd->byte_mode);
				if (op_num == 2) {
					rarvm_decode_arg(rarvm_data, rarvm_input,
							&cur_cmd->op2, cur_cmd->byte_mode);
				} else {
					if (cur_cmd->op1.type == VM_OPINT &&
							(vm_cmdflags[cur_cmd->op_code] &
							(VMCF_JUMP|VMCF_PROC))) {
						distance = cur_cmd->op1.data;
						//rar_dbgmsg("distance = %d\n", distance);
						if (distance >= 256) {
							distance -= 256;
						} else {
							if (distance >=136) {
								distance -= 264;
							} else {
								if (distance >= 16) {
									distance -= 8;
								} else if (distance >= 8) {
									distance -= 16;
								}
							}
							distance += prg->cmd_count;
						}
						//rar_dbgmsg("distance = %d\n", distance);
						cur_cmd->op1.data = distance;
					}
				}
			}
			prg->cmd_count++;
		}
	}
	rar_cmd_array_add(&prg->cmd,1);
	cur_cmd = &prg->cmd.array[prg->cmd_count++];
	cur_cmd->op_code = VM_RET;
	cur_cmd->op1.addr = &cur_cmd->op1.data;
	cur_cmd->op2.addr = &cur_cmd->op2.data;
	cur_cmd->op1.type = cur_cmd->op2.type = VM_OPNONE;

	for (i=0 ; i < prg->cmd_count ; i++) {
		cmd = &prg->cmd.array[i];
		//rar_dbgmsg("op_code[%d]=%d\n", i, cmd->op_code);
		if (cmd->op1.addr == NULL) {
			cmd->op1.addr = &cmd->op1.data;
		}
		if (cmd->op2.addr == NULL) {
			cmd->op2.addr = &cmd->op2.data;
		}
	}

	if (code_size!=0) {
		rarvm_optimize(prg);
	}

	return 1;
}
