/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

integer i, j;
integer k = 0;

//
// Memory is 32 words (x32-bit) per thread.
// Memory layout as delivered via unit_input:
// 0 - cnt
// 1 - salt_len
// 2..5 - salt
// 6..7 - IDs
// 8 - key_len
// 9 - unused
// 10..10+(key_len/4-1) - key
//
`define	ADDR_cnt			0
`define	ADDR_salt_len	1
`define	ADDR_salt		2
`define	ADDR_ids0		6
`define	ADDR_ids1		7
`define	ADDR_key_len	8
`define	ADDR_key			10
`define	ADDR_alt_result	26
`define	ADDR_magic		31
//
// 16 (x16-bit) registers per thread.
//
`define	R_salt_len	`R12
`define	R_key_len	`R13
`define	R_cnt_l		`R14
`define	R_cnt_u		`R15
//
//
initial begin
	// ************************************************************
	//
	// Algorithm notes:
	// - key_len=0 is supported
	// - salt_len=0, cnt=0 NOT supported
	// - max. key_len:
	//
	// ************************************************************

	// ************************************************************
	//
	// - Execution of a thread starts when it receives
	// an input data packet, that sets thread_state to WR_RDY
	//
	// ************************************************************
	instr_mem[00] = `NOP;
	instr_mem[01] = `NOP;
	instr_mem[02] = `NOP;
	instr_mem[03] = `NOP;
	instr_mem[04] = `NOP;
	// - Read from the memory: MV_R_MEM_L, MV_R_MEM_U read
	// lower,upper halves of 32-bit word, respectively.
	// Takes 4 cycles to execute (if memory is not busy -
	// read for block formation has priority over CPU).
	//
	// - MV_R_MEM_2X reads full 32-bit word, stores
	// into 2 registers. Takes 5+ cycles to execute.
	// (disabled)
	//
	//instr_mem[05] = `MV_R_MEM_2X(`R_cnt_l,`ADDR_cnt);
	instr_mem[05] = `MV_R_MEM_L(`R_cnt_l,`ADDR_cnt);
	instr_mem[06] = `NOP;//`MV_R_MEM_U(`R_cnt_u,`ADDR_cnt);
	instr_mem[07] = `MV_R_MEM_L(`R_salt_len,`ADDR_salt_len);
	instr_mem[08] = `MV_R_MEM_L(`R_key_len,`ADDR_key_len);
	instr_mem[09] = `NOP;
	instr_mem[10] = `NOP;//`JMP(80);


	// ************************************************************
	//
	// Computing md5crypt
	//
	/*
	 * Copyright (c) 2003 Poul-Henning Kamp
	 * All rights reserved.
	 */
	// #include <sys/cdefs.h>
	// __FBSDID("$FreeBSD: head/lib/libcrypt/crypt-md5.c 115733 2003-06-02 21:43:14Z markm $");
	//
	// ************************************************************

	// computation #1:
	// "MD5(pw,salt,pw)"
	instr_mem[11] = `NEW_CTX(`ADDR_alt_result,4);
	instr_mem[12] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len);
	instr_mem[13] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[14] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_key,`R_key_len);

	// computation #2:
	// "The password first, since that is what is most unknown"
	// "Then our magic string"
	// "Then the raw salt"
	// "Then just as many characters of the MD5(pw,salt,pw)"

	// - We have data at `ADDR_alt_result and we set the same address
	// for output. Data is safe until FINISH_CTX.
	// - Arguments to NEW_CTX remain in internal registers,
	// the instruction can be skipped if arguments remain the same.
	// Computation starts after PROCESS_BYTES.
	//instr_mem[15] = `NEW_CTX(`ADDR_alt_result,4);

	instr_mem[15] = `MV_R_R(`R0,`R_key_len);
	instr_mem[16] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len);
	instr_mem[17] = `PROCESS_BYTES_C(`ADDR_magic,3);
	instr_mem[18] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);

	instr_mem[19] = `SUB_R_C(`R0,`R0,16);
	`IF(`IF_CARRY)
	instr_mem[20] = `PROCESS_BYTES_R(`ADDR_alt_result,`R0); `IF(`IF_NONE)
	`IF(`IF_CARRY)
	instr_mem[21] = `JMP(24); `IF(`IF_NONE)
	instr_mem[22] = `PROCESS_BYTES_C(`ADDR_alt_result,16);
	instr_mem[23] = `JMP(19);

	instr_mem[24] = `NOP;
	instr_mem[25] = `NOP;
	instr_mem[26] = `NOP;
	instr_mem[27] = `NOP;
	instr_mem[28] = `MV_R_R(`R0,`R_key_len);
	instr_mem[29] = `NOP;
	instr_mem[30] = `NOP;
	instr_mem[31] = `NOP;
	instr_mem[32] = `NOP;


	// - On SHR1, Zero Flag (ZF) sets if operand A equals to 0.
	// - One Flag (OF). Operand A, bit 0 is copied into OF.
	instr_mem[33] = `SHR1(`R0);
	`IF(`IF_ZERO)
	instr_mem[34] = `JMP(38); `IF(`IF_NONE)

	`IF(`IF_ONE)
	instr_mem[35] = `PROCESS_BYTES_C(30,1); `IF(`IF_NONE)
	`IF(`IF_NOT_ONE)
	instr_mem[36] = `PROCESS_BYTES_C(`ADDR_key,1); `IF(`IF_NONE)
	instr_mem[37] = `JMP(33);

	instr_mem[38] = `FINISH_CTX;
	instr_mem[39] = `NOP;


	// ************************************************************
	//
	// Main loop
	//
	// ************************************************************
	instr_mem[40] = `NOP;
	instr_mem[41] = `NOP;
	instr_mem[42] = `NOP;
	instr_mem[43] = `MV_R_R(`R0,`R_cnt_l);
	instr_mem[44] = `MV_R_C(`R2,2);
	instr_mem[45] = `MV_R_C(`R3,6);
	instr_mem[46] = `RST_UF;
	instr_mem[47] = `SUB_R_C(`R0,`R0,1);
	instr_mem[48] = `NOP;
	instr_mem[49] = `NOP;

	`IF(`IF_UF)
	instr_mem[50] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len); `IF(`IF_NONE)
	`IF(`IF_NOT_UF)
	instr_mem[51] = `PROCESS_BYTES_C(`ADDR_alt_result,16); `IF(`IF_NONE)

	instr_mem[52] = `INC_RST(`R2,2);
	`IF(`IF_NOT_ZERO)
	instr_mem[53] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len); `IF(`IF_NONE)

	instr_mem[54] = `INC_RST(`R3,6);
	`IF(`IF_NOT_ZERO)
	instr_mem[55] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len); `IF(`IF_NONE)

	`IF(`IF_UF)
	instr_mem[56] = `PROCESS_BYTES_C_FINISH_CTX(`ADDR_alt_result,16); `IF(`IF_NONE)
	`IF(`IF_NOT_UF)
	instr_mem[57] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_key,`R_key_len); `IF(`IF_NONE)

	instr_mem[58] = `INV_UF;
	instr_mem[59] = `SUB_R_C(`R0,`R0,1);
	`IF(`IF_NOT_CARRY)
	instr_mem[60] = `JMP(50); `IF(`IF_NONE)

	// - On FINISH_CTX, it sets thread_state to BUSY and it continues
	// running until JMP or EXEC_OPT_TS_WR_RDY-flagged instruction.
	// On such instruction, thread switches. It restores back
	// only after thread_state changes to WR_RDY, that happens
	// after computation is complete.
	// We need computation to be complete before output.
	instr_mem[61] = `JMP(70);

	// ************************************************************
	//
	// Output is 12 words (x16-bit)
	// First 4 words must contain IDs.
	//
	// ************************************************************
	instr_mem[70] = `MV_R_MEM_L(`R0,`ADDR_ids0);
	instr_mem[71] = `MV_R_MEM_U(`R1,`ADDR_ids0);
	instr_mem[72] = `MV_R_MEM_L(`R2,`ADDR_ids1);
	instr_mem[73] = `MV_R_MEM_U(`R3,`ADDR_ids1);
	instr_mem[74] = `MV_R_MEM_L(`R4,`ADDR_alt_result + 5'd0);
	instr_mem[75] = `MV_R_MEM_U(`R5,`ADDR_alt_result + 5'd0);
	instr_mem[76] = `MV_R_MEM_L(`R6,`ADDR_alt_result + 5'd1);
	instr_mem[77] = `MV_R_MEM_U(`R7,`ADDR_alt_result + 5'd1);
	instr_mem[78] = `MV_R_MEM_L(`R8,`ADDR_alt_result + 5'd2);
	instr_mem[79] = `MV_R_MEM_U(`R9,`ADDR_alt_result + 5'd2);
	instr_mem[80] = `MV_R_MEM_L(`R10,`ADDR_alt_result + 5'd3);
	instr_mem[81] = `MV_R_MEM_U(`R11,`ADDR_alt_result + 5'd3);

	instr_mem[82] = `MV_UOB_R(0,`R0);
	instr_mem[83] = `MV_UOB_R(1,`R1);
	instr_mem[84] = `MV_UOB_R(2,`R2);
	instr_mem[85] = `MV_UOB_R(3,`R3);
	instr_mem[86] = `MV_UOB_R(4,`R4);
	instr_mem[87] = `MV_UOB_R(5,`R5);
	instr_mem[88] = `MV_UOB_R(6,`R6);
	instr_mem[89] = `MV_UOB_R(7,`R7);
	instr_mem[90] = `MV_UOB_R(8,`R8);
	instr_mem[91] = `MV_UOB_R(9,`R9);
	instr_mem[92] = `MV_UOB_R(10,`R10);
	instr_mem[93] = `MV_UOB_R(11,`R11);

	// - SET_OUTPUT_COMPLETE instruction:
	// 1) to be called after there was at least 1 write to the UOB;
	// 2) enqueues UOB content for output;
	// 3) changes thread_state to NONE, that excludes the thread
	// from execution and makes it available for input;
	// 4) Suggested JMP immediately after the instruction.
	instr_mem[94] = `SET_OUTPUT_COMPLETE;
	instr_mem[95] = `JMP(01);
	instr_mem[96] = `NOP;


	// ************************************************************
	//
	// PHPASS program (entry pt.1 = 150)
	//
	// ************************************************************

	instr_mem[150] = `NOP;
	instr_mem[151] = `MV_R_MEM_L(`R_cnt_l,`ADDR_cnt);
	instr_mem[152] = `MV_R_MEM_U(`R_cnt_u,`ADDR_cnt);
	instr_mem[153] = `MV_R_MEM_L(`R_salt_len,`ADDR_salt_len);
	instr_mem[154] = `MV_R_MEM_L(`R_key_len,`ADDR_key_len);
	instr_mem[155] = `MV_R_R(`R0,`R_cnt_l);
	instr_mem[156] = `MV_R_R(`R1,`R_cnt_u);
	instr_mem[157] = `NEW_CTX(`ADDR_alt_result,4);
	instr_mem[158] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[159] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_key,`R_key_len);
	instr_mem[160] = `NOP;
	instr_mem[161] = `SUB_R_C(`R0,`R0,1);
	instr_mem[162] = `SUBB_R_C(`R1,`R1,0);
	instr_mem[163] = `NOP;
	instr_mem[164] = `PROCESS_BYTES_C(`ADDR_alt_result,16);
	instr_mem[165] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_key,`R_key_len);
	instr_mem[166] = `SUB_R_C(`R0,`R0,1);
	instr_mem[167] = `SUBB_R_C(`R1,`R1,0);
	`IF(`IF_NOT_CARRY)
	instr_mem[168] = `JMP(164); `IF(`IF_NONE)
	instr_mem[169] = `JMP(170);
	// JMP ensures - computation complete, result written into memory
	
	instr_mem[170] = `MV_R_MEM_L(`R0,`ADDR_ids0);
	instr_mem[171] = `MV_R_MEM_U(`R1,`ADDR_ids0);
	instr_mem[172] = `MV_R_MEM_L(`R2,`ADDR_ids1);
	instr_mem[173] = `MV_R_MEM_U(`R3,`ADDR_ids1);
	instr_mem[174] = `MV_R_MEM_L(`R4,`ADDR_alt_result + 5'd0);
	instr_mem[175] = `MV_R_MEM_U(`R5,`ADDR_alt_result + 5'd0);
	instr_mem[176] = `MV_R_MEM_L(`R6,`ADDR_alt_result + 5'd1);
	instr_mem[177] = `MV_R_MEM_U(`R7,`ADDR_alt_result + 5'd1);
	instr_mem[178] = `MV_R_MEM_L(`R8,`ADDR_alt_result + 5'd2);
	instr_mem[179] = `MV_R_MEM_U(`R9,`ADDR_alt_result + 5'd2);
	instr_mem[180] = `MV_R_MEM_L(`R10,`ADDR_alt_result + 5'd3);
	instr_mem[181] = `MV_R_MEM_U(`R11,`ADDR_alt_result + 5'd3);

	instr_mem[182] = `MV_UOB_R(0,`R0);
	instr_mem[183] = `MV_UOB_R(1,`R1);
	instr_mem[184] = `MV_UOB_R(2,`R2);
	instr_mem[185] = `MV_UOB_R(3,`R3);
	instr_mem[186] = `MV_UOB_R(4,`R4);
	instr_mem[187] = `MV_UOB_R(5,`R5);
	instr_mem[188] = `MV_UOB_R(6,`R6);
	instr_mem[189] = `MV_UOB_R(7,`R7);
	instr_mem[190] = `MV_UOB_R(8,`R8);
	instr_mem[191] = `MV_UOB_R(9,`R9);
	instr_mem[192] = `MV_UOB_R(10,`R10);
	instr_mem[193] = `MV_UOB_R(11,`R11);

	instr_mem[194] = `SET_OUTPUT_COMPLETE;
	instr_mem[195] = `JMP(150);
	instr_mem[196] = `NOP;

end

