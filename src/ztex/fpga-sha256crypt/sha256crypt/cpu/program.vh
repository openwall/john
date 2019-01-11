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
// Memory layout for sha256crypt as delivered via unit_input:
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
`define	ADDR_s_bytes	`ADDR_salt
`define	ADDR_ids0		6
`define	ADDR_ids1		7
`define	ADDR_key_len	8
`define	ADDR_key			10
`define	ADDR_p_bytes	`ADDR_key
`define	ADDR_alt_result	24
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
	// - max. key_len is 32
	// - salt_len=0, cnt=0 NOT supported
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
	instr_mem[06] = `MV_R_MEM_U(`R_cnt_u,`ADDR_cnt);
	instr_mem[07] = `MV_R_MEM_L(`R_salt_len,`ADDR_salt_len);
	instr_mem[08] = `MV_R_MEM_L(`R_key_len,`ADDR_key_len);
	instr_mem[09] = `NOP;
	instr_mem[10] = `NOP;//`JMP(80);


	// ************************************************************
	//
	// "Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
	// final result will be added to the first context."
	//
	// ************************************************************

	// - Usage: NEW_CTX(save_addr,save_len)
	instr_mem[11] = `NEW_CTX(`ADDR_alt_result,8);
	instr_mem[12] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len);
	instr_mem[13] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[14] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_key,`R_key_len);

/*
	instr_mem[15] = `JMP(16);
	instr_mem[16] = `SET_OUTPUT_COMPLETE;
	instr_mem[17] = `HALT;
	instr_mem[18] = `NOP;
*/


	// ************************************************************
	//
	// "Prepare for the real work."
	//
	// ************************************************************

	// - We have data at `ADDR_alt_result and we set the same address
	// for output. Data is safe until FINISH_CTX.
	instr_mem[15] = `NEW_CTX(`ADDR_alt_result,8);

	// - Update value in a register: new value is not available immediately.
	// If an instruction at address ADDR modifies a register, new value
	// is available for an instruction at ADDR+4, or after successful JMP.
	// Until that the previous value is available if there was
	// no thread switch.
	instr_mem[16] = `MV_R_R(`R0,`R_key_len);

	// "Add the key string."
	// "The last part is the salt string."
	// "Add for any character in the key one byte of the alternate sum."
	instr_mem[17] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len);
	instr_mem[18] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[19] = `PROCESS_BYTES_R(`ADDR_alt_result,`R_key_len);



	// ************************************************************
	//
	// "Take the binary representation of the length of the key and
	// for every 1 add the alternate sum, for every 0 the key."
	//
	// ************************************************************

	// - On SHR1, Zero Flag (ZF) sets if operand A equals to 0.
	// - One Flag (OF). Operand A, bit 0 is copied into OF.
// 24 ->
	instr_mem[20] = `SHR1(`R0);
	// - Many instruction types may have execution condition
	// (if condition is not met then the instruction is skipped).
	`IF(`IF_ZERO)
	instr_mem[21] = `JMP(25); `IF(`IF_NONE)

	`IF(`IF_ONE)
	instr_mem[22] = `PROCESS_BYTES_C(`ADDR_alt_result,32); `IF(`IF_NONE)
	`IF(`IF_NOT_ONE)
	instr_mem[23] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len); `IF(`IF_NONE)
	instr_mem[24] = `JMP(20);

// 21 ->
	instr_mem[25] = `FINISH_CTX;
	instr_mem[26] = `NOP;



	// ************************************************************
	//
	// "Start computation of P byte sequence."
	// "For every character in the password add the entire password."
	//
	// ************************************************************
	instr_mem[27] = `MV_R_R(`R0,`R_key_len);
	instr_mem[28] = `NOP;
	instr_mem[29] = `NOP;
	instr_mem[30] = `NEW_CTX(`ADDR_p_bytes,8);
	// - On subtraction, ZF is set if operand A equals to operand B.
	instr_mem[31] = `SUB_R_C(`R0,`R0,0);
	`IF(`IF_ZERO)
	instr_mem[32] = `JMP(37); `IF(`IF_NONE)
// 35 ->
	instr_mem[33] = `PROCESS_BYTES_R(`ADDR_key,`R_key_len);
	instr_mem[34] = `SUB_R_C(`R0,`R0,1);
	`IF(`IF_NOT_ZERO)
	instr_mem[35] = `JMP(33); `IF(`IF_NONE)

	instr_mem[36] = `NOP;
// 32 ->
	instr_mem[37] = `FINISH_CTX;
	instr_mem[38] = `NOP;



	// ************************************************************
	//
	// "Start computation of S byte sequence."
	// "for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
	//    sha512_process_bytes (salt, salt_len, &alt_ctx);"
	//
	// ************************************************************

	// - Only 4 words (x32 bit) are saved into memory (save_len=4)
	instr_mem[39] = `NEW_CTX(`ADDR_s_bytes,4);
	//
	// - *_FINISH_CTX/STOP_CTX is a non-blocking instruction.
	// - NEW_CTX is a blocking one (it waits until the previous
	// computation is finished).
	//
	instr_mem[40] = `MV_R_MEM_L(`R0,`ADDR_alt_result + 5'd0);
	instr_mem[41] = `NOP;
	instr_mem[42] = `NOP;
	instr_mem[43] = `NOP;
	// - AND is an 8-bit instruction. Upper bits are zeroed.
	// - Integer instructions are able to read from one register
	// and save into other one.
	instr_mem[44] = `AND_R_C(`R0,`R0,255);
	instr_mem[45] = `NOP;
	instr_mem[46] = `NOP;
	instr_mem[47] = `NOP;
	instr_mem[48] = `ADD_R_C(`R0,16);
	instr_mem[49] = `NOP;
	instr_mem[50] = `NOP;
	instr_mem[51] = `NOP;

// 59 ->
	instr_mem[52] = `SUB_R_C(`R1,`R0,4);
	`IF(`IF_CARRY)
	instr_mem[53] = `JMP(60); `IF(`IF_NONE)
	// Internal buffer for process_bytes is 4 elements.
	instr_mem[54] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[55] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[56] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[57] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[58] = `SUB_R_C(`R0,`R0,4);
	`IF(`IF_NOT_CARRY)
	instr_mem[59] = `JMP(52); `IF(`IF_NONE)

// 53 ->
	instr_mem[60] = `SUB_R_C(`R0,`R0,0);
	`IF(`IF_ZERO)
	instr_mem[61] = `JMP(65); `IF(`IF_NONE)
// 64 ->
	instr_mem[62] = `PROCESS_BYTES_R(`ADDR_salt,`R_salt_len);
	instr_mem[63] = `SUB_R_C(`R0,`R0,1);
	`IF(`IF_NOT_ZERO)
	instr_mem[64] = `JMP(62); `IF(`IF_NONE)
// 61 ->
	instr_mem[65] = `FINISH_CTX;

	instr_mem[66] = `JMP(76);



	// ************************************************************
	//
	// "Repeatedly run the collected hash value through SHA256 to burn
	// CPU cycles."
	//
	// ************************************************************
// 66 ->
	instr_mem[76] = `MV_R_R(`R0,`R_cnt_l);
	instr_mem[77] = `MV_R_R(`R1,`R_cnt_u);
	instr_mem[78] = `MV_R_C(`R2,2);
	instr_mem[79] = `MV_R_C(`R3,6);
	instr_mem[80] = `RST_UF;
	instr_mem[81] = `NOP;
	instr_mem[82] = `SUB_R_C(`R0,`R0,1);
	`IF(`IF_CARRY)
	instr_mem[83] = `SUB_R_C(`R1,`R1,1); `IF(`IF_NONE)
	// TODO: some error handling / reporting
	// - IF_CARRY -> raise error (cnt == 0)

	// "New context."
	// - Arguments to NEW_CTX remain in internal registers,
	// the instruction can be skipped if arguments remain the same.
	// Computation starts after PROCESS_BYTES.
	instr_mem[84] = `NEW_CTX(`ADDR_alt_result,8);

	// "Add key or last result."
// 96 ->
	`IF(`IF_UF)
	instr_mem[85] = `PROCESS_BYTES_R(`ADDR_p_bytes,`R_key_len); `IF(`IF_NONE)
	`IF(`IF_NOT_UF)
	instr_mem[86] = `PROCESS_BYTES_C(`ADDR_alt_result,32); `IF(`IF_NONE)

	// "Add salt for numbers not divisible by 3."
	//
	// - INC_RST instruction:
	// 1) loads value from given register, compares with supplied constant;
	// 2) if equals, saves 0, sets ZF, else saves value incremented by 1;
	// 3) is 8-bit instruction.
	instr_mem[87] = `INC_RST(`R2,2);
	`IF(`IF_NOT_ZERO)
	instr_mem[88] = `PROCESS_BYTES_R(`ADDR_s_bytes,`R_salt_len); `IF(`IF_NONE)

	// "Add key for numbers not divisible by 7."
	instr_mem[89] = `INC_RST(`R3,6);
	`IF(`IF_NOT_ZERO)
	instr_mem[90] = `PROCESS_BYTES_R(`ADDR_p_bytes,`R_key_len); `IF(`IF_NONE)

	// "Add key or last result."
	`IF(`IF_UF)
	instr_mem[91] = `PROCESS_BYTES_C_FINISH_CTX(`ADDR_alt_result,32); `IF(`IF_NONE)
	`IF(`IF_NOT_UF)
	instr_mem[92] = `PROCESS_BYTES_R_FINISH_CTX(`ADDR_p_bytes,`R_key_len); `IF(`IF_NONE)

	instr_mem[93] = `INV_UF;
	instr_mem[94] = `SUB_R_C(`R0,`R0,1);
	`IF(`IF_NOT_CARRY)
	instr_mem[95] = `JMP(85); `IF(`IF_NONE)
	instr_mem[96] = `SUB_R_C(`R1,`R1,1);
	`IF(`IF_NOT_CARRY)
	instr_mem[97] = `JMP(85); `IF(`IF_NONE)

	// - On FINISH_CTX, it sets thread_state to BUSY and it continues
	// running until JMP or EXEC_OPT_TS_WR_RDY-flagged instruction.
	// On such instruction, thread switches. It restores back
	// only after thread_state changes to WR_RDY, that happens
	// after computation is complete.
	// We need computation to be complete before output.
/*
	instr_mem[97] = `JMP(100);
	instr_mem[98] = `NOP;
	instr_mem[99] = `NOP;

	// ************************************************************
	//
	// - Unit's Output Buffer (UOB) is designed for collecting
	// output data. There's a single UOB instance for all threads.
	// 16-bit storage operation (UOB <- Reg) is available.
	// Constant UOB address (for 16-bit word) must be supplied.
	// 20 first words from the UOB are output.
	// First 4 words must contain IDs.
	//
	// ************************************************************
	instr_mem[100] = `MV_R_MEM_2X(`R0,`ADDR_ids0);
	instr_mem[101] = `MV_R_MEM_2X(`R2,`ADDR_ids1);
	instr_mem[102] = `MV_R_MEM_2X(`R4,`ADDR_alt_result + 5'd0);
	instr_mem[103] = `MV_R_MEM_2X(`R6,`ADDR_alt_result + 5'd1);
	instr_mem[104] = `MV_R_MEM_2X(`R8,`ADDR_alt_result + 5'd2);
	instr_mem[105] = `MV_R_MEM_2X(`R10,`ADDR_alt_result + 5'd3);

	instr_mem[106] = `MV_UOB_R(0,`R0);
	instr_mem[107] = `MV_UOB_R(1,`R1);
	instr_mem[108] = `MV_UOB_R(2,`R2);
	instr_mem[109] = `MV_UOB_R(3,`R3);
	instr_mem[110] = `MV_UOB_R(4,`R4);
	instr_mem[111] = `MV_UOB_R(5,`R5);
	instr_mem[112] = `MV_UOB_R(6,`R6);
	instr_mem[113] = `MV_UOB_R(7,`R7);
	instr_mem[114] = `MV_UOB_R(8,`R8);
	instr_mem[115] = `MV_UOB_R(9,`R9);
	instr_mem[116] = `MV_UOB_R(10,`R10);
	instr_mem[117] = `MV_UOB_R(11,`R11);

	instr_mem[118] = `MV_R_MEM_2X(`R0,`ADDR_alt_result + 5'd4);
	instr_mem[119] = `MV_R_MEM_2X(`R2,`ADDR_alt_result + 5'd5);
	instr_mem[120] = `MV_R_MEM_2X(`R4,`ADDR_alt_result + 5'd6);
	instr_mem[121] = `MV_R_MEM_2X(`R6,`ADDR_alt_result + 5'd7);

	instr_mem[122] = `MV_UOB_R(12,`R0);
	instr_mem[123] = `MV_UOB_R(13,`R1);
	instr_mem[124] = `MV_UOB_R(14,`R2);
	instr_mem[125] = `MV_UOB_R(15,`R3);
	instr_mem[126] = `MV_UOB_R(16,`R4);
	instr_mem[127] = `MV_UOB_R(17,`R5);
	instr_mem[128] = `MV_UOB_R(18,`R6);
	instr_mem[129] = `MV_UOB_R(19,`R7);

	instr_mem[130] = `SET_OUTPUT_COMPLETE;
	instr_mem[131] = `JMP(01);
*/

	instr_mem[98] = `JMP(100);
	instr_mem[99] = `NOP;
	instr_mem[100] = `MV_R_MEM_L(`R0,`ADDR_ids0);
	instr_mem[101] = `MV_R_MEM_U(`R1,`ADDR_ids0);
	instr_mem[102] = `MV_R_MEM_L(`R2,`ADDR_ids1);
	instr_mem[103] = `MV_R_MEM_U(`R3,`ADDR_ids1);
	instr_mem[104] = `MV_R_MEM_L(`R4,`ADDR_alt_result + 5'd0);
	instr_mem[105] = `MV_R_MEM_U(`R5,`ADDR_alt_result + 5'd0);
	instr_mem[106] = `MV_R_MEM_L(`R6,`ADDR_alt_result + 5'd1);
	instr_mem[107] = `MV_R_MEM_U(`R7,`ADDR_alt_result + 5'd1);
	instr_mem[108] = `MV_R_MEM_L(`R8,`ADDR_alt_result + 5'd2);
	instr_mem[109] = `MV_R_MEM_U(`R9,`ADDR_alt_result + 5'd2);
	instr_mem[110] = `MV_R_MEM_L(`R10,`ADDR_alt_result + 5'd3);
	instr_mem[111] = `MV_R_MEM_U(`R11,`ADDR_alt_result + 5'd3);

	instr_mem[112] = `MV_UOB_R(0,`R0);
	instr_mem[113] = `MV_UOB_R(1,`R1);
	instr_mem[114] = `MV_UOB_R(2,`R2);
	instr_mem[115] = `MV_UOB_R(3,`R3);
	instr_mem[116] = `MV_UOB_R(4,`R4);
	instr_mem[117] = `MV_UOB_R(5,`R5);
	instr_mem[118] = `MV_UOB_R(6,`R6);
	instr_mem[119] = `MV_UOB_R(7,`R7);
	instr_mem[120] = `MV_UOB_R(8,`R8);
	instr_mem[121] = `MV_UOB_R(9,`R9);
	instr_mem[122] = `MV_UOB_R(10,`R10);
	instr_mem[123] = `MV_UOB_R(11,`R11);

	instr_mem[124] = `MV_R_MEM_L(`R0,`ADDR_alt_result + 5'd4);
	instr_mem[125] = `MV_R_MEM_U(`R1,`ADDR_alt_result + 5'd4);
	instr_mem[126] = `MV_R_MEM_L(`R2,`ADDR_alt_result + 5'd5);
	instr_mem[127] = `MV_R_MEM_U(`R3,`ADDR_alt_result + 5'd5);
	instr_mem[128] = `MV_R_MEM_L(`R4,`ADDR_alt_result + 5'd6);
	instr_mem[129] = `MV_R_MEM_U(`R5,`ADDR_alt_result + 5'd6);
	instr_mem[130] = `MV_R_MEM_L(`R6,`ADDR_alt_result + 5'd7);
	instr_mem[131] = `MV_R_MEM_U(`R7,`ADDR_alt_result + 5'd7);

	instr_mem[132] = `MV_UOB_R(12,`R0);
	instr_mem[133] = `MV_UOB_R(13,`R1);
	instr_mem[134] = `MV_UOB_R(14,`R2);
	instr_mem[135] = `MV_UOB_R(15,`R3);
	instr_mem[136] = `MV_UOB_R(16,`R4);
	instr_mem[137] = `MV_UOB_R(17,`R5);
	instr_mem[138] = `MV_UOB_R(18,`R6);
	instr_mem[139] = `MV_UOB_R(19,`R7);


	// ************************************************************
	//
	// - SET_OUTPUT_COMPLETE instruction:
	// 1) to be called after there was at least 1 write to the UOB;
	// 2) enqueues UOB content for output;
	// 3) changes thread_state to NONE, that excludes the thread
	// from execution and makes it available for input;
	// 4) Suggested JMP immediately after the instruction.
	//
	// ************************************************************
	instr_mem[140] = `SET_OUTPUT_COMPLETE;
	instr_mem[141] = `JMP(01);


	// ************************************************************
	//
	//
	// ************************************************************



/*
	instr_mem[] = `JMP();
	instr_mem[] = `HALT;
	instr_mem[] = `NOP;
	instr_mem[] = `NOP;
*/

end

