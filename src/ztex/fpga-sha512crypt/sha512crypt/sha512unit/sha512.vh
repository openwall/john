/*
 * This software is Copyright (c) 2017-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Include Verilog code for "blackbox" modules
// (ISE Project Navigator requires restart after switching this)
`define	SIMULATION


// ===== SHA512 algorithm constants and operations =====
//
`define	CYCLIC(w,s)	((w >> s) | (w << (64 - s)))

`define	SWAP(x)	(((x) << 56)	\
   | (((x) & 16'hff00) << 40)	\
   | (((x) & 24'hff0000) << 24)	\
   | (((x) & 32'hff000000) << 8)	\
   | (((x) >> 8) & 32'hff000000)	\
   | (((x) >> 24) & 24'hff0000)	\
   | (((x) >> 40) & 16'hff00)	\
   | ((x) >> 56))

`define	SHA512_IV	{ 128'h_5be0cd19137e2179_1f83d9abfb41bd6b, \
	192'h_9b05688c2b3e6c1f_510e527fade682d1_a54ff53a5f1d36f1, \
	192'h_3c6ef372fe94f82b_bb67ae8584caa73b_6a09e667f3bcc908 }


// ===== Block processing options =====
//
`define	BLK_OP_MSB	6
// What context to use for processing the block:
// 0 - new/load context; 1 - continue existing context (2nd+ block)
`define	BLK_OP_IF_CONTINUE_CTX(r)	r[5]
// If new/load context: 1 - new, 0 - load
`define	BLK_OP_IF_NEW_CTX(r)		r[0]
// If load context: 0..N - load saved context from slot 0..N
`define	BLK_OP_LOAD_CTX_NUM(r)	r[2:1]
// Where to save the context: 0..N - save into slot 0..N
`define	BLK_OP_SAVE_CTX_NUM(r)	r[4:3]
// 1) Output computed result;
// 2) Used to set thread state.
`define	BLK_OP_END_COMP_OUTPUT(r)	r[6]


// ===== sha512crypt engine (services several cores) =====
//
// "Main" memory (per thread; in 64-bit words; 2**ADDR_MSB-1)
// 4 = 32x8 = 256 bytes
`define	MEM_ADDR_MSB	4
// "Main" memory (total words, for all threads(max.16))
`define	MEM_TOTAL_MSB	(`MEM_ADDR_MSB + 4)

// process_bytes (in bytes)
//`define	PROCB_CNT_MSB		7
//`define	PROCB_TOTAL_MSB	15
// max.key_len=64 (comp.len <8k)
`define	PROCB_CNT_MSB		6
`define	PROCB_TOTAL_MSB	12

// unit's I/O
`define	UNIT_INPUT_WIDTH		8
`define	UNIT_OUTPUT_WIDTH		2
// Address in Unit's output buffer (UOB) memory in 32-bit words
`define	UOB_ADDR_MSB	4


// ===== computation state (per thread) =====
//
`define	THREAD_STATE_MSB		1

`define	THREAD_STATE_NONE		2'd0
`define	THREAD_STATE_WR_RDY	2'd1
`define	THREAD_STATE_RD_RDY	2'd2
`define	THREAD_STATE_BUSY		2'd3


// ===== comp_buf, procb_buf, saved_procb_state =====
//
`define	COMP_DATA1_MSB		(1 + 2 + 2)-1
`define	COMP_DATA2_MSB		(`MEM_ADDR_MSB+1 + 4)-1

// address width for procb records (per thread)
`define	PROCB_N_RECORDS	4
`define	PROCB_A_WIDTH		3
// width of each procb record
`define	PROCB_D_WIDTH		(`MEM_ADDR_MSB+1 + `PROCB_CNT_MSB+1 +2)

`define	PROCB_SAVE_MSB		(`MEM_ADDR_MSB+3 + `PROCB_CNT_MSB+1 \
	+ `PROCB_TOTAL_MSB+1 + 5)


// ===== CPU =====
//
`define	N_STAGES			4
// 16 registers
`define	REG_ADDR_MSB	3
// Program entry points
`define	ENTRY_PT_MSB	0
//
// Each instruction consists of:
`define	OP_CODE_LEN		5
`define	OP_CODE			5'd
// Field A contains exclusively register to read from
`define	FIELD_A_LEN		(`REG_ADDR_MSB+1)
`define	FIELD_A			4'd
// Field B contains register for write, memory address or other data
`define	FIELD_B_LEN		(`MEM_ADDR_MSB+1)
// OMG - adjust this if MEM_ADDR_MSB changes
`define	FIELD_B			5'd
// Field C typically contains a constant.
`define	FIELD_C_LEN		8
`define	FIELD_C			8'd
// Conditions determine the result of instruction execution.
`define	CONDITION_LEN	4
// Instruction execution options.
`define	EXEC_OPT_LEN	2

`define	PARTIAL_INSTR_LEN	(`CONDITION_LEN \
	+ `FIELD_B_LEN + `FIELD_C_LEN + `OP_CODE_LEN)
`define	INSTR_LEN	(`FIELD_A_LEN + `EXEC_OPT_LEN + `PARTIAL_INSTR_LEN)
	

// Instruction Address length: must fit into field_c
`define	IADDR_LEN		8

// *** Instruction execution options ***
`define	EXEC_OPT_NONE			2'b00
// EXEC_OPT_RD_REG - not implemented
`define	EXEC_OPT_RD_REG		2'b01
// EXEC_OPT_TS_WR_RDY - requires thread_state to be WR_RDY
`define	EXEC_OPT_TS_WR_RDY	2'b10

// *** CPU flags ***
`define	N_FLAGS		4
`define	FLAG_ZERO(r)	r[0]
`define	FLAG_ONE(r)		r[1]
`define	FLAG_CARRY(r)	r[2]
`define	FLAG_USER(r)	r[3]

// *** Conditions ***
`define	IF_NONE		4'b0000

`define	IF_ONE			4'b0010
`define	IF_NOT_ONE		4'b0011
`define	IF_ZERO			4'b0100
`define	IF_NOT_ZERO		4'b0101
`define	IF_CARRY			4'b0110
`define	IF_NOT_CARRY	4'b0111
`define	IF_UF				4'b1000
`define	IF_NOT_UF		4'b1001
//`define	IF

`define	CONDITION `IF_NONE
`define	IF(cond) \
`undef	CONDITION \
`define	CONDITION cond

// *** Operation codes ***
`define	OP_CODE_PROCB_C		`OP_CODE 8
`define	OP_CODE_PROCB_C_FIN	`OP_CODE 10
`define	OP_CODE_PROCB_C_STOP	`OP_CODE 9
`define	OP_CODE_PROCB_R		`OP_CODE 12
`define	OP_CODE_PROCB_R_FIN	`OP_CODE 14
`define	OP_CODE_PROCB_R_STOP	`OP_CODE 13

`define	OP_TYPE_PROCB(c)		(c >= 8 & c <= 15)
`define	OP_TYPE_PROCB_R(c)	(c >= 12 & c <= 15)

`define	OP_CODE_NEW_CTX		`OP_CODE 7
`define	OP_CODE_LOAD_CTX		`OP_CODE 6

`define	OP_TYPE_INIT_CTX(c)	(c == 6 | c == 7)

`define	OP_CODE_NOP			`OP_CODE 0
`define	OP_CODE_HALT		`OP_CODE 1

`define	OP_CODE_ADD_R_C	`OP_CODE 16
`define	OP_CODE_SUB_R_C	`OP_CODE 17
`define	OP_CODE_INC_RST	`OP_CODE 18
`define	OP_CODE_MV_R_C		`OP_CODE 19
`define	OP_CODE_SHR1		`OP_CODE 20
`define	OP_CODE_MV_R_R		`OP_CODE 21
`define	OP_CODE_AND			`OP_CODE 22
//`define	OP_CODE_			`OP_CODE 23

// op:a[1:0](1-set, 2-reset, 3-invert) mask:b
`define	OP_CODE_FLAG		`OP_CODE 24

`define	OP_CODE_MV_UOB_R	`OP_CODE 25
`define	OP_CODE_SET_OUTPUT_COMPLETE	`OP_CODE 26
//`define	OP_CODE_			`OP_CODE 27

`define	OP_CODE_MV_R_MEM_U	`OP_CODE 28
`define	OP_CODE_MV_R_MEM_L	`OP_CODE 29

`define	OP_TYPE_MV_R_MEM(c)	(c == 28 | c == 29)

//`define	OP_CODE_			`OP_CODE 30
`define	OP_CODE_JMP			`OP_CODE 31

//`define	OP_CODE_ILLEGAL(c) ( ~( \
//	c ==

`define	OP_TYPE_SETS_ZF(c) ( \
	c == `OP_CODE_SUB_R_C | c == `OP_CODE_INC_RST | c == `OP_CODE_SHR1)

`define	OP_TYPE_SETS_OF(c) ( \
	c == `OP_CODE_SHR1)

`define	OP_TYPE_SETS_CF(c) ( \
	c == `OP_CODE_ADD_R_C | c == `OP_CODE_SUB_R_C)

//`define	OP_CODE_USE_REG(c) ( \
//	c == `OP_CODE_ADD_R_C | c == `OP_CODE_SUB_R_C | c == `OP_CODE_INC_RST \
//	| c == `OP_CODE_MV_R_C | c == `OP_CODE_SHR1)

// This op. potentially writes into a register
// (write might not be performed because of conditions).
`define	OP_TYPE_WRITE_REG(c) ( \
	c == `OP_CODE_ADD_R_C | c == `OP_CODE_SUB_R_C | c == `OP_CODE_INC_RST \
	| c == `OP_CODE_MV_R_C | c == `OP_CODE_SHR1 | c == `OP_CODE_MV_R_R \
	| c == `OP_CODE_AND)

// read register only from field_a (timing issue)

// These ops check conditions
//`define	OP_TYPE_CHECK_CONDITION(c) ( \
//	`OP_TYPE_WRITE_REG(c) | `OP_TYPE_PROCB(c) | c == `OP_CODE_JMP)


// ===== Instructions =====
//
// *** Instructions - SHA512 subsystem ***
`define	NEW_CTX(save_addr,save_len) {`FIELD_A 0, `EXEC_OPT_TS_WR_RDY, \
	`IF_NONE, `FIELD_B save_addr, `FIELD_C save_len, `OP_CODE_NEW_CTX}
	
`define	PROCESS_BYTES_C(addr,cnt) \
	{`FIELD_A 0, `EXEC_OPT_TS_WR_RDY, \
	`CONDITION, `FIELD_B addr, `FIELD_C cnt, `OP_CODE_PROCB_C}
`define	PROCESS_BYTES_C_FINISH_CTX(addr,cnt) \
	{`FIELD_A 0, `EXEC_OPT_TS_WR_RDY, \
	`CONDITION, `FIELD_B addr, `FIELD_C cnt, `OP_CODE_PROCB_C_FIN}

`define	PROCESS_BYTES_R(addr,r) \
	{`FIELD_A r, `EXEC_OPT_RD_REG + `EXEC_OPT_TS_WR_RDY, \
	`CONDITION, `FIELD_B addr, `FIELD_C 0, `OP_CODE_PROCB_R}
`define	PROCESS_BYTES_R_FINISH_CTX(addr,r) \
	{`FIELD_A r, `EXEC_OPT_RD_REG + `EXEC_OPT_TS_WR_RDY, \
	`CONDITION, `FIELD_B addr, `FIELD_C 0, `OP_CODE_PROCB_R_FIN}

`define	FINISH_CTX	`PROCESS_BYTES_C_FINISH_CTX(0,0)


// *** Instructions - integer ***
`define	NOP	{`FIELD_A 0, `EXEC_OPT_NONE, \
	`IF_NONE, `FIELD_B 0, `FIELD_C 0, `OP_CODE_NOP}
`define	HALT	{`FIELD_A 0, `EXEC_OPT_NONE, \
	`IF_NONE, `FIELD_B 0, `FIELD_C 0, `OP_CODE_HALT}

`define	ADD_R_C(r,const) {`FIELD_A r, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B r, `FIELD_C const, `OP_CODE_ADD_R_C}
`define	SUB_R_C(dst,src,const) {`FIELD_A src, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B dst, `FIELD_C const, `OP_CODE_SUB_R_C}
`define	INC_RST(r,const) {`FIELD_A r, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B r, `FIELD_C const, `OP_CODE_INC_RST}
`define	MV_R_C(r,const) {`FIELD_A r, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B r, `FIELD_C const, `OP_CODE_MV_R_C}
`define	SHR1(r) {`FIELD_A r, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B r, `FIELD_C 0, `OP_CODE_SHR1}
// We can read from one register and store into other one
`define	MV_R_R(dst,src) {`FIELD_A src, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B dst, `FIELD_C 0, `OP_CODE_MV_R_R}
`define	TEST(src) {`FIELD_A src, `EXEC_OPT_RD_REG, \
	`IF_FALSE, `FIELD_B 0, `FIELD_C 0, `OP_CODE_MV_R_R}
`define	AND_R_C(dst,src,const) {`FIELD_A src, `EXEC_OPT_RD_REG, \
	`CONDITION, `FIELD_B dst, `FIELD_C const, `OP_CODE_AND}


// *** Instructions - I/O ***
`define	MV_R_MEM_L(r,addr) {`FIELD_A 0, `EXEC_OPT_NONE, \
	`IF_NONE, `FIELD_B r, `FIELD_C addr, `OP_CODE_MV_R_MEM_L}
`define	MV_R_MEM_U(r,addr) {`FIELD_A 0, `EXEC_OPT_NONE, \
	`IF_NONE, `FIELD_B r, `FIELD_C addr, `OP_CODE_MV_R_MEM_U}

`define	MV_UOB_R(uob_addr,r) {`FIELD_A r, `EXEC_OPT_TS_WR_RDY, \
	`IF_NONE, `FIELD_B 0, `FIELD_C uob_addr, `OP_CODE_MV_UOB_R}
`define	SET_OUTPUT_COMPLETE {`FIELD_A 0, `EXEC_OPT_TS_WR_RDY, \
	`IF_NONE, `FIELD_B 0, `FIELD_C 0, `OP_CODE_SET_OUTPUT_COMPLETE}


// *** Instructions - execution control ***
`define	JMP(addr) {`FIELD_A 0, `EXEC_OPT_NONE, \
	`CONDITION, `FIELD_B 0, `FIELD_C addr, `OP_CODE_JMP}

`define	SET_UF {`FIELD_A 0, `EXEC_OPT_NONE, \
	`CONDITION, `FIELD_B 1, `FIELD_C 0, `OP_CODE_FLAG}
`define	RST_UF {`FIELD_A 0, `EXEC_OPT_NONE, \
	`CONDITION, `FIELD_B 2, `FIELD_C 0, `OP_CODE_FLAG}
`define	INV_UF {`FIELD_A 0, `EXEC_OPT_NONE, \
	`CONDITION, `FIELD_B 3, `FIELD_C 0, `OP_CODE_FLAG}


// *** Registers - BRAM ***
`define	R0		0
`define	R1		1
`define	R2		2
`define	R3		3
`define	R4		4
`define	R5		5
`define	R6		6
`define	R7		7
`define	R8		8
`define	R9		9
`define	R10	10
`define	R11	11
`define	R12	12
`define	R13	13
`define	R14	14
`define	R15	15

