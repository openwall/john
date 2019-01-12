`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha256.vh"


module cpu #(
	parameter WIDTH = 16,
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	input [`ENTRY_PT_MSB:0] entry_pt_curr,	
	// thread_state (ts)
	output [N_THREADS_MSB :0] ts_rd_num, ts_wr_num, // Thread #
	output reg ts_wr_en = 0,
	output reg [`THREAD_STATE_MSB :0] ts_wr,
	input [`THREAD_STATE_MSB :0] ts_rd,

	// comp_buf & procb_buf
	output reg comp_wr_en = 0, procb_wr_en = 0,
	output reg [N_THREADS_MSB :0] comp_procb_wr_thread_num,
	input [`PROCB_A_WIDTH-1 :0] procb_wr_cnt,
	output reg [`COMP_DATA1_MSB + `COMP_DATA2_MSB+1 :0] comp_dout,
	output reg [`PROCB_D_WIDTH-1 :0] procb_dout,
	
	// input from the memory
	output reg mem_rd_request = 0,
	output reg [`MEM_TOTAL_MSB :0] mem_rd_addr,
	input mem_rd_valid,
	input [2*WIDTH-1:0] mem_din,
	
	// unit_output_buf
	output [15:0] uob_dout,
	output uob_wr_en, uob_set_input_complete,
	output [`UOB_ADDR_MSB :0] uob_wr_addr,
	input uob_ready, uob_full,
	output err
	);

	reg z;
	
	wire INVALIDATE_eqn, INSTR_WAIT_eqn;
	reg EXECUTED = 0;
	reg NEXT_THREAD = 0;
	reg INSTR_WAIT = 0;
	reg JUMP = 0;
	reg [`IADDR_LEN-1 :0] jump_addr;


	// Thread State Changed flag.
	// A thread runs only in WR_RDY state, when thread_state
	// changes it has to switch current thread (that takes 4 cycles).
	//
	// The feature allows it to continue running until JMP
	// or until EXEC_OPT_TS_WR_RDY instruction (that requires WR_RDY state).
	//
	reg ts_changed = 0;
	always @(posedge CLK)
		if (thread_almost_switched)
			ts_changed <= 0;
		else if (thread_state_change)
			ts_changed <= 1;


	// *****************************************************************
	//
	// Instruction Execution
	// - the instruction right out from memory is available here.
	//
	// *****************************************************************
	wire [N_THREADS_MSB :0] thread_num;
	
	wire [`N_STAGES-1:0] stage_allow;
	//wire STAGE_INSTR_AVAIL = stage_allow[];
	wire STAGE_RD0 = stage_allow[1];
	wire STAGE_RD1 = stage_allow[2];
	wire STAGE_EXEC = stage_allow[3];
	
	wire [`FIELD_A_LEN-1 :0] field_a_in;
	wire [`EXEC_OPT_LEN-1: 0] exec_opt_in;
	wire [`PARTIAL_INSTR_LEN-1 :0] partial_instruction;
	
	instruction #( .N_CORES(N_CORES)
	) instruction(
		.CLK(CLK),
		.entry_pt_curr(entry_pt_curr),
		.ts_rd_num(ts_rd_num), .ts_rd(ts_rd),
		.thread_num(thread_num),
		// Asserts for 1 cycle at STAGE_RD1
		.thread_almost_switched(thread_almost_switched),
		.instruction({ field_a_in, exec_opt_in, partial_instruction }),
		.INVALIDATE(INVALIDATE_eqn),
		.INSTR_WAIT(INSTR_WAIT_eqn | INSTR_WAIT),
		.NEXT_THREAD(NEXT_THREAD), .EXECUTED(EXECUTED),
		.JUMP(JUMP), .jump_addr(jump_addr),
		.stage_allow(stage_allow),
		.err(err),
		// dummy 2nd port
		.wr_en_dummy(1'b0), .wr_addr_dummy(1'b0)
	);

	assign ts_wr_num = thread_num;

	wire op_type_use_reg0
		= `OP_TYPE_USE_REG(partial_instruction [`OP_CODE_LEN-1 :0]);


	// *****************************************************************
	//
	// Input from the memory
	//
	// *****************************************************************
	reg mem_rd_valid_r = 0, mem_wr_lower = 0;

`ifdef CPU_MV_R_MEM_2X
	// support for MV_R_MEM_2X
	reg [2*WIDTH-1:0] mem_r;
	reg mem_wr_2x = 0, mem_rd_valid_r2 = 0;

	always @(posedge CLK) begin
		if (mem_rd_valid)
			mem_r <= mem_din;
		mem_rd_valid_r <= mem_rd_valid;
		mem_rd_valid_r2 <= mem_rd_valid_r;
	end

	wire mem_rd_wr_en = mem_rd_valid_r | mem_wr_2x & mem_rd_valid_r2;
	// 0: lower half, 1: upper half
	wire mem_wr_select = ~(mem_rd_valid_r & (mem_wr_2x | mem_wr_lower));
	// writing upper half into the next register
	wire mem_rd_wr_2x = mem_wr_2x & mem_rd_valid_r2;
	wire mem_rd_complete = mem_wr_2x ? mem_rd_valid_r2 : mem_rd_valid_r;

`else
	reg [WIDTH-1:0] mem_r;

	always @(posedge CLK) begin
		if (mem_rd_valid)
			mem_r <= mem_wr_lower ? mem_din[15:0] : mem_din[31:16];
		mem_rd_valid_r <= mem_rd_valid;
	end

	wire mem_rd_wr_en = mem_rd_valid_r;
	wire mem_rd_complete = mem_rd_valid_r;

`endif


	// *****************************************************************
	//
	// Going to stage STAGE_RD0.
	//
	// *****************************************************************
	reg [`EXEC_OPT_LEN-1: 0] exec_opt;
	reg [`CONDITION_LEN-1 :0] op_condition;
	reg [`FIELD_B_LEN-1 :0] field_b;
	reg [`FIELD_C_LEN-1 :0] field_c;
	reg [`OP_CODE_LEN-1:0] op_code;
	
	always @(posedge CLK)
		if (STAGE_RD0) begin
			exec_opt <= exec_opt_in;
			{ op_condition, field_b, field_c, op_code }
				<= partial_instruction;
		end

	wire op_type_use_reg = `OP_TYPE_USE_REG(op_code);


	// *****************************************************************
	//
	// Registers
	// - load is 2 cycles (rd_en0, rd_en1)
	// - 4 inputs (controlled with reg_din_select)
	//
	// *****************************************************************
	wire [WIDTH-1:0] reg_din1, reg_din2, reg_din3, reg_dout;
	wire [1:0] reg_din_select;
	(* SHREG_EXTRACT="no" *)
	// Write enable, for stages 3,4 respectively
	reg reg_wr_en3 = 0, reg_wr_en4 = 0;
	reg [`REG_ADDR_MSB :0] reg_wr_addr4;
	reg [N_THREADS_MSB :0] reg_wr_thread4;

	registers_bram #( .WIDTH(WIDTH), .N_THREADS(N_THREADS)
	) registers(
		.CLK(CLK),
		.din1(reg_din1), .din2(reg_din2), .din3(reg_din3),

`ifdef CPU_MV_R_MEM_2X
		.mem_din(mem_wr_select ? mem_r[2*WIDTH-1:WIDTH] : mem_r[WIDTH-1:0]),
		.wr_addr( { reg_wr_addr4[`REG_ADDR_MSB:1],
				mem_rd_wr_2x ? 1'b1 : reg_wr_addr4[0] } ),
`else
		.mem_din(mem_r), .wr_addr(reg_wr_addr4),
`endif
		
		.mem_wr_en(mem_rd_wr_en), .wr_en(reg_wr_en4),
		.reg_din_select(reg_din_select),
		.wr_thread_num(reg_wr_thread4),
		
		.rd_addr(field_a_in),
		.rd_en0(STAGE_RD0),// & op_type_use_reg0),
		.rd_en1(STAGE_RD1 & op_type_use_reg),
		.rd_thread_num(thread_num), .dout(reg_dout)
	);


	// *****************************************************************
	//
	// Going to stage STAGE_RD1.
	//
	// *****************************************************************
	reg [`EXEC_OPT_LEN-1: 0] exec_opt1;
	reg [`CONDITION_LEN-1 :0] op_condition1;
	reg [`FIELD_B_LEN-1 :0] field_b1;
	reg [`FIELD_C_LEN-1 :0] field_c1;
	reg [N_THREADS_MSB :0] thread_num1;
	reg [`OP_CODE_LEN-1:0] op_code1;
	
	always @(posedge CLK)
		if (STAGE_RD1) begin
			exec_opt1 <= exec_opt;
			op_condition1 <= op_condition;
			field_b1 <= field_b;
			field_c1 <= field_c;
			thread_num1 <= thread_num;
			op_code1 <= op_code;
		end
	
	always @(posedge CLK)
		if (STAGE_EXEC) begin
			reg_wr_addr4 <= field_b1 [`REG_ADDR_MSB :0];
			reg_wr_thread4 <= thread_num1;
		end


	// *****************************************************************
	//
	// Integer Operations
	//
	// - no "reg <- reg (op) reg" operations so far
	//
	// *****************************************************************
	wire [`N_FLAGS-1 :0] flags;
		
	// iops (controls for integer operations)
	reg iop_addsub = 0, iop_sub = 0, iop_use_cf = 0,
		iop_grp2 = 0, iop_grp3 = 0, iop_shr1 = 0;
	reg [1:0] iop_grp2_select = 0;

	integer_ops #( .WIDTH(WIDTH) ) integer_ops(
		.CLK(CLK),
		.dina(reg_dout), .dinb(field_c1), .en(STAGE_EXEC),
		.in_cf(`FLAG_CARRY(flags)),
		.iops({ iop_addsub, iop_sub, iop_use_cf,
				iop_grp2, iop_grp3, iop_shr1 }),
		.iop_grp2_select(iop_grp2_select),
		
		.dout_select(reg_din_select),
		.dout1(reg_din1), .dout2(reg_din2), .dout3(reg_din3),
		.flag_zf(flag_zf_in), .flag_of(flag_of_in), .flag_cf(flag_cf_in)
	);
	

	// *****************************************************************
	//
	// Internal CPU Operations - STAGE_RD1
	//
	// - op_code is available
	//
	// *****************************************************************
	reg iop_sets_uf = 0, iop_sets_cf = 0, iop_sets_of = 0, iop_sets_zf = 0;
	reg [1:0] iop_flag_code = 0;
	reg iop_jmp = 0, iop_halt = 0;

	always @(posedge CLK)
		if (STAGE_RD1) begin
			iop_addsub <=
				op_code == `OP_CODE_ADD_R_C | op_code == `OP_CODE_SUB_R_C
				| op_code == `OP_CODE_ADDC_R_C | op_code == `OP_CODE_SUBB_R_C;
			iop_sub <= op_code == `OP_CODE_SUB_R_C
				| op_code == `OP_CODE_SUBB_R_C;
`ifdef INSTR_SUBB_EN
			iop_use_cf <= `OP_TYPE_USE_CF(op_code);
`endif

			iop_grp2 <= op_code == `OP_CODE_INC_RST
				| op_code == `OP_CODE_MV_R_C | op_code == `OP_CODE_AND;
			iop_grp2_select <=
				op_code == `OP_CODE_INC_RST ? 2'd1 :
				op_code == `OP_CODE_AND ? 2'd2 :
				2'd0;
			if (op_code == `OP_CODE_INC_RST)
				z <= 1;
			
			iop_grp3 <= op_code == `OP_CODE_SHR1 | op_code == `OP_CODE_MV_R_R;
			iop_shr1 <= op_code == `OP_CODE_SHR1;
			
			// This op. potentially writes into a register
			// (write might not be performed dependent on conditions).
			reg_wr_en3 <= `OP_TYPE_WRITE_REG(op_code);
			
			// It's hardcoded(hardwired?) when instruction checks conditions.
			//op_checks_conditions <= OP_TYPE_CHECK_CONDITION(op_code);
			
			iop_sets_zf <= `OP_TYPE_SETS_ZF(op_code);
			iop_sets_of <= `OP_TYPE_SETS_OF(op_code);
			iop_sets_cf = `OP_TYPE_SETS_CF(op_code);
			
			// OP_CODE_FLAG: applicable to UF only
			iop_sets_uf <= op_code == `OP_CODE_FLAG;
			if (op_code == `OP_CODE_FLAG)
				z <= 1;
			iop_flag_code <= field_b[1:0];
			
			iop_jmp <= op_code == `OP_CODE_JMP;
			if (op_code == `OP_CODE_JMP)
				z <= 1;
			
			iop_halt <= op_code == `OP_CODE_HALT;
			if (op_code == `OP_CODE_HALT)
				z <= 1;
		end

	
	// *****************************************************************
	//
	// Internal CPU Operations - STAGE_EXEC
	//
	// - writes integer_ops.dout
	// - checks conditions
	// - sets flags
	//
	// *****************************************************************
	cpu_flags #( .N(`N_FLAGS), .N_THREADS(N_THREADS)
	) cpu_flags(
		.CLK(CLK),
		.thread_num(thread_num),
		.load_en(thread_almost_switched), .save_en(NEXT_THREAD),
		.flags(flags),
		.op_condition(op_condition1),	.condition_is_true(condition_is_true),
		
		.set_flags(STAGE_EXEC),
		.iop_flag_mask({ iop_sets_uf, iop_sets_cf, iop_sets_of, iop_sets_zf }),
		.flags_in({ flag_uf_in, flag_cf_in, flag_of_in, flag_zf_in })
	);

	assign flag_uf_in =
			iop_flag_code == 2'b00 ? `FLAG_USER(flags) :
			iop_flag_code == 2'b01 ? 1'b1 :
			iop_flag_code == 2'b10 ? 1'b0 :
			~`FLAG_USER(flags);


	always @(posedge CLK) begin
		// Check conditions for all integer operations that write registers
		reg_wr_en4 <= STAGE_EXEC & reg_wr_en3 & condition_is_true;

		if (iop_jmp)
			jump_addr <= field_c1 [`IADDR_LEN-1 :0];

		if (op_condition1 == `IF_CARRY)
			z <= 1;
	end
	

	// *****************************************************************
	//
	// Input/Output Operations.
	//
	// - MV_R_MEM_{2X|L|U} (Reg <- Memory)
	// - MV_UOB_R (Unit output buf. <- Reg)
	// - SET_OUTPUT_COMPLETE
	//
	// *****************************************************************
	reg op_mv_r_mem = 0, op_mv_r_mem2x = 0, op_mv_r_mem_lower = 0;
	
	always @(posedge CLK)
		if (STAGE_RD1) begin
			op_mv_r_mem <= `OP_TYPE_MV_R_MEM(op_code);
`ifdef CPU_MV_R_MEM_2X
			op_mv_r_mem2x <= op_code == `OP_CODE_MV_R_MEM_2X;
`endif
			op_mv_r_mem_lower <= op_code == `OP_CODE_MV_R_MEM_L;
			op_mv_uob_r <= op_code == `OP_CODE_MV_UOB_R;
			op_set_output_complete <= op_code == `OP_CODE_SET_OUTPUT_COMPLETE;
		end

	always @(posedge CLK) //!
		if (STAGE_EXEC & op_mv_r_mem) begin
			mem_rd_request <= 1;
			mem_rd_addr <= { thread_num, field_c1 [`MEM_ADDR_MSB :0] };
`ifdef CPU_MV_R_MEM_2X
			mem_wr_2x <= op_mv_r_mem2x;
`endif
			mem_wr_lower <= op_mv_r_mem_lower;
		end
		else if (mem_rd_valid)
			mem_rd_request <= 0; // data on mem_r; mem_rd_valid_r asserts


	// UOB (unit's output buffer). (-)Output takes 2 cycles.
	// uob_wr_en asserts only on the 1st cycle.
	reg op_mv_uob_r = 0, op_set_output_complete = 0;
	reg [N_THREADS_MSB :0] uob_thread_num;
	//reg mv_uob_r_cycle2 = 0;
	reg uob_thread_num_eq_thread_num = 0;

	always @(posedge CLK) begin
		if (thread_almost_switched)
			uob_thread_num_eq_thread_num <= uob_thread_num == thread_num;
		if (uob_eqn) begin
			if (uob_ready)
				uob_thread_num <= thread_num;
			//mv_uob_r_cycle2 <= 1;
			uob_thread_num_eq_thread_num <= 1;
		end
		//else
		//	mv_uob_r_cycle2 <= 0;
	end
	
	assign uob_dout = reg_dout;
	assign uob_wr_addr = field_c1 [`UOB_ADDR_MSB :0];
	assign uob_wr_en = uob_eqn;
	
	assign uob_eqn = STAGE_EXEC & op_mv_uob_r
		& (uob_ready | uob_thread_num_eq_thread_num & ~uob_full);
	

	assign uob_set_input_complete = STAGE_EXEC & op_set_output_complete;
	

	// *****************************************************************
	//
	// Integrated (Cryptographic core) Operations - STAGE_RD1
	//
	// *****************************************************************
	(* SHREG_EXTRACT="no" *)
	reg op_init_ctx = 0, op_init_new = 0, op_procb = 0, op_procb_r = 0;
	reg op_procb_flags = 0;

	always @(posedge CLK)
		if (STAGE_RD1) begin
			op_init_ctx <= `OP_TYPE_INIT_CTX(op_code);
			//op_init_new <= op_code[0];//op_code == `OP_CODE_NEW_CTX;
				
			op_procb <= `OP_TYPE_PROCB(op_code);
			op_procb_r <= `OP_TYPE_PROCB_R(op_code);
			op_procb_flags <= op_code[1];
		end


	reg [`PROCB_A_WIDTH-1 :0] procb_wr_cnt_r;
	always @(posedge CLK) begin
		comp_procb_wr_thread_num <= thread_num;
		if (thread_almost_switched)
			procb_wr_cnt_r <= procb_wr_cnt;
		else if (procb_eqn)
			procb_wr_cnt_r <= procb_wr_cnt_r + 1'b1;
	end
	assign procb_full = procb_wr_cnt_r == `PROCB_N_RECORDS;
	assign procb_afull = procb_wr_cnt_r == `PROCB_N_RECORDS - 1;
	

	// *****************************************************************
	//
	// Integrated (Cryptographic core) Operations - STAGE_EXEC
	//
	// *****************************************************************
	// thread_state disables execution (applicable at STAGE_EXEC)
	wire ts_disable_exec = (exec_opt1 & `EXEC_OPT_TS_WR_RDY) != 0 & ts_changed;

	// procb_eqn: writes procb_wr_en if thread_state allows
	assign procb_eqn = op_procb & condition_is_true & ~ts_disable_exec;// & ~procb_full;

	always @(posedge CLK) begin
		comp_wr_en <= STAGE_EXEC & op_init_ctx & ~ts_disable_exec;
		if (op_init_ctx)
			comp_dout <= { 1'b1, field_b1, field_c1[3:0] };

		procb_wr_en <= STAGE_EXEC & procb_eqn;
		if (op_procb)
			//procb_dout <= { field_b1, reg_dout[7:0], op_procb_flags };
			// Allow constant 'cnt' (length)
			procb_dout <= { field_b1, (op_procb_r
				? reg_dout[`PROCB_CNT_MSB:0] : field_c1[`PROCB_CNT_MSB:0]),
				op_procb_flags };
	end
	


	// *****************************************************************

	wire JUMP_eqn = STAGE_EXEC & (iop_jmp & condition_is_true);

	wire NEXT_THREAD_eqn = STAGE_EXEC & (1'b0
		| iop_halt
		| ts_disable_exec & condition_is_true

		// Switch to the next thread when:
		// - Successful PROCESS_BYTES with fin/stop or procb_buf full
		//| procb_eqn & (op_procb_flags != 0 | procb_afull)

		// - move to UOB, UOB is full or used by other thread
		| op_mv_uob_r & ~(uob_ready | uob_thread_num_eq_thread_num & ~uob_full)
		// 
		//| op_set_output_complete
		//
		// - JUMP_eqn forces NEXT_THREAD
	);

	
	// Invalidate loaded instructions, start loading from the beginning
	// when:
	// - Successful jump is performed
	// - Thread is switched
	assign INVALIDATE_eqn = NEXT_THREAD_eqn | JUMP_eqn;

	// Oops. On INSTR_WAIT, it doesn't preserve reg_dout, field_[b|c]1 etc.
	assign INSTR_WAIT_eqn = STAGE_EXEC & (1'b0
		| op_mv_r_mem
		//| uob_eqn
	);
	
	wire INSTR_CONTINUE_eqn = 1'b0
		| mem_rd_complete
		//| mv_uob_r_cycle2
	;


	// *****************************************************************

	always @(posedge CLK) begin

		// TODO: improve condition?
		if (INSTR_CONTINUE_eqn)
			INSTR_WAIT <= 0;
		else if (INSTR_WAIT_eqn)
			INSTR_WAIT <= 1;
		

		NEXT_THREAD <= NEXT_THREAD_eqn | JUMP_eqn;

		JUMP <= JUMP_eqn;
		
		EXECUTED <= STAGE_EXEC & (1'b0
			// Instruction typically executed when:
			// - No Invalidate condition, no Wait condition
			| (~INVALIDATE_eqn & ~INSTR_WAIT_eqn)
			// Exceptions:
			// - execution disabled because of wrong thread_state
				& ~(ts_disable_exec & condition_is_true)
			//| procb_eqn & (op_procb_flags != 0 | procb_afull)

		) | (1'b0
			// - It continues after Wait condition
			| (INSTR_WAIT & INSTR_CONTINUE_eqn)
		);


		if (ts_wr_en)
			ts_wr_en <= 0;
		else if (thread_state_change)
			ts_wr_en <= 1;

		ts_wr <=
			op_set_output_complete ? `THREAD_STATE_NONE :
			`THREAD_STATE_RD_RDY
		;

	end

	assign thread_state_change = STAGE_EXEC & (1'b0
		// Successful PROCESS_BYTES with fin/stop or procb_buf becoming full
		| procb_eqn & (op_procb_flags != 0 | procb_afull)
		// Sending UOB content for output
		| op_set_output_complete
	);


`ifdef SIMULATION
	reg [23:0] X_THREAD_SWITCHES = 0;
	reg [23:0] X_JUMPS = 0;
	
	always @(posedge CLK) begin
		if (NEXT_THREAD)
			X_THREAD_SWITCHES <= X_THREAD_SWITCHES + 1'b1;
		if (JUMP)
			X_JUMPS <= X_JUMPS + 1'b1;
	end
`endif

endmodule
