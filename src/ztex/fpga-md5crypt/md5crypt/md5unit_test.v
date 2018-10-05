`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "md5.vh"


module md5unit_test();

	reg READ_ALL_FROM_UOB = 1;

	localparam N_CORES = 3;

	integer i;

	initial begin
		// *****************************************************************
		//
		// Send an internal data packet exactly as from pkt_comm.arbiter_tx
		// to the unit.
		//
		// Usage: send_data_packet(cnt,salt_len,key_len,"salt","key");
		//
		// Data is written to the beginning of the first idle thread's
		// memory, then program starts.
		//
		// Result from 1 thread appears in the UOB, the rest remains
		// in unit's main memory.
		// The unit has no internal check for the count of rounds.
		//
		// *****************************************************************
		#1000;
		//
		//   SMALL ROUND COUNT
		//
/*
		// crypt_md5("abc","12345678");
		// 3 ROUNDS
		// hash: $1$12345678$R/GHVeY2oOgDNBsFpXRO/0
		// result: 473e124d 4a20f569 81d883c6 59b4a15d
		//
		send_data_packet(3,8,3,"12345678","abc");
		send_data_packet(3,8,3,"12345678","abc");
		#20;
*/
		//
		//   DEFAULT ROUND COUNT
		//

		// crypt_md5("abc","12345678");
		// 1000 ROUNDS
		// hash: $1$12345678$GVDEjIF51EkM3MPmFX6dO1
		// result: c9631d40 15f8d1a4 da88b604 05032f52
		//
		send_data_packet(1000,8,3,"12345678","abc");
		#20;

		// *****************************************************************
		//
		// Send internal initialization packet.
		// Restrictions:
		// - must wait ~16 cycles after startup (wouldn't happen
		//   on a real device)
		// - units must be idle (typically init packet is sent after GSR)
		//
		// Arguments:
		// 0 - default program (entry pt.0)
		//
		// *****************************************************************
		#1000;
/*
		send_int_init_packet(1);

		// {"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"}
		send_data_packet(2048,8,8,"00000000","openwall");
*/
	end


	// ***************************************************************
	integer k, k1, salt_real_len, key_real_len;

	reg CLK = 0; // Each cycle is 20ns

	reg [`UNIT_INPUT_WIDTH-1 :0] in;
	reg ctrl = 0, wr_en = 0;


	md5unit #( .N_CORES(N_CORES) ) md5unit(
		.CLK(CLK),
		.unit_in(in), .unit_in_ctrl(ctrl),
		.unit_in_wr_en(wr_en), .unit_in_afull(afull),
		.unit_in_ready(ready),

		.PKT_COMM_CLK(CLK),
		.dout(), .rd_en(READ_ALL_FROM_UOB), .empty()
	);


	// ***************************************************************
	task check_afull;
		begin
			while (afull) begin
				wr_en <=0; #20;
			end
			wr_en <= 1;
		end
	endtask


	// *************************************************************
	//
	// Unit accepts packets.
	// - packet header (1 input word). It isn't written into memory.
	// - cnt (number of rounds) - 32 bit
	// - salt_len - 32 bit
	// - salt data - 16 bytes (2x64 bits), regardless of salt_len
	// - IDs - 64 bit
	// - key_len - 32 bit
	// - unused - 32 bit
	// - key data (rounded up to 32 bits), variable size
	//
	// Packet is written to the beginning of thread's memory.
	// If packet length is not divisible by 4 bytes, excess
	// bytes get trashed.
	//
	// *************************************************************
	task send_data_packet;
		input [31:0] cnt;
		input [7:0] salt_len, key_len;
		input [0:127] salt;
		input [0:511] key; // 64 bytes max.
		begin
			while (~ready) #20;
			check_afull();

			// word #0: packet type (0 - data packet)
			ctrl <= 1; in <= 0; #20;
			ctrl <= 0;

			check_afull();
			for (k=0; k < 4; k=k+1) begin
				in <= cnt[k*8 +:8]; #20;
			end

			check_afull();
			in <= salt_len; #20; in <= 8'h00; #(3*20);//#(7*20);

			check_afull();
			salt_real_len = 0;
			for (k=0; k < 16; k=k+1) begin
				check_afull();
				if (salt[k*8 +:8] != 0) begin
					in <= salt[k*8 +:8];
					salt_real_len = salt_real_len+1;
					#20;
				end
			end

			for (k=salt_real_len; k < 16; k=k+1) begin
				check_afull();
				in <= 8'h00;
				#20;
			end

			check_afull();
			for (k=0; k < 8; k=k+1) begin
				in <= 8'h0f; #20; // IDs (64-bit)
			end

			check_afull();
			in <= key_len; #20; in <= 8'h00; #(7*20);

			key_real_len = 0;
			for (k=0; k < 64; k=k+1) begin
				check_afull();
				if (key[k*8 +:8] != 0) begin
					in <= key[k*8 +:8];
					key_real_len = key_real_len+1;
					#20;
				end
			end

			for (k=key_real_len; k < 64; k=k+1) begin
				check_afull();
				in <= 8'h00;
				#20;
			end

			ctrl <= 1; #20;
			ctrl <= 0; wr_en <= 0; #20;
			#(4*20);
		end
	endtask


	// *************************************************************
	//
	// Initialization packet.
	// Contains only header (1 word).
	// 3 lowest bits are 3'b001, bits 7-4 contain init data.
	//
	// *************************************************************
	task send_int_init_packet;
		input [7:0] din;
		begin
			ctrl <= 1; wr_en <= 1;
			in <= { din[4:0], 3'b001 }; #20;
			#20;
			ctrl <= 0; wr_en <= 0;
		end
	endtask


	// ***************************************************************

	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule
