`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"


module sha512unit_test();

	reg READ_ALL_FROM_UOB = 1;

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

		for (i=0; i < 10; i=i+1)
			send_data_packet(10,8,8,"ssssssss","11111111"); // fe43fc48..93c527d7

		send_data_packet(1,1,48,"1", // c5ca32ea..616d07c0
			"sha512crypt-ztex test #3 (salt_len=1, A0>200) .z");

		send_data_packet(1,16,48,"salt_length_is16", // 835c56d2..5f5718a3
			"sha512crypt-ztex test #1 (salt=16,key_len=48) ..");

		send_data_packet(1,15,48,"salt_lengthis15", // 3df01467..d842a83e
			"sha512crypt-ztex test #2 (salt=15,key_len=48) ..");
				
		send_data_packet(1,1,48,"1", // c5ca32ea..616d07c0
			"sha512crypt-ztex test #3 (salt_len=1, A0>200) .z");

		send_data_packet(1,16,56,"1234567890aBcdef", // f463f9d8..e3026ee8
			"sha512crypt-ztex test #4 (salt_len=16, key_len=56) .....");

		send_data_packet(1,15,56,"1234567890aBcde", // d799d060..60d1ccb4
			"sha512crypt-ztex test #5 (salt_len=15, key_len=56) .....");


		// *****************************************************************
		//
		// Send internal initialization packet.
		// Restrictions:
		// - must wait ~16 cycles after startup (wouldn't happen
		//   on a real device)
		// - units must be idle (typically init packet is sent after GSR)
		//
		// Arguments:
		// 0 - default sha512crypt program (entry pt.0)
		// 1 - Drupal7 program
		//
		// *****************************************************************
/*
		#1000;
		send_int_init_packet(1);

		// *****************************************************************
		//
		// Usage: send_data_packet(cnt,salt_len,key_len,"salt","key");
		//
		// Send Drupal7 packet for the following:
		//
		//	{"$S$CFURCPa.k6FAEbJPgejaW4nijv7rYgGc4dUJtChQtV4KLJTPTC/u", "password"}
		//
		// *****************************************************************

		send_data_packet(16384,8,8,"FURCPa.k","password");
*/
	end


	// ***************************************************************
	integer k, k1, salt_real_len, key_real_len;

	reg CLK = 0; // Each cycle is 20ns

	reg [`UNIT_INPUT_WIDTH-1 :0] in;
	reg ctrl = 0, wr_en = 0;


	sha512unit sha512unit(
		.CLK(CLK),
		.unit_in(in), .unit_in_ctrl(ctrl),
		.unit_in_wr_en(wr_en), .unit_in_afull(afull),
		.unit_in_ready(ready),
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
