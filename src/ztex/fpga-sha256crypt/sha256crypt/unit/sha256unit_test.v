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


module sha256unit_test();

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
		
		// { "$5$rounds=3$saltstring", "Hello world!",
		// "$5$rounds=3$saltstring$xMhNpyTgkOg7GDuj2Z5DDLiNiI9DgAITfm86Y82iqxB" },
		//
		// Hash (MSB 1st):
		// df76a4ac 7d2ee53c ... 433ccf79 bfb0ff66
		send_data_packet(3,10,12,"saltstring","Hello world!");

		// { "$5$rounds=10$=", "salt_len1",
		// "$5$rounds=10$=$6xbUmUoT3ar.pSyHy3wyYp1.PFjzlnvdhokMQn14449" },
		// b186dc0d ... 4f854882
		send_data_packet(10,1,9,"=","salt_len1");

		// { "$5$rounds=10$.", "abc",
		// "$5$rounds=10$.$RqqFgOjl6uw9cciogvv9qYLzWJu5JgBivoh1TDMJTj3" },
		// 5bdfdfdd ... d288f647
		send_data_packet(10,1,3,".","abc");

		// { "$5$rounds=7$012/4567/9ab/def", "abc",
		// "$5$rounds=7$012/4567/9ab/def$PuWZaW9xjN7hQqLxTwMi.LSDm9xztq00tGdz8khP/wC" },
		// ef010a94 ... f56fb896
		send_data_packet(7,16,3,"012/4567/9ab/def","abc");

		// { "$5$rounds=10$012.456789.bedef", "test #3: salt_len=16, key_len=32",
		// "$5$rounds=10$012.456789.bedef$XMH8OphJozuO.eUybsWi33AKE9Gigj6JwNLyjp6MYY8" },
		// a9246f76 ... faf4dd29
		send_data_packet(10,16,32,"012.456789.bedef","test #3: salt_len=16, key_len=32");

		// { "$5$rounds=10$0//3456789//edef", "key_len=11.",
		// "$5$rounds=10$0//3456789//edef$PSqu85Ls/ajCpozZexq3yEZhffR0avwyFklOQhdAgD5" },
		// 73ec5c1c ... 978171eb
		send_data_packet(10,16,11,"0//3456789//edef","key_len=11.");

		// { "$5$rounds=10$0.2.456789.bede", "key_len8",
		// "$5$rounds=10$0.2.456789.bede$Oa3.7QX2HSXd/8uxwAEGULC2/GdKxiaUhYkCeeXtSo4" },
		// 6d1eaa09 ... f7933700
		send_data_packet(10,15,8,"0.2.456789.bede","key_len8");

		#20;

		//
		//   DEFAULT ROUND COUNT
		//
/*
		// { "$5$saltstring", "Hello world!",
		// "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
		// 7a104d5d ... 7f80e9ec
		send_data_packet(5000,10,12,"saltstring","Hello world!");

		// { "$5$rounds=5019$0.2345.789.bede", "salt15,key=13",
		// "$5$rounds=5019$0.2345.789.bede$MkvvIivtYEIOJcDzMEvma3ParB1/s9Ht02poIWA1RK7"},
		// 959d9451 ... fc24bbef
		send_data_packet(5019,15,13,"0.2345.789.bede","salt15,key=13");

		// { "$5$=", "salt1,key11",
		// "$5$=$Qh125aRhMbwg8Phe/jIjQwos/v9I.vR/e7R1rjiYfBC"},
		// e36bf7d2 ... aad8d910
		send_data_packet(5000,1,11,"=","salt1,key11");

		// { "$5$rounds=4970$0.234.6789.bc/ef", "12345678",
		// "$5$rounds=4970$0.234.6789.bc/ef$7NDazjArUHJs988r5ovAyd5tIkJybwD9JOibJfzgWuD"},
		// fea2d5e6 ... dce0cb98
		send_data_packet(4970,16,8,"0.234.6789.bc/ef","12345678");

		// { "$5$rounds=4972$0/2345.789//edef", "abc",
		// "$5$rounds=4972$0/2345.789//edef$DDPKQRM7xJkpe4pdf13My8qCJPeFmXn6nNiwYk.R.wB"},
		// df0024e6 ... a77d8759
		send_data_packet(4972,16,3,"0/2345.789//edef","abc");

		// { "$5$012/45.7/9ab/def", "test #3: salt_len=16, key_len=32",
		// "$5$012/45.7/9ab/def$wz2Bni8S/YVASQHPTNWPiUd17QwYow5qLbmSUvgZhd1"},
		// 3a6de029 ... 6d01ab34
		send_data_packet(5000,16,32,"012/45.7/9ab/def","test #3: salt_len=16, key_len=32");
*/


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
		
		//send_int_init_packet(1);
		
	end
	

	// ***************************************************************
	integer k, k1, salt_real_len, key_real_len;

	reg CLK = 0; // Each cycle is 20ns
	
	reg [`UNIT_INPUT_WIDTH-1 :0] in;
	reg ctrl = 0, wr_en = 0;
	

	sha256unit sha256unit(
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
