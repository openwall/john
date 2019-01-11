/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`ifndef _PKT_COMM_TEST_HELPER_VH_
`define _PKT_COMM_TEST_HELPER_VH_

// ***************************************************************
//
// Helper functions to create pkt_comm packets.
// Operates 8-bit input:
// reg [7:0] din
// reg wr_en
//
// ***************************************************************


// ***************************************************************
//
// Packet type PKT_TYPE_CONFIG (0x06)
//
// ***************************************************************
task send_config_packet;
	input [7:0] subtype;
	input [7:0] len; // data length (excl. subtype & reserved)
	input [511:0] data; // 64 max.
	begin: doit
		integer i;
		wr_en <= 1;
		din <= 2; #20; din <= 6; #20; // ver, type
		din <= 0; #40; // reserved0
		din <= len+2; #20; din <= 0; #20;
		din <= 0; #20;
		din <= 0; #20; // reserved1
		din <= 8'h00; #40; // IDs in PKT_TYPE_CONFIG not used
		din <= 0; #80; // checksum
		// body
		din <= subtype; #20;
		for (i = 0; i < len; i=i+1) begin
			din <= data[i*8 +:8]; #20;
		end
		din <= 0; #20; // reserved
		din <= 0; #80; // checksum
		wr_en <= 0;
	end
endtask


// ***************************************************************
//
// Packet type PKT_TYPE_INIT (0x05)
//
// ***************************************************************
task send_init_packet;
	input [7:0] data;
	begin
		wr_en <= 1;
		din <= 2; #20; din <= 5; #20; // ver, type
		din <= 0; #40; // reserved0
		din <= 1; #20; din <= 0; #20; // len=1
		din <= 0; #20;
		din <= 0; #20; // reserved1
		din <= 8'h00; #40; // IDs in PKT_TYPE_INIT not used
		din <= 0; #80; // checksum
		// body
		din <= data; #20;
		din <= 0; #80; // checksum
		wr_en <= 0;
	end
endtask


// ***************************************************************
//
// Packet type CMP_CONFIG (0x03)
//
// ***************************************************************
integer cmp_iter_count, cmp_salt_len, cmp_num_hashes;
reg [0:8*16-1] cmp_salt;
reg [0:32*`NUM_HASHES-1] cmp_hashes;

task cmp_config_create;
	input [31:0] iter_count;
	input [7:0] salt_len;
	input [0:8*16-1] salt;
	begin: doit
		integer i, salt_ptr;
		salt_ptr = 0;
		
		cmp_iter_count = iter_count;
		cmp_salt_len = salt_len;
		for (i=0; i < 16; i=i+1)
			if (salt[8*i +:8] != 0) begin
				cmp_salt[8*salt_ptr +:8] = salt[8*i +:8];
				salt_ptr = salt_ptr + 1;
			end
		for (i=salt_ptr; i < 16; i=i+1)
			cmp_salt[8*i +:8] = 0;
		cmp_num_hashes = 0;
	end
endtask


task cmp_config_add_hash;
	input [31:0] hash;
	begin
		cmp_hashes [cmp_num_hashes*32 +:32]
			<= { hash[7:0], hash[15:8], hash[23:16], hash[31:24] };
		cmp_num_hashes = cmp_num_hashes + 1;
	end
endtask


task send_cmp_config;
	begin: doit
		integer i, len;
		len = 18 + 4 + 2 + 4*cmp_num_hashes + 1;
		
		wr_en <= 1;
		din <= 2; #20; din <= 3; #20; // ver, type
		din <= 0; #40; // reserved0
		din <= len[7:0]; #20; din <= len[15:8]; #20;
		din <= len[23:16]; #20;
		din <= 0; #20; // reserved1
		din <= 8'h00; #40; // IDs in CMP_CONFIG not used
		din <= 0; #80; // checksum
		// body
		din <= 0; #20; // unused (1 byte), must be 0
		din <= cmp_salt_len; #20; // salt_len (1 byte)
		for (i=0; i < 16; i=i+1) begin
			din <= cmp_salt[i*8 +:8]; #20;
		end
		din <= cmp_iter_count[7:0]; #20;
		din <= cmp_iter_count[15:8]; #20;
		din <= cmp_iter_count[23:16]; #20;
		din <= cmp_iter_count[31:24]; #20;

		din <= cmp_num_hashes[7:0]; #20;
		din <= cmp_num_hashes[15:8]; #20;
		for (i=0; i < 4*cmp_num_hashes; i=i+1) begin
			din <= cmp_hashes[8*i +:8]; #20;
		end
		
		din <= 8'hCC; #20;
		din <= 0; #80;
		wr_en <= 0;
	end
endtask


// ***************************************************************
//
// Packet type WORD_GEN (0x02)
//
// *****************************************************************
task send_empty_word_gen;
	input [15:0] pkt_id;
	begin
		// WORD_GEN packet (type 2), "empty" (words pass-by)
		wr_en <= 1;
		din <= 2; #20; din <= 2; #20; din <= 0; #40;
		din <= 6; #20; // len[7:0]
		din <= 0; #60;
		din <= pkt_id[7:0]; #20; din <= pkt_id[15:8]; #20;
		din <= 0; #80; // checksum
		din <= 0; #20; // num_ranges
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum
		wr_en <= 0;
	end
endtask


integer word_gen_num_ranges = 0;
integer word_gen_total_num_chars = 0;
reg [8:0] word_gen_range_num_chars [0:3];
reg [7:0] word_gen_chars [0:1023]; // up to 4 ranges X 256 chars
reg [8:0] num_chars;

task word_gen_add_range;
	input [0 :8*256-1] chars;
	begin: doit
		integer i, num_chars;
		num_chars = 0;
		
		for (i=0; i < 256; i=i+1)
			if (chars[8*i +:8] != 0) begin
				word_gen_chars[256*word_gen_num_ranges + num_chars]
					= chars[8*i +:8];
				num_chars = num_chars + 1;
				word_gen_total_num_chars = word_gen_total_num_chars + 1;
			end
		
		word_gen_range_num_chars [word_gen_num_ranges] = num_chars;
		word_gen_num_ranges = word_gen_num_ranges + 1;
	end
endtask

task send_word_gen;
	input [15:0] pkt_id;
	begin: doit
		integer i, j, len;
		len = 6 + 2*word_gen_num_ranges + word_gen_total_num_chars;
		
		wr_en <= 1;
		din <= 2; #20; din <= 2; #20; din <= 0; #40;
		din <= len[7:0]; #20; din <= len[15:8]; #20;
		din <= 0; #40;
		din <= pkt_id[7:0]; #20; din <= pkt_id[15:8]; #20;
		din <= 0; #80; // checksum
		// body
		din <= word_gen_num_ranges; #20;
		for (i=0; i < word_gen_num_ranges; i=i+1) begin
			din <= word_gen_range_num_chars[i]; #20;
			din <= 0; #20;
			for (j=0; j < word_gen_range_num_chars[i]; j=j+1) begin
				din <= word_gen_chars [256*i+j]; #20;
			end
		end
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum
		wr_en <= 0;

		word_gen_num_ranges = 0;
		word_gen_total_num_chars = 0;
	end
endtask


// ***************************************************************
//
// Packet type WORD_LIST (0x01), TEMPLATE_LIST (0x04)
//
// *****************************************************************
integer word_list_total_len = 0;
reg [0:2**19-1] word_list_data; // 64 Kbytes
integer is_template_list = 0;
	
task word_list_add;
	input [0: 8*`PLAINTEXT_LEN-1] word; // up to 64 bytes
	begin: doit
		integer word_len, cur_off;
		word_len = 0;
		
		for (cur_off=0; cur_off < `PLAINTEXT_LEN; cur_off=cur_off+1)
			if (word [8*cur_off +:8] != 0) begin
				word_list_data [8*word_list_total_len +:8]
					= word [8*cur_off +:8];
				word_len = word_len + 1;
				word_list_total_len = word_list_total_len + 1;
			end
		
		// Add trailing '\0' where necessary
		if (word_len < `PLAINTEXT_LEN) begin
			word_list_data [8*word_list_total_len +:8] = 8'h00;
			word_list_total_len = word_list_total_len + 1;
		end
	end
endtask

task range_info_add;
	input [7:0] pos0, pos1, pos2, pos3;
	begin: doit
		integer cnt;
		cnt = 0;
		
		wr_en <= 1;
		if (pos0 != 0) begin
			word_list_data [8*word_list_total_len +:8] = pos0;
			word_list_total_len = word_list_total_len + 1;
			cnt = cnt + 1;
		end
		if (pos1 != 0) begin
			word_list_data [8*word_list_total_len +:8] = pos1;
			word_list_total_len = word_list_total_len + 1;
			cnt = cnt + 1;
		end
		if (pos2 != 0) begin
			word_list_data [8*word_list_total_len +:8] = pos2;
			word_list_total_len = word_list_total_len + 1;
			cnt = cnt + 1;
		end
		if (pos3 != 0) begin
			word_list_data [8*word_list_total_len +:8] = pos3;
			word_list_total_len = word_list_total_len + 1;
			cnt = cnt + 1;
		end
		if (cnt < 4) begin
			word_list_data [8*word_list_total_len +:8] = 0;
			word_list_total_len = word_list_total_len + 1;
		end
		wr_en <= 0;
		is_template_list = 1;
	end
endtask


task send_word_list;
	begin: doit
		integer cur_off;

		wr_en <= 1;
		// header
		din <= 2; #20;
		din <= is_template_list ? 4 : 1; #20;
		din <= 0; #40;
		din <= word_list_total_len[7:0]; #20; // len[7:0]
		din <= word_list_total_len[15:8]; #20; // len[15:8]
		din <= 0; #40; din <= 8'h07; #40; din <= 0; #80;
		// body
		for (cur_off=0; cur_off < word_list_total_len;
				cur_off=cur_off+1) begin
			din <= word_list_data [8*cur_off +:8]; #20;
		end
		din <= 0; #80; // checksum
		wr_en <= 0;
		
		word_list_total_len = 0;
		is_template_list = 0;
	end
endtask


`endif
