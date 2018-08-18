`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// processes input (from the point of view from FPGA) headers
// of version VERSION.
// packet header is 10 bytes.
//
//	struct pkt {
//		unsigned char version;
//		unsigned char type;
//		unsigned short reserved0;
//		unsigned char data_len0;
//		unsigned char data_len1;
//		unsigned char data_len2; // doesn't count header
//		unsigned char reserved1;
//		unsigned short id;
//		unsigned char data[pkt_data_len];
//	};
//
// assumes PKT_MAX_LEN is no less than 65536
// packets not aligned to 2-byte word can be padded with 0
//
// Checksum is PKT_CHECKSUM_LEN bytes long. Words added and inverted.
// Checksum is not included in data length.
// - inserted after packet header
// - after each PKT_CHECKSUM_INTERVAL bytes <-- not implemented
// - after the end of packet
//
// TODO: some improved CRC check
//

module inpkt_header #(
	parameter VERSION = -1,
	parameter PKT_MAX_LEN = 65536,
	parameter PKT_MAX_TYPE = -1,
	parameter PKT_TYPE_MSB = `MSB(PKT_MAX_TYPE),
	parameter DISABLE_CHECKSUM = 0
	)(
	input CLK,
	input [7:0] din,
	input wr_en,

	output reg [PKT_TYPE_MSB:0] pkt_type = 0,
	output reg [15:0] pkt_id,
	output pkt_data, // asserts when it goes packet data
	output pkt_end, // asserts when it goes the last byte of data
	output reg err_pkt_version = 0, err_pkt_type = 0, err_pkt_len = 0, err_pkt_checksum = 0
	);

	
	localparam PKT_LEN_MSB = `MSB(PKT_MAX_LEN);

	reg [31:0] checksum = 0;
	reg [31:0] checksum_tmp = 0;
	reg [1:0] checksum_byte_count = 0;
	
	// flag is set when checksum_tmp contains checksum value from data-in
	reg checksum_check_flag = 0;
	// flag is set when header is processed, cleared when data starts
	reg pkt_header = 1;

	reg [PKT_LEN_MSB:0] pkt_byte_count_max, pkt_byte_count_max_tmp;
	reg [PKT_LEN_MSB:0] pkt_byte_count;
	
	localparam PKT_STATE_VERSION = 1,
					PKT_STATE_TYPE = 2,
					PKT_STATE_RESERVED0_0 = 3,
					PKT_STATE_RESERVED0_1 = 4,
					PKT_STATE_LEN0 = 5,
					PKT_STATE_LEN1 = 6,
					PKT_STATE_LEN2 = 7,
					PKT_STATE_RESERVED1 = 8,
					PKT_STATE_ID0 = 9,
					PKT_STATE_ID1 = 10,
					PKT_STATE_DATA = 11,
					PKT_STATE_ERROR = 12,
					PKT_STATE_CHECKSUM = 13;
	
	(* FSM_EXTRACT = "true", FSM_ENCODING = "auto" *)
	reg [3:0] pkt_state = PKT_STATE_VERSION;

	// Verify checksum regardless of wr_en
	always @(posedge CLK)
		if (checksum_check_flag) begin
			if (~checksum != checksum_tmp & ~DISABLE_CHECKSUM[0])
				err_pkt_checksum <= 1;
		end

	always @(posedge CLK) begin
		if (err_pkt_checksum)
			pkt_state <= PKT_STATE_ERROR;
			
		if (wr_en) begin
			if (pkt_state != PKT_STATE_CHECKSUM & ~(pkt_state == PKT_STATE_VERSION & !din)) begin

				checksum_check_flag <= 0;
			
				if (checksum_byte_count == 0) begin
					checksum_tmp[31:8] <= 0;
					if (~checksum_check_flag)
						checksum <= checksum + checksum_tmp;
					else
						checksum <= 0;
				end

				checksum_tmp[8*(checksum_byte_count+1)-1 -:8] <= din;
				checksum_byte_count <= checksum_byte_count + 1'b1;
			end

			case (pkt_state)
			PKT_STATE_VERSION: begin
				if (din == 0) begin
					// input 0 - skip
				end
				else begin
					if (din != VERSION) begin
						// wrong packet version
						err_pkt_version <= 1;
						pkt_state <= PKT_STATE_ERROR;
					end
					else
						pkt_state <= PKT_STATE_TYPE;
				end
			end

			PKT_STATE_TYPE: begin
				pkt_header <= 1;
				pkt_byte_count <= 0;
				
				if (din == 0 || din[PKT_TYPE_MSB:0] > PKT_MAX_TYPE || din[7:PKT_TYPE_MSB+1]) begin
					// wrong packet type
					err_pkt_type <= 1;
					pkt_state <= PKT_STATE_ERROR;
				end
				else begin
					pkt_type <= din[PKT_TYPE_MSB:0];
					pkt_state <= PKT_STATE_RESERVED0_0;
				end
			end
			
			PKT_STATE_RESERVED0_0: begin
				pkt_state <= PKT_STATE_RESERVED0_1;
			end
			
			PKT_STATE_RESERVED0_1: begin
				pkt_state <= PKT_STATE_LEN0;
			end

			PKT_STATE_LEN0: begin
				//pkt_byte_count_max[7:0] <= din;
				pkt_byte_count_max_tmp[7:0] <= din;
				pkt_state <= PKT_STATE_LEN1;
			end
			
			PKT_STATE_LEN1: begin
				//pkt_byte_count_max[15:8] <= din;
				pkt_byte_count_max_tmp[15:8] <= din;
				pkt_state <= PKT_STATE_LEN2;
			end

			PKT_STATE_LEN2: begin
				//pkt_byte_count_max <= { din[PKT_LEN_MSB-16:0], pkt_byte_count_max[15:0] } - 1'b1;
				pkt_byte_count_max <= { din[PKT_LEN_MSB-16:0], pkt_byte_count_max_tmp[15:0] } - 1'b1;
				
				//if ( din[7:PKT_LEN_MSB-16+1] || !(din[PKT_LEN_MSB-16:0] || pkt_byte_count_max[15:0]) ) begin
				if ( din[7:PKT_LEN_MSB-16+1] || !(din[PKT_LEN_MSB-16:0] || pkt_byte_count_max_tmp[15:0]) ) begin
					// wrong packet length
					err_pkt_len <= 1;
					pkt_state <= PKT_STATE_ERROR;
				end
				else begin
					pkt_state <= PKT_STATE_RESERVED1;
				end
			end

			PKT_STATE_RESERVED1: begin
				pkt_state <= PKT_STATE_ID0;
			end

			PKT_STATE_ID0: begin
				pkt_id[7:0] <= din;
				pkt_state <= PKT_STATE_ID1;
			end

			PKT_STATE_ID1: begin
				pkt_id[15:8] <= din;
				checksum_byte_count <= 0;
				pkt_state <= PKT_STATE_CHECKSUM;
			end

			PKT_STATE_DATA: begin
				pkt_header <= 0;
				if (pkt_byte_count == pkt_byte_count_max) begin
					checksum_byte_count <= 0;
					pkt_state <= PKT_STATE_CHECKSUM;
				end
				else
					pkt_byte_count <= pkt_byte_count + 1'b1;
			end
			
			PKT_STATE_CHECKSUM: begin
				checksum_tmp[8*(checksum_byte_count+1)-1 -:8] <= din;
				checksum_byte_count <= checksum_byte_count + 1'b1;
				
				if (checksum_byte_count == 0) begin
					checksum <= checksum + checksum_tmp;
				end
				else if (checksum_byte_count == 3) begin
					checksum_check_flag <= 1;
					// Suppose checksum_byte_count is a power of 2
					//checksum_byte_count <= 0;
					if (~pkt_header) //pkt_byte_count == pkt_byte_count_max) <-- bug caused error if pkt_len=1
						pkt_state <= PKT_STATE_VERSION;
					else
						pkt_state <= PKT_STATE_DATA;
				end
			end
			
			PKT_STATE_ERROR: begin
			end
			endcase
			
		end // wr_en
	end

	assign pkt_data = pkt_state == PKT_STATE_DATA;

	assign pkt_end = pkt_data && pkt_byte_count == pkt_byte_count_max;

	
endmodule
