`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module outpkt_join #(
	parameter N = 1
	)(
	input CLK,

	input [16*N-1:0] din,
	input [N-1:0] pkt_end,
	input [N-1:0] wr_en,
	output reg [N-1:0] full = N == 1 ? 1'b0 : {N{1'b1}},

	output reg [15:0] dout,
	input rd_en,
	output reg empty = 1
	);

	reg [`MSB(N-1):0] selected_num = 0;
	wire [`MSB(N-1):0] new_selected_num =
			selected_num == N-1 ? {N{1'b0}} : selected_num + 1'b1;
	reg pkt_end_r = 0;

	localparam STATE_SELECT = 0,
				STATE_WRITE = 1,
				STATE_READ = 2;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_SELECT;

	always @(posedge CLK) begin
		case (state)
		STATE_SELECT: begin
			if (wr_en[selected_num]) begin
				dout <= din[16*(selected_num+1)-1 -:16];
				full[selected_num] <= 1;
				empty <= 0;
				state <= STATE_READ;
			end
			else if (N != 1) begin
				full[selected_num] <= 1;
				full[new_selected_num] <= 0;
				selected_num <= new_selected_num;
			end
		end

		STATE_READ: if (rd_en) begin
			empty <= 1;
			pkt_end_r <= 0;
			if (pkt_end_r) begin
				if (N == 1)
					full[selected_num] <= 0;
				state <= STATE_SELECT;
			end
			else begin
				full[selected_num] <= 0;
				state <= STATE_WRITE;
			end
		end

		STATE_WRITE: if (wr_en[selected_num]) begin
			dout <= din[16*(selected_num+1)-1 -:16];
			full[selected_num] <= 1;
			empty <= 0;
			if (pkt_end[selected_num])
				pkt_end_r <= 1;
			state <= STATE_READ;
		end
		endcase
	end

endmodule
