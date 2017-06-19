`timescale 1ns / 1ps

// Creates expanded key (EK) out of key.
//
// First-Word Fall-Through type source - allows to operate
// without creating a copy of 576-bit key.
//
// Outputs in 32-bit words.
//
module bcrypt_expand_key #(
	parameter KEY_LEN = 72
	)(
	input CLK,
	input [8*KEY_LEN-1:0] din,
	input wr_en,
	output reg full = 1,
	input data_valid,
	input sign_extension_bug,
	
	output reg [31:0] dout = 0,
	input rd_en,
	output reg empty = 1
	);

	reg [`MSB(KEY_LEN):0] input_byte_count = 0;
	reg [1:0] output_byte_count = 0;
	reg [`MSB(KEY_LEN)-2:0] output_word_count = 0;
	
	(* KEEP="true" *)
	wire [7:0] input_byte = din [8*(input_byte_count+1'b1)-1 -:8];
	
	localparam STATE_IDLE = 0,
				STATE_INPUT = 1,
				STATE_OUTPUT = 2,
				STATE_READ_SRC = 3,
				STATE_WAIT1 = 4,
				STATE_WAIT2 = 5;
				
	(* FSM_EXTRACT="true" *)
	reg [2:0] state = STATE_IDLE;
	
	always @(posedge CLK) begin
		case (state)
		STATE_IDLE: begin
			if (data_valid)
				state <= STATE_WAIT1;
		end
		
		STATE_WAIT1:
			state <= STATE_WAIT2;
		
		STATE_WAIT2:
			state <= STATE_INPUT;
			
		STATE_INPUT: begin
			if (sign_extension_bug)
				dout <= (dout << 8) | { {25{input_byte[7]}}, input_byte[6:0] };
			else
				//dout [8*(output_byte_count+1'b1)-1 -:8] <= input_byte; // TODO: sign_extension_bug
				dout <= { dout[23:0], input_byte };
			
			if (input_byte == 0)
				input_byte_count <= 0;
			else
				input_byte_count <= input_byte_count + 1'b1;
			
			if (output_byte_count == 3) begin
				empty <= 0;
				state <= STATE_OUTPUT;
			end
			else
				state <= STATE_WAIT1;
			
			output_byte_count <= output_byte_count + 1'b1;
		end
		
		STATE_OUTPUT: if (rd_en) begin
			empty <= 1;
			if (output_word_count == 17) begin
				full <= 0;
				output_word_count <= 0;
				state <= STATE_READ_SRC;
			end
			else begin
				output_word_count <= output_word_count + 1'b1;
				state <= STATE_WAIT1;
			end
		end

		STATE_READ_SRC: begin
			input_byte_count <= 0;
			full <= 1;
			state <= STATE_IDLE;
		end
		endcase
	end

	
endmodule
