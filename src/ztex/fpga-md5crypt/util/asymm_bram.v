`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

/*
INFO:Xst:3229 - The RAM description <Mram_mem> will not be implemented on the device block RAM because actual implementation does not support asymetric block RAM larger than one block.
    -----------------------------------------------------------------------
    | ram_type           | Distributed                         |          |
    -----------------------------------------------------------------------
    | Port A                                                              |
    |     aspect ratio   | 1024-word x 32-bit                  |          |
    |     clkA           | connected to signal <wr_clk>        | rise     |
    |     weA            | connected to signal <wr_en>         | high     |
    |     addrA          | connected to signal <wr_addr>       |          |
    |     diA            | connected to signal <din>           |          |
    -----------------------------------------------------------------------
    | Port B                                                              |
    |     aspect ratio   | 512-word x 64-bit                   |          |
    |     addrB          | connected to signal <rd_addr>       |          |
    |     doB            | connected to internal node          |          |
    -----------------------------------------------------------------------
*/

//
// Asymmetric BRAM, 1 write port, 1 read port
// Write port has smaller data width
//
module asymm_bram_min_wr #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] wr_addr,

	input rd_clk,
	output reg [minWIDTH*RATIO-1:0] dout = INIT,
	input rd_en,
	input [`MSB(maxDEPTH-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);

	(* RAM_STYLE="BLOCK" *)
	reg [minWIDTH-1:0] mem [0:RATIO*maxDEPTH-1];

	genvar i;

	// Describe the port with the smaller data width exactly as you are used to
	// for symmetric block RAMs
	always @(posedge wr_clk)
		if (wr_en)
			mem[wr_addr] <= din;

	// A generate-for is used to describe the port with the larger data width in a
	// generic and compact way
	generate for (i = 0; i < RATIO; i = i+1)
		begin: portB
			localparam [log2RATIO-1:0] lsbaddr = i;
			always @(posedge rd_clk)
				if (rd_en)
					dout[(i+1)*minWIDTH-1:i*minWIDTH] <= mem[{rd_addr, lsbaddr}];
		end
	endgenerate

endmodule


//
// Asymmetric BRAM, 1 write port, 1 read port
// Read port has smaller data width
//
module asymm_bram_min_rd #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH*RATIO-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH-1) :0] wr_addr,

	input rd_clk,
	output reg [minWIDTH-1:0] dout = INIT,
	input rd_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);

	(* RAM_STYLE="BLOCK" *)
	reg [minWIDTH-1:0] mem [0:RATIO*maxDEPTH-1];

	genvar i;

	// Describe the port with the smaller data width exactly as you are used to
	// for symmetric block RAMs
	always @(posedge rd_clk)
		if (rd_en)
			dout <= mem[rd_addr];

	// A generate-for is used to describe the port with the larger data width in a
	// generic and compact way
	generate for (i = 0; i < RATIO; i = i+1)
		begin: portB
			localparam [log2RATIO-1:0] lsbaddr = i;
			always @(posedge wr_clk)
				if (wr_en)
					mem[{wr_addr, lsbaddr}] <= din[(i+1)*minWIDTH-1:i*minWIDTH];
		end
	endgenerate

endmodule

