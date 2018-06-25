`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// Network for broadcast signals
//
module bcast_net #(
	parameter BCAST_WIDTH = -1,
	parameter N_NODES = -1,
	parameter [8*N_NODES-1 :0] NODES_CONF = 0
	//parameter N_UNITS = -1
	)(
	input CLK,
	// entry to the network
	input [BCAST_WIDTH-1 :0] in,
	// output from nodes
	output [N_NODES*BCAST_WIDTH-1 :0] out
	);

	// Node #0 is the entry to the network (unregistered)
	assign out[0 +:BCAST_WIDTH] = in;

	genvar i;
	generate
	for (i=1; i < N_NODES; i=i+1) begin:node

		localparam UPPER_NODE = NODES_CONF[8*i +:8];

		(* SHREG_EXTRACT="no", EQUIVALENT_REGISTER_REMOVAL="no" *)
		reg [BCAST_WIDTH-1 :0] r;
		assign out[i*BCAST_WIDTH +:BCAST_WIDTH] = r;
		
		always @(posedge CLK)
			r <= out[UPPER_NODE*BCAST_WIDTH +:BCAST_WIDTH];

	end
	endgenerate


endmodule
