/*!
 inouttraffic -- custom firmware for ZTEX USB-FPGA Module 1.15y and 1.15y2
 Together with HDL part and proper host software, it allows usage of
 High-Speed interface (Slave FIFO) on a multi-FPGA board.

 This software is Copyright (c) 2016-2017 Denis Burykin
 [denis_burykin yahoo com], [denis-burykin2014 yandex ru]

 Based on

   intraffic -- example showing how the EZ-USB FIFO interface is used on ZTEX USB-FPGA Module 1.15y and 1.15y2
   Copyright (C) 2009-2014 ZTEX GmbH.
   http://www.ztex.de

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 3 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see http://www.gnu.org/licenses/.
!*/

#include[ztex-conf.h]   // Loads the configuration macros, see ztex-conf.h for the available macros
#include[ztex-utils.h]  // include basic functions

// configure endpoint 2, in, quad buffered, 512 bytes, interface 0
EP_CONFIG(2,0,BULK,IN,512,4);

// configure endpoint 6, out, quad buffered, 512 bytes, interface 0
EP_CONFIG(6,0,BULK,OUT,512,4);

// select ZTEX USB FPGA Module 1.15 as target  (required for FPGA configuration)
IDENTITY_UFM_1_15Y(10.15.0.0,0);

// this product string is also used for identification by the host software
#define[PRODUCT_STRING]["inouttraffic 1.0.0 JtR"]

// enables high speed FPGA configuration via EP6
ENABLE_HS_FPGA_CONF(6);

// this is called automatically after FPGA configuration
#define[POST_FPGA_CONFIG][POST_FPGA_CONFIG
	// During High-Speed FPGA configuration
	// IFCLK is set to 48 MHz.
	init_IO();
]

void fifo_reset() {
	EP2CS &= ~bmBIT0;                       // clear stall bit
	EP6CS &= ~bmBIT0;                       // clear stall bit

	FIFORESET = 0x80; SYNCDELAY;
	EP6FIFOCFG = 0x00; SYNCDELAY; //switching to manual mode
	FIFORESET = 6; SYNCDELAY;
	OUTPKTEND = 0x86; SYNCDELAY;  // skip uncommitted pkts in OUT endpoint
	OUTPKTEND = 0x86; SYNCDELAY;
	OUTPKTEND = 0x86; SYNCDELAY;
	OUTPKTEND = 0x86; SYNCDELAY;
	EP6FIFOCFG = bmBIT4 | bmBIT0; SYNCDELAY;        // AUTOOUT, WORDWIDE
	FIFORESET = 0x00; SYNCDELAY;  //Release NAKALL

	FIFORESET = 0x80; SYNCDELAY;
	EP2FIFOCFG = 0x00; SYNCDELAY;
	FIFORESET = 2; SYNCDELAY;
	EP2FIFOCFG = bmBIT3 | bmBIT0; SYNCDELAY;        // AOTUOIN, WORDWIDE
	FIFORESET = 0x00; SYNCDELAY;  //Release NAKALL
}

void init_IO() {
	OEA = bmBIT0 | bmBIT1 | bmBIT7;
	IOA0 = 0; IOA1 = 0; IOA7 = 0;

	REVCTL = 0x3; SYNCDELAY;

	// internal IFCLK, OE, slave FIFO interface
	// bit6: 48 MHz
	IFCONFIG = bmBIT7 | bmBIT6 | bmBIT5 | 3; SYNCDELAY;

	fifo_reset();

	PORTACFG = 0x00; SYNCDELAY; // used PA7/FLAGD as a port pin, not as a FIFO flag
	FIFOPINPOLAR = 0; SYNCDELAY; // set all slave FIFO interface pins as active low

	// EZ-USB automatically commits data in 512-byte chunks
	EP2AUTOINLENH = 0x02; SYNCDELAY;
	EP2AUTOINLENL = 0x00; SYNCDELAY;

	// Set FLAGs be independent from endpoint selection with FIFOADR
	// Bits [7:4] FlagB / Flag D
	// Bits [3:0] FlagA / Flag C
	// 0100 EP2 PF (prog.full) {0x8}
	// 1100 EP2 Full  {0xC}
	// 1010 EP6 Empty {0xA}
	PINFLAGSAB = 0xC8; SYNCDELAY;
	PINFLAGSCD = 0x0A; SYNCDELAY;

	// Programmable-level Flag (PF)
	// Active when zero bytes in endpoint buffer
	EP2FIFOPFH = bmBIT6 | 0; SYNCDELAY;
	EP2FIFOPFL = 0; SYNCDELAY;
}

//===========================================================
// Vendor Commands / Requests 0xA0-0xAF reserved by Cypress
// 0xA0 upload firmware
// 0xA1-0xAF reserved
//===========================================================

//-----------------------------------------------
// VC 0x71 : write to fpga
// multi-byte write
/*
void ep0_write_data () {
	BYTE b;
    OEC = 0xff;
    IOA0 = 0;
    IOC = 0x71;//SETUPDAT[2];
    IOA0 = 1;
    IOA0 = 0;

	IOA7 = 0; //write
    IOA1 = 0;
	for ( b=0; b<EP0BCL; b++ ) {
		IOC = EP0BUF[b];
		IOA1 = 1;
		IOA1 = 0;
	}
}

ADD_EP0_VENDOR_COMMAND((0x71,,
,,
    ep0_write_data();
));;
*/
//-----------------------------------------------
void fpga_set_addr(BYTE addr) {
	OEC = 0xff;
	IOA7 = 0; // write to fpga
	IOA0 = 0;
	IOC = addr;
	IOA0 = 1;
	//NOP;
	IOA0 = 0;
}
//-----------------------------------------------
void ep0_read_data (BYTE offset, BYTE count) {
	BYTE b;
	OEC = 0;
	IOA7 = 1; // read fpga
	IOA1 = 0;
	for ( b=offset; b < offset+count; b++ ) {
		EP0BUF[b] = IOC;
		IOA1 = 1;
		IOA1 = 0;
	}
	IOA7 = 0;
}
void ep0_commit () {
	EP0BCH = 0;
	EP0BCL = ep0_payload_transfer;
}

// fpga_set_app_mode()
ADD_EP0_VENDOR_COMMAND((0x82,,
	fpga_set_addr(0x82);
	IOA1 = 0;
	IOC = SETUPDAT[2];
	IOA1 = 1;
	IOA1 = 0;
,,
));;
// fpga_get_io_state()
ADD_EP0_VENDOR_REQUEST((0x84,,
	fpga_set_addr(0x84);// vcr_io/VCR_GET_IO_STATUS
	ep0_read_data (0,ep0_payload_transfer);//6
	ep0_commit();
,,
));;
// fpga_setup_output()
ADD_EP0_VENDOR_REQUEST((0x85,,
	fpga_set_addr(0x85);// vcr_io/VCR_SETUP_OUTPUT
	ep0_read_data (0,ep0_payload_transfer);//2
	ep0_commit();
,,
));;
// fpga_reset();
ADD_EP0_VENDOR_COMMAND((0x8B,,
	fpga_set_addr(0x81); // 1. disable r/w
	fpga_set_addr(0x8B); // 2. reset FPGA with Global Set Reset (GSR)
	fifo_reset(); // 3. reset ez-usb fifo, invalidate data
	fpga_set_addr(0x80); // 4. enable r/w
,,
));;
// fpga_hs_io_enable/disable()
ADD_EP0_VENDOR_COMMAND((0x80,,
	fpga_set_addr(SETUPDAT[2] ? 0x80 : 0x81);
,,
));;
// fpga_output_limit_enable/disable()
ADD_EP0_VENDOR_COMMAND((0x86,,
	fpga_set_addr(SETUPDAT[2] ? 0x86 : 0x87);
,,
));;
// fpga_set_output_limit_min()
//ADD_EP0_VENDOR_COMMAND((0x83,,
//	fpga_set_addr(0x83);
//	IOA1 = 0;
//	IOC = SETUPDAT[2];
//	IOA1 = 1;
//	IOA1 = 0;
//	IOC = SETUPDAT[3];
//	IOA1 = 1;
//	IOA1 = 0;
//,,
//));;

void fpga_test_get_id()
{
	BYTE i;
	fpga_set_addr(0x88);// vcr_io/VCR_ECHO_REQUEST
	IOA1 = 0;
	for (i = 0; i < 4; i++) {
		IOC = SETUPDAT[i + 2];
		IOA1 = 1;
		IOA1 = 0;
	}
	ep0_read_data (0,4);//ep0_payload_transfer);
	fpga_set_addr(0x8A);// vcr_io/VCR_GET_FPGA_ID
	ep0_read_data (4,1);//ep0_payload_transfer);
	EP0BUF[5] = 0;
	fpga_set_addr(0xA1);//VCR_GET_ID_DATA
	ep0_read_data (6,2);
}
// fpga_test_get_id()
ADD_EP0_VENDOR_REQUEST((0x88,,
	fpga_test_get_id();
	ep0_commit();
,,
));;


__xdata BYTE select_num;
void select_fpga ( BYTE fn );

// fpga_select(): waits for i/o timeout before select_fpga()
void fpga_select(BYTE fpga_num) {
	BYTE timeout;
	BYTE counter = 0;
	if (select_num == fpga_num)
		return;
	for (;;) {
		fpga_set_addr(0x84);// vcr_io/VCR_GET_IO_STATUS
		OEC = 0;
		IOA7 = 1; // read fpga

		IOA1 = 0;
		IOA1 = 1;
		IOA1 = 0;
		// io_timeout is the 2nd byte from FPGA's vcr_io address 0x84
		timeout = IOC;
		if (timeout)
			break;
		// evade hang-up on buggy bitstream
		if (counter++ == 255)
			break;
		NOP; NOP; NOP; NOP; NOP;
	}
	fpga_set_addr(0x81); // 1. disable r/w
	select_fpga(fpga_num);
	fpga_set_addr(0x80); // enable r/w
}

ADD_EP0_VENDOR_COMMAND((0x8E,,
	fpga_select(SETUPDAT[2]);
,,
));;

// fpga_select_setup_io()
void fpga_select_setup_io(BYTE fpga_num) {
	if (select_num != fpga_num) {
		fpga_select(fpga_num);
	}
	fpga_set_addr(0x84);// vcr_io/VCR_GET_IO_STATUS
	ep0_read_data (0,6);
	fpga_set_addr(0x85);// output limit
	ep0_read_data (6,2);
	ep0_commit();
}
// SETUPDAT[2] : fpga_num
ADD_EP0_VENDOR_REQUEST((0x8C,,
	fpga_select_setup_io(SETUPDAT[2]);
,,
));;

//-----------------------------------------------
//
// Programmable clocks
//
//-----------------------------------------------
__xdata BYTE clock_num; // clock being programmed (0..3)

// Up to 4 clocks, programming enabled with IOC2..5
void set_progen(BYTE value) {
	switch (clock_num) {
	case 0: IOC2 = value;
			break;
	case 1: IOC3 = value;
			break;
	case 2: IOC4 = value;
			break;
	case 3: IOC5 = value;
			break;
	};
}

#define[PROGDATA][IOC1]
#define[PROGCLK][IOC0]

void set_freq(BYTE d, BYTE m) {
	BYTE i,j;

	fpga_set_addr(0x00); // Set IOC to raw mode

	set_progen(1);
	// 2-bit LoadD command
    PROGDATA = 1;
    PROGCLK = 1; PROGCLK = 0;
	PROGDATA = 0;
	PROGCLK = 1; PROGCLK = 0;
	// D value
	for (i = 0; i < 8; i++) {
		PROGDATA = d & 1;
		PROGCLK = 1; PROGCLK = 0;
		d >>= 1;
	}

	set_progen(0);
	PROGCLK = 1; PROGCLK = 0;
	PROGCLK = 1; PROGCLK = 0;

	set_progen(1);
	// 2-bit LoadM command
	PROGDATA = 1;
	PROGCLK = 1; PROGCLK = 0;
	PROGCLK = 1; PROGCLK = 0;
	// M value
	for (i = 0; i < 8; i++) {
		PROGDATA = m & 1;
		PROGCLK = 1; PROGCLK = 0;
		m >>= 1;
	}

	set_progen(0);
	PROGCLK = 1; PROGCLK = 0;

	set_progen(1);
	// 1-bit GO command
	PROGDATA = 0;
	PROGCLK = 1; PROGCLK = 0;

	set_progen(0);
	for (i = 50; i; i--) {
		PROGCLK = 1; PROGCLK = 0;
	}

	IOA0 = 1; IOA0 = 0; // Return from raw mode
}

// fpga_progclk()
// SETUPDAT[2] : fpga_num, SETUPDAT[3] : clock_num
// SETUPDAT[4] : D value, SETUPDAT[5] : M value
ADD_EP0_VENDOR_COMMAND((0x93,,
	fpga_select(SETUPDAT[2]);
	clock_num = SETUPDAT[3];
	//fpga_set_addr(0x94); // pll_reset=1
	set_freq(SETUPDAT[4], SETUPDAT[5]);

	// Programmable clock (DCM_CLKGEN) drives the PLL.
	// PLL requires reset when input frequency changes.
	// Some software forces the PLL into reset and waits.
	//
	// Inouttraffic bitstream connects CLKGEN's inverted LOCKED output
	// to PLL's reset so the approach described above is unnecessary.
	//
	//wait(20);
	//fpga_set_addr(0x95); // pll_reset=0
,,
));;

// include the main part of the firmware kit, define the descriptors, ...
#include[ztex.h]

void main(void)
{
	// on startup, CPU frequency is 12 MHz.
	// init_USB() sets 48 MHz and enables clock output
	// (available as FXCLK on FPGA)
	init_USB();

	// Delay initialization until POST_FPGA_CONFIG
	//init_IO();

	while (1) {
	}
}
