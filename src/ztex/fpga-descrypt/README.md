## Overview

- descrypt cracker for ZTEX 1.15y board has performance 973 Mc/s per board (4 FPGA) @190 MHz, has in-FPGA candidate generators and comparators with ability to check computed hashes against up to 2,047 hashes.
- The design has 2 "big units", each one consists of candidate generator, distribution network and 16 cores. A generator produces a candidate key every cycle.
- Each of 32 cores include 16-stage circular pipeline of salted DES rounds and a comparator. 16 keys or intermediate values on the pipeline do circle 25 times, at the same time 16 computed hashes are processed by the comparator.
- Design tools reported possible clock frequency is 221 MHz. Tested boards work reliably at 190 MHz.
Runtime frequency adjustment is available.
- Device utilization summary: 75% LUTs, 62% BRAMs, 38% FFs.
- Current consumption at default frequency (12V input): 2.8A, idle 0.4A.
- Link layer is unable to transfer candidate keys from the host at the rate they are computed and compared.
Unless you use mask mode, you'll see degraded performance, 200-300 times less than possible.


## Communication framework ("Inouttraffic") details

The FPGA application is built on the framework that performs following tasks:
- Communication with USB device controller on a multi-FPGA board;
- Temporary storage of I/O data in input and output buffers;
- Extraction of input application-level data packets from input buffer, checksum verification;
- Creation of output packets from application data, checksum calculation;
- Handling of clocks and reset.
When input packets of type ```PKT_TYPE_WORD_LIST``` and ```PKT_TYPE_TEMPLATE_LIST``` processed,
resulting 0-padded, 56-bit keys or template keys along with their IDs are distributed evenly
across generators with respect to generators' readiness. There's additional ```range_info``` data
associated with template keys, used by generators.


## Design RTL details

Candidate passwords move from the generator to arbiter unit.
- Each candidate has IDs, that's a requirement for proper accounting; totally 16-bit packet ID, 16-bit word ID and 32-bit ID from the generator result in 64 bits of IDs, that's more than a candidate password itself.
- When candidates are sent to cores, IDs are saved into arbiter's memory. In case where a comparator detects equality, IDs are sent for output in CMP_EQUAL packet.
- Host software is expected to reconstruct the candidate password base on IDs, perform hashing and then perform comparison. False positives happen often because FPGA compares only 35 lower bits. There was an idea to simplify host software, send computed result to the host, if that was implemented that would have consumed additional virtual circuitry.
- A total number of computed candidates is also accounted. It sends PROCESSING_DONE packet after it finishes processing of an input packet. Each arbiter sends the PROCESSING_DONE packet.

Input packets of type ```PKT_TYPE_CMP_CONFIG``` contain salt data and lower 35 bits of hashes to compare.
Hashes are transmitted to cores using same distribution network as for keys.


## Notes on performing simulation using ISIM from ISE 14.5

- Select descrypt_test.v as a top module for behavioral simulation.
- For simulation, uncomment ```UNIT_INCLUDE_SRC``` and ```CORE_INCLUDE_SRC```.
- Simulation does not include I/O over USB subsystem. Test data is written into input fifo by the testbench module and results appear in output_fifo/fifo_output0/ram where that can be verified.
- Data being transferred over USB in both directions is protected with a checksum. During the simulation, input checksum verification turns off.


## Design Placement and Routing details

- Substantial attention was paid for optimal placement of individual components. While tools can do that fully automately, it's assumed if developer watches them more then results are better.
- Cores are placed in 4 columns with spacing in between for 2 thin vertical columns (2-3 CLBs wide) for internal data bus. Each one of 32 cores is manually allocated an individual area (typically 30x19 CLBs, containing no less than 4 2K-BRAMs).


## Notes on creation of the bitstream using ISE 14.7

- descrypt_core module is synthesized in separate ISE project. Then the resulting *.ngc file is used in the "main" ISE project. When it sees a declaration of an empty ("blackbox") module then it searches for NGC file in directories specified with -sd option.
- Partitioning is used. In xpartition.pxml file they are listed 32 descrypt_core's in ""/ztex_inouttraffic/pkt_comm/arbiter/wrapper_gen[*].wrapper/core_gen[*].core"" partitions. Please read Hierarchial Design Methodology Guide for details.
- Multi-Pass Place & Route is used. The design allows to declare some cores as "dummy". It was found practical to try 6-8 cores each Map and Place & Route run while the rest of the cores are declared as dummy ones. After such a run, Post Place and Route Static Timing Report is used to find which cores don't violate timing. That cores are marked as "good", declared as "dummy" for the next run, result files containing "good" placement are saved into a separate "export" directory. Typically up to 50% cores in a run are OK, while some cores continue to violate timing after many attempts. In such a case FPGA editor is used to see what's wrong and to make design decisions such as to review area constraints.
- On the final run that includes bitstream generation, all partitions are already built, marked as "import" in xpartition.pxml file.
- If an intermediate check is desired, it's possible to generate a bitstream with a number of "dummy" cores, that will work with reduced performance.


## Further improvements.

Following possible improvements were identified:
- Increase pipeline length from 16 to 80 stages. That increases size of a core and greatly reduces per-core overhead
- More effective comparator design

