## Overview

- bcrypt for ZTEX 1.15y board computes 496 keys in parallel, equipped with on-board candidate generator and comparator.
- Measured performance for the board (4 FPGA) at default frequency on hashes with setting 5 is 118.9 Kc/s, on hashes with setting 12 is 965 c/s (123.5 Kc/s if recalculated to setting 5).
- It operates at 150 MHz. Runtime frequency adjustment is available.
- The design contains 124 cores. On-chip comparison against up to 512 hashes is available. Salts with more than 512 hashes are processed with onboard comparators turned off, computed hashes are output and compared on host, this leads to some reduction in c/s especially on hashes with lower setting and when multiple boards are in use.
- Resource utilization: each core uses 4 BRAMs (x 1 Kbyte), 390 LUTs. Device utilization summary: 96% BRAMs, 55% LUTs, 16% FFs, 1% DSPs.
- Current consumption (12V input): 2.2A, idle 0.4A.


## Design RTL details

- The design was developed with implementation in Spartan-6 hardware in mind. In contrast with other hardware (e.g. Zynq, Virtex-7) it has low memory to logic (BRAM/LUT) ratio. The size of the memory unit (RAMB8BWER) is 1 Kbyte, equal to the size of "S" unit used in the algorithm. It was decided to allocate BRAMs only for "S" units. The rest of the data reside in two 32x32 bit register files that were made of LUTs.
- Initialization values are over 4 Kbytes. To save memory, IVs are stored in only one location and transmitted to computing units ("cores") when required. To reduce bandwith consumption of internal data bus, save routing resources IVs are transmitted in broadcast mode.
- Each core gets IVs, gets data for computation, performs computation and output independently from other cores. The approach where several cores share same control logic was not taken - such an approach would save LUTs while there's an excess of LUTs anyway.
- Each Blowfish round takes 1 cycle. Because BRAM memory allows only synchronous read, the start of the cycle is shifted to the start of such read. Overall, 16 Blowfish rounds take 18 cycles - 2 cycles used for additional XOR's and save into "S" or "P".
- Communication framework including on-chip candidate password generator was initially taken from descrypt-ztex project. bcrypt-ztex has an area-optimized version of the generator.
- Sizes of I/O buffers from communication framework were reviewed. Input buffer was reduced to 10 KB to allow more BRAMs for cores, asserts 'not full' when it has 6 KB free. Output buffer was increased to 8 KB for better USB performance when comparator is off, hashes output to host.


## Design Placement and Routing details

- Substantial attention was paid for optimal placement of individual components. While tools can do that fully automately, it's assumed if developer watches them more then results are better.
- The FPGA has 6 columns of BRAMs. Cores are also placed in 6 columns with spacing in between for 3 thin vertical columns (2-3 CLBs wide) for internal data bus. Each one of 124 cores is manually allocated a (typically rectangular) area with 4 BRAMs and 576-640 LUTs.
- To save routing resources, every 10-12 adjacent cores are grouped and connected to proxy unit, which is connected via internal data bus to arbiter unit.
- Some BRAMs (enough for 4 cores) in corners are located among I/O blocks, more distantly from LUTs. An attempt to use that BRAMs result in worse timing. That BRAMs were left unused.


## Notes on creation of the bitstream using ISE 14.5

- Some modules: bcrypt, bcrypt_core are synthesized in separate ISE projects. Then the resulting *.ngc files are used in the "main" ISE project (fpga-bcrypt-ztex). When it sees a declaration of an empty ("blackbox") module then it searches for NGC file in directories specified with -sd option.
- Partitioning is used. In xpartition.pxml file they are listed bcrypt module in "/ztex_inouttraffic/bcrypt" partition and 124 bcrypt_core's in "/ztex_inouttraffic/wrappers[*].wrapper/proxies[*].proxy/cores[*].core" partitions. Please read Hierarchial Design Methodology Guide for details.
- Multi-Pass Place & Route is used. The design allows to declare some cores as "dummy". It was found practical to try 10-20 cores each Map and Place & Route run while the rest of the cores are declared as dummy ones. After such a run, Post Place and Route Static Timing Report is used to find which cores don't violate timing. That cores are marked as "good", declared as "dummy" for the next run, result files containing "good" placement are saved into a separate "export" directory. Typically up to 50% cores in a run are OK, while some cores continue to violate timing after many attempts. In such a case FPGA editor is used to see what's wrong and to make design decisions such as to review area constraints. It will surely violate timing unless it places two 32-bit adders (8 CLBs each) in columns adjacent to a column of 4 BRAMs.
- "bcrypt" module includes most of the control and communication logic, it's also build as a separate partition.
- On the final run that includes bitstream generation, all partitions are already built, marked as "import" in xpartition.pxml file.
- If an intermediate check is desired, it's possible to generate a bitstream with a number of "dummy" cores, that will work with reduced performance.
