
## Overview

- sha256crypt for ZTEX 1.15y board allows candidate passwords up to
32 bytes, equipped with on-board mask generator and comparator.
The board computes 1104 keys in parallel.
- Power consumption (running at 175 MHz, 12V input): ~3.1A under full load, ~0.4A idle.


## Performance measurements

Performance (at 175 MHz) measured in different modes, with different key lengths, with a comparison
to CPUs is shown in table 1.
```
+--------------+--------+------------+------------+----------------+
|              |        | ZTEX board | i5-4210M   | Intel Celeron  |
|              |        |4x XC6SLX150| OMP x4,AVX2|Stepping 6,SSSE3|
+--------------+--------+------------+------------+----------------+
|   salt length = 8
+--------------+--------+------------+------------+----------------+
| key_len=7    | --mask | 133.2 Kc/s | 6.39 Kc/s  | 0.88 Kc/s      |
| rounds=5000  | --inc  | 127.2 Kc/s | 6.32 Kc/s  | 0.87 Kc/s      |
+--------------+--------+------------+------------+----------------+
|   salt length = 16
+--------------+--------+------------+------------+----------------+
| key_len=5    | --mask | 85.3 Kc/s  | 4.22 Kc/s  | 0.58 Kc/s      |
| rounds=5000  | --inc  | 82.1 Kc/s  | 4.12 Kc/s  | 0.57 Kc/s      |
+--------------+--------+------------+------------+----------------+
| key_len=10   | --mask | 80.3 Kc/s  | 3.96 Kc/s  | 0.38 Kc/s      |
| rounds=5000  | --inc  | 77.4 Kc/s  | 3.70 Kc/s  | 0.37 Kc/s      |
+--------------+--------+------------+------------+----------------+
| key_len=20   | --mask | 68.7 Kc/s  | 3.37 Kc/s  | 0.31 Kc/s      |
| rounds=5000  | --inc  | 66.0 Kc/s  | 3.16 Kc/s  | 0.31 Kc/s      |
+--------------+--------+------------+------------+----------------+
| key_len=10   | --mask | 8.05 Kc/s  | 398 c/s    | 38 c/s         |
| rounds=50000 | --inc  | 8.03 Kc/s  | 390 c/s    | 38 c/s         |
+--------------+--------+------------+------------+----------------+
| key_len=10   | --mask | 804 c/s    | 39 c/s     | N/A (it does   |
| rounds=500000| --inc  | 802 c/s    | 39 c/s     | not respond)   |
+--------------+--------+------------+------------+----------------+
```


## Computing units

- sha256crypt invokes SHA256 in different ways, sometimes that look
very complex. To accomplish the task, a CPU-based computing unit
was implemented.
- Each unit consists of 3 cores, CPU, memory and I/O subsystem.
The approximate schematic of a computing unit is shown at fig.1.

```
           --------------+-------------+--------------
          /             /             /               \
     +--------+    +--------+    +--------+            |
     |        |    |        |    |        |            |
     | SHA256 |    | SHA256 |    | SHA256 |            |
     |  core  |    |  core  |    |  core  |            |
     |   #0   |    |   #1   |    |   #2   |            |
     |        |    |        |    |        |            |
     +--------+    +--------+    +--------+            |
         ^            ^            ^                   |
          \           |           /                    |
           +----------+-----------                     |
           |                                           |
 . . . . . | . . . . . . . . . . . . . . . . . . . . . |. .
           |                                          /
           |                                         /
  +---------------+         -------------           /
  |               |        /             \         /
  | process_bytes |       /    "main"     \ <------
  |               |<--+--|      memory     |
  +---------------+   |   \  (12 x 128 B) / <------
     |      ^         |    \             /         \
 +-------+  |        /      -------------           |
 | procb |  |       /                           +------------+
 | saved |  |      /    +-------------------+   | unit_input |
 | state |  |     /     | thread_state(x12) |   +------------+
 +-------+  |    |      +-------------------+             ^
            |    |                                        |
  +-----------+   \   +-----------------------------+     |
  | procb_buf |    -->|          C.P.U.             |     |
  +-----------+       |  +-----------------------+  |     |
          ^           |  | integer ops. incl.    |  |     |
           \          |  |12 x 16 registers(x16b)|  |     |
            \         |  +-----------------------+  |     |
             ---------|                             |     |
                      |  +----------------------+   |     |
                      |  | thread switch (x12)  |   |     |
    +--------+        |  +----------------------+   |     |
    | unit   |        |  | instruction pointers |   |     |
    | output |<-------|  +----------------------+   |     |
    | buf    |        |  | instruction memory   |   |     |
    +--------+        |  +----------------------+   |     |
        |             +-----------------------------+     |
        |                                                /
         \                                              /
          ---> to arbiter_rx             from arbiter_tx
```

- SHA256 computations are performed using specialized circuits
("cores"). Each cycle, a core computes one of 64 algorithm rounds.
Additionally 8 cycles it's busy with additions at the end of the block.
On some cycle, a round from computation #0 is computed and on the next cycle,
a round from computation #1 is computed. Several cycles before 2 computations
are finished and output, next 2 computations start loading Initial Values (IVs)
and pre-fetching data from core's input buffer.
- Internally cores store result of SHA256, allow to use previously
stored result as IVs for subsequent block. That way the core
is able to handle input of any length.
- Each core performs 4 independent computations in parallel, performs 4 blocks
in (64+8)x4 = 288 cycles.

- CPU runs same program in 12 independent hardware threads.
Each thread has 128 bytes of "main" memory (accessible by SHA256
subsystem), 16 x 16-bit registers. Data movement, integer,
execution flow control operations are available. However there's only
a subset if operations typically implemented in general-purpose CPUs,
enough for the task.
- CPU is heavily integrated with SHA256 subsystem. It has INIT_CTX,
PROCESS_BYTES, FINISH_CTX instructions that are almost equivalent to
init_ctx(), process_bytes(), finish_ctx() from software library.
Each instruction takes 1 cycle to execute.
- SHA256 instructions store instruction data in internal buffer
(procb_buf). A dedicated unit (process_bytes) takes intermediate data,
fetches input data from the memory, creates 16 x 32-bit data blocks
for cores, adds padding and total where necessary. It saves
the state of an unfinished computation, switches to the next core
after each block.
- The program for the CPU is available <a href='https://github.com/openwall/john/blob/bleeding-jumbo/src/ztex/fpga-sha256crypt/sha256crypt/cpu/program.vh'>here</a>.


## Design overview

```
       ------------------+--------+--+--+--------+---------
      /                 /        /  /  /        /          \
 +-----------+   +-----------+             +-----------+    |
 |           |   |           |   X  X  X   |           |    |
 | Computing |   | Computing |             | Computing |    |
 |  Unit #0  |   |  Unit #1  |             |  Unit N   |    |
 |           |   |           |   X  X  X   |           |    |
 +-----------+   +-----------+             +-----------+    |
       ^               ^         ^  ^  ^         ^          |
       |               |         |  |  |        /           |
       +---------------+---------+--+--+--------            |
       |                                                    |
 . . . | . . . . . . . . . . . . . . . . . . . . . . . . . .| .
       |                                                    |
       |                                                    |
  +-----------------+          +----------------+          /
  |     Arbiter     |          |     Arbiter    |<---------
  | (transmit part) |<-------->| (receive part) |
  +-----------------+          +----------------+
       ^                                    |
       |                    +------------+  |  +------
       |      +---------+   |            |<-+->| mode \
       |      | cmp.    |-->| comparator |     | cmp   |--
       |      | config. |   |            |---->| ?    /   \
       |      +---------+   +------------+     +------     |
       |          ^                                        |
 . . . | . . . . .|. . . . . . . . . . . . . . . . . . . . | .
       |          |      Communication framework           |
       |          |                                       /
  +-----------+   |                                      /
  | candidate |   |                                     /
  | generator |   |                                    /
  +-----------+---------+----------------------+      /
  | input pkt. handling | output pkt. creation |<-----
  +---------------------+----------------------+
  | input FIFO          | output FIFO          |
  +---------------------+----------------------+
  |  Prog. clocks  | USB I/O   |  FPGA reset   |
  +--------------------------------------------+

```
fig.2. Overview, FPGA application

- Each FPGA has 23 computing units, that's 69 cores, 276 keys are
computed in parallel.


## Clocking Issues

There's a clock input to the FPGAs, generated by Cypress USB device
controller (you see 24 MHz quartz resonator on the board).
Each FPGA internally generates a number of clocks for various parts of the application:
- IFCLK (48 MHz) is used for external communication.
- PKT_COMM_CLK (96 MHz) is used by communication framework, candidate generator,
comparator.
- CORE_CLK (runtime programmable 135-350 MHz) is used by computing units.
Design tools report possible frequency is 241 MHz. We never encountered a board where
this worked anywhere close to such high frequency. Too high power consumption was
identified as a likely cause for unability to operate at frequency reported by the toolset.
The default is set to 175 MHz, can be adjusted in john.conf. After all computing
units are idle for 10 us, CORE_CLK distribution is turned off to save electricity.


## Resource Usage

Each computing unit uses ~2,650 LUT. Other types of hardware resources
are not limiting. Here's a breakdown of resource usage by individual
components in a unit:

- 3 SHA256 cores 580 LUT each (total 1740 LUT, 65.7%)
- 16-bit multi-threaded CPU: 235 LUT
- "Main" memory I/O: 65 LUT
- Unit's input and output buffers: 90 LUT

The remaining 520 LUT (19.5%) is used mostly by logic that transforms
PROCESS_BYTES instructions into SHA256 data blocks. That includes:

- "procb_buf" (intermediate storage of data submitted by PROCESS_BYTES
instructions): 55 LUT
- "realign" (fetches data from 32-bit memory and performs proper
alignment): 92 LUT
- "process_bytes" (operates the above, creates SHA256 blocks, adds
padding, counts total bytes etc.): 250 LUT
- "thread_state" with 3 independent read and 4 write channels (reflects
state of each thread for CPU and other subsystems): 45 LUT


## Design Placement and Routing

- Used to manually allocate areas for every module. Totally allocated
69 rectangular areas for cores and 23 areas for CPUs and glue logic.
Communication framework used area that would be enough for 1 unit.
- Multi-Pass Place & Route approach was used to build the bitstream.

```
  +--------------+         +--------------+
  |   unit #0    |         |   unit #11   |
  +--------------+         |--------------+
  |   unit #1    |---------+   unit #13   |
  +--------------+ unit #12|--------------+
  |   unit #2    |         |   unit #15   |
  +--------------+---------+--------------+
  |   unit #3    | unit #14|   unit #17   |
  +--------------+         |--------------+
  |   unit #4    |---------+   unit #18   |
  +--------------+ unit #16|--------------+
  |   unit #5    |         |   unit #19   |
  +--------------+---------+--------------+
  |   unit #6    | unit #20|   unit #21   |
  +--------------+         |--------------+
  |   unit #7    |---------+   unit #22   |
  +--------------+ unit #10|--------------+
  |   unit #8    |         /              |
  +--------------+--------/ communication |
  |   unit #9    |--------+   framework   |
  +--------------+        +---------------+

```
fig.3. Area allocation in the FPGA

