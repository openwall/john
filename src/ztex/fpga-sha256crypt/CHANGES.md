
## New version 2019.01

The new version has improved performance and power efficiency.

- SHA256 cores were reworked to compute 2 SHA256 rounds from 2 different computations
in 2 cycles. The result is each core computes 4 blocks in (64+8)x4 = 288 cycles.
Such design takes about 10% more area, able for increased frequency. The number of computing
units in each FPGA were reduced from 25 (75 cores) to 23 (69 cores), number of keys
computed by each FPGA in parallel increases from 150 to 276 (1104 per board).
Possible frequency reported by the toolset increases from 166 to 241 MHz.
Actual frequency (at which tested boards work reliably) increases from 135 to 175 MHz.
- It was observed sha2-crypt designs consume more power than bcrypt, descrypt designs
using same hardware. Too high power consumption was identified as a likely cause for
unability to operate at frequency reported by the toolset. Various measures were
implemented to reduce power consumption while doing same functions, typically at the cost
of negligible to small amount of additional hardware resources.
- Power consumption in previous designs did not depend on the load substantially.
There was identified a big potential in the reduction of idle power consumption.
Measured current (using 12 V input) with new design running at 175 MHz:
~3.1 A under full load, ~0.4 A idle.

Performance (at 175 MHz) in different modes, with different key lengths, with a comparison
to CPUs is shown in table 1.
```
+--------------+--------+------------+------------+----------------+
|              |        | ZTEX board | i5-4210M   | Intel Celeron  |
|              |        | 1.15y      | OMPx4,AVX2 |Stepping 6,SSSE3|
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


## Overview - version 2018.08

- sha256crypt for ZTEX 1.15y board allows candidate passwords up to
32 bytes, equipped with on-board mask generator and comparator.
The board computes 600 keys in parallel.


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
  +---------------+   |   \  (6 x 128 B)  / <------
     |      ^         |    \             /         \
 +-------+  |        /      -------------           |
 | procb |  |       /                           +------------+
 | saved |  |      /    +------------------+    | unit_input |
 | state |  |     /     | thread_state(x6) |    +------------+
 +-------+  |    |      +------------------+              ^
            |    |                                        |
  +-----------+   \   +-----------------------------+     |
  | procb_buf |    -->|          C.P.U.             |     |
  +-----------+       |  +-----------------------+  |     |
          ^           |  | integer ops. incl.    |  |     |
           \          |  | 6 x 16 registers(x16b)|  |     |
            \         |  +-----------------------+  |     |
             ---------|                             |     |
                      |  +----------------------+   |     |
                      |  | thread switch (x6)   |   |     |
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
Several cycles before a computations is finished and output,
next computation starts loading Initial Values (IVs) and pre-fetching
data from core's input buffer.
- internally cores store result of SHA256, allow to use previously
stored result as IVs for subsequent block. That way, the core
is able to handle input of any length.
- So each core performs 2 blocks in (64+8)*2 = 144 cycles.

- CPU runs same program in 6 independent hardware threads.
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

- Each FPGA has 25 computing units, that's 75 cores, 150 keys are
computed in parallel.


## Resource Usage

Each computing unit uses ~2,450 LUT. Other types of hardware resources
are not limiting. Here's a breakdown of resource usage by individual
components in a unit:

- 3 SHA256 cores 540 LUT each (total 1620 LUT, 66.1%)
- 16-bit multi-threaded CPU: 235 LUT (9.6%)
- "Main" memory I/O: 65 LUT (2.7%)
- Unit's input and output buffers: 90 LUT (3.7%)

The remaining 440 LUT (17.9%) is used mostly by logic that transforms
PROCESS_BYTES instructions into SHA256 data blocks. That includes:

- "procb_buf" (intermediate storage of data submitted by PROCESS_BYTES
instructions): 48 LUT (2.0%)
- "realign" (fetches data from 32-bit memory and performs proper
alignment): 92 LUT (3.8%)
- "process_bytes" (operates the above, creates SHA256 blocks, adds
padding, counts total bytes etc.): 235 LUT (9.6%)
- "thread_state" with 3 independent read and 4 write channels (reflects
state of each thread for CPU and other subsystems): 35 LUT (1.4%)


## Design Placement and Routing

- Used to manually allocate areas for every module. Totally allocated
75 rectangular areas for cores and 25 areas for CPUs and glue logic.
Communication framework used area that would be enough for 2 cores.
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
  |   unit #7    |---------+   unit #23   |
  +--------------+ unit #22|--------------+
  |   unit #8    |         |   unit #24   |
  +--------------+---------+--------------+
  |   unit #9    |--------+ communication |
  +--------------+         \ framework    |
  |   unit #10   |          +-------------+
  +--------------+
```
fig.3. Area allocation in the FPGA

