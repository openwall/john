## Overview

- md5crypt ($1$) for ZTEX 1.15y board allows candidate passwords up to
64 bytes, equipped with on-board candidate generator and comparator.
It's also able to compute phpass-MD5 hashes.
The board computes 1536 keys in parallel.
- Current consumption: 2.8A under full load, 0.4A idle.


## Computing units

- md5crypt invokes MD5 in different ways, sometimes that look
very complex. To accomplish the task, a CPU-based computing unit
was implemented.
- Each unit consists of 3 cores, CPU, memory and I/O subsystem.
The approximate schematic of a computing unit is shown at fig.1.

```
           --------------+-------------+--------------
          /             /             /               \
     +--------+    +--------+    +--------+            |
     |        |    |        |    |        |            |
     |   MD5  |    |   MD5  |    |   MD5  |            |
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
           \          |  |12x16 registers(x16bit)|  |     |
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
fig.1. CPU based computing unit

- CPU runs same program in 12 independent hardware threads.
Each thread has 128 bytes of "main" memory (accessible by MD5
subsystem), 16 x 16-bit registers. Data movement, integer,
execution flow control operations are available. However there's only
a subset if operations typically implemented in general-purpose CPUs,
enough for the task.
- CPU is heavily integrated with MD5 subsystem. It has INIT_CTX,
PROCESS_BYTES, FINISH_CTX instructions that are almost equivalent to
init_ctx(), process_bytes(), finish_ctx() from software library.
Each instruction takes 1 cycle to execute.
- MD5 instructions store instruction data in internal buffer
(procb_buf). A dedicated unit (process_bytes) takes intermediate data,
fetches input data from the memory, creates 16 x 32-bit data blocks
for cores, adds padding and total where necessary. It saves
the state of an unfinished computation, switches to the next core
after each block.
- Several programs are hardcoded in CPU's read-only instruction memory.
The program is selected at runtime with input initialization packet.
There're 2 programs: md5crypt and phpass.


## Specialized MD5 circuits ("cores")

- MD5 computations are performed using specialized circuits ("cores").

```
                 md5ctx                   .         md5core
                                          .
  +----+     +---+     +----+      +---+       +----------+
  | C2 |---->| D |---->| D2 |----->| A |  .    |          |
  +----+     +---+     +----+      +---+       |   K(t)   |
    ^          |                     |    .    |          |
    |          |                     |         +----------+
  +----+        \   +-----+          |    .         |
  | C  |----     -->|     |   +---+  |              |    +------+
  +----+    \       |  F  |   | + |<-+    .  +---+  |    |      |
    ^        ------>|     |-->|   |          | + |<-+    | mem1 |
    |               |     |   |   |<---------|   |       |      | din
  +----+     ------>|     |   +---+       .  |   |<------|      |<---
  | B2 |-   /       +-----+     |            |   |       |      |
  +----+ \ /                    |         .  |   |<-+    |      |
    ^     \                      \           +---+  |    |      |
    |    / \                      \       .         |    +------+
  +----+/   \                      |                |
  | B  |     \        +---------+  |      .   +------------+
  +----+      \       |         |  |          |            |
    ^          |      |   <<<   |<-+      .   |    mem2    |
    |   +---+  |      |         |             |            |
    +---| + |<-+      +---------+         .   +------------+
        |   |              |                        ^
        |   |              |              .         |            dout
        |   |<-------------+------------------------+--------------->
        +---+                             .
```
fig.2. MD5 computing circuit ("core")

- Each cycle, a core computes one of 64 algorithm rounds.
Additionally 4 cycles it's busy with additions at the end of the block,
and 4 more cycles it's loading Initial Values (IVs).
Each core runs 2 computations at the same time. On some cycle, a round
from computation #0 is computed and on the next cycle, a round from
computation #1 is computed.
Several cycles before 2 computations are finished and output,
next 2 computations start pre-fetching data from core's input buffer ```mem1```.
- Internally cores store result of MD5 in ```mem2```, allow to use previously
stored result as IVs for subsequent block. Data in ```mem2``` is stored
rotated by 16, when loaded as IVs it's rotated by 16 again.
That helps with optimization of rotator unit, which could take
substantially more space if it had ability for pass-through without rotation.
- So each core runs 4 independent computations in parallel, performs
4 blocks in (64+4+4)*4 = 288 cycles.
- Cores are of 3 types, with same function, timing and interface.
They differ in used hardware resources and occupied area.
Type 0 cores use 3 BRAM units. Type 1 cores use 2 BRAM units, placed
in areas with less BRAM density. Type 2 cores use no BRAM units, placed
in areas with no BRAM.


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
fig.3. Overview, FPGA application

- Each FPGA has 32 computing units, that's 96 cores, 384 keys are
computed in parallel.


## Resource Usage

Each computing unit uses approximately 1,880 to 2,160 LUT. Here's
a breakdown of resource usage by individual components in a unit:

- 3 MD5 cores. Type 0 cores use 340 LUT, Type 1 cores use 370
and Type 2 ones occupy 440 LUT.
- 16-bit multi-threaded CPU: 235 LUT
- Unit's input and output buffers: 115 LUT. Unit's output buffer
includes 16-deep output packet queue.
- Other: ~500 LUT. That's mostly the logic that creates 16x32-bit
data blocks out of PROCESS_BYTES instructions, with ability to
start from memory addresses not aligned to 4 bytes. Also includes
some supplementary logic.

Total resource utilization: 70% LUT, 71% BRAM, 33% FF.

