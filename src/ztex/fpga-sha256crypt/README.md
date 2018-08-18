## Overview

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
  +---------------+   |   \    (16x256b)  / <------
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
- The program for the CPU is available <a href='https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/ztex/fpga-sha256crypt/sha256crypt/cpu/program.vh'>here</a>.


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

