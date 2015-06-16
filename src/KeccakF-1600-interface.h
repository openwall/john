/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakF1600Interface_h_
#define _KeccakF1600Interface_h_

#define KeccakF_width 1600
#define KeccakF_laneInBytes 8

/** Function called at least once before any use of the other KeccakF1600_*
  * functions, possibly to initialize global variables.
  */
void KeccakF1600_Initialize( void );

/** Function to initialize the state to the logical value 0^1600.
  * @param  state   Pointer to the state to initialize.
  */
void KeccakF1600_StateInitialize(void *state);

/** Function to XOR data given as bytes into the state.
  * The bits to modify are restricted to be consecutive and to be in the same lane.
  * The bit positions that are affected by this function are
  * from @a lanePosition*64 + @a offset*8
  * to @a lanePosition*64 + @a offset*8 + @a length*8.
  * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
  * @param  state   Pointer to the state.
  * @param  lanePosition    Index of the lane to be modified (x+5*y,
  *                         or bit position divided by 64).
  * @param  data    Pointer to the input data.
  * @param  offset  Offset in bytes within the lane.
  * @param  length  Number of bytes.
  * @pre    0 ≤ @a lanePosition < 25
  * @pre    0 ≤ @a offset < 8
  * @pre    0 ≤ @a offset + @a length ≤ 8
  */
void KeccakF1600_StateXORBytesInLane(void *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length);

/** Function to XOR data given as bytes into the state.
  * The bits to modify are restricted to start from the bit position 0 and
  * to span a whole number of lanes (i.e., multiple of 8 bytes).
  * @param  state   Pointer to the state.
  * @param  data    Pointer to the input data.
  * @param  laneCount   The number of lanes, i.e., the length of the data
  *                     divided by 64 bits.
  * @pre    0 ≤ @a laneCount ≤ 25
  */
void KeccakF1600_StateXORLanes(void *state, const unsigned char *data, unsigned int laneCount);

/** Function to complement the value of a given bit in the state.
  * This function is typically used to XOR the second bit of the multi-rate
  * padding into the state.
  * @param  state   Pointer to the state.
  * @param  position    The position of the bit to complement.
  * @pre    0 ≤ @a position < 1600
  */
void KeccakF1600_StateComplementBit(void *state, unsigned int position);

/** Function to apply Keccak-f[1600] on the state.
  * @param  state   Pointer to the state.
  */
void KeccakF1600_StatePermute(void *state);

/** Function to retrieve data from the state into bytes.
  * The bits to output are restricted to be consecutive and to be in the same lane.
  * The bit positions that are retrieved by this function are
  * from @a lanePosition*64 + @a offset*8
  * to @a lanePosition*64 + @a offset*8 + @a length*8.
  * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
  * @param  state   Pointer to the state.
  * @param  lanePosition    Index of the lane to be read (x+5*y,
  *                         or bit position divided by 64).
  * @param  data    Pointer to the area where to store output data.
  * @param  offset  Offset in byte within the lane.
  * @param  length  Number of bytes.
  * @pre    0 ≤ @a lanePosition < 25
  * @pre    0 ≤ @a offset < 8
  * @pre    0 ≤ @a offset + @a length ≤ 8
  */
void KeccakF1600_StateExtractBytesInLane(const void *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length);

/** Function to retrieve data from the state into bytes.
  * The bits to output are restricted to start from the bit position 0 and
  * to span a whole number of lanes (i.e., multiple of 8 bytes).
  * @param  state   Pointer to the state.
  * @param  data    Pointer to the area where to store output data.
  * @param  laneCount   The number of lanes, i.e., the length of the data
  *                     divided by 64 bits.
  * @pre    0 ≤ @a laneCount ≤ 25
  */
void KeccakF1600_StateExtractLanes(const void *state, unsigned char *data, unsigned int laneCount);

/** Function to sequentially XOR data bytes, apply the Keccak-f[1600]
  * permutation and retrieve data bytes from the state.
  * The bits to modify and to output are restricted to start from the bit
  * position 0 and  to span a whole number of lanes (i.e., multiple of 8 bytes).
  * Its effect should be functionally identical to calling in order:
  * - KeccakF1600_StateXORLanes(state, inData, inLaneCount);
  * - KeccakF1600_StatePermute(state);
  * - KeccakF1600_StateExtractLanes(state, outData, outLaneCount);
  * @param  state   Pointer to the state.
  * @param  inData  Pointer to the input data.
  * @param  inLaneCount The number of lanes, i.e., the length of the input data
  *                     divided by 64 bits.
  * @param  outData Pointer to the area where to store output data.
  * @param  outLaneCount    The number of lanes, i.e., the length of the output data
  *                     divided by 64 bits.
  * @pre    0 ≤ @a inLaneCount ≤ 25
  * @pre    0 ≤ @a outLaneCount ≤ 25
  */
void KeccakF1600_StateXORPermuteExtract(void *state, const unsigned char *inData, unsigned int inLaneCount, unsigned char *outData, unsigned int outLaneCount);

#endif
