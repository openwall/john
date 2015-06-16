[bits 64]
[CPU intelnop]

; Copyright (c) 2010, Intel Corporation
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;     * Redistributions of source code must retain the above copyright notice,
;       this list of conditions and the following disclaimer.
;     * Redistributions in binary form must reproduce the above copyright notice,
;       this list of conditions and the following disclaimer in the documentation
;       and/or other materials provided with the distribution.
;     * Neither the name of Intel Corporation nor the names of its contributors
;       may be used to endorse or promote products derived from this software
;       without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
; IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
; INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
; BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
; OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
; ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%macro linux_setup 0
;; Needed for OSX too. Who does not need this?
;; %ifdef __linux__
%ifndef __cygwin__
	mov rcx, rdi
	mov rdx, rsi
%endif
%endmacro

%macro inversekey 1
	movdqu  xmm1,%1
	aesimc	xmm0,xmm1
	movdqu	%1,xmm0
%endmacro

%macro aesdeclast1 1
	aesdeclast	xmm0,%1
%endmacro

%macro aesenclast1 1
	aesenclast	xmm0,%1
%endmacro

%macro aesdec1 1
	aesdec	xmm0,%1
%endmacro

%macro aesenc1 1
	aesenc	xmm0,%1
%endmacro


%macro aesdeclast1_u 1
	movdqu xmm4,%1
	aesdeclast	xmm0,xmm4
%endmacro

%macro aesenclast1_u 1
	movdqu xmm4,%1
	aesenclast	xmm0,xmm4
%endmacro

%macro aesdec1_u 1
	movdqu xmm4,%1
	aesdec	xmm0,xmm4
%endmacro

%macro aesenc1_u 1
	movdqu xmm4,%1
	aesenc	xmm0,xmm4
%endmacro

%macro aesdec4 1
	movdqa	xmm4,%1

	aesdec	xmm0,xmm4
	aesdec	xmm1,xmm4
	aesdec	xmm2,xmm4
	aesdec	xmm3,xmm4

%endmacro

%macro aesdeclast4 1
	movdqa	xmm4,%1

	aesdeclast	xmm0,xmm4
	aesdeclast	xmm1,xmm4
	aesdeclast	xmm2,xmm4
	aesdeclast	xmm3,xmm4

%endmacro


%macro aesenc4 1
	movdqa	xmm4,%1

	aesenc	xmm0,xmm4
	aesenc	xmm1,xmm4
	aesenc	xmm2,xmm4
	aesenc	xmm3,xmm4

%endmacro

%macro aesenclast4 1
	movdqa	xmm4,%1

	aesenclast	xmm0,xmm4
	aesenclast	xmm1,xmm4
	aesenclast	xmm2,xmm4
	aesenclast	xmm3,xmm4

%endmacro


%macro load_and_inc4 1
	movdqa	xmm4,%1
	movdqa	xmm0,xmm5
	pshufb	xmm0, xmm6 ; byte swap counter back
	movdqa  xmm1,xmm5
	paddd	xmm1,[counter_add_one wrt rip]
	pshufb	xmm1, xmm6 ; byte swap counter back
	movdqa  xmm2,xmm5
	paddd	xmm2,[counter_add_two wrt rip]
	pshufb	xmm2, xmm6 ; byte swap counter back
	movdqa  xmm3,xmm5
	paddd	xmm3,[counter_add_three wrt rip]
	pshufb	xmm3, xmm6 ; byte swap counter back
	pxor	xmm0,xmm4
	paddd	xmm5,[counter_add_four wrt rip]
	pxor	xmm1,xmm4
	pxor	xmm2,xmm4
	pxor	xmm3,xmm4
%endmacro

%macro xor_with_input4 1
	movdqu xmm4,[%1]
	pxor xmm0,xmm4
	movdqu xmm4,[%1+16]
	pxor xmm1,xmm4
	movdqu xmm4,[%1+32]
	pxor xmm2,xmm4
	movdqu xmm4,[%1+48]
	pxor xmm3,xmm4
%endmacro



%macro load_and_xor4 2
	movdqa	xmm4,%2
	movdqu	xmm0,[%1 + 0*16]
	pxor	xmm0,xmm4
	movdqu	xmm1,[%1 + 1*16]
	pxor	xmm1,xmm4
	movdqu	xmm2,[%1 + 2*16]
	pxor	xmm2,xmm4
	movdqu	xmm3,[%1 + 3*16]
	pxor	xmm3,xmm4
%endmacro

%macro store4 1
	movdqu [%1 + 0*16],xmm0
	movdqu [%1 + 1*16],xmm1
	movdqu [%1 + 2*16],xmm2
	movdqu [%1 + 3*16],xmm3
%endmacro

%macro copy_round_keys 3
	movdqu xmm4,[%2 + ((%3)*16)]
	movdqa [%1 + ((%3)*16)],xmm4
%endmacro


%macro key_expansion_1_192 1
		;; Assumes the xmm3 includes all zeros at this point.
        pshufd xmm2, xmm2, 11111111b
        shufps xmm3, xmm1, 00010000b
        pxor xmm1, xmm3
        shufps xmm3, xmm1, 10001100b
        pxor xmm1, xmm3
		pxor xmm1, xmm2
		movdqu [rdx+%1], xmm1
%endmacro

; Calculate w10 and w11 using calculated w9 and known w4-w5
%macro key_expansion_2_192 1
		movdqa xmm5, xmm4
		pslldq xmm5, 4
		shufps xmm6, xmm1, 11110000b
		pxor xmm6, xmm5
		pxor xmm4, xmm6
		pshufd xmm7, xmm4, 00001110b
		movdqu [rdx+%1], xmm7
%endmacro


section .data
align 16
shuffle_mask:
DD 0FFFFFFFFh
DD 03020100h
DD 07060504h
DD 0B0A0908h

byte_swap_16:
DDQ 0x000102030405060708090A0B0C0D0E0F

align 16
counter_add_one:
DD 1
DD 0
DD 0
DD 0

counter_add_two:
DD 2
DD 0
DD 0
DD 0

counter_add_three:
DD 3
DD 0
DD 0
DD 0

counter_add_four:
DD 4
DD 0
DD 0
DD 0



section .text

align 16
key_expansion256:

    pshufd xmm2, xmm2, 011111111b

    movdqa xmm4, xmm1
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pxor xmm1, xmm2

    movdqu [rdx], xmm1
    add rdx, 0x10

    aeskeygenassist xmm4, xmm1, 0
    pshufd xmm2, xmm4, 010101010b

    movdqa xmm4, xmm3
    pshufb xmm4, xmm5
    pxor xmm3, xmm4
    pshufb xmm4, xmm5
    pxor xmm3, xmm4
    pshufb xmm4, xmm5
    pxor xmm3, xmm4
    pxor xmm3, xmm2

    movdqu [rdx], xmm3
    add rdx, 0x10

    ret



align 16
key_expansion128:
    pshufd xmm2, xmm2, 0xFF;
    movdqa xmm3, xmm1
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; storing the result in the key schedule array
    movdqu [rdx], xmm1
    add rdx, 0x10
    ret






align 16
global iEncExpandKey128
iEncExpandKey128:

		linux_setup

        movdqu xmm1, [rcx]    ; loading the key

        movdqu [rdx], xmm1

        movdqa xmm5, [shuffle_mask wrt rip]

        add rdx,16

        aeskeygenassist xmm2, xmm1, 0x1     ; Generating round key 1
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
        call key_expansion128
        aeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
        call key_expansion128

		ret



align 16
global iEncExpandKey192
iEncExpandKey192:

		linux_setup
		sub rsp,64+8
		movdqa	[rsp],xmm6
		movdqa	[rsp+16],xmm7


        movq xmm7, [rcx+16]	; loading the AES key
        movq [rdx+16], xmm7  ; Storing key in memory where all key expansion
        pshufd xmm4, xmm7, 01001111b
        movdqu xmm1, [rcx]	; loading the AES key
        movdqu [rdx], xmm1  ; Storing key in memory where all key expansion

        pxor xmm3, xmm3		; Set xmm3 to be all zeros. Required for the key_expansion.
        pxor xmm6, xmm6		; Set xmm3 to be all zeros. Required for the key_expansion.

        aeskeygenassist xmm2, xmm4, 0x1     ; Complete round key 1 and generate round key 2
        key_expansion_1_192 24
		key_expansion_2_192 40

        aeskeygenassist xmm2, xmm4, 0x2     ; Generate round key 3 and part of round key 4
        key_expansion_1_192 48
		key_expansion_2_192 64

        aeskeygenassist xmm2, xmm4, 0x4     ; Complete round key 4 and generate round key 5
        key_expansion_1_192 72
		key_expansion_2_192 88

        aeskeygenassist xmm2, xmm4, 0x8     ; Generate round key 6 and part of round key 7
        key_expansion_1_192 96
		key_expansion_2_192 112

        aeskeygenassist xmm2, xmm4, 0x10     ; Complete round key 7 and generate round key 8
        key_expansion_1_192 120
		key_expansion_2_192 136

        aeskeygenassist xmm2, xmm4, 0x20     ; Generate round key 9 and part of round key 10
        key_expansion_1_192 144
		key_expansion_2_192 160

        aeskeygenassist xmm2, xmm4, 0x40     ; Complete round key 10 and generate round key 11
        key_expansion_1_192 168
		key_expansion_2_192 184

        aeskeygenassist xmm2, xmm4, 0x80     ; Generate round key 12
        key_expansion_1_192 192


		movdqa	xmm6,[rsp]
		movdqa	xmm7,[rsp+16]
		add rsp,64+8

		ret




align 16
global iDecExpandKey128
iDecExpandKey128:

	linux_setup
	push rcx
	push rdx
	sub rsp,16+8

	call iEncExpandKey128

	add rsp,16+8
	pop rdx
	pop rcx

	inversekey [rdx + 1*16]
	inversekey [rdx + 2*16]
	inversekey [rdx + 3*16]
	inversekey [rdx + 4*16]
	inversekey [rdx + 5*16]
	inversekey [rdx + 6*16]
	inversekey [rdx + 7*16]
	inversekey [rdx + 8*16]
	inversekey [rdx + 9*16]

	ret


align 16
global iDecExpandKey192
iDecExpandKey192:

	linux_setup
	push rcx
	push rdx
	sub rsp,16+8

	call iEncExpandKey192

	add rsp,16+8
	pop rdx
	pop rcx


	inversekey [rdx + 1*16]
	inversekey [rdx + 2*16]
	inversekey [rdx + 3*16]
	inversekey [rdx + 4*16]
	inversekey [rdx + 5*16]
	inversekey [rdx + 6*16]
	inversekey [rdx + 7*16]
	inversekey [rdx + 8*16]
	inversekey [rdx + 9*16]
	inversekey [rdx + 10*16]
	inversekey [rdx + 11*16]

	ret



align 16
global iDecExpandKey256
iDecExpandKey256:

	linux_setup
	push rcx
	push rdx
	sub rsp,16+8

	call iEncExpandKey256

	add rsp,16+8
	pop rdx
	pop rcx

	inversekey [rdx + 1*16]
	inversekey [rdx + 2*16]
	inversekey [rdx + 3*16]
	inversekey [rdx + 4*16]
	inversekey [rdx + 5*16]
	inversekey [rdx + 6*16]
	inversekey [rdx + 7*16]
	inversekey [rdx + 8*16]
	inversekey [rdx + 9*16]
	inversekey [rdx + 10*16]
	inversekey [rdx + 11*16]
	inversekey [rdx + 12*16]
	inversekey [rdx + 13*16]

	ret




align 16
global iEncExpandKey256
iEncExpandKey256:

	linux_setup

    movdqu xmm1, [rcx]    ; loading the key
    movdqu xmm3, [rcx+16]
    movdqu [rdx], xmm1  ; Storing key in memory where all key schedule will be stored
    movdqu [rdx+16], xmm3

    add rdx,32

    movdqa xmm5, [shuffle_mask wrt rip]  ; this mask is used by key_expansion

    aeskeygenassist xmm2, xmm3, 0x1     ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x2     ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x4     ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x8     ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x10    ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x20    ;
    call key_expansion256
    aeskeygenassist xmm2, xmm3, 0x40    ;
;    call key_expansion256

    pshufd xmm2, xmm2, 011111111b

    movdqa xmm4, xmm1
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pshufb xmm4, xmm5
    pxor xmm1, xmm4
    pxor xmm1, xmm2

    movdqu [rdx], xmm1


	ret






align 16
global iDec128
iDec128:

	linux_setup
	sub rsp,16*16+8


	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test eax,eax
	jz end_dec128

	cmp eax,4
	jl	lp128decsingle

	test	rcx,0xf
	jz		lp128decfour

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	mov rcx,rsp



align 16
lp128decfour:

	test eax,eax
	jz end_dec128

	cmp eax,4
	jl	lp128decsingle

	load_and_xor4 rdx, [rcx+10*16]
	add rdx,16*4
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	sub eax,4
	store4 r8+rdx-(16*4)
	jmp lp128decfour


	align 16
lp128decsingle:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+10*16]
	pxor xmm0, xmm4
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

	add rdx, 16
	movdqu  [r8 + rdx - 16], xmm0
	dec eax
	jnz lp128decsingle

end_dec128:

	add rsp,16*16+8
	ret


align 16
global iDec128_CBC
iDec128_CBC:

	linux_setup
	sub rsp,16*16+8

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu	xmm5,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]


	sub r8,rdx


	test eax,eax
	jz end_dec128_CBC

	cmp eax,4
	jl	lp128decsingle_CBC

	test	rcx,0xf
	jz		lp128decfour_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	mov rcx,rsp


align 16
lp128decfour_CBC:

	test eax,eax
	jz end_dec128_CBC

	cmp eax,4
	jl	lp128decsingle_CBC

	load_and_xor4 rdx, [rcx+10*16]
	add rdx,16*4
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	pxor	xmm0,xmm5
	movdqu	xmm4,[rdx - 16*4 + 0*16]
	pxor	xmm1,xmm4
	movdqu	xmm4,[rdx - 16*4 + 1*16]
	pxor	xmm2,xmm4
	movdqu	xmm4,[rdx - 16*4 + 2*16]
	pxor	xmm3,xmm4
	movdqu	xmm5,[rdx - 16*4 + 3*16]

	sub eax,4
	store4 r8+rdx-(16*4)
	jmp lp128decfour_CBC


	align 16
lp128decsingle_CBC:

	movdqu xmm0, [rdx]
	movdqa	xmm1,xmm0
	movdqu xmm4,[rcx+10*16]
	pxor xmm0, xmm4
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

	pxor	xmm0,xmm5
	movdqa	xmm5,xmm1
	add rdx, 16
	movdqu  [r8 + rdx - 16], xmm0
	dec eax
	jnz lp128decsingle_CBC

end_dec128_CBC:

	mov	   r9,[r9+24]
	movdqu [r9],xmm5
	add rsp,16*16+8
	ret


align 16
global iDec192_CBC
iDec192_CBC:

	linux_setup
	sub rsp,16*16+8

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu	xmm5,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]


	sub r8,rdx

	test eax,eax
	jz end_dec192_CBC

	cmp eax,4
	jl	lp192decsingle_CBC

	test	rcx,0xf
	jz		lp192decfour_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	mov rcx,rsp


align 16
lp192decfour_CBC:

	test eax,eax
	jz end_dec192_CBC

	cmp eax,4
	jl	lp192decsingle_CBC

	load_and_xor4 rdx, [rcx+12*16]
	add rdx,16*4
	aesdec4 [rcx+11*16]
	aesdec4 [rcx+10*16]
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	pxor	xmm0,xmm5
	movdqu	xmm4,[rdx - 16*4 + 0*16]
	pxor	xmm1,xmm4
	movdqu	xmm4,[rdx - 16*4 + 1*16]
	pxor	xmm2,xmm4
	movdqu	xmm4,[rdx - 16*4 + 2*16]
	pxor	xmm3,xmm4
	movdqu	xmm5,[rdx - 16*4 + 3*16]

	sub eax,4
	store4 r8+rdx-(16*4)
	jmp lp192decfour_CBC


	align 16
lp192decsingle_CBC:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+12*16]
	movdqa	xmm1,xmm0
	pxor xmm0, xmm4
	aesdec1_u [rcx+11*16]
	aesdec1_u [rcx+10*16]
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

	pxor	xmm0,xmm5
	movdqa	xmm5,xmm1
	add rdx, 16
	movdqu  [r8 + rdx - 16], xmm0
	dec eax
	jnz lp192decsingle_CBC

end_dec192_CBC:

	mov	   r9,[r9+24]
	movdqu [r9],xmm5
	add rsp,16*16+8
	ret




align 16
global iDec256_CBC
iDec256_CBC:

	linux_setup
	sub rsp,16*16+8

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu	xmm5,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]


	sub r8,rdx

	test eax,eax
	jz end_dec256_CBC

	cmp eax,4
	jl	lp256decsingle_CBC

	test	rcx,0xf
	jz		lp256decfour_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	copy_round_keys rsp,rcx,13
	copy_round_keys rsp,rcx,14
	mov rcx,rsp

align 16
lp256decfour_CBC:

	test eax,eax
	jz end_dec256_CBC

	cmp eax,4
	jl	lp256decsingle_CBC

	load_and_xor4 rdx, [rcx+14*16]
	add rdx,16*4
	aesdec4 [rcx+13*16]
	aesdec4 [rcx+12*16]
	aesdec4 [rcx+11*16]
	aesdec4 [rcx+10*16]
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	pxor	xmm0,xmm5
	movdqu	xmm4,[rdx - 16*4 + 0*16]
	pxor	xmm1,xmm4
	movdqu	xmm4,[rdx - 16*4 + 1*16]
	pxor	xmm2,xmm4
	movdqu	xmm4,[rdx - 16*4 + 2*16]
	pxor	xmm3,xmm4
	movdqu	xmm5,[rdx - 16*4 + 3*16]

	sub eax,4
	store4 r8+rdx-(16*4)
	jmp lp256decfour_CBC


	align 16
lp256decsingle_CBC:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+14*16]
	movdqa	xmm1,xmm0
	pxor xmm0, xmm4
	aesdec1_u [rcx+13*16]
	aesdec1_u [rcx+12*16]
	aesdec1_u [rcx+11*16]
	aesdec1_u [rcx+10*16]
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

	pxor	xmm0,xmm5
	movdqa	xmm5,xmm1
	add rdx, 16
	movdqu  [r8 + rdx - 16], xmm0
	dec eax
	jnz lp256decsingle_CBC

end_dec256_CBC:

	mov	   r9,[r9+24]
	movdqu [r9],xmm5
	add rsp,16*16+8
	ret





align 16
global iDec192
iDec192:

	linux_setup
	sub rsp,16*16+8

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test eax,eax
	jz end_dec192

	cmp eax,4
	jl	lp192decsingle

	test	rcx,0xf
	jz		lp192decfour

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	mov rcx,rsp

align 16
lp192decfour:

	test eax,eax
	jz end_dec192

	cmp eax,4
	jl	lp192decsingle

	load_and_xor4 rdx, [rcx+12*16]
	add rdx,16*4
	aesdec4 [rcx+11*16]
	aesdec4 [rcx+10*16]
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	sub eax,4
	store4 r8+rdx-(16*4)
	jmp lp192decfour


	align 16
lp192decsingle:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+12*16]
	pxor xmm0, xmm4
	aesdec1_u [rcx+11*16]
	aesdec1_u [rcx+10*16]
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

	add rdx, 16
	movdqu  [r8 + rdx - 16], xmm0
	dec eax
	jnz lp192decsingle

end_dec192:

	add rsp,16*16+8
	ret




align 16
global iDec256
iDec256:

	linux_setup
	sub rsp,16*16+8

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test eax,eax
	jz end_dec256

	cmp eax,4
	jl lp256dec

	test	rcx,0xf
	jz		lp256dec4

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	copy_round_keys rsp,rcx,13
	copy_round_keys rsp,rcx,14
	mov rcx,rsp


	align 16
lp256dec4:
	test eax,eax
	jz end_dec256

	cmp eax,4
	jl lp256dec

	load_and_xor4 rdx,[rcx+14*16]
	add rdx, 4*16
	aesdec4 [rcx+13*16]
	aesdec4 [rcx+12*16]
	aesdec4 [rcx+11*16]
	aesdec4 [rcx+10*16]
	aesdec4 [rcx+9*16]
	aesdec4 [rcx+8*16]
	aesdec4 [rcx+7*16]
	aesdec4 [rcx+6*16]
	aesdec4 [rcx+5*16]
	aesdec4 [rcx+4*16]
	aesdec4 [rcx+3*16]
	aesdec4 [rcx+2*16]
	aesdec4 [rcx+1*16]
	aesdeclast4 [rcx+0*16]

	store4 r8+rdx-16*4
	sub eax,4
	jmp lp256dec4

	align 16
lp256dec:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+14*16]
	add rdx, 16
	pxor xmm0, xmm4                    ; Round 0 (only xor)
	aesdec1_u [rcx+13*16]
	aesdec1_u [rcx+12*16]
	aesdec1_u [rcx+11*16]
	aesdec1_u [rcx+10*16]
	aesdec1_u [rcx+9*16]
	aesdec1_u [rcx+8*16]
	aesdec1_u [rcx+7*16]
	aesdec1_u [rcx+6*16]
	aesdec1_u [rcx+5*16]
	aesdec1_u [rcx+4*16]
	aesdec1_u [rcx+3*16]
	aesdec1_u [rcx+2*16]
	aesdec1_u [rcx+1*16]
	aesdeclast1_u [rcx+0*16]

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp256dec

end_dec256:

	add rsp,16*16+8
	ret






align 16
global iEnc128
iEnc128:

	linux_setup
	sub rsp,16*16+8

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test eax,eax
	jz end_enc128

	cmp eax,4
	jl lp128encsingle

	test	rcx,0xf
	jz		lpenc128four

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	mov rcx,rsp


	align 16

lpenc128four:

	test eax,eax
	jz end_enc128

	cmp eax,4
	jl lp128encsingle

	load_and_xor4 rdx,[rcx+0*16]
	add rdx,4*16
	aesenc4	[rcx+1*16]
	aesenc4	[rcx+2*16]
	aesenc4	[rcx+3*16]
	aesenc4	[rcx+4*16]
	aesenc4	[rcx+5*16]
	aesenc4	[rcx+6*16]
	aesenc4	[rcx+7*16]
	aesenc4	[rcx+8*16]
	aesenc4	[rcx+9*16]
	aesenclast4	[rcx+10*16]

	store4 r8+rdx-16*4
	sub eax,4
	jmp lpenc128four

	align 16
lp128encsingle:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp128encsingle

end_enc128:

	add rsp,16*16+8
	ret


align 16
global iEnc128_CTR
iEnc128_CTR:

	linux_setup

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm5,[rax]


	sub rsp,16*16+8+16

	movdqa [rsp+16*16], xmm6
	movdqa xmm6, [byte_swap_16 wrt rip]
	pshufb xmm5, xmm6 ; byte swap counter

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test eax,eax
	jz end_encctr128

	cmp eax,4
	jl lp128encctrsingle

	test	rcx,0xf
	jz		lpencctr128four

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	mov rcx,rsp


	align 16

lpencctr128four:

	test eax,eax
	jz end_encctr128

	cmp eax,4
	jl lp128encctrsingle

	load_and_inc4 [rcx+0*16]
	add rdx,4*16
	aesenc4	[rcx+1*16]
	aesenc4	[rcx+2*16]
	aesenc4	[rcx+3*16]
	aesenc4	[rcx+4*16]
	aesenc4	[rcx+5*16]
	aesenc4	[rcx+6*16]
	aesenc4	[rcx+7*16]
	aesenc4	[rcx+8*16]
	aesenc4	[rcx+9*16]
	aesenclast4	[rcx+10*16]
	xor_with_input4 rdx-(4*16)

	store4 r8+rdx-16*4
	sub eax,4
	jmp lpencctr128four

	align 16
lp128encctrsingle:

	movdqa xmm0,xmm5
	pshufb	xmm0, xmm6 ; byte swap counter back
	paddd	xmm5,[counter_add_one wrt rip]
	add rdx, 16
	movdqu xmm4,[rcx+0*16]
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]
	movdqu xmm4, [rdx-16]
	pxor  xmm0,xmm4

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp128encctrsingle

end_encctr128:

	mov	   r9,[r9+24]

	pshufb xmm5, xmm6 ; byte swap counter
	movdqu [r9],xmm5
	movdqa xmm6, [rsp+16*16]
	add rsp,16*16+8+16
	ret



align 16
global iEnc192_CTR
iEnc192_CTR:

	linux_setup

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm5,[rax]


	sub rsp,16*16+8+16

	movdqa [rsp+16*16], xmm6
	movdqa xmm6, [byte_swap_16 wrt rip]
	pshufb xmm5, xmm6 ; byte swap counter

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test eax,eax
	jz end_encctr192

	cmp eax,4
	jl lp192encctrsingle

	test	rcx,0xf
	jz		lpencctr192four

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	mov rcx,rsp


	align 16

lpencctr192four:

	test eax,eax
	jz end_encctr192

	cmp eax,4
	jl lp192encctrsingle

	load_and_inc4 [rcx+0*16]
	add rdx,4*16
	aesenc4	[rcx+1*16]
	aesenc4	[rcx+2*16]
	aesenc4	[rcx+3*16]
	aesenc4	[rcx+4*16]
	aesenc4	[rcx+5*16]
	aesenc4	[rcx+6*16]
	aesenc4	[rcx+7*16]
	aesenc4	[rcx+8*16]
	aesenc4	[rcx+9*16]
	aesenc4	[rcx+10*16]
	aesenc4	[rcx+11*16]
	aesenclast4	[rcx+12*16]
	xor_with_input4 rdx-(4*16)

	store4 r8+rdx-16*4
	sub eax,4
	jmp lpencctr192four

	align 16
lp192encctrsingle:

	movdqa xmm0,xmm5
	pshufb	xmm0, xmm6 ; byte swap counter back
	movdqu xmm4,[rcx+0*16]
	paddd	xmm5,[counter_add_one wrt rip]
	add rdx, 16
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenc1_u [rcx+10*16]
	aesenc1_u [rcx+11*16]
	aesenclast1_u [rcx+12*16]
	movdqu xmm4, [rdx-16]
	pxor  xmm0,xmm4

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp192encctrsingle

end_encctr192:

	mov	   r9,[r9+24]
	pshufb xmm5, xmm6 ; byte swap counter
	movdqu [r9],xmm5
	movdqa xmm6, [rsp+16*16]
	add rsp,16*16+8+16
	ret


align 16
global iEnc256_CTR
iEnc256_CTR:

	linux_setup

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm5,[rax]


	sub rsp,16*16+8+16

	movdqa [rsp+16*16], xmm6
	movdqa xmm6, [byte_swap_16 wrt rip]
	pshufb xmm5, xmm6 ; byte swap counter

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test eax,eax
	jz end_encctr256

	cmp eax,4
	jl lp256encctrsingle

	test	rcx,0xf
	jz		lpencctr256four

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	copy_round_keys rsp,rcx,13
	copy_round_keys rsp,rcx,14
	mov rcx,rsp


	align 16

lpencctr256four:

	test eax,eax
	jz end_encctr256

	cmp eax,4
	jl lp256encctrsingle

	load_and_inc4 [rcx+0*16]
	add rdx,4*16
	aesenc4	[rcx+1*16]
	aesenc4	[rcx+2*16]
	aesenc4	[rcx+3*16]
	aesenc4	[rcx+4*16]
	aesenc4	[rcx+5*16]
	aesenc4	[rcx+6*16]
	aesenc4	[rcx+7*16]
	aesenc4	[rcx+8*16]
	aesenc4	[rcx+9*16]
	aesenc4	[rcx+10*16]
	aesenc4	[rcx+11*16]
	aesenc4	[rcx+12*16]
	aesenc4	[rcx+13*16]
	aesenclast4	[rcx+14*16]
	xor_with_input4 rdx-(4*16)

	store4 r8+rdx-16*4
	sub eax,4
	jmp lpencctr256four

	align 16
lp256encctrsingle:

	movdqa xmm0,xmm5
	pshufb	xmm0, xmm6 ; byte swap counter back
	movdqu xmm4,[rcx+0*16]
	paddd	xmm5,[counter_add_one wrt rip]
	add rdx, 16
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenc1_u [rcx+10*16]
	aesenc1_u [rcx+11*16]
	aesenc1_u [rcx+12*16]
	aesenc1_u [rcx+13*16]
	aesenclast1_u [rcx+14*16]
	movdqu xmm4, [rdx-16]
	pxor  xmm0,xmm4

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp256encctrsingle

end_encctr256:

	mov	   r9,[r9+24]
	pshufb xmm5, xmm6 ; byte swap counter
	movdqu [r9],xmm5
	movdqa xmm6, [rsp+16*16]
	add rsp,16*16+8+16
	ret







align 16
global iEnc128_CBC
iEnc128_CBC:

	linux_setup
	sub rsp,16*16+8

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm1,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test	rcx,0xf
	jz		lp128encsingle_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	mov rcx,rsp


	align 16

lp128encsingle_CBC:

	movdqu xmm0, [rdx]
	movdqu xmm4,[rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm1
	pxor xmm0, xmm4
	aesenc1 [rcx+1*16]
	aesenc1 [rcx+2*16]
	aesenc1 [rcx+3*16]
	aesenc1 [rcx+4*16]
	aesenc1 [rcx+5*16]
	aesenc1 [rcx+6*16]
	aesenc1 [rcx+7*16]
	aesenc1 [rcx+8*16]
	aesenc1 [rcx+9*16]
	aesenclast1 [rcx+10*16]
	movdqa xmm1,xmm0

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp128encsingle_CBC

	mov	   r9,[r9+24]
	movdqu [r9],xmm1
	add rsp,16*16+8
	ret


align 16
global iEnc192_CBC
iEnc192_CBC:

	linux_setup
	sub rsp,16*16+8
	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm1,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test	rcx,0xf
	jz		lp192encsingle_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	mov rcx,rsp



	align 16

lp192encsingle_CBC:

	movdqu xmm0, [rdx]
	movdqu xmm4, [rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm1
	pxor xmm0, xmm4
	aesenc1 [rcx+1*16]
	aesenc1 [rcx+2*16]
	aesenc1 [rcx+3*16]
	aesenc1 [rcx+4*16]
	aesenc1 [rcx+5*16]
	aesenc1 [rcx+6*16]
	aesenc1 [rcx+7*16]
	aesenc1 [rcx+8*16]
	aesenc1 [rcx+9*16]
	aesenc1 [rcx+10*16]
	aesenc1 [rcx+11*16]
	aesenclast1 [rcx+12*16]
	movdqa xmm1,xmm0

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp192encsingle_CBC

	mov	   r9,[r9+24]
	movdqu [r9],xmm1

	add rsp,16*16+8
	ret


align 16
global iEnc256_CBC
iEnc256_CBC:

	linux_setup
	sub rsp,16*16+8

	mov r9,rcx
	mov rax,[rcx+24]
	movdqu xmm1,[rax]

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test	rcx,0xf
	jz		lp256encsingle_CBC

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	copy_round_keys rsp,rcx,13
	copy_round_keys rsp,rcx,14
	mov rcx,rsp

	align 16

lp256encsingle_CBC:

	movdqu xmm0, [rdx]
	movdqu xmm4, [rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm1
	pxor xmm0, xmm4
	aesenc1 [rcx+1*16]
	aesenc1 [rcx+2*16]
	aesenc1 [rcx+3*16]
	aesenc1 [rcx+4*16]
	aesenc1 [rcx+5*16]
	aesenc1 [rcx+6*16]
	aesenc1 [rcx+7*16]
	aesenc1 [rcx+8*16]
	aesenc1 [rcx+9*16]
	aesenc1 [rcx+10*16]
	aesenc1 [rcx+11*16]
	aesenc1 [rcx+12*16]
	aesenc1 [rcx+13*16]
	aesenclast1 [rcx+14*16]
	movdqa xmm1,xmm0

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp256encsingle_CBC

	mov	   r9,[r9+24]
	movdqu [r9],xmm1
	add rsp,16*16+8
	ret




align 16
global iEnc192
iEnc192:

	linux_setup
	sub rsp,16*16+8

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx

	test eax,eax
	jz end_enc192

	cmp eax,4
	jl lp192encsingle

	test	rcx,0xf
	jz		lpenc192four

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	mov rcx,rsp


	align 16

lpenc192four:

	test eax,eax
	jz end_enc192

	cmp eax,4
	jl lp192encsingle

	load_and_xor4 rdx,[rcx+0*16]
	add rdx,4*16
	aesenc4	[rcx+1*16]
	aesenc4	[rcx+2*16]
	aesenc4	[rcx+3*16]
	aesenc4	[rcx+4*16]
	aesenc4	[rcx+5*16]
	aesenc4	[rcx+6*16]
	aesenc4	[rcx+7*16]
	aesenc4	[rcx+8*16]
	aesenc4	[rcx+9*16]
	aesenc4	[rcx+10*16]
	aesenc4	[rcx+11*16]
	aesenclast4	[rcx+12*16]

	store4 r8+rdx-16*4
	sub eax,4
	jmp lpenc192four

	align 16
lp192encsingle:

	movdqu xmm0, [rdx]
	movdqu xmm4, [rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenc1_u [rcx+10*16]
	aesenc1_u [rcx+11*16]
	aesenclast1_u [rcx+12*16]

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp192encsingle

end_enc192:

	add rsp,16*16+8
	ret






align 16
global iEnc256
iEnc256:

	linux_setup
	sub rsp,16*16+8

	mov eax,[rcx+32] ; numblocks
	mov rdx,[rcx]
	mov r8,[rcx+8]
	mov rcx,[rcx+16]

	sub r8,rdx


	test eax,eax
	jz end_enc256

	cmp eax,4
	jl lp256enc

	test	rcx,0xf
	jz		lp256enc4

	copy_round_keys rsp,rcx,0
	copy_round_keys rsp,rcx,1
	copy_round_keys rsp,rcx,2
	copy_round_keys rsp,rcx,3
	copy_round_keys rsp,rcx,4
	copy_round_keys rsp,rcx,5
	copy_round_keys rsp,rcx,6
	copy_round_keys rsp,rcx,7
	copy_round_keys rsp,rcx,8
	copy_round_keys rsp,rcx,9
	copy_round_keys rsp,rcx,10
	copy_round_keys rsp,rcx,11
	copy_round_keys rsp,rcx,12
	copy_round_keys rsp,rcx,13
	copy_round_keys rsp,rcx,14
	mov rcx,rsp


	align 16

lp256enc4:
	test eax,eax
	jz end_enc256

	cmp eax,4
	jl lp256enc


	load_and_xor4 rdx,[rcx+0*16]
	add rdx, 16*4
	aesenc4 [rcx+1*16]
	aesenc4 [rcx+2*16]
	aesenc4 [rcx+3*16]
	aesenc4 [rcx+4*16]
	aesenc4 [rcx+5*16]
	aesenc4 [rcx+6*16]
	aesenc4 [rcx+7*16]
	aesenc4 [rcx+8*16]
	aesenc4 [rcx+9*16]
	aesenc4 [rcx+10*16]
	aesenc4 [rcx+11*16]
	aesenc4 [rcx+12*16]
	aesenc4 [rcx+13*16]
	aesenclast4 [rcx+14*16]

	store4  r8+rdx-16*4
	sub eax,4
	jmp lp256enc4

	align 16
lp256enc:

	movdqu xmm0, [rdx]
	movdqu xmm4, [rcx+0*16]
	add rdx, 16
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenc1_u [rcx+10*16]
	aesenc1_u [rcx+11*16]
	aesenc1_u [rcx+12*16]
	aesenc1_u [rcx+13*16]
	aesenclast1_u [rcx+14*16]

		; Store output encrypted data into CIPHERTEXT array
	movdqu  [r8+rdx-16], xmm0
	dec eax
	jnz lp256enc

end_enc256:

	add rsp,16*16+8
	ret
