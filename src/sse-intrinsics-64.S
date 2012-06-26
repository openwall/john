	.file "sse-intrinsics.c"
	.text
..TXTST0:
# -- Begin  sse_debug
       .align    16,0x90
	.globl sse_debug
sse_debug:
..B1.1:
..___tag_value_sse_debug.1:
        movl      $1, debug(%rip)
        ret       
        .align    16,0x90
..___tag_value_sse_debug.3:
	.type	sse_debug,@function
	.size	sse_debug,.-sse_debug
	.data
# -- End  sse_debug
	.text
# -- Begin  mmxput
       .align    16,0x90
	.globl mmxput
mmxput:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %edx
# parameter 4: %ecx
# parameter 5: %r8
# parameter 6: %r9d
..B2.1:
..___tag_value_mmxput.4:
        movl      %esi, %eax
        shrl      $2, %eax
        lea       (%rdx,%rdx,2), %r10d
        shll      $8, %eax
        shll      $8, %r10d
        addq      %rax, %rdi
        addq      %r10, %rdi
        testl     %r9d, %r9d
        jbe       ..B2.8
..B2.2:
        movl      %r9d, %edx
        movl      $1, %eax
        shrl      $1, %edx
        xorl      %r10d, %r10d
        testl     %edx, %edx
        jbe       ..B2.6
..B2.3:
        movl      %esi, %eax
        movq      %r15, -24(%rsp)
..___tag_value_mmxput.6:
        andl      $3, %eax
        movq      %rbx, -16(%rsp)
..___tag_value_mmxput.7:
        movq      %rbp, -8(%rsp)
..___tag_value_mmxput.8:
..B2.4:
        lea       (%rcx,%r10,2), %r11d
        movl      %r11d, %r15d
        movl      %r11d, %ebx
        andl      $-4, %r15d
        lea       (%r10,%r10), %ebp
        shll      $2, %r15d
        andl      $3, %ebx
        incl      %r11d
        lea       (%r15,%rax,4), %r15d
        addl      %ebx, %r15d
        lea       1(%r10,%r10), %ebx
        incl      %r10d
        movb      (%rbp,%r8), %bpl
        movb      %bpl, (%r15,%rdi)
        movl      %r11d, %ebp
        andl      $-4, %ebp
        andl      $3, %r11d
        shll      $2, %ebp
        lea       (%rbp,%rax,4), %r15d
        addl      %r11d, %r15d
        cmpl      %edx, %r10d
        movb      (%rbx,%r8), %r11b
        movb      %r11b, (%r15,%rdi)
        jb        ..B2.4
..B2.5:
        movq      -24(%rsp), %r15
..___tag_value_mmxput.9:
        lea       1(%r10,%r10), %eax
        movq      -16(%rsp), %rbx
..___tag_value_mmxput.10:
        movq      -8(%rsp), %rbp
..___tag_value_mmxput.11:
..B2.6:
        cmpl      %r9d, %eax
        ja        ..B2.8
..B2.7:
        andl      $3, %esi
        lea       -1(%rcx,%rax), %ecx
        movl      %ecx, %edx
        decl      %eax
        andl      $-4, %edx
        andl      $3, %ecx
        addl      %edx, %esi
        lea       (%rcx,%rsi,4), %esi
        movb      (%rax,%r8), %r8b
        movb      %r8b, (%rsi,%rdi)
..B2.8:
        ret       
        .align    16,0x90
..___tag_value_mmxput.12:
	.type	mmxput,@function
	.size	mmxput,.-mmxput
	.data
# -- End  mmxput
	.text
# -- Begin  mmxput2
       .align    16,0x90
	.globl mmxput2
mmxput2:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
..B3.1:
..___tag_value_mmxput2.13:
        pushq     %r12
..___tag_value_mmxput2.15:
        pushq     %r13
..___tag_value_mmxput2.17:
        pushq     %r14
..___tag_value_mmxput2.19:
        pushq     %r15
..___tag_value_mmxput2.21:
        pushq     %rbx
..___tag_value_mmxput2.23:
        lea       (%rsi,%rsi,2), %eax
        shll      $8, %eax
        xorl      %esi, %esi
        addq      %rax, %rdi
        movl      %esi, %ebx
        movq      %rdx, %r13
        movl      %esi, %r14d
        movl      %esi, %r12d
        movq      %rdi, %r15
..B3.2:
        movl      %ebx, %edi
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r15, %rdi
        addq      %r13, %rsi
..___tag_value_mmxput2.25:
        call      memcpy
..___tag_value_mmxput2.26:
..B3.3:
        incl      %r12d
        addl      $64, %r14d
        addl      $256, %ebx
        cmpl      $3, %r12d
        jb        ..B3.2
..B3.4:
..___tag_value_mmxput2.27:
        popq      %rbx
..___tag_value_mmxput2.28:
        popq      %r15
..___tag_value_mmxput2.30:
        popq      %r14
..___tag_value_mmxput2.32:
        popq      %r13
..___tag_value_mmxput2.34:
        popq      %r12
..___tag_value_mmxput2.36:
        ret       
        .align    16,0x90
..___tag_value_mmxput2.37:
	.type	mmxput2,@function
	.size	mmxput2,.-mmxput2
	.data
# -- End  mmxput2
	.text
# -- Begin  dispatch
       .align    16,0x90
	.globl dispatch
dispatch:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B4.1:
..___tag_value_dispatch.38:
        pushq     %r12
..___tag_value_dispatch.40:
        pushq     %r13
..___tag_value_dispatch.42:
        pushq     %r14
..___tag_value_dispatch.44:
        pushq     %r15
..___tag_value_dispatch.46:
        pushq     %rbx
..___tag_value_dispatch.48:
        pushq     %rbp
..___tag_value_dispatch.50:
        subq      $40, %rsp
..___tag_value_dispatch.52:
        movq      %rdx, %r8
        movl      $23, %edx
        xorl      %eax, %eax
        movl      %ecx, 24(%rsp)
        movl      %eax, %r14d
        movl      %edx, %r13d
        movq      %rsi, %rbp
        movq      %rdi, %r12
        movq      %r8, %r15
..B4.2:
        cmpl      $40, %r14d
        ja        ..B4.54
..B4.3:
        jmp       *..1..TPKT.6_0.0.6(,%r14,8)
..1.6_0.TAG.015.0.6:
..B4.19:
        movl      $1, %esi
        movq      %r12, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %rbp, %r9
        movl      $1, %ebx
..___tag_value_dispatch.53:
        call      mmxput3
..___tag_value_dispatch.54:
        jmp       ..B4.55
..1.6_0.TAG.01c.0.6:
..1.6_0.TAG.0e.0.6:
..B4.25:
        xorl      %ecx, %ecx
        movl      $5, %ebx
        movl      %r14d, (%rsp)
        movl      %ecx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %ecx, %r13d
        movq      %r15, 16(%rsp)
        movl      %ecx, %r15d
..B4.26:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       3840(%r12,%r13), %rdi
..___tag_value_dispatch.55:
        call      memcpy
..___tag_value_dispatch.56:
..B4.27:
        incl      %r15d
        addl      $64, %r14d
        addl      $256, %r13d
        cmpl      $3, %r15d
        jb        ..B4.26
..B4.28:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.023.0.6:
..1.6_0.TAG.07.0.6:
..B4.34:
        movq      %r12, %rdi
        movl      $4, %esi
        movq      %r15, %rdx
        movl      $1, %ecx
        movq      %rbp, %r9
        movl      $4, %ebx
        movl      24(%rsp), %r8d
..___tag_value_dispatch.57:
        call      mmxput3
..___tag_value_dispatch.58:
        jmp       ..B4.55
..1.6_0.TAG.024.0.6:
..1.6_0.TAG.01e.0.6:
..1.6_0.TAG.018.0.6:
..1.6_0.TAG.012.0.6:
..1.6_0.TAG.0c.0.6:
..1.6_0.TAG.06.0.6:
..B4.36:
        xorl      %ecx, %ecx
        movl      $3, %ebx
        movl      %r14d, (%rsp)
        movl      %ecx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %ecx, %r13d
        movq      %r15, 16(%rsp)
        movl      %ecx, %r15d
..B4.37:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       2304(%r12,%r13), %rdi
..___tag_value_dispatch.59:
        call      memcpy
..___tag_value_dispatch.60:
..B4.38:
        incl      %r15d
        addl      $64, %r14d
        addl      $256, %r13d
        cmpl      $3, %r15d
        jb        ..B4.37
..B4.39:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.027.0.6:
..1.6_0.TAG.021.0.6:
..1.6_0.TAG.01b.0.6:
..1.6_0.TAG.0f.0.6:
..1.6_0.TAG.09.0.6:
..1.6_0.TAG.03.0.6:
..B4.42:
        movl      $2, %esi
        movq      %r12, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %rbp, %r9
        movl      $2, %ebx
..___tag_value_dispatch.61:
        call      mmxput3
..___tag_value_dispatch.62:
        jmp       ..B4.55
..1.6_0.TAG.028.0.6:
..1.6_0.TAG.026.0.6:
..1.6_0.TAG.022.0.6:
..1.6_0.TAG.020.0.6:
..1.6_0.TAG.01a.0.6:
..1.6_0.TAG.016.0.6:
..1.6_0.TAG.014.0.6:
..1.6_0.TAG.010.0.6:
..1.6_0.TAG.0a.0.6:
..1.6_0.TAG.08.0.6:
..1.6_0.TAG.04.0.6:
..1.6_0.TAG.02.0.6:
..B4.44:
        xorl      %ecx, %ecx
        movl      $6, %ebx
        movl      %r14d, (%rsp)
        movl      %ecx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %ecx, %r13d
        movq      %r15, 16(%rsp)
        movl      %ecx, %r15d
..B4.45:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %rbp, %rsi
        lea       4608(%r12,%r13), %rdi
..___tag_value_dispatch.63:
        call      memcpy
..___tag_value_dispatch.64:
..B4.46:
        incl      %r15d
        addl      $64, %r14d
        addl      $256, %r13d
        cmpl      $3, %r15d
        jb        ..B4.45
..B4.47:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.00.0.6:
..B4.50:
        xorl      %ecx, %ecx
        xorl      %ebx, %ebx
        movl      %r14d, (%rsp)
        movl      %ecx, %r14d
        movl      %r13d, 8(%rsp)
        movl      %ecx, %r13d
        movq      %r15, 16(%rsp)
        movl      %ecx, %r15d
..B4.51:
        movl      %r13d, %edi
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r12, %rdi
        addq      %rbp, %rsi
..___tag_value_dispatch.65:
        call      memcpy
..___tag_value_dispatch.66:
..B4.52:
        incl      %r15d
        addl      $64, %r14d
        addl      $256, %r13d
        cmpl      $3, %r15d
        jb        ..B4.51
..B4.53:
        movl      (%rsp), %r14d
        movl      8(%rsp), %r13d
        movq      16(%rsp), %r15
        jmp       ..B4.55
..1.6_0.TAG.DEFAULT.0.6:
..B4.54:
        movq      %r12, %rdi
        movl      $7, %esi
        movq      %r15, %rdx
        movl      $2, %ecx
        movq      %rbp, %r9
        movl      $7, %ebx
        movl      24(%rsp), %r8d
..___tag_value_dispatch.67:
        call      mmxput3
..___tag_value_dispatch.68:
..B4.55:
        movq      %rbp, %rsi
        lea       (%rbx,%rbx,2), %rdi
        shlq      $8, %rdi
        movl      $1, %edx
        addq      %r12, %rdi
..___tag_value_dispatch.69:
        call      SSEmd5body
..___tag_value_dispatch.70:
..B4.56:
        incl      %r14d
        lea       -1(%r14), %ecx
        cmpl      $33, %ecx
        jb        ..B4.2
..B4.57:
        cmpl      $34, %r14d
        jne       ..B4.60
..B4.58:
        testl     %r13d, %r13d
        je        ..B4.61
..B4.59:
        decl      %r13d
        jmp       ..B4.2
..B4.60:
        xorl      %ecx, %ecx
        cmpl      $42, %r14d
        cmovae    %ecx, %r14d
        jmp       ..B4.2
..B4.61:
        addq      $40, %rsp
..___tag_value_dispatch.71:
        popq      %rbp
..___tag_value_dispatch.73:
        popq      %rbx
..___tag_value_dispatch.75:
        popq      %r15
..___tag_value_dispatch.77:
        popq      %r14
..___tag_value_dispatch.79:
        popq      %r13
..___tag_value_dispatch.81:
        popq      %r12
..___tag_value_dispatch.83:
        ret       
        .align    16,0x90
..___tag_value_dispatch.84:
	.type	dispatch,@function
	.size	dispatch,.-dispatch
	.section .rodata, "a"
	.align 32
	.align 32
..1..TPKT.6_0.0.6:
	.quad	..1.6_0.TAG.00.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.02.0.6
	.quad	..1.6_0.TAG.03.0.6
	.quad	..1.6_0.TAG.04.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.06.0.6
	.quad	..1.6_0.TAG.07.0.6
	.quad	..1.6_0.TAG.08.0.6
	.quad	..1.6_0.TAG.09.0.6
	.quad	..1.6_0.TAG.0a.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.0c.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.0e.0.6
	.quad	..1.6_0.TAG.0f.0.6
	.quad	..1.6_0.TAG.010.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.012.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.014.0.6
	.quad	..1.6_0.TAG.015.0.6
	.quad	..1.6_0.TAG.016.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.018.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.01a.0.6
	.quad	..1.6_0.TAG.01b.0.6
	.quad	..1.6_0.TAG.01c.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.01e.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.020.0.6
	.quad	..1.6_0.TAG.021.0.6
	.quad	..1.6_0.TAG.022.0.6
	.quad	..1.6_0.TAG.023.0.6
	.quad	..1.6_0.TAG.024.0.6
	.quad	..1.6_0.TAG.DEFAULT.0.6
	.quad	..1.6_0.TAG.026.0.6
	.quad	..1.6_0.TAG.027.0.6
	.quad	..1.6_0.TAG.028.0.6
	.data
# -- End  dispatch
	.text
# -- Begin  mmxput3
       .align    16,0x90
	.globl mmxput3
mmxput3:
# parameter 1: %rdi
# parameter 2: %esi
# parameter 3: %rdx
# parameter 4: %ecx
# parameter 5: %r8d
# parameter 6: %r9
..B5.1:
..___tag_value_mmxput3.85:
        pushq     %r12
..___tag_value_mmxput3.87:
        pushq     %r13
..___tag_value_mmxput3.89:
        pushq     %r14
..___tag_value_mmxput3.91:
        pushq     %r15
..___tag_value_mmxput3.93:
        pushq     %rbx
..___tag_value_mmxput3.95:
        pushq     %rbp
..___tag_value_mmxput3.97:
        lea       (%rsi,%rsi,2), %r11d
        shll      $8, %r11d
        xorl      %r10d, %r10d
        movl      %ecx, %eax
        addq      %r11, %rdi
        xorl      %r11d, %r11d
        movq      %rdi, -8(%rsp)
        xorl      %esi, %esi
..B5.2:
        movl      %r11d, %ebx
        lea       (,%r10,4), %ebp
        addq      -8(%rsp), %rbx
        movl      (%rdx,%rbp,4), %r14d
        imull     %eax, %r14d
        addl      %r8d, %r14d
        movl      %r14d, %r12d
        andl      $3, %r12d
        shll      $3, %r12d
        testl     %r12d, %r12d
        je        ..B5.4
..B5.3:
        andl      $-4, %r14d
        movl      %r12d, %r13d
        shll      $2, %r14d
        negl      %r13d
        movl      %r13d, %ecx
        movl      $-1, %r15d
        shrl      %cl, %r15d
        movl      %r12d, %ecx
        andl      (%r14,%rbx), %r15d
        movl      %r15d, (%r14,%rbx)
        movl      (%r9,%rsi,4), %ebp
        shll      %cl, %ebp
        movl      %r12d, %ecx
        orl       %ebp, %r15d
        lea       4(%rsi), %ebp
        movl      %r15d, (%r14,%rbx)
        movl      (%r9,%rsi,4), %r15d
        movl      (%r9,%rbp,4), %edi
        shll      %cl, %edi
        movl      %r13d, %ecx
        shrl      %cl, %r15d
        movl      %r12d, %ecx
        orl       %r15d, %edi
        movl      %edi, 16(%r14,%rbx)
        lea       8(%rsi), %edi
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%rdi,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %ebp
        movl      %r12d, %ecx
        orl       %ebp, %r15d
        lea       12(%rsi), %ebp
        movl      %r15d, 32(%r14,%rbx)
        movl      (%r9,%rdi,4), %edi
        movl      (%r9,%rbp,4), %r15d
        shll      %cl, %r15d
        movl      %r13d, %ecx
        shrl      %cl, %edi
        movl      %r12d, %ecx
        orl       %edi, %r15d
        movl      $-1, %edi
        shll      %cl, %edi
        movl      %r13d, %ecx
        andl      64(%r14,%rbx), %edi
        movl      %r15d, 48(%r14,%rbx)
        movl      %edi, 64(%r14,%rbx)
        movl      (%r9,%rbp,4), %r12d
        shrl      %cl, %r12d
        orl       %r12d, %edi
        movl      %edi, 64(%r14,%rbx)
        jmp       ..B5.5
..B5.4:
        shll      $2, %r14d
        lea       4(%rsi), %edi
        lea       8(%rsi), %r13d
        movl      (%r9,%rsi,4), %ebp
        movl      %ebp, (%r14,%rbx)
        lea       12(%rsi), %ebp
        movl      (%r9,%rdi,4), %r12d
        movl      %r12d, 16(%r14,%rbx)
        movl      (%r9,%r13,4), %r15d
        movl      %r15d, 32(%r14,%rbx)
        movl      (%r9,%rbp,4), %ebp
        movl      %ebp, 48(%r14,%rbx)
..B5.5:
        lea       1(,%r10,4), %ebp
        movl      (%rdx,%rbp,4), %r13d
        imull     %eax, %r13d
        addl      %r8d, %r13d
        movl      %r13d, %r14d
        andl      $3, %r14d
        shll      $3, %r14d
        testl     %r14d, %r14d
        je        ..B5.7
..B5.6:
        andl      $-4, %r13d
        movl      %r14d, %r15d
        shll      $2, %r13d
        negl      %r15d
        lea       1(%rsi), %ebp
        movl      %r15d, %ecx
        movl      $-1, %edi
        shrl      %cl, %edi
        movl      %r14d, %ecx
        andl      4(%r13,%rbx), %edi
        movl      %edi, 4(%r13,%rbx)
        movl      (%r9,%rbp,4), %r12d
        shll      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 4(%r13,%rbx)
        lea       5(%rsi), %edi
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%rdi,4), %r12d
        shll      %cl, %r12d
        movl      %r15d, %ecx
        shrl      %cl, %ebp
        movl      %r14d, %ecx
        orl       %ebp, %r12d
        movl      %r12d, 20(%r13,%rbx)
        lea       9(%rsi), %r12d
        movl      (%r9,%rdi,4), %edi
        movl      (%r9,%r12,4), %ebp
        shll      %cl, %ebp
        movl      %r15d, %ecx
        shrl      %cl, %edi
        movl      %r14d, %ecx
        orl       %edi, %ebp
        movl      %ebp, 36(%r13,%rbx)
        lea       13(%rsi), %ebp
        movl      (%r9,%r12,4), %r12d
        movl      (%r9,%rbp,4), %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        shrl      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 52(%r13,%rbx)
        movl      $-1, %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        andl      68(%r13,%rbx), %edi
        movl      %edi, 68(%r13,%rbx)
        movl      (%r9,%rbp,4), %r14d
        shrl      %cl, %r14d
        orl       %r14d, %edi
        movl      %edi, 68(%r13,%rbx)
        jmp       ..B5.8
..B5.7:
        shll      $2, %r13d
        lea       1(%rsi), %ebp
        lea       5(%rsi), %r12d
        lea       9(%rsi), %r15d
        movl      (%r9,%rbp,4), %edi
        movl      %edi, 4(%r13,%rbx)
        movl      (%r9,%r12,4), %r14d
        movl      %r14d, 20(%r13,%rbx)
        movl      (%r9,%r15,4), %ebp
        movl      %ebp, 36(%r13,%rbx)
        lea       13(%rsi), %ebp
        movl      (%r9,%rbp,4), %ebp
        movl      %ebp, 52(%r13,%rbx)
..B5.8:
        lea       2(,%r10,4), %ebp
        movl      (%rdx,%rbp,4), %r13d
        imull     %eax, %r13d
        addl      %r8d, %r13d
        movl      %r13d, %r14d
        andl      $3, %r14d
        shll      $3, %r14d
        testl     %r14d, %r14d
        je        ..B5.10
..B5.9:
        andl      $-4, %r13d
        movl      %r14d, %r15d
        shll      $2, %r13d
        negl      %r15d
        lea       2(%rsi), %ebp
        movl      %r15d, %ecx
        movl      $-1, %edi
        shrl      %cl, %edi
        movl      %r14d, %ecx
        andl      8(%r13,%rbx), %edi
        movl      %edi, 8(%r13,%rbx)
        movl      (%r9,%rbp,4), %r12d
        shll      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 8(%r13,%rbx)
        lea       6(%rsi), %edi
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%rdi,4), %r12d
        shll      %cl, %r12d
        movl      %r15d, %ecx
        shrl      %cl, %ebp
        movl      %r14d, %ecx
        orl       %ebp, %r12d
        movl      %r12d, 24(%r13,%rbx)
        lea       10(%rsi), %r12d
        movl      (%r9,%rdi,4), %edi
        movl      (%r9,%r12,4), %ebp
        shll      %cl, %ebp
        movl      %r15d, %ecx
        shrl      %cl, %edi
        movl      %r14d, %ecx
        orl       %edi, %ebp
        movl      %ebp, 40(%r13,%rbx)
        lea       14(%rsi), %ebp
        movl      (%r9,%r12,4), %r12d
        movl      (%r9,%rbp,4), %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        shrl      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 56(%r13,%rbx)
        movl      $-1, %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        andl      72(%r13,%rbx), %edi
        movl      %edi, 72(%r13,%rbx)
        movl      (%r9,%rbp,4), %r14d
        shrl      %cl, %r14d
        orl       %r14d, %edi
        movl      %edi, 72(%r13,%rbx)
        jmp       ..B5.11
..B5.10:
        shll      $2, %r13d
        lea       2(%rsi), %ebp
        lea       6(%rsi), %r12d
        lea       10(%rsi), %r15d
        movl      (%r9,%rbp,4), %edi
        movl      %edi, 8(%r13,%rbx)
        movl      (%r9,%r12,4), %r14d
        movl      %r14d, 24(%r13,%rbx)
        movl      (%r9,%r15,4), %ebp
        movl      %ebp, 40(%r13,%rbx)
        lea       14(%rsi), %ebp
        movl      (%r9,%rbp,4), %ebp
        movl      %ebp, 56(%r13,%rbx)
..B5.11:
        lea       3(,%r10,4), %ebp
        movl      (%rdx,%rbp,4), %r13d
        imull     %eax, %r13d
        addl      %r8d, %r13d
        movl      %r13d, %r14d
        andl      $3, %r14d
        shll      $3, %r14d
        testl     %r14d, %r14d
        je        ..B5.13
..B5.12:
        andl      $-4, %r13d
        movl      %r14d, %r15d
        shll      $2, %r13d
        negl      %r15d
        lea       3(%rsi), %ebp
        movl      %r15d, %ecx
        movl      $-1, %edi
        shrl      %cl, %edi
        movl      %r14d, %ecx
        andl      12(%r13,%rbx), %edi
        movl      %edi, 12(%r13,%rbx)
        movl      (%r9,%rbp,4), %r12d
        shll      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 12(%r13,%rbx)
        lea       7(%rsi), %edi
        movl      (%r9,%rbp,4), %ebp
        movl      (%r9,%rdi,4), %r12d
        shll      %cl, %r12d
        movl      %r15d, %ecx
        shrl      %cl, %ebp
        movl      %r14d, %ecx
        orl       %ebp, %r12d
        movl      %r12d, 28(%r13,%rbx)
        lea       11(%rsi), %r12d
        movl      (%r9,%rdi,4), %edi
        movl      (%r9,%r12,4), %ebp
        shll      %cl, %ebp
        movl      %r15d, %ecx
        shrl      %cl, %edi
        movl      %r14d, %ecx
        orl       %edi, %ebp
        movl      %ebp, 44(%r13,%rbx)
        lea       15(%rsi), %ebp
        movl      (%r9,%r12,4), %r12d
        movl      (%r9,%rbp,4), %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        shrl      %cl, %r12d
        movl      %r14d, %ecx
        orl       %r12d, %edi
        movl      %edi, 60(%r13,%rbx)
        movl      $-1, %edi
        shll      %cl, %edi
        movl      %r15d, %ecx
        andl      76(%r13,%rbx), %edi
        movl      %edi, 76(%r13,%rbx)
        movl      (%r9,%rbp,4), %r14d
        shrl      %cl, %r14d
        orl       %r14d, %edi
        movl      %edi, 76(%r13,%rbx)
        jmp       ..B5.14
..B5.13:
        shll      $2, %r13d
        lea       3(%rsi), %ebp
        lea       7(%rsi), %r12d
        lea       11(%rsi), %r15d
        movl      (%r9,%rbp,4), %edi
        movl      %edi, 12(%r13,%rbx)
        movl      (%r9,%r12,4), %r14d
        movl      %r14d, 28(%r13,%rbx)
        movl      (%r9,%r15,4), %ebp
        movl      %ebp, 44(%r13,%rbx)
        lea       15(%rsi), %ebp
        movl      (%r9,%rbp,4), %ebp
        movl      %ebp, 60(%r13,%rbx)
..B5.14:
        incl      %r10d
        addl      $256, %r11d
        addl      $16, %esi
        cmpl      $3, %r10d
        jb        ..B5.2
..B5.15:
..___tag_value_mmxput3.99:
        popq      %rbp
..___tag_value_mmxput3.100:
        popq      %rbx
..___tag_value_mmxput3.102:
        popq      %r15
..___tag_value_mmxput3.104:
        popq      %r14
..___tag_value_mmxput3.106:
        popq      %r13
..___tag_value_mmxput3.108:
        popq      %r12
..___tag_value_mmxput3.110:
        ret       
        .align    16,0x90
..___tag_value_mmxput3.111:
	.type	mmxput3,@function
	.size	mmxput3,.-mmxput3
	.data
# -- End  mmxput3
	.text
# -- Begin  SSEmd5body
       .align    16,0x90
	.globl SSEmd5body
SSEmd5body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B6.1:
..___tag_value_SSEmd5body.112:
        subq      $840, %rsp
..___tag_value_SSEmd5body.114:
        movdqa    (%rsi), %xmm0
        testl     %edx, %edx
        movdqa    16(%rsi), %xmm1
        movdqa    32(%rsi), %xmm2
        movdqa    48(%rsi), %xmm3
        movdqa    %xmm0, (%rsp)
        movdqa    %xmm1, 16(%rsp)
        movdqa    %xmm2, 32(%rsp)
        movdqa    %xmm3, 48(%rsp)
        je        ..B6.3
..B6.2:
        movdqa    .L_2il0floatpacket.61(%rip), %xmm4
        movdqa    .L_2il0floatpacket.62(%rip), %xmm3
        movdqa    %xmm4, %xmm8
        movdqa    .L_2il0floatpacket.63(%rip), %xmm10
        movdqa    %xmm3, %xmm9
        movdqa    .L_2il0floatpacket.64(%rip), %xmm11
        movdqa    %xmm10, %xmm12
        movdqa    %xmm11, %xmm14
        movdqa    %xmm4, %xmm1
        movdqa    %xmm3, %xmm2
        movdqa    %xmm10, %xmm0
        movdqa    %xmm11, %xmm6
        jmp       ..B6.4
..B6.3:
        movdqa    (%rsp), %xmm4
        movdqa    16(%rsp), %xmm3
        movdqa    32(%rsp), %xmm10
        movdqa    48(%rsp), %xmm11
        movdqa    64(%rsi), %xmm8
        movdqa    80(%rsi), %xmm9
        movdqa    96(%rsi), %xmm12
        movdqa    112(%rsi), %xmm14
        movdqa    128(%rsi), %xmm1
        movdqa    144(%rsi), %xmm2
        movdqa    160(%rsi), %xmm0
        movdqa    176(%rsi), %xmm6
..B6.4:
        movdqa    %xmm10, %xmm5
        movdqa    %xmm12, %xmm15
        movdqa    .L_2il0floatpacket.65(%rip), %xmm7
        pxor      %xmm11, %xmm5
        paddd     %xmm7, %xmm4
        pand      %xmm3, %xmm5
        paddd     %xmm7, %xmm8
        paddd     %xmm7, %xmm1
        movdqa    %xmm0, %xmm7
        pxor      %xmm11, %xmm5
        pxor      %xmm6, %xmm7
        paddd     %xmm5, %xmm4
        movdqa    (%rdi), %xmm13
        pand      %xmm2, %xmm7
        paddd     %xmm13, %xmm4
        pxor      %xmm14, %xmm15
        pxor      %xmm6, %xmm7
        pand      %xmm9, %xmm15
        movdqa    512(%rdi), %xmm5
        paddd     %xmm7, %xmm1
        movdqa    %xmm4, %xmm7
        pxor      %xmm14, %xmm15
        paddd     %xmm5, %xmm1
        pslld     $7, %xmm7
        psrld     $25, %xmm4
        paddd     %xmm15, %xmm8
        por       %xmm4, %xmm7
        movdqa    %xmm1, %xmm4
        paddd     256(%rdi), %xmm8
        pslld     $7, %xmm4
        psrld     $25, %xmm1
        paddd     %xmm3, %xmm7
        movdqa    %xmm5, 448(%rsp)
        movdqa    %xmm8, %xmm5
        por       %xmm1, %xmm4
        movdqa    %xmm3, %xmm1
        pslld     $7, %xmm5
        psrld     $25, %xmm8
        pxor      %xmm10, %xmm1
        por       %xmm8, %xmm5
        movdqa    .L_2il0floatpacket.66(%rip), %xmm8
        pand      %xmm7, %xmm1
        paddd     %xmm8, %xmm11
        pxor      %xmm10, %xmm1
        paddd     %xmm1, %xmm11
        paddd     %xmm8, %xmm14
        movdqa    %xmm9, %xmm1
        paddd     %xmm8, %xmm6
        movdqa    %xmm2, %xmm8
        paddd     %xmm9, %xmm5
        paddd     %xmm2, %xmm4
        pxor      %xmm12, %xmm1
        pxor      %xmm0, %xmm8
        pand      %xmm5, %xmm1
        movdqa    16(%rdi), %xmm15
        pand      %xmm4, %xmm8
        paddd     %xmm15, %xmm11
        pxor      %xmm12, %xmm1
        pxor      %xmm0, %xmm8
        paddd     %xmm1, %xmm14
        movdqa    528(%rdi), %xmm1
        paddd     %xmm8, %xmm6
        movdqa    %xmm11, %xmm8
        paddd     %xmm1, %xmm6
        pslld     $12, %xmm8
        psrld     $20, %xmm11
        movdqa    %xmm15, 208(%rsp)
        por       %xmm11, %xmm8
        movdqa    272(%rdi), %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm15, %xmm14
        pslld     $12, %xmm11
        psrld     $20, %xmm6
        paddd     %xmm7, %xmm8
        movdqa    %xmm1, 160(%rsp)
        movdqa    %xmm14, %xmm1
        por       %xmm6, %xmm11
        movdqa    %xmm3, %xmm6
        pslld     $12, %xmm1
        psrld     $20, %xmm14
        pxor      %xmm7, %xmm6
        por       %xmm14, %xmm1
        movdqa    .L_2il0floatpacket.67(%rip), %xmm14
        pand      %xmm8, %xmm6
        paddd     %xmm14, %xmm10
        pxor      %xmm3, %xmm6
        paddd     %xmm6, %xmm10
        movdqa    %xmm9, %xmm6
        paddd     %xmm5, %xmm1
        paddd     %xmm14, %xmm12
        pxor      %xmm5, %xmm6
        paddd     %xmm14, %xmm0
        movdqa    %xmm2, %xmm14
        paddd     %xmm4, %xmm11
        pand      %xmm1, %xmm6
        pxor      %xmm4, %xmm14
        movdqa    %xmm15, 176(%rsp)
        pxor      %xmm9, %xmm6
        movdqa    32(%rdi), %xmm15
        pand      %xmm11, %xmm14
        movdqa    %xmm15, 64(%rsp)
        paddd     %xmm15, %xmm10
        movdqa    288(%rdi), %xmm15
        paddd     %xmm6, %xmm12
        pxor      %xmm2, %xmm14
        paddd     %xmm15, %xmm12
        movdqa    544(%rdi), %xmm6
        paddd     %xmm14, %xmm0
        movdqa    %xmm15, 96(%rsp)
        paddd     %xmm6, %xmm0
        movdqa    %xmm6, 80(%rsp)
        movdqa    %xmm10, %xmm15
        movdqa    %xmm12, %xmm6
        pslld     $17, %xmm15
        psrld     $15, %xmm10
        pslld     $17, %xmm6
        psrld     $15, %xmm12
        por       %xmm10, %xmm15
        por       %xmm12, %xmm6
        movdqa    %xmm0, %xmm14
        movdqa    %xmm8, %xmm12
        paddd     %xmm8, %xmm15
        pslld     $17, %xmm14
        psrld     $15, %xmm0
        pxor      %xmm7, %xmm12
        por       %xmm0, %xmm14
        movdqa    .L_2il0floatpacket.68(%rip), %xmm0
        pand      %xmm15, %xmm12
        paddd     %xmm0, %xmm3
        pxor      %xmm7, %xmm12
        paddd     %xmm12, %xmm3
        paddd     %xmm0, %xmm9
        movdqa    %xmm1, %xmm12
        paddd     %xmm0, %xmm2
        movdqa    %xmm11, %xmm0
        paddd     %xmm1, %xmm6
        paddd     %xmm11, %xmm14
        pxor      %xmm5, %xmm12
        pxor      %xmm4, %xmm0
        pand      %xmm6, %xmm12
        pand      %xmm14, %xmm0
        pxor      %xmm5, %xmm12
        pxor      %xmm4, %xmm0
        paddd     %xmm12, %xmm9
        movdqa    48(%rdi), %xmm10
        paddd     %xmm0, %xmm2
        movdqa    560(%rdi), %xmm12
        paddd     %xmm10, %xmm3
        movdqa    %xmm10, 336(%rsp)
        paddd     %xmm12, %xmm2
        movdqa    304(%rdi), %xmm10
        movdqa    %xmm3, %xmm0
        movdqa    %xmm10, 320(%rsp)
        paddd     %xmm10, %xmm9
        movdqa    %xmm2, %xmm10
        pslld     $22, %xmm0
        psrld     $10, %xmm3
        pslld     $22, %xmm10
        psrld     $10, %xmm2
        por       %xmm3, %xmm0
        movdqa    %xmm12, 352(%rsp)
        movdqa    %xmm9, %xmm12
        por       %xmm2, %xmm10
        movdqa    %xmm15, %xmm2
        paddd     %xmm15, %xmm0
        pslld     $22, %xmm12
        psrld     $10, %xmm9
        pxor      %xmm8, %xmm2
        por       %xmm9, %xmm12
        pand      %xmm0, %xmm2
        movdqa    .L_2il0floatpacket.69(%rip), %xmm9
        pxor      %xmm8, %xmm2
        paddd     %xmm9, %xmm7
        paddd     %xmm9, %xmm5
        paddd     %xmm2, %xmm7
        movdqa    %xmm6, %xmm2
        paddd     %xmm9, %xmm4
        movdqa    %xmm14, %xmm9
        paddd     %xmm6, %xmm12
        paddd     %xmm14, %xmm10
        pxor      %xmm1, %xmm2
        pxor      %xmm11, %xmm9
        movdqa    64(%rdi), %xmm3
        pand      %xmm12, %xmm2
        pand      %xmm10, %xmm9
        paddd     %xmm3, %xmm7
        pxor      %xmm1, %xmm2
        pxor      %xmm11, %xmm9
        movdqa    %xmm3, 112(%rsp)
        paddd     %xmm2, %xmm5
        movdqa    320(%rdi), %xmm3
        paddd     %xmm9, %xmm4
        movdqa    %xmm7, %xmm9
        paddd     %xmm3, %xmm5
        pslld     $7, %xmm9
        psrld     $25, %xmm7
        movdqa    576(%rdi), %xmm2
        por       %xmm7, %xmm9
        movdqa    %xmm5, %xmm7
        paddd     %xmm2, %xmm4
        pslld     $7, %xmm7
        psrld     $25, %xmm5
        movdqa    %xmm2, 128(%rsp)
        por       %xmm5, %xmm7
        movdqa    %xmm4, %xmm2
        movdqa    %xmm0, %xmm5
        paddd     %xmm0, %xmm9
        pslld     $7, %xmm2
        psrld     $25, %xmm4
        pxor      %xmm15, %xmm5
        por       %xmm4, %xmm2
        pand      %xmm9, %xmm5
        movdqa    .L_2il0floatpacket.70(%rip), %xmm4
        pxor      %xmm15, %xmm5
        paddd     %xmm4, %xmm8
        paddd     %xmm4, %xmm1
        paddd     %xmm5, %xmm8
        movdqa    %xmm12, %xmm5
        paddd     %xmm4, %xmm11
        movdqa    %xmm10, %xmm4
        paddd     %xmm12, %xmm7
        paddd     %xmm10, %xmm2
        pxor      %xmm6, %xmm5
        pxor      %xmm14, %xmm4
        movdqa    %xmm3, 144(%rsp)
        pand      %xmm7, %xmm5
        movdqa    80(%rdi), %xmm3
        pand      %xmm2, %xmm4
        paddd     %xmm3, %xmm8
        pxor      %xmm6, %xmm5
        pxor      %xmm14, %xmm4
        paddd     %xmm5, %xmm1
        movdqa    %xmm3, 464(%rsp)
        paddd     %xmm4, %xmm11
        movdqa    336(%rdi), %xmm3
        movdqa    %xmm8, %xmm4
        paddd     %xmm3, %xmm1
        pslld     $12, %xmm4
        psrld     $20, %xmm8
        movdqa    592(%rdi), %xmm5
        por       %xmm8, %xmm4
        movdqa    %xmm1, %xmm8
        paddd     %xmm5, %xmm11
        pslld     $12, %xmm8
        psrld     $20, %xmm1
        movdqa    %xmm3, 480(%rsp)
        por       %xmm1, %xmm8
        movdqa    %xmm11, %xmm3
        movdqa    %xmm9, %xmm1
        paddd     %xmm9, %xmm4
        pslld     $12, %xmm3
        psrld     $20, %xmm11
        pxor      %xmm0, %xmm1
        por       %xmm11, %xmm3
        pand      %xmm4, %xmm1
        movdqa    .L_2il0floatpacket.71(%rip), %xmm11
        pxor      %xmm0, %xmm1
        paddd     %xmm11, %xmm15
        paddd     %xmm7, %xmm8
        paddd     %xmm1, %xmm15
        movdqa    %xmm7, %xmm1
        paddd     %xmm11, %xmm6
        pxor      %xmm12, %xmm1
        paddd     %xmm11, %xmm14
        movdqa    %xmm2, %xmm11
        paddd     %xmm2, %xmm3
        pand      %xmm8, %xmm1
        pxor      %xmm10, %xmm11
        pxor      %xmm12, %xmm1
        movdqa    %xmm5, 512(%rsp)
        pand      %xmm3, %xmm11
        movdqa    96(%rdi), %xmm5
        paddd     %xmm1, %xmm6
        movdqa    %xmm5, 256(%rsp)
        paddd     %xmm5, %xmm15
        movdqa    352(%rdi), %xmm5
        pxor      %xmm10, %xmm11
        movdqa    608(%rdi), %xmm1
        paddd     %xmm5, %xmm6
        paddd     %xmm11, %xmm14
        movdqa    %xmm5, 240(%rsp)
        paddd     %xmm1, %xmm14
        movdqa    %xmm1, 224(%rsp)
        movdqa    %xmm15, %xmm5
        movdqa    %xmm6, %xmm1
        pslld     $17, %xmm5
        psrld     $15, %xmm15
        pslld     $17, %xmm1
        psrld     $15, %xmm6
        por       %xmm15, %xmm5
        por       %xmm6, %xmm1
        movdqa    %xmm14, %xmm6
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm5
        pslld     $17, %xmm6
        psrld     $15, %xmm14
        pxor      %xmm9, %xmm15
        por       %xmm14, %xmm6
        movdqa    .L_2il0floatpacket.72(%rip), %xmm14
        pand      %xmm5, %xmm15
        paddd     %xmm14, %xmm0
        pxor      %xmm9, %xmm15
        paddd     %xmm15, %xmm0
        paddd     %xmm14, %xmm12
        movdqa    %xmm8, %xmm15
        paddd     %xmm14, %xmm10
        movdqa    %xmm3, %xmm14
        paddd     %xmm8, %xmm1
        paddd     %xmm3, %xmm6
        pxor      %xmm7, %xmm15
        pxor      %xmm2, %xmm14
        pand      %xmm1, %xmm15
        movdqa    112(%rdi), %xmm11
        pand      %xmm6, %xmm14
        paddd     %xmm11, %xmm0
        pxor      %xmm7, %xmm15
        pxor      %xmm2, %xmm14
        paddd     %xmm15, %xmm12
        movdqa    %xmm11, 608(%rsp)
        paddd     %xmm14, %xmm10
        movdqa    368(%rdi), %xmm11
        movdqa    %xmm0, %xmm14
        paddd     %xmm11, %xmm12
        pslld     $22, %xmm14
        psrld     $10, %xmm0
        movdqa    624(%rdi), %xmm15
        por       %xmm0, %xmm14
        movdqa    %xmm12, %xmm0
        paddd     %xmm15, %xmm10
        pslld     $22, %xmm0
        psrld     $10, %xmm12
        movdqa    %xmm11, 656(%rsp)
        por       %xmm12, %xmm0
        movdqa    %xmm10, %xmm12
        movdqa    %xmm5, %xmm11
        paddd     %xmm5, %xmm14
        pslld     $22, %xmm12
        psrld     $10, %xmm10
        pxor      %xmm4, %xmm11
        por       %xmm10, %xmm12
        pand      %xmm14, %xmm11
        movdqa    .L_2il0floatpacket.73(%rip), %xmm10
        pxor      %xmm4, %xmm11
        paddd     %xmm10, %xmm9
        paddd     %xmm10, %xmm7
        paddd     %xmm11, %xmm9
        movdqa    %xmm1, %xmm11
        paddd     %xmm10, %xmm2
        movdqa    %xmm6, %xmm10
        paddd     %xmm1, %xmm0
        paddd     %xmm6, %xmm12
        pxor      %xmm8, %xmm11
        pxor      %xmm3, %xmm10
        movdqa    %xmm15, 624(%rsp)
        pand      %xmm0, %xmm11
        movdqa    128(%rdi), %xmm15
        pand      %xmm12, %xmm10
        paddd     %xmm15, %xmm9
        pxor      %xmm8, %xmm11
        pxor      %xmm3, %xmm10
        paddd     %xmm11, %xmm7
        movdqa    %xmm15, 432(%rsp)
        paddd     %xmm10, %xmm2
        movdqa    384(%rdi), %xmm15
        movdqa    %xmm9, %xmm10
        paddd     %xmm15, %xmm7
        pslld     $7, %xmm10
        psrld     $25, %xmm9
        movdqa    640(%rdi), %xmm11
        por       %xmm9, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     %xmm11, %xmm2
        pslld     $7, %xmm9
        psrld     $25, %xmm7
        movdqa    %xmm15, 416(%rsp)
        por       %xmm7, %xmm9
        movdqa    %xmm2, %xmm7
        movdqa    %xmm14, %xmm15
        paddd     %xmm14, %xmm10
        pslld     $7, %xmm7
        psrld     $25, %xmm2
        pxor      %xmm5, %xmm15
        por       %xmm2, %xmm7
        pand      %xmm10, %xmm15
        movdqa    .L_2il0floatpacket.74(%rip), %xmm2
        pxor      %xmm5, %xmm15
        paddd     %xmm2, %xmm4
        paddd     %xmm2, %xmm8
        paddd     %xmm15, %xmm4
        movdqa    %xmm0, %xmm15
        paddd     %xmm2, %xmm3
        movdqa    %xmm12, %xmm2
        paddd     %xmm0, %xmm9
        paddd     %xmm12, %xmm7
        pxor      %xmm1, %xmm15
        pxor      %xmm6, %xmm2
        movdqa    %xmm11, 400(%rsp)
        pand      %xmm9, %xmm15
        movdqa    144(%rdi), %xmm11
        pand      %xmm7, %xmm2
        paddd     %xmm11, %xmm4
        pxor      %xmm1, %xmm15
        pxor      %xmm6, %xmm2
        paddd     %xmm15, %xmm8
        movdqa    %xmm11, 192(%rsp)
        paddd     %xmm2, %xmm3
        movdqa    400(%rdi), %xmm11
        movdqa    %xmm4, %xmm2
        paddd     %xmm11, %xmm8
        pslld     $12, %xmm2
        psrld     $20, %xmm4
        movdqa    656(%rdi), %xmm15
        por       %xmm4, %xmm2
        movdqa    %xmm8, %xmm4
        paddd     %xmm15, %xmm3
        pslld     $12, %xmm4
        psrld     $20, %xmm8
        movdqa    %xmm11, 272(%rsp)
        por       %xmm8, %xmm4
        movdqa    %xmm3, %xmm8
        movdqa    %xmm10, %xmm11
        paddd     %xmm10, %xmm2
        pslld     $12, %xmm8
        psrld     $20, %xmm3
        pxor      %xmm14, %xmm11
        por       %xmm3, %xmm8
        pand      %xmm2, %xmm11
        movdqa    .L_2il0floatpacket.75(%rip), %xmm3
        pxor      %xmm14, %xmm11
        paddd     %xmm3, %xmm5
        paddd     %xmm3, %xmm1
        paddd     %xmm11, %xmm5
        movdqa    %xmm9, %xmm11
        paddd     %xmm3, %xmm6
        movdqa    %xmm7, %xmm3
        paddd     %xmm9, %xmm4
        paddd     %xmm7, %xmm8
        pxor      %xmm0, %xmm11
        pxor      %xmm12, %xmm3
        movdqa    %xmm15, 288(%rsp)
        pand      %xmm4, %xmm11
        movdqa    160(%rdi), %xmm15
        pand      %xmm8, %xmm3
        paddd     %xmm15, %xmm5
        pxor      %xmm0, %xmm11
        pxor      %xmm12, %xmm3
        paddd     %xmm11, %xmm1
        movdqa    %xmm15, 576(%rsp)
        paddd     %xmm3, %xmm6
        movdqa    416(%rdi), %xmm15
        movdqa    %xmm5, %xmm3
        paddd     %xmm15, %xmm1
        pslld     $17, %xmm3
        psrld     $15, %xmm5
        movdqa    672(%rdi), %xmm11
        por       %xmm5, %xmm3
        movdqa    %xmm1, %xmm5
        paddd     %xmm11, %xmm6
        pslld     $17, %xmm5
        psrld     $15, %xmm1
        por       %xmm1, %xmm5
        movdqa    %xmm6, %xmm1
        pslld     $17, %xmm1
        psrld     $15, %xmm6
        por       %xmm6, %xmm1
        movdqa    %xmm2, %xmm6
        paddd     %xmm2, %xmm3
        pxor      %xmm10, %xmm6
        movdqa    %xmm15, 592(%rsp)
        pand      %xmm3, %xmm6
        movdqa    .L_2il0floatpacket.76(%rip), %xmm15
        pxor      %xmm10, %xmm6
        paddd     %xmm15, %xmm14
        paddd     %xmm4, %xmm5
        paddd     %xmm6, %xmm14
        paddd     %xmm8, %xmm1
        movdqa    432(%rdi), %xmm6
        paddd     %xmm15, %xmm0
        movdqa    %xmm6, 368(%rsp)
        movdqa    %xmm4, %xmm6
        pxor      %xmm9, %xmm6
        movdqa    %xmm11, 560(%rsp)
        pand      %xmm5, %xmm6
        movdqa    176(%rdi), %xmm11
        pxor      %xmm9, %xmm6
        movdqa    %xmm11, 304(%rsp)
        paddd     %xmm11, %xmm14
        movdqa    256(%rdi), %xmm11
..B6.13:
        movdqa    %xmm11, 816(%rsp)
        movdqa    %xmm8, %xmm11
        pxor      %xmm7, %xmm11
        paddd     %xmm6, %xmm0
        pand      %xmm1, %xmm11
        movdqa    368(%rsp), %xmm6
        pxor      %xmm7, %xmm11
        paddd     .L_2il0floatpacket.76(%rip), %xmm12
        paddd     %xmm6, %xmm0
        movdqa    688(%rdi), %xmm15
        paddd     %xmm11, %xmm12
        movdqa    %xmm15, 384(%rsp)
        paddd     %xmm15, %xmm12
        movdqa    %xmm0, %xmm15
        psrld     $10, %xmm0
        pslld     $22, %xmm15
        movdqa    %xmm14, %xmm11
        por       %xmm0, %xmm15
        movdqa    %xmm12, %xmm0
        pslld     $22, %xmm11
        psrld     $10, %xmm14
        pslld     $22, %xmm0
        psrld     $10, %xmm12
        por       %xmm14, %xmm11
        por       %xmm12, %xmm0
        movdqa    %xmm3, %xmm12
        paddd     %xmm3, %xmm11
        pxor      %xmm2, %xmm12
        paddd     %xmm5, %xmm15
        movdqa    .L_2il0floatpacket.77(%rip), %xmm14
        pand      %xmm11, %xmm12
        paddd     %xmm14, %xmm10
        pxor      %xmm2, %xmm12
        paddd     %xmm12, %xmm10
        paddd     %xmm14, %xmm9
        movdqa    %xmm5, %xmm12
        paddd     %xmm14, %xmm7
        movdqa    %xmm1, %xmm14
        paddd     %xmm1, %xmm0
        pxor      %xmm4, %xmm12
        pxor      %xmm8, %xmm14
        movdqa    %xmm13, 800(%rsp)
        pand      %xmm15, %xmm12
        movdqa    192(%rdi), %xmm13
        pand      %xmm0, %xmm14
        paddd     %xmm13, %xmm10
        pxor      %xmm4, %xmm12
        pxor      %xmm8, %xmm14
        paddd     %xmm12, %xmm9
        movdqa    %xmm13, 688(%rsp)
        paddd     %xmm14, %xmm7
        movdqa    448(%rdi), %xmm13
        movdqa    %xmm10, %xmm14
        paddd     %xmm13, %xmm9
        pslld     $7, %xmm14
        psrld     $25, %xmm10
        movdqa    704(%rdi), %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm9, %xmm10
        paddd     %xmm12, %xmm7
        pslld     $7, %xmm10
        psrld     $25, %xmm9
        movdqa    %xmm13, 672(%rsp)
        por       %xmm9, %xmm10
        movdqa    %xmm7, %xmm9
        movdqa    %xmm3, %xmm13
        paddd     %xmm11, %xmm14
        pslld     $7, %xmm9
        psrld     $25, %xmm7
        pxor      %xmm11, %xmm13
        por       %xmm7, %xmm9
        pand      %xmm14, %xmm13
        movdqa    .L_2il0floatpacket.78(%rip), %xmm7
        pxor      %xmm3, %xmm13
        paddd     %xmm7, %xmm2
        paddd     %xmm7, %xmm4
        paddd     %xmm13, %xmm2
        movdqa    %xmm5, %xmm13
        paddd     %xmm7, %xmm8
        movdqa    %xmm1, %xmm7
        paddd     %xmm15, %xmm10
        paddd     %xmm0, %xmm9
        pxor      %xmm15, %xmm13
        pxor      %xmm0, %xmm7
        movdqa    %xmm12, 704(%rsp)
        pand      %xmm10, %xmm13
        movdqa    208(%rdi), %xmm12
        pand      %xmm9, %xmm7
        paddd     %xmm12, %xmm2
        pxor      %xmm5, %xmm13
        pxor      %xmm1, %xmm7
        paddd     %xmm13, %xmm4
        movdqa    %xmm12, 496(%rsp)
        paddd     %xmm7, %xmm8
        movdqa    464(%rdi), %xmm12
        movdqa    %xmm2, %xmm7
        paddd     %xmm12, %xmm4
        pslld     $12, %xmm7
        psrld     $20, %xmm2
        movdqa    720(%rdi), %xmm13
        por       %xmm2, %xmm7
        movdqa    %xmm4, %xmm2
        paddd     %xmm13, %xmm8
        pslld     $12, %xmm2
        psrld     $20, %xmm4
        por       %xmm4, %xmm2
        movdqa    %xmm8, %xmm4
        pslld     $12, %xmm4
        psrld     $20, %xmm8
        por       %xmm8, %xmm4
        movdqa    %xmm14, %xmm8
        paddd     %xmm14, %xmm7
        pxor      %xmm11, %xmm8
        movdqa    %xmm13, 544(%rsp)
        pand      %xmm7, %xmm8
        movdqa    .L_2il0floatpacket.79(%rip), %xmm13
        pxor      %xmm11, %xmm8
        paddd     %xmm13, %xmm3
        paddd     %xmm13, %xmm5
        paddd     %xmm8, %xmm3
        movdqa    %xmm10, %xmm8
        paddd     %xmm13, %xmm1
        movdqa    %xmm9, %xmm13
        paddd     %xmm10, %xmm2
        paddd     %xmm9, %xmm4
        pxor      %xmm15, %xmm8
        pxor      %xmm0, %xmm13
        movdqa    %xmm12, 528(%rsp)
        pand      %xmm2, %xmm8
        movdqa    224(%rdi), %xmm12
        pand      %xmm4, %xmm13
        paddd     %xmm12, %xmm3
        pxor      %xmm15, %xmm8
        pxor      %xmm0, %xmm13
        paddd     %xmm8, %xmm5
        movdqa    %xmm12, 752(%rsp)
        paddd     %xmm13, %xmm1
        movdqa    480(%rdi), %xmm12
        movdqa    %xmm3, %xmm13
        paddd     %xmm12, %xmm5
        pslld     $17, %xmm13
        psrld     $15, %xmm3
        movdqa    736(%rdi), %xmm8
        por       %xmm3, %xmm13
        movdqa    %xmm5, %xmm3
        paddd     %xmm8, %xmm1
        pslld     $17, %xmm3
        psrld     $15, %xmm5
        movdqa    %xmm12, 720(%rsp)
        por       %xmm5, %xmm3
        movdqa    %xmm1, %xmm5
        movdqa    %xmm7, %xmm12
        paddd     %xmm7, %xmm13
        pslld     $17, %xmm5
        psrld     $15, %xmm1
        pxor      %xmm14, %xmm12
        por       %xmm1, %xmm5
        pand      %xmm13, %xmm12
        movdqa    .L_2il0floatpacket.80(%rip), %xmm1
        pxor      %xmm14, %xmm12
        paddd     %xmm1, %xmm11
        paddd     %xmm1, %xmm15
        paddd     %xmm12, %xmm11
        movdqa    %xmm2, %xmm12
        paddd     %xmm1, %xmm0
        movdqa    %xmm4, %xmm1
        paddd     %xmm2, %xmm3
        paddd     %xmm4, %xmm5
        pxor      %xmm10, %xmm12
        pxor      %xmm9, %xmm1
        pand      %xmm3, %xmm12
        pand      %xmm5, %xmm1
        movdqa    %xmm8, 736(%rsp)
        pxor      %xmm10, %xmm12
        movdqa    240(%rdi), %xmm8
        pxor      %xmm9, %xmm1
        paddd     %xmm8, %xmm11
        paddd     %xmm12, %xmm15
        movdqa    752(%rdi), %xmm12
        paddd     %xmm1, %xmm0
        movdqa    %xmm12, 768(%rsp)
        paddd     %xmm12, %xmm0
        movdqa    %xmm11, %xmm12
        psrld     $10, %xmm11
        pslld     $22, %xmm12
        movdqa    %xmm0, %xmm1
        paddd     496(%rdi), %xmm15
        por       %xmm11, %xmm12
        pslld     $22, %xmm1
        psrld     $10, %xmm0
        paddd     %xmm13, %xmm12
        movdqa    %xmm15, %xmm11
        por       %xmm0, %xmm1
        movdqa    %xmm13, %xmm0
        pslld     $22, %xmm11
        psrld     $10, %xmm15
        pxor      %xmm12, %xmm0
        por       %xmm15, %xmm11
        movdqa    .L_2il0floatpacket.81(%rip), %xmm15
        pand      %xmm7, %xmm0
        paddd     %xmm15, %xmm14
        pxor      %xmm13, %xmm0
        paddd     %xmm3, %xmm11
        paddd     %xmm5, %xmm1
        paddd     %xmm0, %xmm14
        paddd     %xmm15, %xmm10
        movdqa    %xmm3, %xmm0
        paddd     %xmm15, %xmm9
        movdqa    %xmm5, %xmm15
        pxor      %xmm11, %xmm0
        pxor      %xmm1, %xmm15
        pand      %xmm2, %xmm0
        pand      %xmm4, %xmm15
        pxor      %xmm3, %xmm0
        paddd     208(%rsp), %xmm14
        pxor      %xmm5, %xmm15
        paddd     %xmm0, %xmm10
        paddd     %xmm15, %xmm9
        movdqa    %xmm14, %xmm15
        psrld     $27, %xmm14
        paddd     176(%rsp), %xmm10
        pslld     $5, %xmm15
        por       %xmm14, %xmm15
        movdqa    %xmm10, %xmm14
        paddd     160(%rsp), %xmm9
        pslld     $5, %xmm14
        psrld     $27, %xmm10
        paddd     %xmm12, %xmm15
        por       %xmm10, %xmm14
        movdqa    %xmm9, %xmm10
        pslld     $5, %xmm10
        psrld     $27, %xmm9
        movdqa    %xmm12, %xmm0
        por       %xmm9, %xmm10
        movdqa    .L_2il0floatpacket.82(%rip), %xmm9
        pxor      %xmm15, %xmm0
        paddd     %xmm1, %xmm10
        paddd     %xmm9, %xmm7
        pand      %xmm13, %xmm0
        paddd     %xmm9, %xmm2
        paddd     %xmm9, %xmm4
        movdqa    %xmm1, %xmm9
        pxor      %xmm12, %xmm0
        pxor      %xmm10, %xmm9
        paddd     %xmm11, %xmm14
        paddd     %xmm0, %xmm7
        movdqa    %xmm11, %xmm0
        pand      %xmm5, %xmm9
        pxor      %xmm14, %xmm0
        pxor      %xmm1, %xmm9
        paddd     256(%rsp), %xmm7
        pand      %xmm3, %xmm0
        paddd     %xmm9, %xmm4
        pxor      %xmm11, %xmm0
        paddd     224(%rsp), %xmm4
        movdqa    %xmm7, %xmm9
        paddd     %xmm0, %xmm2
        pslld     $9, %xmm9
        psrld     $23, %xmm7
        movdqa    %xmm4, %xmm0
        paddd     240(%rsp), %xmm2
        por       %xmm7, %xmm9
        pslld     $9, %xmm0
        psrld     $23, %xmm4
        paddd     %xmm15, %xmm9
        movdqa    %xmm2, %xmm7
        por       %xmm4, %xmm0
        movdqa    %xmm15, %xmm4
        pslld     $9, %xmm7
        psrld     $23, %xmm2
        pxor      %xmm9, %xmm4
        por       %xmm2, %xmm7
        movdqa    .L_2il0floatpacket.83(%rip), %xmm2
        pand      %xmm12, %xmm4
        paddd     %xmm2, %xmm13
        pxor      %xmm15, %xmm4
        paddd     %xmm14, %xmm7
        paddd     %xmm4, %xmm13
        movdqa    %xmm14, %xmm4
        paddd     %xmm2, %xmm3
        pxor      %xmm7, %xmm4
        paddd     %xmm10, %xmm0
        pand      %xmm11, %xmm4
        paddd     %xmm2, %xmm5
        pxor      %xmm14, %xmm4
        paddd     %xmm4, %xmm3
        paddd     %xmm6, %xmm3
        movdqa    %xmm10, %xmm6
        pxor      %xmm0, %xmm6
        pand      %xmm1, %xmm6
        pxor      %xmm10, %xmm6
        paddd     304(%rsp), %xmm13
        paddd     %xmm6, %xmm5
        paddd     688(%rdi), %xmm5
        movdqa    %xmm13, %xmm2
        pslld     $14, %xmm2
        psrld     $18, %xmm13
        movdqa    %xmm5, %xmm4
        por       %xmm13, %xmm2
        pslld     $14, %xmm4
        psrld     $18, %xmm5
        paddd     %xmm9, %xmm2
        movdqa    %xmm3, %xmm6
        por       %xmm5, %xmm4
        movdqa    %xmm9, %xmm5
        pslld     $14, %xmm6
        psrld     $18, %xmm3
        pxor      %xmm2, %xmm5
        por       %xmm3, %xmm6
        movdqa    .L_2il0floatpacket.84(%rip), %xmm3
        pand      %xmm15, %xmm5
        paddd     %xmm3, %xmm12
        pxor      %xmm9, %xmm5
        paddd     %xmm7, %xmm6
        paddd     %xmm5, %xmm12
        movdqa    %xmm7, %xmm5
        paddd     %xmm0, %xmm4
        pxor      %xmm6, %xmm5
        paddd     %xmm3, %xmm11
        pand      %xmm14, %xmm5
        paddd     %xmm3, %xmm1
        movdqa    %xmm0, %xmm3
        pxor      %xmm7, %xmm5
        movdqa    800(%rsp), %xmm13
        pxor      %xmm4, %xmm3
        paddd     %xmm13, %xmm12
        paddd     %xmm5, %xmm11
        pand      %xmm10, %xmm3
        movdqa    %xmm12, %xmm5
        paddd     816(%rsp), %xmm11
        pxor      %xmm0, %xmm3
        paddd     %xmm3, %xmm1
        pslld     $20, %xmm5
        psrld     $12, %xmm12
        movdqa    %xmm11, %xmm3
        paddd     448(%rsp), %xmm1
        por       %xmm12, %xmm5
        pslld     $20, %xmm3
        psrld     $12, %xmm11
        paddd     %xmm2, %xmm5
        por       %xmm11, %xmm3
        movdqa    %xmm1, %xmm12
        movdqa    %xmm2, %xmm11
        pslld     $20, %xmm12
        psrld     $12, %xmm1
        pxor      %xmm5, %xmm11
        por       %xmm1, %xmm12
        movdqa    .L_2il0floatpacket.85(%rip), %xmm1
        pand      %xmm9, %xmm11
        paddd     %xmm1, %xmm15
        pxor      %xmm2, %xmm11
        paddd     %xmm6, %xmm3
        paddd     %xmm4, %xmm12
        paddd     %xmm11, %xmm15
        paddd     %xmm1, %xmm14
        movdqa    %xmm6, %xmm11
        paddd     %xmm1, %xmm10
        movdqa    %xmm4, %xmm1
        pxor      %xmm3, %xmm11
        pxor      %xmm12, %xmm1
        pand      %xmm7, %xmm11
        pand      %xmm0, %xmm1
        pxor      %xmm6, %xmm11
        paddd     464(%rsp), %xmm15
        pxor      %xmm4, %xmm1
        paddd     %xmm11, %xmm14
        paddd     %xmm1, %xmm10
        movdqa    %xmm15, %xmm1
        psrld     $27, %xmm15
        paddd     480(%rsp), %xmm14
        pslld     $5, %xmm1
        por       %xmm15, %xmm1
        movdqa    %xmm14, %xmm15
        paddd     512(%rsp), %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     %xmm5, %xmm1
        por       %xmm14, %xmm15
        movdqa    %xmm10, %xmm14
        movdqa    %xmm5, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm10
        pxor      %xmm1, %xmm11
        por       %xmm10, %xmm14
        pand      %xmm2, %xmm11
        movdqa    .L_2il0floatpacket.86(%rip), %xmm10
        pxor      %xmm5, %xmm11
        paddd     %xmm10, %xmm9
        paddd     %xmm3, %xmm15
        paddd     %xmm12, %xmm14
        paddd     %xmm11, %xmm9
        paddd     %xmm10, %xmm7
        movdqa    %xmm3, %xmm11
        paddd     %xmm10, %xmm0
        movdqa    %xmm12, %xmm10
        pxor      %xmm15, %xmm11
        pxor      %xmm14, %xmm10
        pand      %xmm6, %xmm11
        pand      %xmm4, %xmm10
        paddd     576(%rsp), %xmm9
        pxor      %xmm3, %xmm11
        pxor      %xmm12, %xmm10
        paddd     %xmm11, %xmm7
        paddd     %xmm10, %xmm0
        movdqa    %xmm9, %xmm10
        paddd     592(%rsp), %xmm7
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        movdqa    %xmm1, %xmm11
        por       %xmm9, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     560(%rsp), %xmm0
        pslld     $9, %xmm9
        psrld     $23, %xmm7
        paddd     %xmm1, %xmm10
        por       %xmm7, %xmm9
        movdqa    %xmm0, %xmm7
        pslld     $9, %xmm7
        psrld     $23, %xmm0
        pxor      %xmm10, %xmm11
        por       %xmm0, %xmm7
        movdqa    .L_2il0floatpacket.87(%rip), %xmm0
        pand      %xmm5, %xmm11
        paddd     %xmm0, %xmm2
        pxor      %xmm1, %xmm11
        paddd     %xmm11, %xmm2
        paddd     %xmm15, %xmm9
        movdqa    %xmm8, 640(%rsp)
        paddd     %xmm14, %xmm7
        paddd     %xmm8, %xmm2
        paddd     %xmm0, %xmm6
        movdqa    %xmm15, %xmm8
        paddd     %xmm0, %xmm4
        movdqa    %xmm14, %xmm0
        pxor      %xmm9, %xmm8
        pxor      %xmm7, %xmm0
        pand      %xmm3, %xmm8
        pand      %xmm12, %xmm0
        pxor      %xmm15, %xmm8
        pxor      %xmm14, %xmm0
        paddd     %xmm8, %xmm6
        movdqa    496(%rdi), %xmm8
        paddd     %xmm0, %xmm4
        movdqa    %xmm2, %xmm0
        paddd     %xmm8, %xmm6
        pslld     $14, %xmm0
        psrld     $18, %xmm2
        por       %xmm2, %xmm0
        movdqa    %xmm6, %xmm2
        paddd     752(%rdi), %xmm4
        pslld     $14, %xmm2
        psrld     $18, %xmm6
        paddd     %xmm10, %xmm0
        por       %xmm6, %xmm2
        movdqa    %xmm4, %xmm6
        movdqa    %xmm10, %xmm11
        pslld     $14, %xmm6
        psrld     $18, %xmm4
        pxor      %xmm0, %xmm11
        por       %xmm4, %xmm6
        pand      %xmm1, %xmm11
        movdqa    .L_2il0floatpacket.88(%rip), %xmm4
        pxor      %xmm10, %xmm11
        paddd     %xmm4, %xmm5
        paddd     %xmm9, %xmm2
        paddd     %xmm7, %xmm6
        paddd     %xmm11, %xmm5
        paddd     %xmm4, %xmm3
        movdqa    %xmm9, %xmm11
        paddd     %xmm4, %xmm12
        movdqa    %xmm7, %xmm4
        pxor      %xmm2, %xmm11
        pxor      %xmm6, %xmm4
        pand      %xmm15, %xmm11
        pand      %xmm14, %xmm4
        paddd     112(%rsp), %xmm5
        pxor      %xmm9, %xmm11
        pxor      %xmm7, %xmm4
        paddd     %xmm11, %xmm3
        paddd     %xmm4, %xmm12
        movdqa    %xmm5, %xmm4
        paddd     144(%rsp), %xmm3
        pslld     $20, %xmm4
        psrld     $12, %xmm5
        por       %xmm5, %xmm4
        movdqa    %xmm3, %xmm5
        pslld     $20, %xmm5
        psrld     $12, %xmm3
        paddd     128(%rsp), %xmm12
        paddd     %xmm0, %xmm4
        movdqa    816(%rsp), %xmm11
        por       %xmm3, %xmm5
..B6.12:
        movdqa    %xmm12, %xmm3
        psrld     $12, %xmm12
        movdqa    %xmm8, 784(%rsp)
        pslld     $20, %xmm3
        movdqa    %xmm0, %xmm8
        por       %xmm12, %xmm3
        pxor      %xmm4, %xmm8
        paddd     %xmm2, %xmm5
        movdqa    %xmm11, 816(%rsp)
        paddd     %xmm6, %xmm3
        movdqa    %xmm13, 800(%rsp)
        pand      %xmm10, %xmm8
        movdqa    .L_2il0floatpacket.89(%rip), %xmm11
        movdqa    %xmm2, %xmm13
        movdqa    %xmm6, %xmm12
        paddd     %xmm11, %xmm1
        pxor      %xmm0, %xmm8
        pxor      %xmm5, %xmm13
        pxor      %xmm3, %xmm12
        paddd     %xmm8, %xmm1
        pand      %xmm9, %xmm13
        pand      %xmm7, %xmm12
        paddd     192(%rsp), %xmm1
        paddd     %xmm11, %xmm15
        pxor      %xmm2, %xmm13
        paddd     %xmm11, %xmm14
        pxor      %xmm6, %xmm12
        paddd     %xmm13, %xmm15
        paddd     %xmm12, %xmm14
        movdqa    %xmm1, %xmm12
        paddd     272(%rsp), %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm1
        movdqa    %xmm5, %xmm8
        por       %xmm1, %xmm12
        movdqa    %xmm15, %xmm1
        paddd     288(%rsp), %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm12
        por       %xmm15, %xmm1
        movdqa    %xmm14, %xmm15
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm4, %xmm14
        pxor      %xmm12, %xmm14
        paddd     %xmm5, %xmm1
        movdqa    .L_2il0floatpacket.90(%rip), %xmm13
        pand      %xmm0, %xmm14
        paddd     %xmm13, %xmm10
        pxor      %xmm4, %xmm14
        paddd     %xmm3, %xmm15
        paddd     %xmm14, %xmm10
        movdqa    %xmm3, %xmm14
        pxor      %xmm1, %xmm8
        pxor      %xmm15, %xmm14
        pand      %xmm2, %xmm8
        pand      %xmm6, %xmm14
        paddd     %xmm13, %xmm9
        paddd     752(%rsp), %xmm10
        pxor      %xmm5, %xmm8
        paddd     %xmm13, %xmm7
        pxor      %xmm3, %xmm14
        paddd     %xmm8, %xmm9
        paddd     %xmm14, %xmm7
        movdqa    %xmm10, %xmm11
        psrld     $23, %xmm10
        paddd     720(%rsp), %xmm9
        pslld     $9, %xmm11
        paddd     736(%rsp), %xmm7
        por       %xmm10, %xmm11
        movdqa    %xmm9, %xmm10
        movdqa    %xmm7, %xmm14
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        pslld     $9, %xmm14
        psrld     $23, %xmm7
        paddd     %xmm12, %xmm11
        por       %xmm9, %xmm10
        por       %xmm7, %xmm14
        movdqa    %xmm12, %xmm9
        paddd     %xmm15, %xmm14
        pxor      %xmm11, %xmm9
        movdqa    %xmm15, %xmm13
        paddd     %xmm1, %xmm10
        movdqa    .L_2il0floatpacket.91(%rip), %xmm8
        pand      %xmm4, %xmm9
        movdqa    %xmm1, %xmm7
        pxor      %xmm14, %xmm13
        paddd     %xmm8, %xmm0
        pxor      %xmm12, %xmm9
        pxor      %xmm10, %xmm7
        pand      %xmm3, %xmm13
        paddd     %xmm9, %xmm0
        pand      %xmm5, %xmm7
        paddd     %xmm8, %xmm6
        pxor      %xmm15, %xmm13
        paddd     336(%rsp), %xmm0
        paddd     %xmm8, %xmm2
        pxor      %xmm1, %xmm7
        paddd     %xmm13, %xmm6
        paddd     352(%rsp), %xmm6
        paddd     %xmm7, %xmm2
        movdqa    %xmm0, %xmm13
        psrld     $18, %xmm0
        paddd     320(%rsp), %xmm2
        pslld     $14, %xmm13
        movdqa    %xmm6, %xmm8
        por       %xmm0, %xmm13
        movdqa    %xmm2, %xmm9
        pslld     $14, %xmm8
        psrld     $18, %xmm6
        paddd     %xmm11, %xmm13
        movdqa    .L_2il0floatpacket.92(%rip), %xmm7
        pslld     $14, %xmm9
        psrld     $18, %xmm2
        por       %xmm6, %xmm8
        movdqa    %xmm11, %xmm0
        por       %xmm2, %xmm9
        paddd     %xmm14, %xmm8
        paddd     %xmm7, %xmm4
        pxor      %xmm13, %xmm0
        paddd     %xmm7, %xmm5
        paddd     %xmm7, %xmm3
        movdqa    %xmm14, %xmm7
        paddd     %xmm10, %xmm9
        pand      %xmm12, %xmm0
        movdqa    %xmm10, %xmm6
        pxor      %xmm8, %xmm7
        pxor      %xmm11, %xmm0
        pxor      %xmm9, %xmm6
        pand      %xmm15, %xmm7
        paddd     %xmm0, %xmm4
        movdqa    432(%rsp), %xmm2
        pand      %xmm1, %xmm6
        pxor      %xmm14, %xmm7
        paddd     %xmm2, %xmm4
        pxor      %xmm10, %xmm6
        paddd     %xmm7, %xmm3
        movdqa    416(%rsp), %xmm0
        paddd     %xmm6, %xmm5
        paddd     400(%rsp), %xmm3
        movdqa    %xmm4, %xmm7
        paddd     %xmm0, %xmm5
        pslld     $20, %xmm7
        psrld     $12, %xmm4
        movdqa    %xmm3, %xmm6
        por       %xmm4, %xmm7
        movdqa    %xmm5, %xmm4
        pslld     $20, %xmm6
        psrld     $12, %xmm3
        paddd     %xmm13, %xmm7
        pslld     $20, %xmm4
        psrld     $12, %xmm5
        por       %xmm3, %xmm6
        movdqa    %xmm13, %xmm3
        por       %xmm5, %xmm4
        movdqa    .L_2il0floatpacket.93(%rip), %xmm5
        pxor      %xmm7, %xmm3
        paddd     %xmm8, %xmm6
        paddd     %xmm5, %xmm12
        pand      %xmm11, %xmm3
        paddd     %xmm5, %xmm1
        paddd     %xmm5, %xmm15
        movdqa    %xmm8, %xmm5
        pxor      %xmm13, %xmm3
        pxor      %xmm6, %xmm5
        paddd     %xmm9, %xmm4
        paddd     %xmm3, %xmm12
        movdqa    %xmm9, %xmm3
        pand      %xmm14, %xmm5
        pxor      %xmm4, %xmm3
        pxor      %xmm8, %xmm5
        paddd     496(%rsp), %xmm12
        pand      %xmm10, %xmm3
        paddd     %xmm5, %xmm15
        pxor      %xmm9, %xmm3
        paddd     544(%rsp), %xmm15
        movdqa    %xmm12, %xmm5
        paddd     %xmm3, %xmm1
        pslld     $5, %xmm5
        psrld     $27, %xmm12
        movdqa    %xmm15, %xmm3
        paddd     528(%rsp), %xmm1
        por       %xmm12, %xmm5
        pslld     $5, %xmm3
        psrld     $27, %xmm15
        paddd     %xmm7, %xmm5
        movdqa    %xmm1, %xmm12
        por       %xmm15, %xmm3
        movdqa    %xmm7, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm1
        pxor      %xmm5, %xmm15
        por       %xmm1, %xmm12
        movdqa    .L_2il0floatpacket.94(%rip), %xmm1
        pand      %xmm13, %xmm15
        paddd     %xmm1, %xmm11
        pxor      %xmm7, %xmm15
        paddd     %xmm4, %xmm12
        paddd     %xmm6, %xmm3
        paddd     %xmm15, %xmm11
        paddd     %xmm1, %xmm10
        movdqa    %xmm4, %xmm15
        paddd     %xmm1, %xmm14
        movdqa    %xmm6, %xmm1
        pxor      %xmm12, %xmm15
        pxor      %xmm3, %xmm1
        pand      %xmm9, %xmm15
        pand      %xmm8, %xmm1
        pxor      %xmm4, %xmm15
        paddd     64(%rsp), %xmm11
        pxor      %xmm6, %xmm1
        paddd     %xmm15, %xmm10
        paddd     %xmm1, %xmm14
        movdqa    %xmm11, %xmm1
        psrld     $23, %xmm11
        paddd     96(%rsp), %xmm10
        pslld     $9, %xmm1
        por       %xmm11, %xmm1
        movdqa    %xmm10, %xmm11
        paddd     80(%rsp), %xmm14
        pslld     $9, %xmm11
        psrld     $23, %xmm10
        paddd     %xmm5, %xmm1
        por       %xmm10, %xmm11
        movdqa    %xmm14, %xmm10
        pslld     $9, %xmm10
        psrld     $23, %xmm14
        por       %xmm14, %xmm10
        movdqa    %xmm5, %xmm14
        pxor      %xmm1, %xmm14
        paddd     %xmm12, %xmm11
        movdqa    .L_2il0floatpacket.95(%rip), %xmm15
        pand      %xmm7, %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm5, %xmm14
        paddd     %xmm3, %xmm10
        paddd     %xmm14, %xmm13
        paddd     %xmm15, %xmm9
        movdqa    %xmm12, %xmm14
        paddd     %xmm15, %xmm8
        movdqa    %xmm3, %xmm15
        pxor      %xmm11, %xmm14
        pxor      %xmm10, %xmm15
        pand      %xmm4, %xmm14
        pand      %xmm6, %xmm15
        paddd     608(%rsp), %xmm13
        pxor      %xmm12, %xmm14
        pxor      %xmm3, %xmm15
        paddd     %xmm14, %xmm9
        paddd     %xmm15, %xmm8
        movdqa    %xmm13, %xmm15
        paddd     656(%rsp), %xmm9
        pslld     $14, %xmm15
        psrld     $18, %xmm13
        por       %xmm13, %xmm15
        movdqa    %xmm9, %xmm13
        paddd     624(%rsp), %xmm8
        pslld     $14, %xmm13
        psrld     $18, %xmm9
        paddd     %xmm1, %xmm15
        por       %xmm9, %xmm13
        movdqa    %xmm8, %xmm9
        pslld     $14, %xmm9
        psrld     $18, %xmm8
        por       %xmm8, %xmm9
        movdqa    %xmm1, %xmm8
        pxor      %xmm15, %xmm8
        paddd     %xmm11, %xmm13
        movdqa    .L_2il0floatpacket.96(%rip), %xmm14
        pand      %xmm5, %xmm8
        paddd     %xmm14, %xmm7
        pxor      %xmm1, %xmm8
        paddd     %xmm8, %xmm7
        movdqa    %xmm11, %xmm8
        pxor      %xmm13, %xmm8
        paddd     %xmm10, %xmm9
        paddd     %xmm14, %xmm4
        pand      %xmm12, %xmm8
        paddd     %xmm14, %xmm6
        movdqa    %xmm10, %xmm14
        paddd     688(%rsp), %xmm7
        pxor      %xmm11, %xmm8
        pxor      %xmm9, %xmm14
        paddd     %xmm8, %xmm4
        pand      %xmm3, %xmm14
        movdqa    %xmm7, %xmm8
        paddd     672(%rsp), %xmm4
        pxor      %xmm10, %xmm14
        pslld     $20, %xmm8
        psrld     $12, %xmm7
        paddd     %xmm14, %xmm6
        por       %xmm7, %xmm8
        movdqa    %xmm4, %xmm7
        psrld     $12, %xmm4
        paddd     704(%rsp), %xmm6
        pslld     $20, %xmm7
        por       %xmm4, %xmm7
        movdqa    %xmm6, %xmm4
        pslld     $20, %xmm4
        psrld     $12, %xmm6
        movdqa    %xmm15, %xmm14
        paddd     %xmm15, %xmm8
        por       %xmm6, %xmm4
        pxor      %xmm1, %xmm14
        movdqa    .L_2il0floatpacket.97(%rip), %xmm6
        pxor      %xmm8, %xmm14
        paddd     %xmm6, %xmm5
        paddd     %xmm6, %xmm12
        paddd     %xmm6, %xmm3
        movdqa    %xmm9, %xmm6
        paddd     %xmm9, %xmm4
        paddd     %xmm14, %xmm5
        movdqa    %xmm13, %xmm14
        pxor      %xmm10, %xmm6
        paddd     %xmm13, %xmm7
        pxor      %xmm11, %xmm14
        pxor      %xmm4, %xmm6
        pxor      %xmm7, %xmm14
        paddd     464(%rsp), %xmm5
        paddd     %xmm6, %xmm3
        paddd     512(%rsp), %xmm3
        paddd     %xmm14, %xmm12
        movdqa    %xmm5, %xmm6
        psrld     $28, %xmm5
        paddd     480(%rsp), %xmm12
        pslld     $4, %xmm6
        movdqa    %xmm3, %xmm14
        por       %xmm5, %xmm6
        movdqa    %xmm12, %xmm5
        pslld     $4, %xmm14
        psrld     $28, %xmm3
        pslld     $4, %xmm5
        psrld     $28, %xmm12
        por       %xmm3, %xmm14
        movdqa    %xmm8, %xmm3
        paddd     %xmm8, %xmm6
        por       %xmm12, %xmm5
        pxor      %xmm15, %xmm3
        movdqa    .L_2il0floatpacket.98(%rip), %xmm12
        pxor      %xmm6, %xmm3
        paddd     %xmm12, %xmm1
        paddd     %xmm7, %xmm5
        paddd     %xmm3, %xmm1
        paddd     %xmm12, %xmm11
        paddd     %xmm2, %xmm1
        movdqa    %xmm7, %xmm2
        pxor      %xmm13, %xmm2
        paddd     %xmm4, %xmm14
        pxor      %xmm5, %xmm2
        paddd     %xmm12, %xmm10
        paddd     %xmm2, %xmm11
        paddd     %xmm0, %xmm11
        movdqa    %xmm4, %xmm0
        pxor      %xmm9, %xmm0
        movdqa    %xmm11, %xmm12
        pxor      %xmm14, %xmm0
        pslld     $11, %xmm12
        paddd     %xmm0, %xmm10
        psrld     $21, %xmm11
        paddd     400(%rsp), %xmm10
        movdqa    %xmm1, %xmm0
        movdqa    %xmm10, %xmm3
        por       %xmm11, %xmm12
        pslld     $11, %xmm3
        psrld     $21, %xmm10
        movdqa    %xmm5, %xmm11
        pslld     $11, %xmm0
        psrld     $21, %xmm1
        paddd     %xmm5, %xmm12
        por       %xmm10, %xmm3
        pxor      %xmm7, %xmm11
        movdqa    .L_2il0floatpacket.99(%rip), %xmm10
        por       %xmm1, %xmm0
        paddd     %xmm10, %xmm15
        movdqa    %xmm6, %xmm1
        paddd     %xmm10, %xmm13
        pxor      %xmm12, %xmm11
        paddd     %xmm10, %xmm9
        movdqa    %xmm14, %xmm10
        paddd     %xmm6, %xmm0
        paddd     %xmm14, %xmm3
        pxor      %xmm8, %xmm1
        paddd     %xmm11, %xmm13
        pxor      %xmm4, %xmm10
        pxor      %xmm0, %xmm1
        paddd     368(%rsp), %xmm13
        pxor      %xmm3, %xmm10
        paddd     %xmm1, %xmm15
        paddd     %xmm10, %xmm9
        pshufhw   $177, %xmm13, %xmm1
        movdqa    %xmm12, %xmm11
        paddd     304(%rsp), %xmm15
        pxor      %xmm5, %xmm11
        paddd     384(%rsp), %xmm9
        movdqa    %xmm3, %xmm13
        pshuflw   $177, %xmm1, %xmm1
        pxor      %xmm14, %xmm13
        pshufhw   $177, %xmm15, %xmm2
        paddd     %xmm12, %xmm1
        pshufhw   $177, %xmm9, %xmm9
        movdqa    %xmm0, %xmm15
        movdqa    .L_2il0floatpacket.100(%rip), %xmm10
        pxor      %xmm1, %xmm11
        pshuflw   $177, %xmm2, %xmm2
        paddd     %xmm10, %xmm7
        pshuflw   $177, %xmm9, %xmm9
        paddd     %xmm0, %xmm2
        paddd     %xmm3, %xmm9
        pxor      %xmm6, %xmm15
        paddd     %xmm11, %xmm7
        paddd     %xmm10, %xmm8
        paddd     720(%rsp), %xmm7
        pxor      %xmm2, %xmm15
        paddd     %xmm10, %xmm4
        pxor      %xmm9, %xmm13
        paddd     %xmm15, %xmm8
        paddd     %xmm13, %xmm4
        movdqa    %xmm7, %xmm15
        psrld     $9, %xmm7
        paddd     752(%rsp), %xmm8
        pslld     $23, %xmm15
        paddd     736(%rsp), %xmm4
        movdqa    %xmm8, %xmm10
        por       %xmm7, %xmm15
        movdqa    %xmm4, %xmm7
        pslld     $23, %xmm10
        psrld     $9, %xmm8
        pslld     $23, %xmm7
        psrld     $9, %xmm4
        por       %xmm8, %xmm10
        por       %xmm4, %xmm7
        movdqa    %xmm2, %xmm4
        paddd     %xmm2, %xmm10
        movdqa    .L_2il0floatpacket.101(%rip), %xmm11
        pxor      %xmm0, %xmm4
        paddd     %xmm11, %xmm6
        pxor      %xmm10, %xmm4
        movdqa    %xmm1, %xmm8
        paddd     %xmm1, %xmm15
        paddd     %xmm4, %xmm6
        pxor      %xmm12, %xmm8
        paddd     208(%rsp), %xmm6
        paddd     %xmm11, %xmm5
        pxor      %xmm15, %xmm8
        movdqa    %xmm9, %xmm13
        paddd     %xmm9, %xmm7
        paddd     %xmm8, %xmm5
        pxor      %xmm3, %xmm13
        movdqa    %xmm6, %xmm4
        paddd     176(%rsp), %xmm5
        paddd     %xmm11, %xmm14
        pxor      %xmm7, %xmm13
        pslld     $4, %xmm4
        psrld     $28, %xmm6
        paddd     %xmm13, %xmm14
        por       %xmm6, %xmm4
        movdqa    %xmm5, %xmm6
        paddd     160(%rsp), %xmm14
        pslld     $4, %xmm6
        psrld     $28, %xmm5
        paddd     %xmm10, %xmm4
        por       %xmm5, %xmm6
        movdqa    %xmm14, %xmm5
        pslld     $4, %xmm5
        psrld     $28, %xmm14
        por       %xmm14, %xmm5
        movdqa    %xmm10, %xmm14
        movdqa    .L_2il0floatpacket.102(%rip), %xmm8
        pxor      %xmm2, %xmm14
        movdqa    %xmm15, %xmm11
        paddd     %xmm15, %xmm6
        paddd     %xmm8, %xmm0
        pxor      %xmm4, %xmm14
        pxor      %xmm1, %xmm11
        paddd     %xmm14, %xmm0
        paddd     %xmm8, %xmm12
        pxor      %xmm6, %xmm11
        paddd     112(%rsp), %xmm0
        paddd     %xmm7, %xmm5
        movdqa    784(%rsp), %xmm8
        paddd     %xmm11, %xmm12
        movdqa    816(%rsp), %xmm11
        movdqa    800(%rsp), %xmm13
..B6.11:
        movdqa    %xmm8, 784(%rsp)
        movdqa    %xmm7, %xmm8
        pxor      %xmm9, %xmm8
        movdqa    %xmm4, %xmm14
        paddd     .L_2il0floatpacket.102(%rip), %xmm3
        pxor      %xmm5, %xmm8
        paddd     %xmm8, %xmm3
        movdqa    %xmm0, %xmm8
        paddd     144(%rsp), %xmm12
        pslld     $11, %xmm8
        psrld     $21, %xmm0
        pxor      %xmm10, %xmm14
        por       %xmm0, %xmm8
        movdqa    %xmm12, %xmm0
        paddd     128(%rsp), %xmm3
        pslld     $11, %xmm0
        psrld     $21, %xmm12
        paddd     %xmm4, %xmm8
        por       %xmm12, %xmm0
        movdqa    %xmm3, %xmm12
        pslld     $11, %xmm12
        psrld     $21, %xmm3
        por       %xmm3, %xmm12
        pxor      %xmm8, %xmm14
        movdqa    .L_2il0floatpacket.103(%rip), %xmm3
        paddd     %xmm6, %xmm0
        paddd     %xmm3, %xmm2
        paddd     %xmm3, %xmm1
        paddd     %xmm14, %xmm2
        movdqa    %xmm6, %xmm14
        paddd     %xmm3, %xmm9
        movdqa    %xmm5, %xmm3
        paddd     608(%rsp), %xmm2
        paddd     %xmm5, %xmm12
        pxor      %xmm15, %xmm14
        pxor      %xmm7, %xmm3
        pshufhw   $177, %xmm2, %xmm2
        pxor      %xmm0, %xmm14
        pxor      %xmm12, %xmm3
        paddd     %xmm14, %xmm1
        pshuflw   $177, %xmm2, %xmm2
        paddd     %xmm3, %xmm9
        movdqa    %xmm4, %xmm3
        paddd     %xmm8, %xmm2
        paddd     656(%rsp), %xmm1
        pxor      %xmm8, %xmm3
        paddd     624(%rsp), %xmm9
        pxor      %xmm2, %xmm3
        movdqa    .L_2il0floatpacket.104(%rip), %xmm14
        pshufhw   $177, %xmm1, %xmm1
        paddd     %xmm14, %xmm10
        pshufhw   $177, %xmm9, %xmm9
        paddd     %xmm3, %xmm10
        pshuflw   $177, %xmm1, %xmm1
        paddd     %xmm14, %xmm15
        pshuflw   $177, %xmm9, %xmm9
        movdqa    %xmm6, %xmm3
        paddd     %xmm14, %xmm7
        movdqa    %xmm5, %xmm14
        paddd     %xmm0, %xmm1
        paddd     %xmm12, %xmm9
        pxor      %xmm0, %xmm3
        pxor      %xmm12, %xmm14
        paddd     576(%rsp), %xmm10
        pxor      %xmm1, %xmm3
        pxor      %xmm9, %xmm14
        paddd     %xmm3, %xmm15
        paddd     %xmm14, %xmm7
        movdqa    %xmm10, %xmm14
        paddd     592(%rsp), %xmm15
        pslld     $23, %xmm14
        psrld     $9, %xmm10
        movdqa    %xmm2, %xmm3
        por       %xmm10, %xmm14
        movdqa    %xmm15, %xmm10
        paddd     560(%rsp), %xmm7
        pslld     $23, %xmm10
        psrld     $9, %xmm15
        paddd     %xmm2, %xmm14
        por       %xmm15, %xmm10
        movdqa    %xmm7, %xmm15
        pslld     $23, %xmm15
        psrld     $9, %xmm7
        por       %xmm7, %xmm15
        pxor      %xmm8, %xmm3
        movdqa    .L_2il0floatpacket.105(%rip), %xmm7
        pxor      %xmm14, %xmm3
        paddd     %xmm7, %xmm4
        paddd     %xmm7, %xmm6
        paddd     %xmm3, %xmm4
        movdqa    %xmm1, %xmm3
        paddd     %xmm7, %xmm5
        movdqa    %xmm9, %xmm7
        paddd     %xmm1, %xmm10
        paddd     %xmm9, %xmm15
        pxor      %xmm0, %xmm3
        pxor      %xmm12, %xmm7
        paddd     496(%rsp), %xmm4
        pxor      %xmm10, %xmm3
        pxor      %xmm15, %xmm7
        paddd     %xmm3, %xmm6
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm7
        paddd     528(%rsp), %xmm6
        pslld     $4, %xmm7
        psrld     $28, %xmm4
        movdqa    %xmm14, %xmm3
        por       %xmm4, %xmm7
        movdqa    %xmm6, %xmm4
        paddd     544(%rsp), %xmm5
        pslld     $4, %xmm4
        psrld     $28, %xmm6
        paddd     %xmm14, %xmm7
        por       %xmm6, %xmm4
        movdqa    %xmm5, %xmm6
        pslld     $4, %xmm6
        psrld     $28, %xmm5
        por       %xmm5, %xmm6
        pxor      %xmm2, %xmm3
        movdqa    .L_2il0floatpacket.106(%rip), %xmm5
        pxor      %xmm7, %xmm3
        paddd     %xmm5, %xmm8
        paddd     %xmm10, %xmm4
        paddd     %xmm3, %xmm8
        movdqa    %xmm10, %xmm3
        pxor      %xmm1, %xmm3
        paddd     %xmm5, %xmm0
        pxor      %xmm4, %xmm3
        paddd     %xmm5, %xmm12
        movdqa    %xmm15, %xmm5
        paddd     %xmm15, %xmm6
        paddd     %xmm3, %xmm0
        pxor      %xmm9, %xmm5
        paddd     %xmm11, %xmm0
        pxor      %xmm6, %xmm5
        paddd     %xmm5, %xmm12
        movdqa    %xmm0, %xmm5
        paddd     448(%rsp), %xmm12
        paddd     %xmm13, %xmm8
        pslld     $11, %xmm5
        psrld     $21, %xmm0
        movdqa    %xmm8, %xmm3
        por       %xmm0, %xmm5
        movdqa    %xmm12, %xmm0
        pslld     $11, %xmm3
        psrld     $21, %xmm8
        pslld     $11, %xmm0
        psrld     $21, %xmm12
        por       %xmm8, %xmm3
        por       %xmm12, %xmm0
        movdqa    %xmm7, %xmm8
        movdqa    .L_2il0floatpacket.107(%rip), %xmm12
        paddd     %xmm7, %xmm3
        paddd     %xmm12, %xmm2
        pxor      %xmm14, %xmm8
        paddd     %xmm12, %xmm1
        paddd     %xmm12, %xmm9
        movdqa    %xmm6, %xmm12
        paddd     %xmm6, %xmm0
        pxor      %xmm3, %xmm8
        pxor      %xmm15, %xmm12
        paddd     %xmm8, %xmm2
        movdqa    %xmm4, %xmm8
        pxor      %xmm0, %xmm12
        paddd     %xmm4, %xmm5
        paddd     336(%rsp), %xmm2
        pxor      %xmm10, %xmm8
        paddd     %xmm12, %xmm9
        pxor      %xmm5, %xmm8
        paddd     352(%rsp), %xmm9
        paddd     %xmm8, %xmm1
        pshufhw   $177, %xmm2, %xmm2
        movdqa    %xmm3, %xmm12
        pshuflw   $177, %xmm2, %xmm2
        pxor      %xmm7, %xmm12
        pshufhw   $177, %xmm9, %xmm8
        paddd     %xmm3, %xmm2
        paddd     320(%rsp), %xmm1
        pxor      %xmm2, %xmm12
        pshuflw   $177, %xmm8, %xmm9
        movdqa    .L_2il0floatpacket.108(%rip), %xmm8
        paddd     %xmm0, %xmm9
        pshufhw   $177, %xmm1, %xmm1
        paddd     %xmm8, %xmm14
        pshuflw   $177, %xmm1, %xmm1
        paddd     %xmm12, %xmm14
        paddd     %xmm8, %xmm10
        movdqa    %xmm5, %xmm12
        paddd     %xmm8, %xmm15
        movdqa    %xmm0, %xmm8
        paddd     %xmm5, %xmm1
        pxor      %xmm4, %xmm12
        pxor      %xmm6, %xmm8
        pxor      %xmm1, %xmm12
        paddd     256(%rsp), %xmm14
        pxor      %xmm9, %xmm8
        paddd     %xmm12, %xmm10
        paddd     %xmm8, %xmm15
        movdqa    %xmm14, %xmm8
        psrld     $9, %xmm14
        paddd     240(%rsp), %xmm10
        pslld     $23, %xmm8
        por       %xmm14, %xmm8
        movdqa    %xmm10, %xmm14
        paddd     224(%rsp), %xmm15
        pslld     $23, %xmm14
        psrld     $9, %xmm10
        movdqa    %xmm2, %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm15, %xmm10
        pslld     $23, %xmm10
        psrld     $9, %xmm15
        paddd     %xmm2, %xmm8
        por       %xmm15, %xmm10
        movdqa    .L_2il0floatpacket.109(%rip), %xmm15
        pxor      %xmm3, %xmm12
        paddd     %xmm15, %xmm7
        pxor      %xmm8, %xmm12
        paddd     %xmm12, %xmm7
        paddd     %xmm15, %xmm4
        movdqa    %xmm1, %xmm12
        paddd     %xmm15, %xmm6
        movdqa    %xmm9, %xmm15
        paddd     %xmm1, %xmm14
        paddd     %xmm9, %xmm10
        pxor      %xmm5, %xmm12
        pxor      %xmm0, %xmm15
        pxor      %xmm14, %xmm12
        paddd     192(%rsp), %xmm7
        pxor      %xmm10, %xmm15
        paddd     %xmm12, %xmm4
        paddd     %xmm15, %xmm6
        movdqa    %xmm7, %xmm15
        psrld     $28, %xmm7
        paddd     272(%rsp), %xmm4
        pslld     $4, %xmm15
        por       %xmm7, %xmm15
        movdqa    %xmm4, %xmm7
        paddd     288(%rsp), %xmm6
        pslld     $4, %xmm7
        psrld     $28, %xmm4
        movdqa    %xmm8, %xmm12
        por       %xmm4, %xmm7
        movdqa    %xmm6, %xmm4
        pslld     $4, %xmm4
        psrld     $28, %xmm6
        paddd     %xmm8, %xmm15
        por       %xmm6, %xmm4
        movdqa    .L_2il0floatpacket.110(%rip), %xmm6
        pxor      %xmm2, %xmm12
        paddd     %xmm6, %xmm3
        pxor      %xmm15, %xmm12
        paddd     %xmm12, %xmm3
        paddd     %xmm6, %xmm5
        movdqa    %xmm14, %xmm12
        paddd     %xmm6, %xmm0
        movdqa    %xmm10, %xmm6
        paddd     %xmm14, %xmm7
        paddd     %xmm10, %xmm4
        pxor      %xmm1, %xmm12
        pxor      %xmm9, %xmm6
        pxor      %xmm7, %xmm12
        paddd     688(%rsp), %xmm3
        pxor      %xmm4, %xmm6
        paddd     %xmm12, %xmm5
        paddd     %xmm6, %xmm0
        movdqa    %xmm3, %xmm6
        psrld     $21, %xmm3
        paddd     672(%rsp), %xmm5
        pslld     $11, %xmm6
        por       %xmm3, %xmm6
        movdqa    %xmm5, %xmm3
        paddd     704(%rsp), %xmm0
        pslld     $11, %xmm3
        psrld     $21, %xmm5
        movdqa    %xmm15, %xmm12
        por       %xmm5, %xmm3
        movdqa    %xmm0, %xmm5
        pslld     $11, %xmm5
        psrld     $21, %xmm0
        por       %xmm0, %xmm5
        paddd     %xmm15, %xmm6
        movdqa    .L_2il0floatpacket.111(%rip), %xmm0
        pxor      %xmm8, %xmm12
        paddd     %xmm0, %xmm2
        paddd     %xmm0, %xmm1
        paddd     %xmm0, %xmm9
        movdqa    %xmm4, %xmm0
        paddd     %xmm4, %xmm5
        pxor      %xmm6, %xmm12
        pxor      %xmm10, %xmm0
        paddd     %xmm12, %xmm2
        movdqa    %xmm7, %xmm12
        pxor      %xmm5, %xmm0
        paddd     640(%rsp), %xmm2
        paddd     %xmm7, %xmm3
        pxor      %xmm14, %xmm12
        paddd     %xmm0, %xmm9
        paddd     768(%rsp), %xmm9
        pxor      %xmm3, %xmm12
        pshufhw   $177, %xmm2, %xmm2
        paddd     %xmm12, %xmm1
        pshuflw   $177, %xmm2, %xmm2
        movdqa    %xmm6, %xmm0
        pshufhw   $177, %xmm9, %xmm12
        paddd     %xmm6, %xmm2
        paddd     784(%rsp), %xmm1
        pxor      %xmm15, %xmm0
        pshuflw   $177, %xmm12, %xmm9
        pxor      %xmm2, %xmm0
        movdqa    .L_2il0floatpacket.112(%rip), %xmm12
        paddd     %xmm5, %xmm9
        pshufhw   $177, %xmm1, %xmm1
        paddd     %xmm12, %xmm8
        pshuflw   $177, %xmm1, %xmm1
        paddd     %xmm0, %xmm8
        movdqa    %xmm3, %xmm0
        paddd     %xmm3, %xmm1
        pxor      %xmm7, %xmm0
        paddd     %xmm12, %xmm14
        pxor      %xmm1, %xmm0
        paddd     %xmm12, %xmm10
        movdqa    %xmm5, %xmm12
        paddd     %xmm0, %xmm14
        pxor      %xmm4, %xmm12
        paddd     64(%rsp), %xmm8
        pxor      %xmm9, %xmm12
        paddd     96(%rsp), %xmm14
        movdqa    %xmm8, %xmm0
        paddd     %xmm12, %xmm10
        movdqa    %xmm14, %xmm12
        pslld     $23, %xmm0
        psrld     $9, %xmm8
        paddd     80(%rsp), %xmm10
        pslld     $23, %xmm12
        psrld     $9, %xmm14
        por       %xmm8, %xmm0
        por       %xmm14, %xmm12
        movdqa    %xmm10, %xmm14
        pcmpeqd   %xmm8, %xmm8
        paddd     %xmm2, %xmm0
        movdqa    %xmm6, 800(%rsp)
        pslld     $23, %xmm14
        psrld     $9, %xmm10
        pandn     %xmm8, %xmm6
        por       %xmm10, %xmm14
        por       %xmm0, %xmm6
        movdqa    .L_2il0floatpacket.113(%rip), %xmm10
        pxor      %xmm2, %xmm6
        paddd     %xmm10, %xmm15
        paddd     %xmm1, %xmm12
        paddd     %xmm6, %xmm15
        paddd     %xmm10, %xmm7
        paddd     %xmm13, %xmm15
        movdqa    %xmm3, %xmm13
        pandn     %xmm8, %xmm13
        paddd     %xmm9, %xmm14
        por       %xmm12, %xmm13
        paddd     %xmm10, %xmm4
        pxor      %xmm1, %xmm13
        movdqa    %xmm15, %xmm10
        paddd     %xmm13, %xmm7
        pslld     $6, %xmm10
        paddd     %xmm11, %xmm7
        movdqa    %xmm5, %xmm11
        pandn     %xmm8, %xmm11
        psrld     $26, %xmm15
        por       %xmm14, %xmm11
        por       %xmm15, %xmm10
        pxor      %xmm9, %xmm11
        movdqa    %xmm7, %xmm6
        paddd     %xmm11, %xmm4
        paddd     %xmm0, %xmm10
        paddd     448(%rsp), %xmm4
        pslld     $6, %xmm6
        movdqa    %xmm4, %xmm11
        psrld     $26, %xmm4
        pslld     $6, %xmm11
        psrld     $26, %xmm7
        por       %xmm4, %xmm11
        movdqa    %xmm2, %xmm4
        pandn     %xmm8, %xmm4
        por       %xmm7, %xmm6
        movdqa    800(%rsp), %xmm13
        por       %xmm10, %xmm4
        movdqa    .L_2il0floatpacket.114(%rip), %xmm15
        movdqa    %xmm1, %xmm7
        paddd     %xmm12, %xmm6
        paddd     %xmm15, %xmm13
        pxor      %xmm0, %xmm4
        pandn     %xmm8, %xmm7
        paddd     %xmm4, %xmm13
        por       %xmm6, %xmm7
        movdqa    %xmm9, %xmm4
        paddd     %xmm14, %xmm11
        paddd     %xmm15, %xmm3
        pxor      %xmm12, %xmm7
        pandn     %xmm8, %xmm4
        paddd     %xmm7, %xmm3
        por       %xmm11, %xmm4
        paddd     %xmm15, %xmm5
        paddd     608(%rsp), %xmm13
        pxor      %xmm14, %xmm4
        paddd     656(%rsp), %xmm3
        paddd     %xmm4, %xmm5
        movdqa    %xmm13, %xmm4
        movdqa    %xmm3, %xmm7
        pslld     $10, %xmm4
        psrld     $22, %xmm13
        pslld     $10, %xmm7
        psrld     $22, %xmm3
        por       %xmm13, %xmm4
        por       %xmm3, %xmm7
        movdqa    %xmm0, %xmm3
        paddd     %xmm10, %xmm4
        paddd     624(%rsp), %xmm5
        pandn     %xmm8, %xmm3
        movdqa    .L_2il0floatpacket.115(%rip), %xmm15
        movdqa    %xmm5, %xmm13
        por       %xmm4, %xmm3
        pslld     $10, %xmm13
        psrld     $22, %xmm5
        paddd     %xmm15, %xmm2
        pxor      %xmm10, %xmm3
        por       %xmm5, %xmm13
        paddd     %xmm3, %xmm2
        movdqa    %xmm12, %xmm5
        movdqa    %xmm14, %xmm3
        paddd     %xmm6, %xmm7
        paddd     %xmm11, %xmm13
        pandn     %xmm8, %xmm5
        pandn     %xmm8, %xmm3
        por       %xmm7, %xmm5
        por       %xmm13, %xmm3
        paddd     %xmm15, %xmm1
        paddd     752(%rsp), %xmm2
        pxor      %xmm6, %xmm5
        paddd     %xmm15, %xmm9
        pxor      %xmm11, %xmm3
        paddd     %xmm5, %xmm1
        paddd     %xmm3, %xmm9
        movdqa    %xmm2, %xmm3
        psrld     $17, %xmm2
        paddd     720(%rsp), %xmm1
        pslld     $15, %xmm3
        por       %xmm2, %xmm3
        movdqa    %xmm1, %xmm2
        pslld     $15, %xmm2
        psrld     $17, %xmm1
        paddd     736(%rsp), %xmm9
        por       %xmm1, %xmm2
        movdqa    %xmm6, %xmm5
        paddd     %xmm7, %xmm2
        movdqa    %xmm9, %xmm1
        pandn     %xmm8, %xmm5
        movdqa    .L_2il0floatpacket.116(%rip), %xmm15
        pslld     $15, %xmm1
        psrld     $17, %xmm9
        por       %xmm2, %xmm5
        por       %xmm9, %xmm1
        movdqa    %xmm10, %xmm9
        paddd     %xmm15, %xmm12
        pxor      %xmm7, %xmm5
        paddd     %xmm4, %xmm3
        pandn     %xmm8, %xmm9
        paddd     %xmm5, %xmm12
        movdqa    %xmm11, %xmm5
        paddd     %xmm13, %xmm1
        por       %xmm3, %xmm9
        pandn     %xmm8, %xmm5
        paddd     %xmm15, %xmm0
        pxor      %xmm4, %xmm9
        por       %xmm1, %xmm5
        paddd     %xmm9, %xmm0
        paddd     %xmm15, %xmm14
        pxor      %xmm13, %xmm5
        paddd     464(%rsp), %xmm0
        paddd     %xmm5, %xmm14
        paddd     480(%rsp), %xmm12
        movdqa    784(%rsp), %xmm8
..B6.10:
        movdqa    %xmm0, %xmm5
        psrld     $11, %xmm0
        pslld     $21, %xmm5
        movdqa    %xmm4, %xmm15
        por       %xmm0, %xmm5
        movdqa    %xmm12, %xmm0
        paddd     512(%rsp), %xmm14
        pslld     $21, %xmm0
        psrld     $11, %xmm12
        pcmpeqd   %xmm9, %xmm9
        por       %xmm12, %xmm0
        movdqa    %xmm14, %xmm12
        paddd     %xmm3, %xmm5
        pslld     $21, %xmm12
        psrld     $11, %xmm14
        pandn     %xmm9, %xmm15
        por       %xmm14, %xmm12
        por       %xmm5, %xmm15
        movdqa    .L_2il0floatpacket.117(%rip), %xmm14
        pxor      %xmm3, %xmm15
        paddd     %xmm14, %xmm10
        paddd     %xmm14, %xmm6
        paddd     %xmm15, %xmm10
        movdqa    %xmm7, %xmm15
        paddd     %xmm14, %xmm11
        movdqa    %xmm13, %xmm14
        paddd     %xmm2, %xmm0
        paddd     %xmm1, %xmm12
        pandn     %xmm9, %xmm15
        pandn     %xmm9, %xmm14
        por       %xmm0, %xmm15
        por       %xmm12, %xmm14
        paddd     688(%rsp), %xmm10
        pxor      %xmm2, %xmm15
        pxor      %xmm1, %xmm14
        paddd     %xmm15, %xmm6
        paddd     %xmm14, %xmm11
        movdqa    %xmm10, %xmm14
        paddd     672(%rsp), %xmm6
        pslld     $6, %xmm14
        psrld     $26, %xmm10
        movdqa    %xmm3, %xmm15
        por       %xmm10, %xmm14
        movdqa    %xmm6, %xmm10
        paddd     704(%rsp), %xmm11
        pslld     $6, %xmm10
        psrld     $26, %xmm6
        paddd     %xmm5, %xmm14
        por       %xmm6, %xmm10
        movdqa    %xmm11, %xmm6
        pslld     $6, %xmm6
        psrld     $26, %xmm11
        pandn     %xmm9, %xmm15
        por       %xmm11, %xmm6
        movdqa    .L_2il0floatpacket.118(%rip), %xmm11
        por       %xmm14, %xmm15
        paddd     %xmm11, %xmm4
        pxor      %xmm5, %xmm15
        paddd     %xmm15, %xmm4
        paddd     %xmm11, %xmm7
        movdqa    %xmm2, %xmm15
        paddd     %xmm11, %xmm13
        movdqa    %xmm1, %xmm11
        paddd     %xmm0, %xmm10
        paddd     %xmm12, %xmm6
        pandn     %xmm9, %xmm15
        pandn     %xmm9, %xmm11
        por       %xmm10, %xmm15
        por       %xmm6, %xmm11
        pxor      %xmm0, %xmm15
        paddd     336(%rsp), %xmm4
        pxor      %xmm12, %xmm11
        paddd     %xmm15, %xmm7
        paddd     %xmm11, %xmm13
        movdqa    %xmm4, %xmm11
        psrld     $22, %xmm4
        paddd     320(%rsp), %xmm7
        pslld     $10, %xmm11
        por       %xmm4, %xmm11
        movdqa    %xmm7, %xmm4
        paddd     352(%rsp), %xmm13
        pslld     $10, %xmm4
        psrld     $22, %xmm7
        paddd     %xmm14, %xmm11
        por       %xmm7, %xmm4
        movdqa    %xmm13, %xmm7
        pslld     $10, %xmm7
        psrld     $22, %xmm13
        por       %xmm13, %xmm7
        movdqa    %xmm5, %xmm13
        pandn     %xmm9, %xmm13
        paddd     %xmm10, %xmm4
        movdqa    .L_2il0floatpacket.119(%rip), %xmm15
        por       %xmm11, %xmm13
        paddd     %xmm15, %xmm3
        pxor      %xmm14, %xmm13
        paddd     %xmm13, %xmm3
        movdqa    %xmm0, %xmm13
        pandn     %xmm9, %xmm13
        paddd     %xmm15, %xmm2
        por       %xmm4, %xmm13
        paddd     %xmm15, %xmm1
        movdqa    %xmm12, %xmm15
        paddd     %xmm6, %xmm7
        paddd     576(%rsp), %xmm3
        pxor      %xmm10, %xmm13
        pandn     %xmm9, %xmm15
        paddd     %xmm13, %xmm2
        por       %xmm7, %xmm15
        movdqa    %xmm3, %xmm13
        paddd     592(%rsp), %xmm2
        pxor      %xmm6, %xmm15
        pslld     $15, %xmm13
        psrld     $17, %xmm3
        paddd     %xmm15, %xmm1
        por       %xmm3, %xmm13
        movdqa    %xmm2, %xmm3
        psrld     $17, %xmm2
        paddd     560(%rsp), %xmm1
        pslld     $15, %xmm3
        por       %xmm2, %xmm3
        movdqa    %xmm1, %xmm2
        movdqa    %xmm14, %xmm15
        paddd     %xmm11, %xmm13
        pslld     $15, %xmm2
        psrld     $17, %xmm1
        pandn     %xmm9, %xmm15
        por       %xmm1, %xmm2
        movdqa    .L_2il0floatpacket.120(%rip), %xmm1
        por       %xmm13, %xmm15
        paddd     %xmm1, %xmm5
        pxor      %xmm11, %xmm15
        paddd     %xmm15, %xmm5
        movdqa    %xmm10, %xmm15
        paddd     %xmm4, %xmm3
        pandn     %xmm9, %xmm15
        paddd     %xmm1, %xmm0
        por       %xmm3, %xmm15
        paddd     %xmm1, %xmm12
        movdqa    %xmm6, %xmm1
        paddd     %xmm7, %xmm2
        pxor      %xmm4, %xmm15
        pandn     %xmm9, %xmm1
        paddd     %xmm15, %xmm0
        por       %xmm2, %xmm1
        paddd     176(%rsp), %xmm0
        pxor      %xmm7, %xmm1
        paddd     %xmm1, %xmm12
        movdqa    %xmm0, %xmm1
        paddd     208(%rsp), %xmm5
        pslld     $21, %xmm1
        paddd     160(%rsp), %xmm12
        psrld     $11, %xmm0
        movdqa    %xmm5, %xmm15
        por       %xmm0, %xmm1
        movdqa    %xmm12, %xmm0
        pslld     $21, %xmm15
        psrld     $11, %xmm5
        pslld     $21, %xmm0
        psrld     $11, %xmm12
        por       %xmm5, %xmm15
        por       %xmm12, %xmm0
        movdqa    %xmm11, %xmm12
        paddd     %xmm13, %xmm15
        pandn     %xmm9, %xmm12
        movdqa    .L_2il0floatpacket.121(%rip), %xmm5
        por       %xmm15, %xmm12
        paddd     %xmm5, %xmm14
        pxor      %xmm13, %xmm12
        paddd     %xmm12, %xmm14
        movdqa    %xmm4, %xmm12
        paddd     %xmm3, %xmm1
        pandn     %xmm9, %xmm12
        paddd     %xmm5, %xmm10
        por       %xmm1, %xmm12
        paddd     %xmm5, %xmm6
        movdqa    %xmm7, %xmm5
        paddd     432(%rsp), %xmm14
        paddd     %xmm2, %xmm0
        pxor      %xmm3, %xmm12
        pandn     %xmm9, %xmm5
        paddd     %xmm12, %xmm10
        por       %xmm0, %xmm5
        movdqa    %xmm14, %xmm12
        pxor      %xmm2, %xmm5
        paddd     416(%rsp), %xmm10
        pslld     $6, %xmm12
        psrld     $26, %xmm14
        paddd     %xmm5, %xmm6
        por       %xmm14, %xmm12
        movdqa    %xmm10, %xmm14
        paddd     400(%rsp), %xmm6
        pslld     $6, %xmm14
        psrld     $26, %xmm10
        paddd     %xmm15, %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm6, %xmm10
        pslld     $6, %xmm10
        psrld     $26, %xmm6
        por       %xmm6, %xmm10
        movdqa    %xmm13, %xmm6
        pandn     %xmm9, %xmm6
        paddd     %xmm1, %xmm14
        movdqa    .L_2il0floatpacket.122(%rip), %xmm5
        por       %xmm12, %xmm6
        paddd     %xmm5, %xmm11
        pxor      %xmm15, %xmm6
        paddd     %xmm6, %xmm11
        movdqa    %xmm3, %xmm6
        pandn     %xmm9, %xmm6
        paddd     %xmm5, %xmm4
        por       %xmm14, %xmm6
        paddd     %xmm0, %xmm10
        pxor      %xmm1, %xmm6
        paddd     %xmm5, %xmm7
        paddd     %xmm6, %xmm4
        paddd     %xmm8, %xmm4
        movdqa    %xmm2, %xmm8
        paddd     640(%rsp), %xmm11
        pandn     %xmm9, %xmm8
        por       %xmm10, %xmm8
        movdqa    %xmm11, %xmm6
        pxor      %xmm0, %xmm8
        pslld     $10, %xmm6
        psrld     $22, %xmm11
        paddd     %xmm8, %xmm7
        por       %xmm11, %xmm6
        movdqa    %xmm4, %xmm11
        paddd     768(%rsp), %xmm7
        pslld     $10, %xmm11
        psrld     $22, %xmm4
        movdqa    %xmm7, %xmm8
        por       %xmm4, %xmm11
        movdqa    %xmm1, %xmm4
        paddd     %xmm14, %xmm11
        pslld     $10, %xmm8
        psrld     $22, %xmm7
        pandn     %xmm9, %xmm4
        movdqa    .L_2il0floatpacket.123(%rip), %xmm5
        por       %xmm7, %xmm8
        movdqa    %xmm15, %xmm7
        por       %xmm11, %xmm4
        paddd     %xmm12, %xmm6
        pandn     %xmm9, %xmm7
        paddd     %xmm5, %xmm3
        pxor      %xmm14, %xmm4
        por       %xmm6, %xmm7
        paddd     %xmm4, %xmm3
        movdqa    %xmm0, %xmm4
        paddd     %xmm10, %xmm8
        paddd     %xmm5, %xmm13
        pxor      %xmm12, %xmm7
        pandn     %xmm9, %xmm4
        paddd     %xmm7, %xmm13
        por       %xmm8, %xmm4
        paddd     %xmm5, %xmm2
        paddd     256(%rsp), %xmm13
        pxor      %xmm10, %xmm4
        paddd     %xmm4, %xmm2
        movdqa    %xmm13, %xmm4
        paddd     240(%rsp), %xmm3
        pslld     $15, %xmm4
        psrld     $17, %xmm13
        movdqa    %xmm14, %xmm5
        por       %xmm13, %xmm4
        movdqa    %xmm3, %xmm13
        paddd     224(%rsp), %xmm2
        pslld     $15, %xmm13
        psrld     $17, %xmm3
        paddd     %xmm6, %xmm4
        por       %xmm3, %xmm13
        movdqa    %xmm2, %xmm3
        pslld     $15, %xmm3
        psrld     $17, %xmm2
        por       %xmm2, %xmm3
        movdqa    %xmm12, %xmm2
        pandn     %xmm9, %xmm2
        paddd     %xmm11, %xmm13
        movdqa    .L_2il0floatpacket.124(%rip), %xmm7
        por       %xmm4, %xmm2
        paddd     %xmm7, %xmm15
        pxor      %xmm6, %xmm2
        paddd     %xmm2, %xmm15
        movdqa    %xmm10, %xmm2
        paddd     %xmm8, %xmm3
        pandn     %xmm9, %xmm5
        pandn     %xmm9, %xmm2
        por       %xmm13, %xmm5
        por       %xmm3, %xmm2
        paddd     %xmm7, %xmm1
        paddd     496(%rsp), %xmm15
        pxor      %xmm11, %xmm5
        paddd     %xmm7, %xmm0
        pxor      %xmm8, %xmm2
        paddd     %xmm5, %xmm1
        paddd     %xmm2, %xmm0
        movdqa    %xmm15, %xmm2
        psrld     $11, %xmm15
        paddd     528(%rsp), %xmm1
        pslld     $21, %xmm2
        por       %xmm15, %xmm2
        movdqa    %xmm1, %xmm15
        paddd     544(%rsp), %xmm0
        pslld     $21, %xmm15
        psrld     $11, %xmm1
        paddd     %xmm4, %xmm2
        por       %xmm1, %xmm15
        movdqa    %xmm0, %xmm1
        pslld     $21, %xmm1
        psrld     $11, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm6, %xmm0
        pandn     %xmm9, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    .L_2il0floatpacket.125(%rip), %xmm7
        por       %xmm2, %xmm0
        paddd     %xmm7, %xmm12
        pxor      %xmm4, %xmm0
        paddd     %xmm0, %xmm12
        movdqa    %xmm8, %xmm0
        pandn     %xmm9, %xmm0
        movdqa    %xmm11, %xmm5
        por       %xmm1, %xmm0
        paddd     %xmm13, %xmm15
        pandn     %xmm9, %xmm5
        paddd     %xmm7, %xmm10
        pxor      %xmm3, %xmm0
        por       %xmm15, %xmm5
        paddd     %xmm0, %xmm10
        paddd     %xmm7, %xmm14
        paddd     112(%rsp), %xmm12
        pxor      %xmm13, %xmm5
        paddd     128(%rsp), %xmm10
        paddd     %xmm5, %xmm14
        movdqa    %xmm12, %xmm7
        movdqa    %xmm10, %xmm0
        paddd     144(%rsp), %xmm14
        pslld     $6, %xmm7
        psrld     $26, %xmm12
        pslld     $6, %xmm0
        psrld     $26, %xmm10
        por       %xmm12, %xmm7
        movdqa    %xmm14, %xmm5
        por       %xmm10, %xmm0
        movdqa    %xmm4, %xmm10
        paddd     %xmm2, %xmm7
        pslld     $6, %xmm5
        psrld     $26, %xmm14
        pandn     %xmm9, %xmm10
        por       %xmm14, %xmm5
        movdqa    .L_2il0floatpacket.126(%rip), %xmm14
        por       %xmm7, %xmm10
        paddd     %xmm14, %xmm6
        pxor      %xmm2, %xmm10
        paddd     %xmm10, %xmm6
        movdqa    %xmm13, %xmm12
        movdqa    %xmm3, %xmm10
        paddd     %xmm15, %xmm5
        paddd     %xmm1, %xmm0
        pandn     %xmm9, %xmm12
        pandn     %xmm9, %xmm10
        por       %xmm5, %xmm12
        por       %xmm0, %xmm10
        paddd     %xmm14, %xmm11
        paddd     304(%rsp), %xmm6
        pxor      %xmm15, %xmm12
        paddd     %xmm14, %xmm8
        pxor      %xmm1, %xmm10
        paddd     %xmm12, %xmm11
        paddd     %xmm10, %xmm8
        movdqa    %xmm6, %xmm12
        psrld     $22, %xmm6
        paddd     368(%rsp), %xmm11
        pslld     $10, %xmm12
        paddd     384(%rsp), %xmm8
        por       %xmm6, %xmm12
        movdqa    %xmm11, %xmm10
        movdqa    %xmm8, %xmm6
        pslld     $10, %xmm10
        psrld     $22, %xmm11
        pslld     $10, %xmm6
        psrld     $22, %xmm8
        por       %xmm11, %xmm10
        por       %xmm8, %xmm6
        movdqa    %xmm15, %xmm8
        paddd     %xmm5, %xmm10
        pandn     %xmm9, %xmm8
        movdqa    %xmm2, %xmm11
        movdqa    .L_2il0floatpacket.127(%rip), %xmm14
        por       %xmm10, %xmm8
        paddd     %xmm7, %xmm12
        pandn     %xmm9, %xmm11
        paddd     %xmm14, %xmm13
        pxor      %xmm5, %xmm8
        por       %xmm12, %xmm11
        paddd     %xmm8, %xmm13
        movdqa    %xmm1, %xmm8
        paddd     %xmm0, %xmm6
        paddd     %xmm14, %xmm4
        pxor      %xmm7, %xmm11
        pandn     %xmm9, %xmm8
        paddd     %xmm11, %xmm4
        por       %xmm6, %xmm8
        paddd     %xmm14, %xmm3
        paddd     64(%rsp), %xmm4
        pxor      %xmm0, %xmm8
        paddd     %xmm8, %xmm3
        movdqa    %xmm4, %xmm11
        paddd     80(%rsp), %xmm3
        pslld     $15, %xmm11
        psrld     $17, %xmm4
        por       %xmm4, %xmm11
        movdqa    %xmm3, %xmm4
        pslld     $15, %xmm4
        psrld     $17, %xmm3
        por       %xmm3, %xmm4
        movdqa    %xmm7, %xmm3
        paddd     96(%rsp), %xmm13
        paddd     %xmm12, %xmm11
        pandn     %xmm9, %xmm3
        movdqa    %xmm13, %xmm8
        movdqa    .L_2il0floatpacket.128(%rip), %xmm14
        por       %xmm11, %xmm3
        pslld     $15, %xmm8
        psrld     $17, %xmm13
        paddd     %xmm14, %xmm2
        pxor      %xmm12, %xmm3
        por       %xmm13, %xmm8
        paddd     %xmm3, %xmm2
        movdqa    %xmm5, %xmm13
        movdqa    %xmm0, %xmm3
        paddd     %xmm10, %xmm8
        paddd     %xmm6, %xmm4
        pandn     %xmm9, %xmm13
        pandn     %xmm9, %xmm3
        por       %xmm8, %xmm13
        por       %xmm4, %xmm3
        paddd     192(%rsp), %xmm2
        paddd     %xmm14, %xmm15
        pxor      %xmm10, %xmm13
        paddd     %xmm14, %xmm1
        pxor      %xmm6, %xmm3
        paddd     %xmm13, %xmm15
        paddd     %xmm3, %xmm1
        movdqa    %xmm2, %xmm9
        paddd     272(%rsp), %xmm15
        pslld     $21, %xmm9
        paddd     288(%rsp), %xmm1
        psrld     $11, %xmm2
        por       %xmm2, %xmm9
        movdqa    %xmm15, %xmm3
        movdqa    %xmm1, %xmm2
        pslld     $21, %xmm3
        psrld     $11, %xmm15
        pslld     $21, %xmm2
        psrld     $11, %xmm1
        por       %xmm15, %xmm3
        por       %xmm1, %xmm2
        paddd     %xmm11, %xmm9
        paddd     %xmm8, %xmm3
        paddd     %xmm4, %xmm2
        je        ..B6.6
..B6.5:
        movdqa    .L_2il0floatpacket.129(%rip), %xmm1
        movdqa    .L_2il0floatpacket.62(%rip), %xmm13
        paddd     %xmm1, %xmm7
        movdqa    .L_2il0floatpacket.63(%rip), %xmm14
        paddd     %xmm13, %xmm9
        movdqa    .L_2il0floatpacket.64(%rip), %xmm15
        paddd     %xmm14, %xmm11
        paddd     %xmm15, %xmm12
        paddd     %xmm1, %xmm5
        paddd     %xmm13, %xmm3
        paddd     %xmm14, %xmm8
        paddd     %xmm15, %xmm10
        paddd     %xmm1, %xmm0
        paddd     %xmm13, %xmm2
        paddd     %xmm14, %xmm4
        paddd     %xmm15, %xmm6
        movdqa    %xmm7, (%rsi)
        movdqa    %xmm9, 16(%rsi)
        movdqa    %xmm11, 32(%rsi)
        movdqa    %xmm12, 48(%rsi)
        movdqa    %xmm5, 64(%rsi)
        movdqa    %xmm3, 80(%rsi)
        movdqa    %xmm8, 96(%rsi)
        movdqa    %xmm10, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm2, 144(%rsi)
        movdqa    %xmm4, 160(%rsi)
        movdqa    %xmm6, 176(%rsi)
        addq      $840, %rsp
..___tag_value_SSEmd5body.115:
        ret       
..___tag_value_SSEmd5body.116:
..B6.6:
        paddd     (%rsp), %xmm7
        paddd     16(%rsp), %xmm9
        paddd     32(%rsp), %xmm11
        paddd     48(%rsp), %xmm12
        paddd     64(%rsi), %xmm5
        paddd     80(%rsi), %xmm3
        paddd     96(%rsi), %xmm8
        paddd     112(%rsi), %xmm10
        paddd     128(%rsi), %xmm0
        paddd     144(%rsi), %xmm2
        paddd     160(%rsi), %xmm4
        paddd     176(%rsi), %xmm6
        movdqa    %xmm7, (%rsi)
        movdqa    %xmm9, 16(%rsi)
        movdqa    %xmm11, 32(%rsi)
        movdqa    %xmm12, 48(%rsi)
        movdqa    %xmm5, 64(%rsi)
        movdqa    %xmm3, 80(%rsi)
        movdqa    %xmm8, 96(%rsi)
        movdqa    %xmm10, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm2, 144(%rsi)
        movdqa    %xmm4, 160(%rsi)
        movdqa    %xmm6, 176(%rsi)
..B6.7:
        addq      $840, %rsp
..___tag_value_SSEmd5body.117:
        ret       
        .align    16,0x90
..___tag_value_SSEmd5body.118:
	.type	SSEmd5body,@function
	.size	SSEmd5body,.-SSEmd5body
	.data
# -- End  SSEmd5body
	.text
# -- Begin  md5cryptsse
       .align    16,0x90
	.globl md5cryptsse
md5cryptsse:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B7.1:
..___tag_value_md5cryptsse.119:
        pushq     %r12
..___tag_value_md5cryptsse.121:
        pushq     %r13
..___tag_value_md5cryptsse.123:
        pushq     %r14
..___tag_value_md5cryptsse.125:
        pushq     %r15
..___tag_value_md5cryptsse.127:
        pushq     %rbx
..___tag_value_md5cryptsse.129:
        pushq     %rbp
..___tag_value_md5cryptsse.131:
        subq      $6808, %rsp
..___tag_value_md5cryptsse.133:
        movq      %rdx, %r14
        movq      %rsi, %r15
        movq      %rdi, %rbp
        xorl      %esi, %esi
        lea       6304(%rsp), %rdi
        movl      $192, %edx
        movl      %ecx, %ebx
..___tag_value_md5cryptsse.134:
        call      memset
..___tag_value_md5cryptsse.135:
..B7.2:
        xorl      %esi, %esi
        lea       (%rsp), %rdi
        movl      $6144, %edx
..___tag_value_md5cryptsse.136:
        call      memset
..___tag_value_md5cryptsse.137:
..B7.3:
        movq      %r15, %rdi
..___tag_value_md5cryptsse.138:
        call      strlen
..___tag_value_md5cryptsse.139:
..B7.206:
        movq      %rax, %rcx
..B7.4:
        movl      %ecx, %eax
        xorl      %edx, %edx
        movl      %ecx, %esi
        movl      %eax, %ecx
        shrl      $1, %ecx
        movl      %eax, %r12d
        movl      %ecx, 6744(%rsp)
        movq      %rsi, 6752(%rsp)
        lea       (,%rax,8), %edi
        movl      %edi, 6760(%rsp)
        movq      %rbp, 6768(%rsp)
        movq      %r15, 6776(%rsp)
        movq      %r14, 6296(%rsp)
        movl      %ebx, 6784(%rsp)
        movl      %edx, %ebx
..B7.5:
        movl      %ebx, %r14d
        shlq      $4, %r14
        addq      6768(%rsp), %r14
        movq      %r14, %rdi
..___tag_value_md5cryptsse.140:
        call      strlen
..___tag_value_md5cryptsse.141:
..B7.207:
        movq      %rax, 6736(%rsp)
..B7.6:
        movl      %ebx, %ebp
        shrl      $2, %ebp
        movl      %ebp, %edi
        shll      $8, %edi
        movq      6736(%rsp), %r15
        testl     %r15d, %r15d
        lea       (%rsp,%rdi), %rsi
        jbe       ..B7.13
..B7.7:
        movl      %r15d, %ecx
        movl      %ebx, %r13d
        shrl      $1, %ecx
        xorl      %edx, %edx
        andl      $3, %r13d
        movl      $1, %r8d
        testl     %ecx, %ecx
        jbe       ..B7.11
..B7.9:
        lea       16(%rdx,%rdx), %r10d
        movl      %r10d, %r9d
        andl      $3, %r10d
        andl      $-4, %r9d
        lea       (%rdx,%rdx), %r8d
        shll      $2, %r9d
        lea       (%r9,%r13,4), %r11d
        addl      %r10d, %r11d
        lea       17(%rdx,%rdx), %r10d
        movl      %r10d, %r9d
        andl      $3, %r10d
        andl      $-4, %r9d
        shll      $2, %r9d
        movb      (%r8,%r14), %r8b
        movb      %r8b, (%r11,%rsi)
        lea       1(%rdx,%rdx), %r8d
        lea       (%r9,%r13,4), %r9d
        addl      %r10d, %r9d
        incl      %edx
        cmpl      %ecx, %edx
        movb      (%r8,%r14), %r8b
        movb      %r8b, (%r9,%rsi)
        jb        ..B7.9
..B7.10:
        lea       1(%rdx,%rdx), %r8d
..B7.11:
        cmpl      %r15d, %r8d
        ja        ..B7.14
..B7.12:
        lea       15(%r8), %ecx
        decl      %r8d
        movl      %ecx, %r9d
        andl      $3, %ecx
        andl      $-4, %r9d
        addl      %r13d, %r9d
        lea       (%rcx,%r9,4), %r10d
        movb      (%r8,%r14), %r11b
        movb      %r11b, (%r10,%rsi)
        jmp       ..B7.14
..B7.13:
        movl      %ebx, %r13d
        andl      $3, %r13d
..B7.14:
        lea       16(%r15), %r8d
        movl      %r8d, %ecx
        andl      $-4, %r8d
        andl      $3, %ecx
        addl      %r13d, %r8d
        testl     %r15d, %r15d
        lea       (%rcx,%r8,4), %r9d
        movb      $128, (%r9,%rsi)
        jbe       ..B7.21
..B7.15:
        movl      %r15d, %r8d
        xorl      %r10d, %r10d
        shrl      $1, %r8d
        movl      $1, %ecx
        testl     %r8d, %r8d
        jbe       ..B7.19
..B7.17:
        lea       (%r10,%r10), %eax
        movl      %eax, %r11d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %eax, %ecx
        andl      $3, %eax
        lea       (%r11,%r13,4), %r11d
        addl      %eax, %r11d
        movb      (%rcx,%r14), %cl
        movb      %cl, 768(%r11,%rsi)
        lea       1(%r10,%r10), %r11d
        movl      %r11d, %ecx
        incl      %r10d
        andl      $-4, %ecx
        shll      $2, %ecx
        movl      %r11d, %edx
        andl      $3, %r11d
        lea       (%rcx,%r13,4), %ecx
        addl      %r11d, %ecx
        cmpl      %r8d, %r10d
        movb      (%rdx,%r14), %r11b
        movb      %r11b, 768(%rcx,%rsi)
        jb        ..B7.17
..B7.18:
        lea       1(%r10,%r10), %ecx
..B7.19:
        cmpl      %r15d, %ecx
        ja        ..B7.215
..B7.20:
        decl      %ecx
        lea       1536(%rsp,%rdi), %rax
        movl      %ecx, %r8d
        andl      $-4, %r8d
        movl      %ecx, %r10d
        andl      $3, %ecx
        addl      %r13d, %r8d
        movb      (%r10,%r14), %r11b
        lea       (%rcx,%r8,4), %ecx
        movb      %r11b, 768(%rcx,%rsi)
        movb      $128, 768(%r9,%rsi)
        jmp       ..B7.22
..B7.21:
        movb      $128, 768(%r9,%rsi)
        lea       1536(%rsp,%rdi), %rax
        jbe       ..B7.34
..B7.22:
        movl      %r15d, %r8d
        xorl      %r9d, %r9d
        shrl      $1, %r8d
        movl      $1, %ecx
        testl     %r8d, %r8d
        jbe       ..B7.26
..B7.24:
        lea       (%r9,%r9), %r11d
        movl      %r11d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r11d, %ecx
        andl      $3, %r11d
        lea       (%r10,%r13,4), %r10d
        addl      %r11d, %r10d
        movb      (%rcx,%r14), %cl
        movb      %cl, (%r10,%rax)
        lea       1(%r9,%r9), %ecx
        movl      %ecx, %r11d
        incl      %r9d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %ecx, %edx
        andl      $3, %ecx
        lea       (%r11,%r13,4), %r10d
        addl      %ecx, %r10d
        cmpl      %r8d, %r9d
        movb      (%rdx,%r14), %cl
        movb      %cl, (%r10,%rax)
        jb        ..B7.24
..B7.25:
        lea       1(%r9,%r9), %ecx
..B7.26:
        cmpl      %r15d, %ecx
        ja        ..B7.28
..B7.27:
        decl      %ecx
        movl      %ecx, %r8d
        andl      $-4, %r8d
        movl      %ecx, %r9d
        andl      $3, %ecx
        addl      %r13d, %r8d
        movb      (%r9,%r14), %r10b
        lea       (%rcx,%r8,4), %ecx
        movb      %r10b, (%rcx,%rax)
..B7.28:
        movl      %r15d, %r8d
        xorl      %r9d, %r9d
        shrl      $1, %r8d
        movl      $1, %ecx
        testl     %r8d, %r8d
        jbe       ..B7.32
..B7.30:
        lea       (%r15,%r9,2), %r10d
        movl      %r10d, %r11d
        lea       (%r9,%r9), %ecx
        andl      $-4, %r11d
        shll      $2, %r11d
        lea       (%r11,%r13,4), %edx
        movl      %r10d, %r11d
        andl      $3, %r11d
        incl      %r10d
        addl      %r11d, %edx
        movl      %r10d, %r11d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        movb      (%rcx,%r14), %cl
        movb      %cl, (%rdx,%rax)
        lea       1(%r9,%r9), %edx
        lea       (%r11,%r13,4), %ecx
        addl      %r10d, %ecx
        incl      %r9d
        cmpl      %r8d, %r9d
        movb      (%rdx,%r14), %r10b
        movb      %r10b, (%rcx,%rax)
        jb        ..B7.30
..B7.31:
        lea       1(%r9,%r9), %ecx
..B7.32:
        cmpl      %r15d, %ecx
        ja        ..B7.34
..B7.33:
        lea       -1(%rcx,%r15), %r8d
        decl      %ecx
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        addl      %r13d, %r9d
        lea       (%r8,%r9,4), %r10d
        movb      (%rcx,%r14), %r11b
        movb      %r11b, (%r10,%rax)
..B7.34:
        lea       16(%r15,%r15), %r8d
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        lea       (%r15,%r15), %ecx
        addl      %r13d, %r9d
        testl     %r15d, %r15d
        lea       (%r8,%r9,4), %r8d
        movb      $128, 1536(%r8,%rsi)
        jbe       ..B7.47
..B7.35:
        movl      %r15d, %eax
        xorl      %edx, %edx
        shrl      $1, %eax
        movl      $1, %r9d
        testl     %eax, %eax
        jbe       ..B7.39
..B7.37:
        lea       16(%rdx,%rdx), %r9d
        movl      %r9d, %r10d
        lea       (%rdx,%rdx), %r11d
        andl      $-4, %r10d
        andl      $3, %r9d
        shll      $2, %r10d
        lea       (%r10,%r13,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%r14), %r9b
        movb      %r9b, 2304(%r10,%rsi)
        lea       17(%rdx,%rdx), %r10d
        movl      %r10d, %r11d
        lea       1(%rdx,%rdx), %r9d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        incl      %edx
        lea       (%r11,%r13,4), %r11d
        addl      %r10d, %r11d
        cmpl      %eax, %edx
        movb      (%r9,%r14), %r9b
        movb      %r9b, 2304(%r11,%rsi)
        jb        ..B7.37
..B7.38:
        lea       1(%rdx,%rdx), %r9d
..B7.39:
        cmpl      %r15d, %r9d
        ja        ..B7.41
..B7.40:
        lea       15(%r9), %r10d
        decl      %r9d
        movl      %r10d, %r11d
        andl      $3, %r10d
        andl      $-4, %r11d
        addl      %r13d, %r11d
        lea       (%r10,%r11,4), %r10d
        movb      (%r9,%r14), %r9b
        movb      %r9b, 2304(%r10,%rsi)
..B7.41:
        movl      %r15d, %eax
        xorl      %edx, %edx
        shrl      $1, %eax
        movl      $1, %r9d
        testl     %eax, %eax
        jbe       ..B7.45
..B7.42:
        movl      %r12d, 6728(%rsp)
..B7.43:
        lea       (%r15,%rdx,2), %r12d
        lea       16(%r12), %r11d
        addl      $17, %r12d
        movl      %r11d, %r9d
        lea       (%rdx,%rdx), %r10d
        andl      $-4, %r9d
        andl      $3, %r11d
        shll      $2, %r9d
        lea       (%r9,%r13,4), %r9d
        addl      %r11d, %r9d
        movb      (%r10,%r14), %r11b
        movl      %r12d, %r10d
        andl      $-4, %r10d
        andl      $3, %r12d
        shll      $2, %r10d
        movb      %r11b, 2304(%r9,%rsi)
        lea       1(%rdx,%rdx), %r9d
        lea       (%r10,%r13,4), %r11d
        addl      %r12d, %r11d
        incl      %edx
        cmpl      %eax, %edx
        movb      (%r9,%r14), %r12b
        movb      %r12b, 2304(%r11,%rsi)
        jb        ..B7.43
..B7.44:
        movl      6728(%rsp), %r12d
        lea       1(%rdx,%rdx), %r9d
..B7.45:
        cmpl      %r15d, %r9d
        ja        ..B7.214
..B7.46:
        lea       15(%r9,%r15), %r10d
        decl      %r9d
        movl      %r10d, %r11d
        andl      $3, %r10d
        andl      $-4, %r11d
        addl      %r13d, %r11d
        lea       (%r10,%r11,4), %r10d
        movb      (%r9,%r14), %r9b
        movb      %r9b, 2304(%r10,%rsi)
        movb      $128, 2304(%r8,%rsi)
        lea       3072(%rsp,%rdi), %r8
        jmp       ..B7.48
..B7.47:
        movb      $128, 2304(%r8,%rsi)
        lea       3072(%rsp,%rdi), %r8
        jbe       ..B7.54
..B7.48:
        movl      %r15d, %edx
        xorl      %eax, %eax
        shrl      $1, %edx
        movl      $1, %r9d
        testl     %edx, %edx
        jbe       ..B7.52
..B7.50:
        lea       (%rax,%rax), %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r9d, %r11d
        andl      $3, %r9d
        lea       (%r10,%r13,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%r14), %r11b
        movb      %r11b, (%r10,%r8)
        lea       1(%rax,%rax), %r10d
        movl      %r10d, %r11d
        incl      %eax
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %r9d
        andl      $3, %r10d
        lea       (%r11,%r13,4), %r11d
        addl      %r10d, %r11d
        cmpl      %edx, %eax
        movb      (%r9,%r14), %r9b
        movb      %r9b, (%r11,%r8)
        jb        ..B7.50
..B7.51:
        lea       1(%rax,%rax), %r9d
..B7.52:
        cmpl      %r15d, %r9d
        ja        ..B7.54
..B7.53:
        decl      %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        movl      %r9d, %r11d
        addl      %r13d, %r10d
        andl      $3, %r9d
        lea       (%r9,%r10,4), %r9d
        movb      (%r11,%r14), %r10b
        movb      %r10b, (%r9,%r8)
..B7.54:
        testl     %r12d, %r12d
        jbe       ..B7.61
..B7.55:
        xorl      %eax, %eax
        movl      $1, %edx
        cmpl      $0, 6744(%rsp)
        jbe       ..B7.59
..B7.56:
        movl      %ebx, 6696(%rsp)
        movl      %r12d, 6728(%rsp)
        movl      6744(%rsp), %r9d
        movq      6776(%rsp), %r10
..B7.57:
        lea       (%r15,%rax,2), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %edx
        andl      $-4, %r12d
        lea       (%rax,%rax), %ebx
        shll      $2, %r12d
        andl      $3, %edx
        incl      %r11d
        lea       (%r12,%r13,4), %r12d
        addl      %edx, %r12d
        lea       1(%rax,%rax), %edx
        incl      %eax
        movb      (%rbx,%r10), %bl
        movb      %bl, (%r12,%r8)
        movl      %r11d, %ebx
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%r13,4), %r12d
        addl      %r11d, %r12d
        cmpl      %r9d, %eax
        movb      (%rdx,%r10), %r11b
        movb      %r11b, (%r12,%r8)
        jb        ..B7.57
..B7.58:
        movl      6696(%rsp), %ebx
        lea       1(%rax,%rax), %edx
        movl      6728(%rsp), %r12d
..B7.59:
        cmpl      %r12d, %edx
        ja        ..B7.61
..B7.60:
        lea       -1(%rdx,%r15), %r9d
        decl      %edx
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %r13d, %r10d
        lea       (%r9,%r10,4), %r11d
        movq      6776(%rsp), %r9
        movb      (%rdx,%r9), %r9b
        movb      %r9b, (%r11,%r8)
..B7.61:
        lea       16(%r12,%r15), %edx
        movl      %edx, %r10d
        movl      %edx, %r9d
        andl      $-4, %r10d
        andl      $3, %r9d
        addl      %r13d, %r10d
        lea       (%r12,%r15), %r8d
        movl      %r8d, 6792(%rsp)
        testl     %r12d, %r12d
        lea       (%r9,%r10,4), %eax
        movb      $128, 3072(%rax,%rsi)
        jbe       ..B7.71
..B7.62:
        xorl      %r9d, %r9d
        movl      $1, %r8d
        cmpl      $0, 6744(%rsp)
        jbe       ..B7.66
..B7.63:
        movl      %ebx, 6696(%rsp)
        movl      %r12d, 6728(%rsp)
        movl      6744(%rsp), %ebx
        movq      6776(%rsp), %r8
..B7.64:
        lea       16(%r9,%r9), %r10d
        movl      %r10d, %r11d
        lea       (%r9,%r9), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%r13,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%r8), %r10b
        movb      %r10b, 3840(%r11,%rsi)
        lea       17(%r9,%r9), %r11d
        movl      %r11d, %r12d
        lea       1(%r9,%r9), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %r9d
        lea       (%r12,%r13,4), %r12d
        addl      %r11d, %r12d
        cmpl      %ebx, %r9d
        movb      (%r10,%r8), %r10b
        movb      %r10b, 3840(%r12,%rsi)
        jb        ..B7.64
..B7.65:
        movl      6696(%rsp), %ebx
        lea       1(%r9,%r9), %r8d
        movl      6728(%rsp), %r12d
..B7.66:
        cmpl      %r12d, %r8d
        ja        ..B7.69
..B7.67:
        lea       15(%r8), %r9d
        decl      %r8d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %r13d, %r10d
        testl     %r15d, %r15d
        lea       (%r9,%r10,4), %r11d
        movq      6776(%rsp), %r9
        movb      (%r8,%r9), %r8b
        movb      %r8b, 3840(%r11,%rsi)
        ja        ..B7.72
..B7.68:
        movb      $128, 3840(%rax,%rsi)
        lea       4608(%rsp,%rdi), %r9
        jmp       ..B7.79
..B7.69:
        testl     %r15d, %r15d
        ja        ..B7.72
..B7.70:
        movb      $128, 3840(%rax,%rsi)
        lea       4608(%rsp,%rdi), %r9
        jmp       ..B7.79
..B7.71:
        testl     %r15d, %r15d
        jbe       ..B7.85
..B7.72:
        movl      %r15d, %r9d
        xorl      %r8d, %r8d
        shrl      $1, %r9d
        movl      $1, %r10d
        testl     %r9d, %r9d
        jbe       ..B7.76
..B7.73:
        movl      %ebp, 6704(%rsp)
        movl      %ebx, 6696(%rsp)
..B7.74:
        lea       (%r12,%r8,2), %r11d
        lea       16(%r11), %r10d
        addl      $17, %r11d
        movl      %r10d, %ebx
        lea       (%r8,%r8), %ebp
        andl      $-4, %ebx
        andl      $3, %r10d
        shll      $2, %ebx
        lea       (%rbx,%r13,4), %ebx
        addl      %r10d, %ebx
        movb      (%rbp,%r14), %r10b
        movl      %r11d, %ebp
        andl      $-4, %ebp
        andl      $3, %r11d
        shll      $2, %ebp
        movb      %r10b, 3840(%rbx,%rsi)
        lea       1(%r8,%r8), %ebx
        lea       (%rbp,%r13,4), %r10d
        addl      %r11d, %r10d
        incl      %r8d
        cmpl      %r9d, %r8d
        movb      (%rbx,%r14), %r11b
        movb      %r11b, 3840(%r10,%rsi)
        jb        ..B7.74
..B7.75:
        movl      6704(%rsp), %ebp
        lea       1(%r8,%r8), %r10d
        movl      6696(%rsp), %ebx
..B7.76:
        cmpl      %r15d, %r10d
        ja        ..B7.78
..B7.77:
        lea       15(%r12,%r10), %r8d
        decl      %r10d
        movl      %r8d, %r9d
        andl      $3, %r8d
        andl      $-4, %r9d
        addl      %r13d, %r9d
        movb      (%r10,%r14), %r10b
        lea       (%r8,%r9,4), %r11d
        movb      %r10b, 3840(%r11,%rsi)
..B7.78:
        movb      $128, 3840(%rax,%rsi)
        lea       4608(%rsp,%rdi), %r9
        testl     %r12d, %r12d
        jbe       ..B7.212
..B7.79:
        xorl      %r8d, %r8d
        movl      $1, %edi
        cmpl      $0, 6744(%rsp)
        jbe       ..B7.83
..B7.80:
        movl      %r12d, 6728(%rsp)
        movl      6744(%rsp), %eax
        movq      6776(%rsp), %rdi
..B7.81:
        lea       16(%r8,%r8), %r10d
        movl      %r10d, %r11d
        lea       (%r8,%r8), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%r13,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%rdi), %r10b
        movb      %r10b, (%r11,%r9)
        lea       17(%r8,%r8), %r11d
        movl      %r11d, %r12d
        lea       1(%r8,%r8), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %r8d
        lea       (%r12,%r13,4), %r12d
        addl      %r11d, %r12d
        cmpl      %eax, %r8d
        movb      (%r10,%rdi), %r10b
        movb      %r10b, (%r12,%r9)
        jb        ..B7.81
..B7.82:
        movl      6728(%rsp), %r12d
        lea       1(%r8,%r8), %edi
..B7.83:
        cmpl      %r12d, %edi
        ja        ..B7.212
..B7.84:
        lea       15(%rdi), %r8d
        decl      %edi
        movl      %r8d, %r10d
        andl      $3, %r8d
        andl      $-4, %r10d
        addl      %r13d, %r10d
        testl     %r15d, %r15d
        lea       (%r8,%r10,4), %r11d
        movq      6776(%rsp), %r8
        movb      (%rdi,%r8), %dil
        movb      %dil, (%r11,%r9)
        ja        ..B7.87
        jmp       ..B7.99
..B7.85:
        movb      $128, 3840(%rax,%rsi)
        lea       4608(%rsp,%rdi), %r9
..B7.86:
        jbe       ..B7.99
..B7.87:
        movl      %r15d, %eax
        xorl      %edi, %edi
        shrl      $1, %eax
        movl      $1, %r8d
        testl     %eax, %eax
        jbe       ..B7.91
..B7.88:
        movl      %ebx, 6696(%rsp)
..B7.89:
        lea       (%r12,%rdi,2), %r11d
        lea       16(%r11), %r10d
        addl      $17, %r11d
        movl      %r10d, %ebx
        lea       (%rdi,%rdi), %r8d
        andl      $-4, %ebx
        andl      $3, %r10d
        shll      $2, %ebx
        lea       (%rbx,%r13,4), %ebx
        addl      %r10d, %ebx
        movb      (%r8,%r14), %r10b
        movl      %r11d, %r8d
        andl      $-4, %r8d
        andl      $3, %r11d
        shll      $2, %r8d
        movb      %r10b, (%rbx,%r9)
        lea       1(%rdi,%rdi), %ebx
        lea       (%r8,%r13,4), %r10d
        addl      %r11d, %r10d
        incl      %edi
        cmpl      %eax, %edi
        movb      (%rbx,%r14), %r11b
        movb      %r11b, (%r10,%r9)
        jb        ..B7.89
..B7.90:
        movl      6696(%rsp), %ebx
        lea       1(%rdi,%rdi), %r8d
..B7.91:
        cmpl      %r15d, %r8d
        ja        ..B7.93
..B7.92:
        lea       15(%r12,%r8), %edi
        decl      %r8d
        movl      %edi, %r10d
        andl      $3, %edi
        andl      $-4, %r10d
        addl      %r13d, %r10d
        lea       (%rdi,%r10,4), %r11d
        movb      (%r8,%r14), %dil
        movb      %dil, (%r11,%r9)
..B7.93:
        movl      %r15d, %r11d
        xorl      %r10d, %r10d
        shrl      $1, %r11d
        movl      $1, %edi
        testl     %r11d, %r11d
        jbe       ..B7.97
..B7.94:
        movl      %r12d, 6728(%rsp)
..B7.95:
        lea       (%rdx,%r10,2), %r8d
        movl      %r8d, %r12d
        movl      %r8d, %eax
        andl      $-4, %r12d
        lea       (%r10,%r10), %edi
        shll      $2, %r12d
        andl      $3, %eax
        incl      %r8d
        lea       (%r12,%r13,4), %r12d
        addl      %eax, %r12d
        lea       1(%r10,%r10), %eax
        incl      %r10d
        movb      (%rdi,%r14), %dil
        movb      %dil, (%r12,%r9)
        movl      %r8d, %edi
        andl      $-4, %edi
        andl      $3, %r8d
        shll      $2, %edi
        lea       (%rdi,%r13,4), %r12d
        addl      %r8d, %r12d
        cmpl      %r11d, %r10d
        movb      (%rax,%r14), %r8b
        movb      %r8b, (%r12,%r9)
        jb        ..B7.95
..B7.96:
        movl      6728(%rsp), %r12d
        lea       1(%r10,%r10), %edi
..B7.97:
        cmpl      %r15d, %edi
        ja        ..B7.99
..B7.98:
        lea       -1(%rdx,%rdi), %r8d
        decl      %edi
        movl      %r8d, %r10d
        andl      $3, %r8d
        andl      $-4, %r10d
        addl      %r13d, %r10d
        movb      (%rdi,%r14), %dil
        lea       (%r8,%r10,4), %r11d
        movb      %dil, (%r11,%r9)
..B7.99:
        lea       16(%r12,%r15,2), %edi
        movl      %edi, %r8d
        andl      $3, %edi
        andl      $-4, %r8d
        addl      %r13d, %r8d
        testl     %r15d, %r15d
        lea       (%rdi,%r8,4), %eax
        movb      $128, 4608(%rax,%rsi)
        jbe       ..B7.107
..B7.100:
        movl      %r15d, %r9d
        xorl      %r8d, %r8d
        shrl      $1, %r9d
        movl      $1, %edi
        testl     %r9d, %r9d
        jbe       ..B7.104
..B7.102:
        lea       (%r8,%r8), %r11d
        movl      %r11d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r11d, %edi
        andl      $3, %r11d
        lea       (%r10,%r13,4), %r10d
        addl      %r11d, %r10d
        movb      (%rdi,%r14), %dil
        movb      %dil, 5376(%r10,%rsi)
        lea       1(%r8,%r8), %edi
        movl      %edi, %r11d
        incl      %r8d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %edi, %edx
        andl      $3, %edi
        lea       (%r11,%r13,4), %r10d
        addl      %edi, %r10d
        cmpl      %r9d, %r8d
        movb      (%rdx,%r14), %dil
        movb      %dil, 5376(%r10,%rsi)
        jb        ..B7.102
..B7.103:
        lea       1(%r8,%r8), %edi
..B7.104:
        cmpl      %r15d, %edi
        ja        ..B7.106
..B7.105:
        decl      %edi
        movl      %edi, %r8d
        andl      $-4, %r8d
        movl      %edi, %r9d
        addl      %r13d, %r8d
        andl      $3, %edi
        testl     %r12d, %r12d
        movb      (%r9,%r14), %r10b
        lea       (%rdi,%r8,4), %edi
        movb      %r10b, 5376(%rdi,%rsi)
        ja        ..B7.108
        jmp       ..B7.115
..B7.106:
        testl     %r12d, %r12d
        ja        ..B7.108
        jmp       ..B7.115
..B7.107:
        testl     %r12d, %r12d
        jbe       ..B7.121
..B7.108:
        xorl      %r11d, %r11d
        movl      $1, %edi
        cmpl      $0, 6744(%rsp)
        jbe       ..B7.112
..B7.109:
        movl      %r12d, 6728(%rsp)
        movl      6744(%rsp), %r8d
        movq      6776(%rsp), %r9
..B7.110:
        lea       (%r15,%r11,2), %r10d
        movl      %r10d, %r12d
        lea       (%r11,%r11), %edi
        andl      $-4, %r12d
        shll      $2, %r12d
        lea       (%r12,%r13,4), %edx
        movl      %r10d, %r12d
        andl      $3, %r12d
        incl      %r10d
        addl      %r12d, %edx
        movl      %r10d, %r12d
        andl      $-4, %r12d
        andl      $3, %r10d
        shll      $2, %r12d
        movb      (%rdi,%r9), %dil
        movb      %dil, 5376(%rdx,%rsi)
        lea       1(%r11,%r11), %edx
        lea       (%r12,%r13,4), %edi
        addl      %r10d, %edi
        incl      %r11d
        cmpl      %r8d, %r11d
        movb      (%rdx,%r9), %r10b
        movb      %r10b, 5376(%rdi,%rsi)
        jb        ..B7.110
..B7.111:
        movl      6728(%rsp), %r12d
        lea       1(%r11,%r11), %edi
..B7.112:
        cmpl      %r12d, %edi
        ja        ..B7.114
..B7.113:
        movq      6776(%rsp), %r11
        lea       -1(%rdi,%r15), %r8d
        movl      %r8d, %r9d
        decl      %edi
        andl      $-4, %r9d
        andl      $3, %r8d
        addl      %r13d, %r9d
        lea       (%r8,%r9,4), %r10d
        movb      (%rdi,%r11), %dil
        movb      %dil, 5376(%r10,%rsi)
..B7.114:
        testl     %r15d, %r15d
        jbe       ..B7.121
..B7.115:
        movl      %r15d, %r10d
        xorl      %r11d, %r11d
        shrl      $1, %r10d
        movl      $1, %r8d
        testl     %r10d, %r10d
        jbe       ..B7.119
..B7.116:
        movl      %r12d, 6728(%rsp)
        movl      6792(%rsp), %r8d
..B7.117:
        lea       (%r8,%r11,2), %r9d
        movl      %r9d, %r12d
        lea       (%r11,%r11), %edi
        andl      $-4, %r12d
        shll      $2, %r12d
        lea       (%r12,%r13,4), %edx
        movl      %r9d, %r12d
        andl      $3, %r12d
        incl      %r9d
        addl      %r12d, %edx
        movl      %r9d, %r12d
        andl      $-4, %r12d
        andl      $3, %r9d
        shll      $2, %r12d
        movb      (%rdi,%r14), %dil
        movb      %dil, 5376(%rdx,%rsi)
        lea       1(%r11,%r11), %edx
        lea       (%r12,%r13,4), %edi
        addl      %r9d, %edi
        incl      %r11d
        cmpl      %r10d, %r11d
        movb      (%rdx,%r14), %r9b
        movb      %r9b, 5376(%rdi,%rsi)
        jb        ..B7.117
..B7.118:
        movl      6728(%rsp), %r12d
        lea       1(%r11,%r11), %r8d
..B7.119:
        cmpl      %r15d, %r8d
        ja        ..B7.121
..B7.120:
        movl      6792(%rsp), %edi
        lea       -1(%rdi,%r8), %r9d
        decl      %r8d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %r13d, %r10d
        lea       (%r9,%r10,4), %r11d
        movb      (%r8,%r14), %dil
        movb      %dil, 5376(%r11,%rsi)
..B7.121:
        movb      $128, 5376(%rax,%rsi)
        movl      %ebp, %esi
        shll      $6, %esi
        lea       6496(%rsp), %rdi
        lea       128(,%r15,8), %r9d
        lea       128(,%rcx,8), %r10d
        lea       56(%r13,%rsi), %r8d
        movl      6760(%rsp), %esi
        lea       128(%rsi,%r15,8), %r11d
        lea       128(%rsi,%rcx,8), %ecx
        movl      %r9d, (%rsp,%r8,4)
        movl      %r9d, 768(%rsp,%r8,4)
        movl      %r10d, 1536(%rsp,%r8,4)
        movl      %r10d, 2304(%rsp,%r8,4)
        movl      %r11d, 3072(%rsp,%r8,4)
        movl      %r11d, 3840(%rsp,%r8,4)
        movl      %ecx, 4608(%rsp,%r8,4)
        movl      %ecx, 5376(%rsp,%r8,4)
..___tag_value_md5cryptsse.142:
        call      MD5_Init
..___tag_value_md5cryptsse.143:
..B7.122:
        movl      6736(%rsp), %edx
        lea       6496(%rsp), %rdi
        movq      %r14, %rsi
        movq      %rdx, 6800(%rsp)
..___tag_value_md5cryptsse.144:
        call      MD5_Update
..___tag_value_md5cryptsse.145:
..B7.123:
        cmpl      $1, 6784(%rsp)
        je        ..B7.203
..B7.124:
        movl      $.L_2__STRING.2, %esi
        lea       6496(%rsp), %rdi
        movl      $3, %edx
..___tag_value_md5cryptsse.146:
        call      MD5_Update
..___tag_value_md5cryptsse.147:
..B7.125:
        movq      6776(%rsp), %rsi
        lea       6496(%rsp), %rdi
        movq      6752(%rsp), %rdx
..___tag_value_md5cryptsse.148:
        call      MD5_Update
..___tag_value_md5cryptsse.149:
..B7.126:
        lea       6144(%rsp), %rdi
..___tag_value_md5cryptsse.150:
        call      MD5_Init
..___tag_value_md5cryptsse.151:
..B7.127:
        movq      %r14, %rsi
        lea       6144(%rsp), %rdi
        movq      6800(%rsp), %rdx
..___tag_value_md5cryptsse.152:
        call      MD5_Update
..___tag_value_md5cryptsse.153:
..B7.128:
        movq      6776(%rsp), %rsi
        lea       6144(%rsp), %rdi
        movq      6752(%rsp), %rdx
..___tag_value_md5cryptsse.154:
        call      MD5_Update
..___tag_value_md5cryptsse.155:
..B7.129:
        movq      %r14, %rsi
        lea       6144(%rsp), %rdi
        movq      6800(%rsp), %rdx
..___tag_value_md5cryptsse.156:
        call      MD5_Update
..___tag_value_md5cryptsse.157:
..B7.130:
        lea       6712(%rsp), %rdi
        lea       6144(%rsp), %rsi
..___tag_value_md5cryptsse.158:
        call      MD5_Final
..___tag_value_md5cryptsse.159:
..B7.131:
        movq      6800(%rsp), %rdx
        lea       6496(%rsp), %rdi
        lea       6712(%rsp), %rsi
..___tag_value_md5cryptsse.160:
        call      MD5_Update
..___tag_value_md5cryptsse.161:
..B7.132:
        testl     %r15d, %r15d
        movl      %r15d, 6648(%rsp,%rbx,4)
        je        ..B7.139
..B7.134:
        testl     $1, %r15d
        je        ..B7.136
..B7.135:
        movl      $.L_2__STRING.3, %esi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.162:
        call      MD5_Update
..___tag_value_md5cryptsse.163:
        jmp       ..B7.137
..B7.136:
        movq      %r14, %rsi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.164:
        call      MD5_Update
..___tag_value_md5cryptsse.165:
..B7.137:
        shrl      $1, %r15d
        testl     %r15d, %r15d
        jne       ..B7.134
..B7.139:
        lea       6712(%rsp), %rdi
        lea       6496(%rsp), %rsi
..___tag_value_md5cryptsse.166:
        call      MD5_Final
..___tag_value_md5cryptsse.167:
..B7.140:
        shll      $4, %ebp
        incl      %ebx
        movl      6712(%rsp), %esi
        cmpl      $12, %ebx
        movl      6716(%rsp), %r8d
        movl      6720(%rsp), %r10d
        movl      6724(%rsp), %r11d
        lea       (%r13,%rbp), %ecx
        lea       4(%rbp,%r13), %edi
        lea       8(%rbp,%r13), %r9d
        lea       12(%rbp,%r13), %ebp
        movl      %esi, 6304(%rsp,%rcx,4)
        movl      %r8d, 6304(%rsp,%rdi,4)
        movl      %r10d, 6304(%rsp,%r9,4)
        movl      %r11d, 6304(%rsp,%rbp,4)
        jb        ..B7.5
..B7.141:
        xorl      %ebp, %ebp
        movl      %r12d, %eax
        movl      $23, %ebx
        movl      %eax, %r12d
        xorl      %r15d, %r15d
        lea       (%rsp), %r13
..B7.142:
        cmpl      $40, %ebp
        ja        ..B7.194
..B7.143:
        jmp       *..1..TPKT.6_0.0.6.38(,%rbp,8)
..1.6_0.TAG.015.0.6.38:
..B7.159:
        movl      $1, %esi
        movq      %r13, %rdi
        movl      %esi, %ecx
        lea       6648(%rsp), %rdx
        xorl      %r8d, %r8d
        lea       6304(%rsp), %r9
        movl      $1, %r14d
..___tag_value_md5cryptsse.168:
        call      mmxput3
..___tag_value_md5cryptsse.169:
        jmp       ..B7.195
..1.6_0.TAG.01c.0.6.38:
..1.6_0.TAG.0e.0.6.38:
..B7.165:
        movl      %r15d, %ecx
        movl      $5, %r14d
        movl      %ecx, %edx
        movl      %ecx, %r15d
        movl      %edx, %eax
        lea       6304(%rsp), %r13
        movl      %ebp, 6696(%rsp)
        movl      %edx, %ebp
        movl      %ebx, 6704(%rsp)
        lea       3840(%rsp), %rbx
        movl      %r12d, 6728(%rsp)
        movl      %eax, %r12d
..B7.166:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %rbx, %rdi
        addq      %r13, %rsi
..___tag_value_md5cryptsse.170:
        call      memcpy
..___tag_value_md5cryptsse.171:
..B7.167:
        incl      %r15d
        addl      $64, %ebp
        addl      $256, %r12d
        cmpl      $3, %r15d
        jb        ..B7.166
..B7.168:
        movl      6696(%rsp), %ebp
        xorl      %r15d, %r15d
        movl      6704(%rsp), %ebx
        lea       (%rsp), %r13
        movl      6728(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.023.0.6.38:
..1.6_0.TAG.07.0.6.38:
..B7.174:
        movq      %r13, %rdi
        movl      $4, %esi
        movl      $1, %ecx
        lea       6648(%rsp), %rdx
        movl      %r12d, %r8d
        lea       6304(%rsp), %r9
        movl      $4, %r14d
..___tag_value_md5cryptsse.172:
        call      mmxput3
..___tag_value_md5cryptsse.173:
        jmp       ..B7.195
..1.6_0.TAG.024.0.6.38:
..1.6_0.TAG.01e.0.6.38:
..1.6_0.TAG.018.0.6.38:
..1.6_0.TAG.012.0.6.38:
..1.6_0.TAG.0c.0.6.38:
..1.6_0.TAG.06.0.6.38:
..B7.176:
        movl      %r15d, %ecx
        movl      $3, %r14d
        movl      %ecx, %edx
        movl      %ecx, %r15d
        movl      %edx, %eax
        lea       6304(%rsp), %r13
        movl      %ebp, 6696(%rsp)
        movl      %edx, %ebp
        movl      %ebx, 6704(%rsp)
        lea       2304(%rsp), %rbx
        movl      %r12d, 6728(%rsp)
        movl      %eax, %r12d
..B7.177:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %rbx, %rdi
        addq      %r13, %rsi
..___tag_value_md5cryptsse.174:
        call      memcpy
..___tag_value_md5cryptsse.175:
..B7.178:
        incl      %r15d
        addl      $64, %ebp
        addl      $256, %r12d
        cmpl      $3, %r15d
        jb        ..B7.177
..B7.179:
        movl      6696(%rsp), %ebp
        xorl      %r15d, %r15d
        movl      6704(%rsp), %ebx
        lea       (%rsp), %r13
        movl      6728(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.027.0.6.38:
..1.6_0.TAG.021.0.6.38:
..1.6_0.TAG.01b.0.6.38:
..1.6_0.TAG.0f.0.6.38:
..1.6_0.TAG.09.0.6.38:
..1.6_0.TAG.03.0.6.38:
..B7.182:
        movl      $2, %esi
        movq      %r13, %rdi
        movl      %esi, %ecx
        lea       6648(%rsp), %rdx
        xorl      %r8d, %r8d
        lea       6304(%rsp), %r9
        movl      $2, %r14d
..___tag_value_md5cryptsse.176:
        call      mmxput3
..___tag_value_md5cryptsse.177:
        jmp       ..B7.195
..1.6_0.TAG.028.0.6.38:
..1.6_0.TAG.026.0.6.38:
..1.6_0.TAG.022.0.6.38:
..1.6_0.TAG.020.0.6.38:
..1.6_0.TAG.01a.0.6.38:
..1.6_0.TAG.016.0.6.38:
..1.6_0.TAG.014.0.6.38:
..1.6_0.TAG.010.0.6.38:
..1.6_0.TAG.0a.0.6.38:
..1.6_0.TAG.08.0.6.38:
..1.6_0.TAG.04.0.6.38:
..1.6_0.TAG.02.0.6.38:
..B7.184:
        movl      %r15d, %ecx
        movl      $6, %r14d
        movl      %ecx, %edx
        movl      %ecx, %r15d
        movl      %edx, %eax
        lea       6304(%rsp), %r13
        movl      %ebp, 6696(%rsp)
        movl      %edx, %ebp
        movl      %ebx, 6704(%rsp)
        lea       4608(%rsp), %rbx
        movl      %r12d, 6728(%rsp)
        movl      %eax, %r12d
..B7.185:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %rbx, %rdi
        addq      %r13, %rsi
..___tag_value_md5cryptsse.178:
        call      memcpy
..___tag_value_md5cryptsse.179:
..B7.186:
        incl      %r15d
        addl      $64, %ebp
        addl      $256, %r12d
        cmpl      $3, %r15d
        jb        ..B7.185
..B7.187:
        movl      6696(%rsp), %ebp
        xorl      %r15d, %r15d
        movl      6704(%rsp), %ebx
        lea       (%rsp), %r13
        movl      6728(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.00.0.6.38:
..B7.190:
        movl      %r15d, %ecx
        xorl      %r14d, %r14d
        movl      %ecx, %edx
        movl      %ecx, %r15d
        movl      %edx, %eax
        movl      %ebp, 6696(%rsp)
        movl      %edx, %ebp
        movl      %ebx, 6704(%rsp)
        lea       6304(%rsp), %rbx
        movl      %r12d, 6728(%rsp)
        movl      %eax, %r12d
..B7.191:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %r13, %rdi
        addq      %rbx, %rsi
..___tag_value_md5cryptsse.180:
        call      memcpy
..___tag_value_md5cryptsse.181:
..B7.192:
        incl      %r15d
        addl      $64, %ebp
        addl      $256, %r12d
        cmpl      $3, %r15d
        jb        ..B7.191
..B7.193:
        movl      6696(%rsp), %ebp
        xorl      %r15d, %r15d
        movl      6704(%rsp), %ebx
        movl      6728(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.DEFAULT.0.6.38:
..B7.194:
        movq      %r13, %rdi
        movl      $7, %esi
        movl      $2, %ecx
        lea       6648(%rsp), %rdx
        movl      %r12d, %r8d
        lea       6304(%rsp), %r9
        movl      $7, %r14d
..___tag_value_md5cryptsse.182:
        call      mmxput3
..___tag_value_md5cryptsse.183:
..B7.195:
        movl      $1, %edx
        lea       (%r14,%r14,2), %rdi
        shlq      $8, %rdi
        lea       6304(%rsp), %rsi
        addq      %r13, %rdi
..___tag_value_md5cryptsse.184:
        call      SSEmd5body
..___tag_value_md5cryptsse.185:
..B7.196:
        incl      %ebp
        lea       -1(%rbp), %edx
        cmpl      $33, %edx
        jb        ..B7.142
..B7.197:
        cmpl      $34, %ebp
        jne       ..B7.200
..B7.198:
        testl     %ebx, %ebx
        je        ..B7.201
..B7.199:
        decl      %ebx
        jmp       ..B7.142
..B7.200:
        cmpl      $42, %ebp
        cmovae    %r15d, %ebp
        jmp       ..B7.142
..B7.201:
        movq      6296(%rsp), %r14
        movq      %r14, %rdi
        movl      $192, %edx
        lea       6304(%rsp), %rsi
..___tag_value_md5cryptsse.186:
        call      memcpy
..___tag_value_md5cryptsse.187:
..B7.202:
        addq      $6808, %rsp
..___tag_value_md5cryptsse.188:
        popq      %rbp
..___tag_value_md5cryptsse.190:
        popq      %rbx
..___tag_value_md5cryptsse.192:
        popq      %r15
..___tag_value_md5cryptsse.194:
        popq      %r14
..___tag_value_md5cryptsse.196:
        popq      %r13
..___tag_value_md5cryptsse.198:
        popq      %r12
..___tag_value_md5cryptsse.200:
        ret       
..___tag_value_md5cryptsse.201:
..B7.203:
        movl      $.L_2__STRING.1, %esi
        lea       6496(%rsp), %rdi
        movl      $6, %edx
..___tag_value_md5cryptsse.208:
        call      MD5_Update
..___tag_value_md5cryptsse.209:
        jmp       ..B7.125
..B7.212:
        testl     %r15d, %r15d
        ja        ..B7.87
        jmp       ..B7.99
..B7.214:
        testl     %r15d, %r15d
        jmp       ..B7.47
..B7.215:
        testl     %r15d, %r15d
        jmp       ..B7.21
        .align    16,0x90
..___tag_value_md5cryptsse.210:
	.type	md5cryptsse,@function
	.size	md5cryptsse,.-md5cryptsse
	.section .rodata, "a"
	.space 24, 0x00 	# pad
	.align 32
..1..TPKT.6_0.0.6.38:
	.quad	..1.6_0.TAG.00.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.02.0.6.38
	.quad	..1.6_0.TAG.03.0.6.38
	.quad	..1.6_0.TAG.04.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.06.0.6.38
	.quad	..1.6_0.TAG.07.0.6.38
	.quad	..1.6_0.TAG.08.0.6.38
	.quad	..1.6_0.TAG.09.0.6.38
	.quad	..1.6_0.TAG.0a.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.0c.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.0e.0.6.38
	.quad	..1.6_0.TAG.0f.0.6.38
	.quad	..1.6_0.TAG.010.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.012.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.014.0.6.38
	.quad	..1.6_0.TAG.015.0.6.38
	.quad	..1.6_0.TAG.016.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.018.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.01a.0.6.38
	.quad	..1.6_0.TAG.01b.0.6.38
	.quad	..1.6_0.TAG.01c.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.01e.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.020.0.6.38
	.quad	..1.6_0.TAG.021.0.6.38
	.quad	..1.6_0.TAG.022.0.6.38
	.quad	..1.6_0.TAG.023.0.6.38
	.quad	..1.6_0.TAG.024.0.6.38
	.quad	..1.6_0.TAG.DEFAULT.0.6.38
	.quad	..1.6_0.TAG.026.0.6.38
	.quad	..1.6_0.TAG.027.0.6.38
	.quad	..1.6_0.TAG.028.0.6.38
	.data
# -- End  md5cryptsse
	.text
# -- Begin  SSEmd4body
       .align    16,0x90
	.globl SSEmd4body
SSEmd4body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %edx
..B8.1:
..___tag_value_SSEmd4body.211:
        subq      $840, %rsp
..___tag_value_SSEmd4body.213:
        movdqa    (%rsi), %xmm0
        testl     %edx, %edx
        movdqa    16(%rsi), %xmm1
        movdqa    32(%rsi), %xmm2
        movdqa    48(%rsi), %xmm3
        movdqa    %xmm0, (%rsp)
        movdqa    %xmm1, 48(%rsp)
        movdqa    %xmm2, 32(%rsp)
        movdqa    %xmm3, 16(%rsp)
        je        ..B8.3
..B8.2:
        movdqa    .L_2il0floatpacket.475(%rip), %xmm4
        movdqa    .L_2il0floatpacket.476(%rip), %xmm2
        movdqa    %xmm4, %xmm7
        movdqa    .L_2il0floatpacket.477(%rip), %xmm3
        movdqa    %xmm2, %xmm5
        movdqa    .L_2il0floatpacket.478(%rip), %xmm0
        movdqa    %xmm3, %xmm11
        movdqa    %xmm0, %xmm12
        movdqa    %xmm4, %xmm15
        movdqa    %xmm2, %xmm6
        movdqa    %xmm3, %xmm14
        movdqa    %xmm0, %xmm13
        jmp       ..B8.4
..B8.3:
        movdqa    (%rsp), %xmm4
        movdqa    48(%rsp), %xmm2
        movdqa    32(%rsp), %xmm3
        movdqa    16(%rsp), %xmm0
        movdqa    64(%rsi), %xmm7
        movdqa    80(%rsi), %xmm5
        movdqa    96(%rsi), %xmm11
        movdqa    112(%rsi), %xmm12
        movdqa    128(%rsi), %xmm15
        movdqa    144(%rsi), %xmm6
        movdqa    160(%rsi), %xmm14
        movdqa    176(%rsi), %xmm13
..B8.4:
        movdqa    %xmm3, %xmm8
        movdqa    %xmm11, %xmm9
        pxor      %xmm0, %xmm8
        pxor      %xmm1, %xmm1
        pand      %xmm2, %xmm8
        paddd     %xmm1, %xmm4
        pxor      %xmm0, %xmm8
        pxor      %xmm12, %xmm9
        movdqa    (%rdi), %xmm10
        paddd     %xmm8, %xmm4
        movdqa    %xmm10, 784(%rsp)
        paddd     %xmm10, %xmm4
        pand      %xmm5, %xmm9
        movdqa    %xmm14, %xmm10
        paddd     %xmm1, %xmm7
        pxor      %xmm12, %xmm9
        pxor      %xmm13, %xmm10
        paddd     %xmm9, %xmm7
        movdqa    256(%rdi), %xmm8
        pand      %xmm6, %xmm10
        paddd     %xmm8, %xmm7
        paddd     %xmm1, %xmm15
        pxor      %xmm13, %xmm10
        paddd     %xmm1, %xmm0
        movdqa    %xmm8, 800(%rsp)
        paddd     %xmm10, %xmm15
        movdqa    512(%rdi), %xmm8
        movdqa    %xmm7, %xmm10
        movdqa    %xmm8, 752(%rsp)
        paddd     %xmm8, %xmm15
        movdqa    %xmm4, %xmm8
        pslld     $3, %xmm10
        psrld     $29, %xmm7
        pslld     $3, %xmm8
        psrld     $29, %xmm4
        por       %xmm7, %xmm10
        movdqa    %xmm2, %xmm7
        por       %xmm4, %xmm8
        pxor      %xmm3, %xmm7
        movdqa    %xmm15, %xmm9
        pand      %xmm8, %xmm7
        pslld     $3, %xmm9
        psrld     $29, %xmm15
        pxor      %xmm3, %xmm7
        movdqa    %xmm5, %xmm4
        por       %xmm15, %xmm9
        movdqa    16(%rdi), %xmm15
        paddd     %xmm7, %xmm0
        pxor      %xmm11, %xmm4
        paddd     %xmm15, %xmm0
        movdqa    %xmm15, 112(%rsp)
        pand      %xmm10, %xmm4
        movdqa    %xmm6, %xmm15
        paddd     %xmm1, %xmm12
        pxor      %xmm11, %xmm4
        pxor      %xmm14, %xmm15
        movdqa    272(%rdi), %xmm7
        paddd     %xmm4, %xmm12
        pand      %xmm9, %xmm15
        paddd     %xmm7, %xmm12
        paddd     %xmm1, %xmm13
        pxor      %xmm14, %xmm15
        movdqa    %xmm7, 176(%rsp)
        paddd     %xmm15, %xmm13
        movdqa    528(%rdi), %xmm7
        movdqa    %xmm12, %xmm4
        movdqa    %xmm7, 192(%rsp)
        paddd     %xmm7, %xmm13
        movdqa    %xmm0, %xmm7
        pslld     $7, %xmm4
        psrld     $25, %xmm12
        pslld     $7, %xmm7
        psrld     $25, %xmm0
        por       %xmm12, %xmm4
        movdqa    %xmm2, %xmm12
        por       %xmm0, %xmm7
        pxor      %xmm8, %xmm12
        movdqa    %xmm13, %xmm0
        pand      %xmm7, %xmm12
        paddd     %xmm1, %xmm3
        pxor      %xmm2, %xmm12
        pslld     $7, %xmm0
        psrld     $25, %xmm13
        paddd     %xmm12, %xmm3
        movdqa    %xmm5, %xmm12
        movdqa    %xmm6, %xmm15
        por       %xmm13, %xmm0
        pxor      %xmm10, %xmm12
        pxor      %xmm9, %xmm15
        pand      %xmm4, %xmm12
        pand      %xmm0, %xmm15
        paddd     %xmm1, %xmm11
        movdqa    32(%rdi), %xmm13
        pxor      %xmm5, %xmm12
        paddd     %xmm1, %xmm14
        pxor      %xmm6, %xmm15
        paddd     %xmm13, %xmm3
        paddd     %xmm12, %xmm11
        movdqa    544(%rdi), %xmm12
        paddd     %xmm15, %xmm14
        movdqa    %xmm13, 272(%rsp)
        paddd     %xmm12, %xmm14
        movdqa    288(%rdi), %xmm13
        paddd     %xmm1, %xmm2
        movdqa    %xmm12, 304(%rsp)
        movdqa    %xmm3, %xmm12
        paddd     %xmm13, %xmm11
        pslld     $11, %xmm12
        psrld     $21, %xmm3
        movdqa    %xmm0, %xmm15
        por       %xmm3, %xmm12
        movdqa    %xmm11, %xmm3
        pslld     $11, %xmm3
        psrld     $21, %xmm11
        por       %xmm11, %xmm3
        movdqa    %xmm7, %xmm11
        pxor      %xmm8, %xmm11
        paddd     %xmm1, %xmm5
        pand      %xmm12, %xmm11
        pxor      %xmm9, %xmm15
        pxor      %xmm8, %xmm11
        paddd     %xmm1, %xmm6
        paddd     %xmm11, %xmm2
        movdqa    %xmm4, %xmm11
        movdqa    %xmm13, 288(%rsp)
        movdqa    %xmm14, %xmm13
        pxor      %xmm10, %xmm11
        pslld     $11, %xmm13
        psrld     $21, %xmm14
        pand      %xmm3, %xmm11
        por       %xmm14, %xmm13
        pxor      %xmm10, %xmm11
        movdqa    48(%rdi), %xmm14
        paddd     %xmm11, %xmm5
        movdqa    %xmm14, 64(%rsp)
        paddd     %xmm14, %xmm2
        movdqa    304(%rdi), %xmm14
        pand      %xmm13, %xmm15
        paddd     %xmm14, %xmm5
        pxor      %xmm9, %xmm15
        paddd     %xmm15, %xmm6
        movdqa    %xmm5, %xmm15
        movdqa    %xmm14, 80(%rsp)
        movdqa    %xmm2, %xmm14
        pslld     $19, %xmm15
        psrld     $13, %xmm5
        pslld     $19, %xmm14
        psrld     $13, %xmm2
        por       %xmm5, %xmm15
        movdqa    %xmm12, %xmm5
        movdqa    560(%rdi), %xmm11
        por       %xmm2, %xmm14
        pxor      %xmm7, %xmm5
        paddd     %xmm11, %xmm6
        pand      %xmm14, %xmm5
        movdqa    %xmm6, %xmm2
        paddd     %xmm1, %xmm8
        pxor      %xmm7, %xmm5
        movdqa    %xmm11, 96(%rsp)
        pslld     $19, %xmm2
        psrld     $13, %xmm6
        paddd     %xmm5, %xmm8
        movdqa    %xmm3, %xmm5
        movdqa    %xmm13, %xmm11
        por       %xmm6, %xmm2
        pxor      %xmm4, %xmm5
        pxor      %xmm0, %xmm11
        pand      %xmm15, %xmm5
        pand      %xmm2, %xmm11
        paddd     %xmm1, %xmm10
        movdqa    64(%rdi), %xmm6
        pxor      %xmm4, %xmm5
        paddd     %xmm1, %xmm9
        pxor      %xmm0, %xmm11
        paddd     %xmm6, %xmm8
        paddd     %xmm5, %xmm10
        movdqa    576(%rdi), %xmm5
        paddd     %xmm11, %xmm9
        movdqa    %xmm6, 480(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    320(%rdi), %xmm6
        paddd     %xmm1, %xmm7
        movdqa    %xmm5, 512(%rsp)
        movdqa    %xmm8, %xmm5
        paddd     %xmm6, %xmm10
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        movdqa    %xmm2, %xmm11
        por       %xmm8, %xmm5
        movdqa    %xmm10, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm10
        por       %xmm10, %xmm8
        movdqa    %xmm14, %xmm10
        pxor      %xmm12, %xmm10
        pxor      %xmm13, %xmm11
        pand      %xmm5, %xmm10
        paddd     %xmm1, %xmm4
        movdqa    %xmm6, 496(%rsp)
        movdqa    %xmm9, %xmm6
        pxor      %xmm12, %xmm10
        pslld     $3, %xmm6
        psrld     $29, %xmm9
        paddd     %xmm10, %xmm7
        movdqa    %xmm15, %xmm10
        por       %xmm9, %xmm6
        pxor      %xmm3, %xmm10
        pand      %xmm6, %xmm11
        pand      %xmm8, %xmm10
        paddd     %xmm1, %xmm0
        movdqa    80(%rdi), %xmm9
        pxor      %xmm3, %xmm10
        pxor      %xmm13, %xmm11
        paddd     %xmm9, %xmm7
        paddd     %xmm10, %xmm4
        paddd     %xmm11, %xmm0
        movdqa    592(%rdi), %xmm10
        paddd     %xmm1, %xmm12
        movdqa    %xmm9, 208(%rsp)
        paddd     %xmm10, %xmm0
        movdqa    336(%rdi), %xmm9
        movdqa    %xmm6, %xmm11
        movdqa    %xmm10, 240(%rsp)
        movdqa    %xmm7, %xmm10
        paddd     %xmm9, %xmm4
        pslld     $7, %xmm10
        psrld     $25, %xmm7
        pxor      %xmm2, %xmm11
        por       %xmm7, %xmm10
        movdqa    %xmm4, %xmm7
        pslld     $7, %xmm7
        psrld     $25, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm5, %xmm4
        pxor      %xmm14, %xmm4
        paddd     %xmm1, %xmm3
        pand      %xmm10, %xmm4
        paddd     %xmm1, %xmm13
        movdqa    %xmm9, 224(%rsp)
        movdqa    %xmm0, %xmm9
        pxor      %xmm14, %xmm4
        pslld     $7, %xmm9
        psrld     $25, %xmm0
        paddd     %xmm4, %xmm12
        movdqa    %xmm8, %xmm4
        por       %xmm0, %xmm9
        pxor      %xmm15, %xmm4
        pand      %xmm9, %xmm11
        pand      %xmm7, %xmm4
        pxor      %xmm2, %xmm11
        movdqa    96(%rdi), %xmm0
        pxor      %xmm15, %xmm4
        paddd     %xmm0, %xmm12
        paddd     %xmm4, %xmm3
        movdqa    608(%rdi), %xmm4
        paddd     %xmm11, %xmm13
        movdqa    %xmm0, 400(%rsp)
        paddd     %xmm4, %xmm13
        movdqa    352(%rdi), %xmm0
        paddd     %xmm1, %xmm14
        movdqa    %xmm4, 432(%rsp)
        movdqa    %xmm12, %xmm4
        paddd     %xmm0, %xmm3
        pslld     $11, %xmm4
        psrld     $21, %xmm12
        movdqa    %xmm9, %xmm11
        por       %xmm12, %xmm4
        movdqa    %xmm3, %xmm12
        pslld     $11, %xmm12
        psrld     $21, %xmm3
        por       %xmm3, %xmm12
        movdqa    %xmm10, %xmm3
        pxor      %xmm5, %xmm3
        pxor      %xmm6, %xmm11
        pand      %xmm4, %xmm3
        paddd     %xmm1, %xmm15
        movdqa    %xmm0, 416(%rsp)
        movdqa    %xmm13, %xmm0
        pxor      %xmm5, %xmm3
        pslld     $11, %xmm0
        psrld     $21, %xmm13
        paddd     %xmm3, %xmm14
        movdqa    %xmm7, %xmm3
        por       %xmm13, %xmm0
        pxor      %xmm8, %xmm3
        pand      %xmm0, %xmm11
        pand      %xmm12, %xmm3
        paddd     %xmm1, %xmm2
        pxor      %xmm8, %xmm3
        pxor      %xmm6, %xmm11
        paddd     %xmm3, %xmm15
        paddd     %xmm11, %xmm2
        movdqa    624(%rdi), %xmm3
        paddd     %xmm1, %xmm5
        movdqa    112(%rdi), %xmm13
        paddd     %xmm3, %xmm2
        paddd     %xmm13, %xmm14
        movdqa    %xmm2, %xmm11
        movdqa    %xmm3, 128(%rsp)
        movdqa    %xmm14, %xmm3
        pslld     $19, %xmm11
        psrld     $13, %xmm2
        movdqa    %xmm13, 160(%rsp)
        pslld     $19, %xmm3
        movdqa    368(%rdi), %xmm13
        psrld     $13, %xmm14
        por       %xmm2, %xmm11
        movdqa    %xmm4, %xmm2
        paddd     %xmm13, %xmm15
        por       %xmm14, %xmm3
        pxor      %xmm10, %xmm2
        paddd     %xmm1, %xmm8
        movdqa    %xmm13, 144(%rsp)
        movdqa    %xmm15, %xmm13
        pand      %xmm3, %xmm2
        pslld     $19, %xmm13
        psrld     $13, %xmm15
        pxor      %xmm10, %xmm2
        movdqa    128(%rdi), %xmm14
        por       %xmm15, %xmm13
        paddd     %xmm2, %xmm5
        movdqa    %xmm12, %xmm15
        movdqa    %xmm14, 640(%rsp)
        paddd     %xmm14, %xmm5
        pxor      %xmm7, %xmm15
        movdqa    %xmm0, %xmm14
        pand      %xmm13, %xmm15
        pxor      %xmm9, %xmm14
        pxor      %xmm7, %xmm15
        pand      %xmm11, %xmm14
        movdqa    384(%rdi), %xmm2
        paddd     %xmm15, %xmm8
        paddd     %xmm1, %xmm6
        pxor      %xmm9, %xmm14
        movdqa    %xmm2, 688(%rsp)
        paddd     %xmm2, %xmm8
        movdqa    640(%rdi), %xmm2
        paddd     %xmm14, %xmm6
        movdqa    %xmm2, 656(%rsp)
        paddd     %xmm2, %xmm6
        movdqa    %xmm5, %xmm2
        psrld     $29, %xmm5
        pslld     $3, %xmm2
        paddd     %xmm1, %xmm10
        por       %xmm5, %xmm2
        movdqa    %xmm8, %xmm5
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        por       %xmm8, %xmm5
        movdqa    %xmm6, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm6
        por       %xmm6, %xmm8
        movdqa    %xmm3, %xmm6
        pxor      %xmm4, %xmm6
        movdqa    %xmm13, %xmm14
        pand      %xmm2, %xmm6
        pxor      %xmm12, %xmm14
        pxor      %xmm4, %xmm6
        pand      %xmm5, %xmm14
        movdqa    144(%rdi), %xmm15
        paddd     %xmm6, %xmm10
        movdqa    %xmm15, 384(%rsp)
        paddd     %xmm15, %xmm10
        movdqa    %xmm11, %xmm15
        paddd     %xmm1, %xmm7
        pxor      %xmm0, %xmm15
        pxor      %xmm12, %xmm14
        pand      %xmm8, %xmm15
        paddd     %xmm14, %xmm7
        movdqa    400(%rdi), %xmm6
        paddd     %xmm1, %xmm9
        pxor      %xmm0, %xmm15
        paddd     %xmm6, %xmm7
        movdqa    %xmm6, 368(%rsp)
        paddd     %xmm15, %xmm9
        movdqa    656(%rdi), %xmm6
        paddd     %xmm1, %xmm4
        movdqa    %xmm6, 352(%rsp)
        paddd     %xmm6, %xmm9
        movdqa    %xmm10, %xmm6
        psrld     $25, %xmm10
        pslld     $7, %xmm6
        movdqa    %xmm5, %xmm15
        por       %xmm10, %xmm6
        movdqa    %xmm7, %xmm10
        pslld     $7, %xmm10
        psrld     $25, %xmm7
        por       %xmm7, %xmm10
        movdqa    %xmm9, %xmm7
        pslld     $7, %xmm7
        psrld     $25, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm2, %xmm9
        pxor      %xmm3, %xmm9
        pxor      %xmm13, %xmm15
        pand      %xmm6, %xmm9
        pand      %xmm10, %xmm15
        pxor      %xmm3, %xmm9
        paddd     %xmm1, %xmm12
        movdqa    160(%rdi), %xmm14
        paddd     %xmm9, %xmm4
        movdqa    %xmm14, 560(%rsp)
        paddd     %xmm14, %xmm4
        movdqa    %xmm8, %xmm14
        pxor      %xmm13, %xmm15
        pxor      %xmm11, %xmm14
        paddd     %xmm15, %xmm12
        pand      %xmm7, %xmm14
        paddd     %xmm1, %xmm0
        movdqa    416(%rdi), %xmm9
        pxor      %xmm11, %xmm14
        movdqa    %xmm9, 576(%rsp)
        paddd     %xmm9, %xmm12
        movdqa    672(%rdi), %xmm9
        paddd     %xmm14, %xmm0
        movdqa    %xmm9, 592(%rsp)
        paddd     %xmm9, %xmm0
        movdqa    %xmm4, %xmm9
        psrld     $21, %xmm4
        pslld     $11, %xmm9
        paddd     %xmm1, %xmm3
        por       %xmm4, %xmm9
        movdqa    %xmm12, %xmm4
        pslld     $11, %xmm4
        psrld     $21, %xmm12
        por       %xmm12, %xmm4
        movdqa    %xmm0, %xmm12
        pslld     $11, %xmm12
        psrld     $21, %xmm0
        por       %xmm0, %xmm12
        movdqa    %xmm6, %xmm0
        pxor      %xmm2, %xmm0
        movdqa    %xmm10, %xmm15
        pand      %xmm9, %xmm0
        pxor      %xmm5, %xmm15
        pxor      %xmm2, %xmm0
        pand      %xmm4, %xmm15
        movdqa    176(%rdi), %xmm14
        paddd     %xmm0, %xmm3
        movdqa    %xmm14, 256(%rsp)
        paddd     %xmm14, %xmm3
        movdqa    %xmm7, %xmm14
        paddd     %xmm1, %xmm13
        pxor      %xmm8, %xmm14
        pxor      %xmm5, %xmm15
        pand      %xmm12, %xmm14
        paddd     %xmm15, %xmm13
        movdqa    432(%rdi), %xmm0
        paddd     %xmm1, %xmm11
        pxor      %xmm8, %xmm14
        paddd     %xmm0, %xmm13
        movdqa    %xmm0, 320(%rsp)
        paddd     %xmm14, %xmm11
        movdqa    688(%rdi), %xmm0
        paddd     %xmm1, %xmm2
        movdqa    %xmm0, 336(%rsp)
        paddd     %xmm0, %xmm11
        movdqa    %xmm3, %xmm0
        psrld     $13, %xmm3
        pslld     $19, %xmm0
        paddd     %xmm1, %xmm5
        por       %xmm3, %xmm0
        movdqa    %xmm13, %xmm3
        pslld     $19, %xmm3
        psrld     $13, %xmm13
        por       %xmm13, %xmm3
        movdqa    %xmm11, %xmm13
        pslld     $19, %xmm13
        psrld     $13, %xmm11
        por       %xmm11, %xmm13
        movdqa    %xmm9, %xmm11
        pxor      %xmm6, %xmm11
        movdqa    %xmm4, %xmm15
        pand      %xmm0, %xmm11
        paddd     %xmm1, %xmm8
        movdqa    %xmm12, %xmm1
        pxor      %xmm6, %xmm11
        pxor      %xmm10, %xmm15
        pxor      %xmm7, %xmm1
        movdqa    192(%rdi), %xmm14
        paddd     %xmm11, %xmm2
        pand      %xmm3, %xmm15
        pand      %xmm13, %xmm1
        paddd     %xmm14, %xmm2
        pxor      %xmm10, %xmm15
        pxor      %xmm7, %xmm1
        paddd     %xmm15, %xmm5
        movdqa    448(%rdi), %xmm11
        paddd     %xmm1, %xmm8
        movdqa    %xmm2, %xmm1
        paddd     %xmm11, %xmm5
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        movdqa    %xmm11, 736(%rsp)
        por       %xmm2, %xmm1
        movdqa    704(%rdi), %xmm11
        movdqa    %xmm5, %xmm2
        movdqa    %xmm14, 704(%rsp)
        paddd     %xmm11, %xmm8
        movdqa    %xmm11, 720(%rsp)
        pslld     $3, %xmm2
        psrld     $29, %xmm5
..B8.12:
        movdqa    %xmm3, %xmm15
        por       %xmm5, %xmm2
        pxor      %xmm4, %xmm15
        movdqa    %xmm0, %xmm14
        pxor      %xmm11, %xmm11
        pand      %xmm2, %xmm15
        movdqa    %xmm8, %xmm5
        paddd     %xmm11, %xmm10
        pxor      %xmm4, %xmm15
        pxor      %xmm9, %xmm14
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        paddd     %xmm15, %xmm10
        movdqa    %xmm13, %xmm15
        pand      %xmm1, %xmm14
        por       %xmm8, %xmm5
        pxor      %xmm12, %xmm15
        paddd     %xmm11, %xmm6
        pxor      %xmm9, %xmm14
        pand      %xmm5, %xmm15
        paddd     %xmm14, %xmm6
        paddd     %xmm11, %xmm7
        movdqa    464(%rdi), %xmm14
        pxor      %xmm12, %xmm15
        movdqa    %xmm14, 528(%rsp)
        paddd     %xmm14, %xmm10
        movdqa    720(%rdi), %xmm14
        paddd     %xmm15, %xmm7
        movdqa    208(%rdi), %xmm8
        paddd     %xmm14, %xmm7
        movdqa    %xmm14, 464(%rsp)
        paddd     %xmm8, %xmm6
        movdqa    %xmm7, %xmm14
        movdqa    %xmm6, %xmm15
        pslld     $7, %xmm14
        psrld     $25, %xmm7
        pslld     $7, %xmm15
        psrld     $25, %xmm6
        por       %xmm7, %xmm14
        movdqa    %xmm1, %xmm7
        por       %xmm6, %xmm15
        pxor      %xmm0, %xmm7
        pand      %xmm15, %xmm7
        movdqa    %xmm10, %xmm6
        paddd     %xmm11, %xmm9
        pxor      %xmm0, %xmm7
        pslld     $7, %xmm6
        psrld     $25, %xmm10
        paddd     %xmm7, %xmm9
        movdqa    %xmm3, %xmm7
        por       %xmm10, %xmm6
        pxor      %xmm2, %xmm7
        pand      %xmm6, %xmm7
        paddd     %xmm11, %xmm4
        pxor      %xmm3, %xmm7
        paddd     %xmm11, %xmm12
        paddd     %xmm7, %xmm4
        movdqa    %xmm13, %xmm7
        pxor      %xmm5, %xmm7
        paddd     %xmm11, %xmm0
        movdqa    224(%rdi), %xmm10
        pand      %xmm14, %xmm7
        movdqa    %xmm10, 672(%rsp)
        paddd     %xmm10, %xmm9
        movdqa    480(%rdi), %xmm10
        pxor      %xmm13, %xmm7
        movdqa    %xmm10, 608(%rsp)
        paddd     %xmm10, %xmm4
        movdqa    736(%rdi), %xmm10
        paddd     %xmm7, %xmm12
        paddd     %xmm10, %xmm12
        movdqa    %xmm9, %xmm7
        movdqa    %xmm10, 624(%rsp)
        movdqa    %xmm12, %xmm10
        pslld     $11, %xmm10
        psrld     $21, %xmm12
        pslld     $11, %xmm7
        psrld     $21, %xmm9
        por       %xmm12, %xmm10
        movdqa    %xmm1, %xmm12
        por       %xmm9, %xmm7
        pxor      %xmm15, %xmm12
        pand      %xmm7, %xmm12
        movdqa    %xmm4, %xmm9
        pxor      %xmm1, %xmm12
        pslld     $11, %xmm9
        psrld     $21, %xmm4
        paddd     %xmm12, %xmm0
        movdqa    %xmm6, %xmm12
        por       %xmm4, %xmm9
        paddd     %xmm11, %xmm3
        pxor      %xmm2, %xmm12
        paddd     %xmm11, %xmm13
        movdqa    %xmm14, %xmm11
        pand      %xmm9, %xmm12
        pxor      %xmm5, %xmm11
        movdqa    240(%rdi), %xmm4
        pxor      %xmm2, %xmm12
        pand      %xmm10, %xmm11
        paddd     %xmm4, %xmm0
        movdqa    %xmm4, 448(%rsp)
        paddd     %xmm12, %xmm3
        movdqa    496(%rdi), %xmm4
        pxor      %xmm5, %xmm11
        movdqa    752(%rdi), %xmm12
        paddd     %xmm4, %xmm3
        paddd     %xmm11, %xmm13
        movdqa    %xmm0, %xmm11
        movdqa    %xmm12, 768(%rsp)
        paddd     %xmm12, %xmm13
        movdqa    %xmm3, %xmm12
        psrld     $13, %xmm3
        pslld     $19, %xmm12
        pslld     $19, %xmm11
        movdqa    %xmm4, 816(%rsp)
        psrld     $13, %xmm0
        por       %xmm3, %xmm12
        movdqa    %xmm13, %xmm4
        movdqa    %xmm7, %xmm3
        por       %xmm0, %xmm11
        pslld     $19, %xmm4
        psrld     $13, %xmm13
        por       %xmm15, %xmm3
        movdqa    %xmm7, %xmm0
        por       %xmm13, %xmm4
        pand      %xmm11, %xmm3
        movdqa    .L_2il0floatpacket.479(%rip), %xmm13
        pand      %xmm15, %xmm0
        paddd     %xmm13, %xmm1
        por       %xmm0, %xmm3
        paddd     %xmm3, %xmm1
        movdqa    %xmm9, %xmm3
        por       %xmm6, %xmm3
        movdqa    %xmm9, %xmm0
        pand      %xmm12, %xmm3
        pand      %xmm6, %xmm0
        paddd     %xmm13, %xmm2
        por       %xmm0, %xmm3
        paddd     %xmm3, %xmm2
        movdqa    %xmm10, %xmm3
        por       %xmm14, %xmm3
        movdqa    %xmm10, %xmm0
        paddd     784(%rsp), %xmm1
        pand      %xmm4, %xmm3
        pand      %xmm14, %xmm0
        paddd     %xmm13, %xmm5
        por       %xmm0, %xmm3
        movdqa    %xmm1, %xmm0
        paddd     800(%rsp), %xmm2
        pslld     $3, %xmm0
        psrld     $29, %xmm1
        paddd     %xmm3, %xmm5
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        paddd     752(%rsp), %xmm5
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        movdqa    %xmm11, %xmm3
        por       %xmm2, %xmm1
        movdqa    %xmm5, %xmm2
        pslld     $3, %xmm2
        psrld     $29, %xmm5
        por       %xmm5, %xmm2
        por       %xmm7, %xmm3
        movdqa    %xmm11, %xmm5
        pand      %xmm0, %xmm3
        pand      %xmm7, %xmm5
        paddd     %xmm13, %xmm15
        por       %xmm5, %xmm3
        movdqa    %xmm12, %xmm5
        paddd     %xmm3, %xmm15
        movdqa    %xmm12, %xmm3
        por       %xmm9, %xmm3
        pand      %xmm9, %xmm5
        pand      %xmm1, %xmm3
        paddd     %xmm13, %xmm6
        por       %xmm5, %xmm3
        movdqa    %xmm4, %xmm5
        paddd     %xmm3, %xmm6
        movdqa    %xmm4, %xmm3
        por       %xmm10, %xmm3
        pand      %xmm10, %xmm5
        pand      %xmm2, %xmm3
        paddd     %xmm13, %xmm14
        paddd     480(%rsp), %xmm15
        por       %xmm5, %xmm3
        paddd     %xmm3, %xmm14
        movdqa    %xmm15, %xmm3
        paddd     512(%rsp), %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm7
        paddd     496(%rsp), %xmm6
        por       %xmm15, %xmm3
        movdqa    %xmm14, %xmm15
        movdqa    %xmm6, %xmm5
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm6
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        por       %xmm6, %xmm5
        por       %xmm11, %xmm14
        movdqa    %xmm0, %xmm6
        pand      %xmm3, %xmm14
        pand      %xmm11, %xmm6
        paddd     %xmm13, %xmm9
        por       %xmm6, %xmm14
        movdqa    %xmm1, %xmm6
        paddd     %xmm14, %xmm7
        movdqa    %xmm1, %xmm14
        por       %xmm12, %xmm14
        pand      %xmm12, %xmm6
        pand      %xmm5, %xmm14
        paddd     %xmm13, %xmm10
        por       %xmm6, %xmm14
        movdqa    %xmm2, %xmm6
        paddd     %xmm14, %xmm9
        movdqa    %xmm2, %xmm14
        por       %xmm4, %xmm14
        pand      %xmm4, %xmm6
        paddd     640(%rsp), %xmm7
        pand      %xmm15, %xmm14
        por       %xmm6, %xmm14
        movdqa    %xmm7, %xmm6
        paddd     688(%rsp), %xmm9
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        paddd     %xmm14, %xmm10
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        paddd     656(%rsp), %xmm10
        pslld     $9, %xmm7
        psrld     $23, %xmm9
        movdqa    %xmm3, %xmm14
        por       %xmm9, %xmm7
        movdqa    %xmm10, %xmm9
        pslld     $9, %xmm9
        psrld     $23, %xmm10
        por       %xmm10, %xmm9
        por       %xmm0, %xmm14
        movdqa    %xmm3, %xmm10
        pand      %xmm6, %xmm14
        pand      %xmm0, %xmm10
        paddd     %xmm13, %xmm11
        por       %xmm10, %xmm14
        movdqa    %xmm5, %xmm10
        paddd     %xmm14, %xmm11
        movdqa    %xmm5, %xmm14
        por       %xmm1, %xmm14
        pand      %xmm1, %xmm10
        pand      %xmm7, %xmm14
        paddd     %xmm13, %xmm12
        por       %xmm10, %xmm14
        movdqa    %xmm15, %xmm10
        paddd     %xmm14, %xmm12
        movdqa    %xmm15, %xmm14
        por       %xmm2, %xmm14
        pand      %xmm2, %xmm10
        pand      %xmm9, %xmm14
        paddd     %xmm13, %xmm4
        paddd     704(%rsp), %xmm11
        por       %xmm10, %xmm14
        paddd     736(%rsp), %xmm12
        paddd     %xmm14, %xmm4
        movdqa    %xmm11, %xmm14
        psrld     $19, %xmm11
        paddd     720(%rsp), %xmm4
        pslld     $13, %xmm14
        movdqa    %xmm12, %xmm10
        por       %xmm11, %xmm14
        pslld     $13, %xmm10
        psrld     $19, %xmm12
        movdqa    %xmm4, %xmm11
        por       %xmm12, %xmm10
        pslld     $13, %xmm11
        psrld     $19, %xmm4
        movdqa    %xmm6, %xmm12
        por       %xmm4, %xmm11
        por       %xmm3, %xmm12
        movdqa    %xmm6, %xmm4
        pand      %xmm14, %xmm12
        pand      %xmm3, %xmm4
        paddd     %xmm13, %xmm0
        por       %xmm4, %xmm12
        paddd     %xmm12, %xmm0
        movdqa    %xmm7, %xmm12
        por       %xmm5, %xmm12
        movdqa    %xmm7, %xmm4
        pand      %xmm10, %xmm12
        pand      %xmm5, %xmm4
        paddd     %xmm13, %xmm1
        por       %xmm4, %xmm12
        paddd     %xmm12, %xmm1
        movdqa    %xmm9, %xmm12
        por       %xmm15, %xmm12
        movdqa    %xmm9, %xmm4
        pand      %xmm11, %xmm12
        pand      %xmm15, %xmm4
        paddd     112(%rsp), %xmm0
        paddd     %xmm13, %xmm2
        por       %xmm4, %xmm12
        movdqa    %xmm14, %xmm4
        paddd     %xmm12, %xmm2
        movdqa    %xmm0, %xmm12
        paddd     176(%rsp), %xmm1
        pslld     $3, %xmm12
        psrld     $29, %xmm0
        por       %xmm6, %xmm4
        por       %xmm0, %xmm12
        movdqa    %xmm1, %xmm0
        paddd     192(%rsp), %xmm2
        pslld     $3, %xmm0
        psrld     $29, %xmm1
        pand      %xmm12, %xmm4
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        pslld     $3, %xmm1
        psrld     $29, %xmm2
        por       %xmm2, %xmm1
        movdqa    %xmm14, %xmm2
        pand      %xmm6, %xmm2
        paddd     %xmm13, %xmm3
        por       %xmm2, %xmm4
        movdqa    %xmm10, %xmm2
        paddd     %xmm4, %xmm3
        movdqa    %xmm10, %xmm4
        por       %xmm7, %xmm4
        pand      %xmm7, %xmm2
        pand      %xmm0, %xmm4
        paddd     %xmm13, %xmm5
        por       %xmm2, %xmm4
        movdqa    %xmm11, %xmm2
        paddd     %xmm4, %xmm5
        movdqa    %xmm11, %xmm4
        por       %xmm9, %xmm4
        pand      %xmm9, %xmm2
        paddd     208(%rsp), %xmm3
        pand      %xmm1, %xmm4
        paddd     %xmm13, %xmm15
        por       %xmm2, %xmm4
        movdqa    %xmm3, %xmm2
        paddd     %xmm4, %xmm15
        paddd     224(%rsp), %xmm5
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        paddd     %xmm13, %xmm6
        paddd     240(%rsp), %xmm15
        por       %xmm3, %xmm2
        movdqa    %xmm5, %xmm3
        psrld     $27, %xmm5
        pslld     $5, %xmm3
        movdqa    %xmm15, %xmm4
        por       %xmm5, %xmm3
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        movdqa    %xmm12, %xmm5
        por       %xmm15, %xmm4
        por       %xmm14, %xmm5
        movdqa    %xmm12, %xmm15
        pand      %xmm2, %xmm5
        pand      %xmm14, %xmm15
        paddd     %xmm13, %xmm7
        por       %xmm15, %xmm5
        movdqa    %xmm0, %xmm15
        paddd     %xmm5, %xmm6
        movdqa    %xmm0, %xmm5
        por       %xmm10, %xmm5
        pand      %xmm10, %xmm15
        pand      %xmm3, %xmm5
        paddd     %xmm13, %xmm9
        por       %xmm15, %xmm5
        movdqa    %xmm1, %xmm15
        paddd     %xmm5, %xmm7
        movdqa    %xmm1, %xmm5
        por       %xmm11, %xmm5
        pand      %xmm11, %xmm15
        pand      %xmm4, %xmm5
        paddd     %xmm13, %xmm14
        paddd     384(%rsp), %xmm6
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm9
        movdqa    %xmm6, %xmm5
        paddd     368(%rsp), %xmm7
        pslld     $9, %xmm5
        psrld     $23, %xmm6
        movdqa    %xmm2, %xmm15
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        paddd     352(%rsp), %xmm9
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        por       %xmm12, %xmm15
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        pslld     $9, %xmm7
        psrld     $23, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm2, %xmm9
        pand      %xmm5, %xmm15
        pand      %xmm12, %xmm9
        por       %xmm9, %xmm15
        movdqa    %xmm3, %xmm9
        paddd     %xmm15, %xmm14
        por       %xmm0, %xmm9
        movdqa    %xmm8, 544(%rsp)
        paddd     %xmm8, %xmm14
        movdqa    %xmm3, %xmm8
        pand      %xmm6, %xmm9
        pand      %xmm0, %xmm8
        paddd     %xmm13, %xmm10
        por       %xmm8, %xmm9
        movdqa    %xmm4, %xmm8
        por       %xmm1, %xmm8
        movdqa    %xmm4, %xmm15
        paddd     %xmm9, %xmm10
        pand      %xmm7, %xmm8
        pand      %xmm1, %xmm15
        paddd     %xmm13, %xmm11
        paddd     464(%rdi), %xmm10
        por       %xmm15, %xmm8
        paddd     %xmm8, %xmm11
        movdqa    %xmm10, %xmm9
        paddd     720(%rdi), %xmm11
        movdqa    %xmm14, %xmm8
        pslld     $13, %xmm9
        psrld     $19, %xmm10
        pslld     $13, %xmm8
        psrld     $19, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        por       %xmm14, %xmm8
        pslld     $13, %xmm10
        psrld     $19, %xmm11
        movdqa    %xmm5, %xmm14
        por       %xmm11, %xmm10
        por       %xmm2, %xmm14
        movdqa    %xmm5, %xmm11
        pand      %xmm8, %xmm14
        pand      %xmm2, %xmm11
        movdqa    %xmm6, %xmm15
        paddd     %xmm13, %xmm12
        por       %xmm11, %xmm14
        por       %xmm3, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm14, %xmm12
        pand      %xmm9, %xmm15
        pand      %xmm3, %xmm11
        movdqa    %xmm7, %xmm14
        por       %xmm11, %xmm15
        por       %xmm4, %xmm14
        movdqa    %xmm7, %xmm11
        paddd     %xmm13, %xmm0
        paddd     272(%rsp), %xmm12
        pand      %xmm10, %xmm14
        pand      %xmm4, %xmm11
        paddd     %xmm15, %xmm0
        paddd     %xmm13, %xmm1
        por       %xmm11, %xmm14
        movdqa    %xmm12, %xmm11
        paddd     %xmm14, %xmm1
        paddd     288(%rsp), %xmm0
        pslld     $3, %xmm11
        psrld     $29, %xmm12
        paddd     %xmm13, %xmm2
        paddd     304(%rsp), %xmm1
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        psrld     $29, %xmm0
        pslld     $3, %xmm12
        movdqa    %xmm1, %xmm14
        por       %xmm0, %xmm12
        pslld     $3, %xmm14
        psrld     $29, %xmm1
        movdqa    %xmm8, %xmm0
        por       %xmm1, %xmm14
        por       %xmm5, %xmm0
        movdqa    %xmm8, %xmm1
        pand      %xmm11, %xmm0
        pand      %xmm5, %xmm1
        movdqa    %xmm9, %xmm15
        por       %xmm1, %xmm0
        pand      %xmm6, %xmm15
        paddd     %xmm0, %xmm2
        movdqa    %xmm9, %xmm0
        por       %xmm6, %xmm0
        paddd     %xmm13, %xmm3
        pand      %xmm12, %xmm0
        movdqa    %xmm10, %xmm1
        por       %xmm15, %xmm0
        pand      %xmm7, %xmm1
        paddd     %xmm0, %xmm3
        movdqa    %xmm10, %xmm0
        por       %xmm7, %xmm0
        paddd     %xmm13, %xmm4
        paddd     400(%rsp), %xmm2
        pand      %xmm14, %xmm0
        paddd     416(%rsp), %xmm3
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        paddd     %xmm0, %xmm4
        pslld     $5, %xmm1
        psrld     $27, %xmm2
        movdqa    %xmm3, %xmm0
        por       %xmm2, %xmm1
        paddd     432(%rsp), %xmm4
        pslld     $5, %xmm0
        psrld     $27, %xmm3
        movdqa    %xmm11, %xmm2
        por       %xmm3, %xmm0
        movdqa    %xmm4, %xmm15
        por       %xmm8, %xmm2
        movdqa    %xmm11, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        pand      %xmm1, %xmm2
        pand      %xmm8, %xmm3
        por       %xmm4, %xmm15
        paddd     %xmm13, %xmm5
        por       %xmm3, %xmm2
..B8.11:
        movdqa    %xmm12, %xmm4
        paddd     %xmm2, %xmm5
        por       %xmm9, %xmm4
        movdqa    %xmm12, %xmm2
        pand      %xmm0, %xmm4
        pand      %xmm9, %xmm2
        paddd     %xmm13, %xmm6
        por       %xmm2, %xmm4
        paddd     %xmm4, %xmm6
        movdqa    %xmm14, %xmm4
        movdqa    560(%rsp), %xmm3
        por       %xmm10, %xmm4
        movdqa    %xmm14, %xmm2
        paddd     %xmm3, %xmm5
        pand      %xmm15, %xmm4
        pand      %xmm10, %xmm2
        por       %xmm2, %xmm4
        movdqa    %xmm5, %xmm2
        paddd     576(%rsp), %xmm6
        paddd     %xmm13, %xmm7
        pslld     $9, %xmm2
        psrld     $23, %xmm5
        paddd     %xmm4, %xmm7
        por       %xmm5, %xmm2
        movdqa    %xmm6, %xmm5
        psrld     $23, %xmm6
        paddd     592(%rsp), %xmm7
        pslld     $9, %xmm5
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        movdqa    %xmm1, %xmm4
        por       %xmm7, %xmm6
        por       %xmm11, %xmm4
        movdqa    %xmm1, %xmm7
        pand      %xmm2, %xmm4
        pand      %xmm11, %xmm7
        paddd     %xmm13, %xmm8
        por       %xmm7, %xmm4
        paddd     %xmm4, %xmm8
        movdqa    %xmm0, %xmm4
        por       %xmm12, %xmm4
        movdqa    %xmm0, %xmm7
        pand      %xmm5, %xmm4
        pand      %xmm12, %xmm7
        paddd     %xmm13, %xmm9
        por       %xmm7, %xmm4
        paddd     %xmm4, %xmm9
        movdqa    %xmm15, %xmm4
        por       %xmm14, %xmm4
        movdqa    %xmm15, %xmm7
        paddd     672(%rsp), %xmm8
        pand      %xmm6, %xmm4
        pand      %xmm14, %xmm7
        paddd     %xmm13, %xmm10
        por       %xmm7, %xmm4
        movdqa    %xmm8, %xmm7
        paddd     608(%rsp), %xmm9
        pslld     $13, %xmm7
        psrld     $19, %xmm8
        paddd     %xmm4, %xmm10
        por       %xmm8, %xmm7
        movdqa    %xmm9, %xmm8
        paddd     624(%rsp), %xmm10
        pslld     $13, %xmm8
        psrld     $19, %xmm9
        movdqa    %xmm1, %xmm4
        por       %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        pslld     $13, %xmm9
        psrld     $19, %xmm10
        por       %xmm10, %xmm9
        por       %xmm2, %xmm4
        movdqa    %xmm1, %xmm10
        pand      %xmm7, %xmm4
        pand      %xmm2, %xmm10
        paddd     %xmm13, %xmm11
        por       %xmm10, %xmm4
        movdqa    %xmm0, %xmm10
        paddd     %xmm4, %xmm11
        movdqa    %xmm0, %xmm4
        por       %xmm5, %xmm4
        pand      %xmm5, %xmm10
        pand      %xmm8, %xmm4
        paddd     %xmm13, %xmm12
        por       %xmm10, %xmm4
        movdqa    %xmm15, %xmm10
        paddd     %xmm4, %xmm12
        movdqa    %xmm15, %xmm4
        por       %xmm6, %xmm4
        pand      %xmm6, %xmm10
        paddd     64(%rsp), %xmm11
        pand      %xmm9, %xmm4
        por       %xmm10, %xmm4
        movdqa    %xmm11, %xmm10
        paddd     80(%rsp), %xmm12
        paddd     %xmm13, %xmm14
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        paddd     %xmm4, %xmm14
        por       %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        psrld     $29, %xmm12
        paddd     96(%rsp), %xmm14
        pslld     $3, %xmm11
        por       %xmm12, %xmm11
        movdqa    %xmm14, %xmm12
        pslld     $3, %xmm12
        psrld     $29, %xmm14
        movdqa    %xmm7, %xmm4
        por       %xmm14, %xmm12
        por       %xmm2, %xmm4
        movdqa    %xmm7, %xmm14
        pand      %xmm10, %xmm4
        pand      %xmm2, %xmm14
        paddd     %xmm13, %xmm1
        por       %xmm14, %xmm4
        paddd     %xmm4, %xmm1
        movdqa    %xmm8, %xmm4
        por       %xmm5, %xmm4
        movdqa    %xmm8, %xmm14
        pand      %xmm11, %xmm4
        pand      %xmm5, %xmm14
        paddd     %xmm13, %xmm0
        por       %xmm14, %xmm4
        paddd     %xmm4, %xmm0
        movdqa    %xmm9, %xmm4
        por       %xmm6, %xmm4
        movdqa    %xmm9, %xmm14
        paddd     160(%rsp), %xmm1
        pand      %xmm12, %xmm4
        pand      %xmm6, %xmm14
        paddd     %xmm13, %xmm15
        por       %xmm14, %xmm4
        movdqa    %xmm1, %xmm14
        paddd     144(%rsp), %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm1
        paddd     %xmm4, %xmm15
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        paddd     128(%rsp), %xmm15
        pslld     $5, %xmm1
        psrld     $27, %xmm0
        movdqa    %xmm10, %xmm4
        por       %xmm0, %xmm1
        movdqa    %xmm15, %xmm0
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        por       %xmm15, %xmm0
        por       %xmm7, %xmm4
        movdqa    %xmm10, %xmm15
        pand      %xmm14, %xmm4
        pand      %xmm7, %xmm15
        paddd     %xmm13, %xmm2
        por       %xmm15, %xmm4
        movdqa    %xmm11, %xmm15
        paddd     %xmm4, %xmm2
        movdqa    %xmm11, %xmm4
        por       %xmm8, %xmm4
        pand      %xmm8, %xmm15
        pand      %xmm1, %xmm4
        paddd     %xmm13, %xmm5
        por       %xmm15, %xmm4
        movdqa    %xmm12, %xmm15
        paddd     %xmm4, %xmm5
        movdqa    %xmm12, %xmm4
        por       %xmm9, %xmm4
        pand      %xmm9, %xmm15
        paddd     256(%rsp), %xmm2
        pand      %xmm0, %xmm4
        paddd     %xmm13, %xmm6
        por       %xmm15, %xmm4
        movdqa    %xmm2, %xmm15
        paddd     %xmm4, %xmm6
        paddd     320(%rsp), %xmm5
        pslld     $9, %xmm15
        psrld     $23, %xmm2
        paddd     %xmm13, %xmm7
        paddd     336(%rsp), %xmm6
        por       %xmm2, %xmm15
        movdqa    %xmm5, %xmm2
        psrld     $23, %xmm5
        pslld     $9, %xmm2
        movdqa    %xmm6, %xmm4
        por       %xmm5, %xmm2
        pslld     $9, %xmm4
        psrld     $23, %xmm6
        movdqa    %xmm14, %xmm5
        por       %xmm6, %xmm4
        por       %xmm10, %xmm5
        movdqa    %xmm14, %xmm6
        pand      %xmm15, %xmm5
        pand      %xmm10, %xmm6
        paddd     %xmm13, %xmm8
        por       %xmm6, %xmm5
        movdqa    %xmm1, %xmm6
        paddd     %xmm5, %xmm7
        movdqa    %xmm1, %xmm5
        por       %xmm11, %xmm5
        pand      %xmm11, %xmm6
        pand      %xmm2, %xmm5
        paddd     %xmm13, %xmm9
        por       %xmm6, %xmm5
        movdqa    %xmm0, %xmm6
        por       %xmm12, %xmm6
        movdqa    %xmm0, %xmm13
        paddd     %xmm5, %xmm8
        pand      %xmm4, %xmm6
        pand      %xmm12, %xmm13
        paddd     816(%rsp), %xmm8
        por       %xmm13, %xmm6
        paddd     %xmm6, %xmm9
        movdqa    %xmm8, %xmm13
        paddd     768(%rsp), %xmm9
        pslld     $13, %xmm13
        psrld     $19, %xmm8
        paddd     448(%rsp), %xmm7
        por       %xmm8, %xmm13
        movdqa    %xmm9, %xmm8
        movdqa    %xmm7, %xmm5
        pslld     $13, %xmm8
        psrld     $19, %xmm9
        pslld     $13, %xmm5
        psrld     $19, %xmm7
        por       %xmm9, %xmm8
        movdqa    %xmm15, %xmm9
        movdqa    .L_2il0floatpacket.480(%rip), %xmm6
        por       %xmm7, %xmm5
        pxor      %xmm14, %xmm9
        paddd     %xmm6, %xmm10
        pxor      %xmm5, %xmm9
        movdqa    %xmm2, %xmm7
        paddd     %xmm9, %xmm10
        movdqa    %xmm4, %xmm9
        pxor      %xmm1, %xmm7
        pxor      %xmm0, %xmm9
        paddd     784(%rsp), %xmm10
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm7
        paddd     %xmm6, %xmm12
        pxor      %xmm8, %xmm9
        paddd     %xmm7, %xmm11
        paddd     %xmm9, %xmm12
        movdqa    %xmm10, %xmm9
        paddd     800(%rsp), %xmm11
        pslld     $3, %xmm9
        psrld     $29, %xmm10
        paddd     %xmm6, %xmm14
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        paddd     752(%rsp), %xmm12
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        movdqa    %xmm13, %xmm7
        por       %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        pslld     $3, %xmm11
        psrld     $29, %xmm12
        por       %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        pxor      %xmm15, %xmm12
        pxor      %xmm2, %xmm7
        pxor      %xmm9, %xmm12
        paddd     %xmm6, %xmm1
        paddd     %xmm12, %xmm14
        movdqa    %xmm8, %xmm12
        pxor      %xmm4, %xmm12
        pxor      %xmm10, %xmm7
        paddd     640(%rsp), %xmm14
        paddd     %xmm6, %xmm0
        pxor      %xmm11, %xmm12
        paddd     %xmm7, %xmm1
        paddd     %xmm12, %xmm0
        movdqa    %xmm14, %xmm12
        paddd     688(%rsp), %xmm1
        pslld     $9, %xmm12
        psrld     $23, %xmm14
        paddd     %xmm6, %xmm15
        por       %xmm14, %xmm12
        movdqa    %xmm1, %xmm14
        paddd     656(%rsp), %xmm0
        pslld     $9, %xmm14
        psrld     $23, %xmm1
        movdqa    %xmm10, %xmm7
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        pslld     $9, %xmm1
        psrld     $23, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        pxor      %xmm5, %xmm0
        pxor      %xmm13, %xmm7
        pxor      %xmm12, %xmm0
        paddd     %xmm6, %xmm2
        paddd     %xmm0, %xmm15
        movdqa    %xmm11, %xmm0
        pxor      %xmm8, %xmm0
        pxor      %xmm14, %xmm7
        paddd     480(%rsp), %xmm15
        paddd     %xmm6, %xmm4
        pxor      %xmm1, %xmm0
        paddd     %xmm7, %xmm2
        paddd     %xmm0, %xmm4
        movdqa    %xmm15, %xmm0
        paddd     496(%rsp), %xmm2
        pslld     $11, %xmm0
        psrld     $21, %xmm15
        movdqa    %xmm14, %xmm7
        por       %xmm15, %xmm0
        movdqa    %xmm2, %xmm15
        paddd     512(%rsp), %xmm4
        pslld     $11, %xmm15
        psrld     $21, %xmm2
        paddd     %xmm6, %xmm5
        por       %xmm2, %xmm15
        movdqa    %xmm4, %xmm2
        pslld     $11, %xmm2
        psrld     $21, %xmm4
        por       %xmm4, %xmm2
        movdqa    %xmm12, %xmm4
        pxor      %xmm9, %xmm4
        pxor      %xmm10, %xmm7
        pxor      %xmm0, %xmm4
        paddd     %xmm6, %xmm13
        paddd     %xmm4, %xmm5
        pxor      %xmm15, %xmm7
        movdqa    %xmm1, %xmm4
        paddd     %xmm7, %xmm13
        pxor      %xmm11, %xmm4
        paddd     %xmm6, %xmm8
        paddd     736(%rsp), %xmm13
        pxor      %xmm2, %xmm4
        paddd     %xmm4, %xmm8
        movdqa    %xmm13, %xmm4
        paddd     720(%rsp), %xmm8
        pslld     $15, %xmm4
        psrld     $17, %xmm13
        paddd     %xmm6, %xmm9
        paddd     704(%rsp), %xmm5
        por       %xmm13, %xmm4
        movdqa    %xmm8, %xmm13
        movdqa    %xmm5, %xmm7
        pslld     $15, %xmm13
        psrld     $17, %xmm8
        pslld     $15, %xmm7
        psrld     $17, %xmm5
        por       %xmm8, %xmm13
        movdqa    %xmm0, %xmm8
        por       %xmm5, %xmm7
        pxor      %xmm12, %xmm8
        pxor      %xmm7, %xmm8
        movdqa    %xmm15, %xmm5
        paddd     %xmm8, %xmm9
        movdqa    %xmm2, %xmm8
        pxor      %xmm14, %xmm5
        pxor      %xmm1, %xmm8
        paddd     272(%rsp), %xmm9
        paddd     %xmm6, %xmm10
        pxor      %xmm4, %xmm5
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm8
        paddd     %xmm5, %xmm10
        paddd     %xmm8, %xmm11
        movdqa    %xmm9, %xmm8
        paddd     288(%rsp), %xmm10
        pslld     $3, %xmm8
        psrld     $29, %xmm9
        paddd     %xmm6, %xmm12
        por       %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        paddd     304(%rsp), %xmm11
        pslld     $3, %xmm9
        psrld     $29, %xmm10
        movdqa    %xmm13, %xmm5
        por       %xmm10, %xmm9
        movdqa    %xmm11, %xmm10
        pslld     $3, %xmm10
        psrld     $29, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm7, %xmm11
        pxor      %xmm0, %xmm11
        pxor      %xmm2, %xmm5
        pxor      %xmm8, %xmm11
        paddd     %xmm6, %xmm1
        paddd     %xmm11, %xmm12
        pxor      %xmm10, %xmm5
        paddd     %xmm3, %xmm12
        movdqa    %xmm4, %xmm3
        pxor      %xmm15, %xmm3
        paddd     %xmm5, %xmm1
        paddd     592(%rsp), %xmm1
        paddd     %xmm6, %xmm14
        pxor      %xmm9, %xmm3
        movdqa    %xmm12, %xmm11
        paddd     %xmm3, %xmm14
        movdqa    %xmm1, %xmm3
        paddd     576(%rsp), %xmm14
        pslld     $9, %xmm3
        psrld     $23, %xmm1
        pslld     $9, %xmm11
        psrld     $23, %xmm12
        movdqa    %xmm14, %xmm5
        por       %xmm1, %xmm3
        movdqa    %xmm8, %xmm1
        por       %xmm12, %xmm11
        pslld     $9, %xmm5
        psrld     $23, %xmm14
        pxor      %xmm7, %xmm1
        por       %xmm14, %xmm5
        paddd     %xmm6, %xmm0
        pxor      %xmm11, %xmm1
        movdqa    %xmm9, %xmm12
        movdqa    %xmm10, %xmm14
        paddd     %xmm1, %xmm0
        pxor      %xmm4, %xmm12
        pxor      %xmm13, %xmm14
        paddd     400(%rsp), %xmm0
        paddd     %xmm6, %xmm15
        pxor      %xmm5, %xmm12
        paddd     %xmm6, %xmm2
        pxor      %xmm3, %xmm14
        paddd     %xmm12, %xmm15
        paddd     %xmm14, %xmm2
        movdqa    %xmm0, %xmm12
        paddd     432(%rsp), %xmm2
        pslld     $11, %xmm12
        psrld     $21, %xmm0
        paddd     %xmm6, %xmm7
        por       %xmm0, %xmm12
        movdqa    %xmm2, %xmm0
        pslld     $11, %xmm0
        psrld     $21, %xmm2
        paddd     416(%rsp), %xmm15
        por       %xmm2, %xmm0
        movdqa    %xmm11, %xmm2
        movdqa    %xmm15, %xmm1
        pxor      %xmm8, %xmm2
        pslld     $11, %xmm1
        psrld     $21, %xmm15
        pxor      %xmm12, %xmm2
        movdqa    %xmm5, %xmm14
        por       %xmm15, %xmm1
        paddd     %xmm2, %xmm7
        pxor      %xmm9, %xmm14
        paddd     672(%rsp), %xmm7
        paddd     %xmm6, %xmm4
        pxor      %xmm1, %xmm14
        movdqa    %xmm3, %xmm15
        paddd     %xmm14, %xmm4
        movdqa    %xmm7, %xmm14
        paddd     608(%rsp), %xmm4
        pslld     $15, %xmm14
        psrld     $17, %xmm7
        pxor      %xmm10, %xmm15
        por       %xmm7, %xmm14
        movdqa    %xmm4, %xmm7
        paddd     %xmm6, %xmm13
        pxor      %xmm0, %xmm15
        pslld     $15, %xmm7
        psrld     $17, %xmm4
        paddd     %xmm15, %xmm13
        por       %xmm4, %xmm7
        movdqa    %xmm12, %xmm4
        paddd     %xmm6, %xmm8
        paddd     624(%rsp), %xmm13
        pxor      %xmm11, %xmm4
        movdqa    %xmm13, %xmm2
        pxor      %xmm14, %xmm4
        pslld     $15, %xmm2
        psrld     $17, %xmm13
        paddd     %xmm4, %xmm8
        movdqa    %xmm0, %xmm4
        por       %xmm13, %xmm2
        pxor      %xmm3, %xmm4
        movdqa    %xmm1, %xmm13
        paddd     %xmm6, %xmm10
        pxor      %xmm2, %xmm4
        pxor      %xmm5, %xmm13
        paddd     %xmm4, %xmm10
        paddd     %xmm6, %xmm9
        paddd     112(%rsp), %xmm8
        pxor      %xmm7, %xmm13
        paddd     192(%rsp), %xmm10
        paddd     %xmm13, %xmm9
        movdqa    %xmm8, %xmm13
        movdqa    %xmm10, %xmm4
        paddd     176(%rsp), %xmm9
        pslld     $3, %xmm13
        psrld     $29, %xmm8
        pslld     $3, %xmm4
        psrld     $29, %xmm10
        por       %xmm8, %xmm13
        movdqa    %xmm9, %xmm8
        por       %xmm10, %xmm4
        movdqa    %xmm14, %xmm10
        pslld     $3, %xmm8
        psrld     $29, %xmm9
        pxor      %xmm12, %xmm10
        por       %xmm9, %xmm8
        paddd     %xmm6, %xmm11
        pxor      %xmm13, %xmm10
        movdqa    %xmm7, %xmm9
        paddd     %xmm10, %xmm11
        pxor      %xmm1, %xmm9
        paddd     384(%rsp), %xmm11
        paddd     %xmm6, %xmm5
        pxor      %xmm8, %xmm9
..B8.10:
        movdqa    %xmm2, %xmm10
        paddd     %xmm9, %xmm5
        pxor      %xmm0, %xmm10
        movdqa    %xmm11, %xmm9
        paddd     368(%rsp), %xmm5
        paddd     %xmm6, %xmm3
        pxor      %xmm4, %xmm10
        pslld     $9, %xmm9
        psrld     $23, %xmm11
        paddd     %xmm10, %xmm3
        por       %xmm11, %xmm9
        movdqa    %xmm5, %xmm11
        paddd     352(%rsp), %xmm3
        pslld     $9, %xmm11
        psrld     $23, %xmm5
        movdqa    %xmm13, %xmm15
        por       %xmm5, %xmm11
        movdqa    %xmm3, %xmm5
        pslld     $9, %xmm5
        psrld     $23, %xmm3
        pxor      %xmm14, %xmm15
        por       %xmm3, %xmm5
        paddd     %xmm6, %xmm12
        pxor      %xmm9, %xmm15
        movdqa    %xmm8, %xmm3
        paddd     %xmm15, %xmm12
        pxor      %xmm7, %xmm3
        paddd     %xmm6, %xmm1
        paddd     208(%rsp), %xmm12
        pxor      %xmm11, %xmm3
        movdqa    %xmm4, %xmm10
        paddd     %xmm3, %xmm1
        pxor      %xmm2, %xmm10
        movdqa    %xmm12, %xmm3
        paddd     224(%rsp), %xmm1
        paddd     %xmm6, %xmm0
        pxor      %xmm5, %xmm10
        pslld     $11, %xmm3
        psrld     $21, %xmm12
        paddd     %xmm10, %xmm0
        por       %xmm12, %xmm3
        movdqa    %xmm1, %xmm12
        paddd     240(%rsp), %xmm0
        pslld     $11, %xmm12
        psrld     $21, %xmm1
        paddd     %xmm6, %xmm14
        por       %xmm1, %xmm12
        movdqa    %xmm0, %xmm1
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        por       %xmm0, %xmm1
        movdqa    %xmm13, %xmm0
        pxor      %xmm9, %xmm0
        movdqa    %xmm8, %xmm10
        pxor      %xmm3, %xmm0
        pxor      %xmm11, %xmm10
        paddd     %xmm0, %xmm14
        paddd     %xmm6, %xmm7
        paddd     544(%rsp), %xmm14
        pxor      %xmm12, %xmm10
        movdqa    %xmm4, %xmm15
        paddd     %xmm10, %xmm7
        pxor      %xmm5, %xmm15
        movdqa    %xmm14, %xmm0
        paddd     528(%rsp), %xmm7
        paddd     %xmm6, %xmm2
        pxor      %xmm1, %xmm15
        pslld     $15, %xmm0
        psrld     $17, %xmm14
        paddd     %xmm15, %xmm2
        por       %xmm14, %xmm0
        movdqa    %xmm7, %xmm14
        paddd     464(%rsp), %xmm2
        pslld     $15, %xmm14
        psrld     $17, %xmm7
        movdqa    %xmm1, %xmm15
        por       %xmm7, %xmm14
        movdqa    %xmm2, %xmm7
        pslld     $15, %xmm7
        psrld     $17, %xmm2
        por       %xmm2, %xmm7
        movdqa    %xmm3, %xmm2
        pxor      %xmm9, %xmm2
        paddd     %xmm6, %xmm13
        pxor      %xmm0, %xmm2
        movdqa    %xmm12, %xmm10
        pxor      %xmm5, %xmm15
        paddd     %xmm2, %xmm13
        pxor      %xmm11, %xmm10
        paddd     %xmm6, %xmm4
        pxor      %xmm7, %xmm15
        paddd     %xmm6, %xmm8
        paddd     64(%rsp), %xmm13
        pxor      %xmm14, %xmm10
        paddd     %xmm15, %xmm4
        paddd     %xmm10, %xmm8
        paddd     96(%rsp), %xmm4
        movdqa    %xmm13, %xmm15
        paddd     80(%rsp), %xmm8
        pslld     $3, %xmm15
        psrld     $29, %xmm13
        movdqa    %xmm4, %xmm2
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm10
        pslld     $3, %xmm2
        psrld     $29, %xmm4
        movdqa    %xmm7, %xmm13
        pslld     $3, %xmm10
        psrld     $29, %xmm8
        por       %xmm4, %xmm2
        movdqa    %xmm0, %xmm4
        pxor      %xmm1, %xmm13
        por       %xmm8, %xmm10
        pxor      %xmm3, %xmm4
        movdqa    %xmm14, %xmm8
        paddd     %xmm6, %xmm5
        pxor      %xmm2, %xmm13
        paddd     %xmm6, %xmm9
        pxor      %xmm15, %xmm4
        pxor      %xmm12, %xmm8
        paddd     %xmm13, %xmm5
        paddd     %xmm4, %xmm9
        paddd     336(%rsp), %xmm5
        paddd     %xmm6, %xmm11
        pxor      %xmm10, %xmm8
        movdqa    %xmm5, %xmm4
        paddd     256(%rsp), %xmm9
        paddd     %xmm8, %xmm11
        paddd     320(%rsp), %xmm11
        movdqa    %xmm9, %xmm13
        pslld     $9, %xmm4
        psrld     $23, %xmm5
        pslld     $9, %xmm13
        psrld     $23, %xmm9
        movdqa    %xmm11, %xmm8
        por       %xmm5, %xmm4
        movdqa    %xmm15, %xmm5
        por       %xmm9, %xmm13
        pslld     $9, %xmm8
        psrld     $23, %xmm11
        pxor      %xmm0, %xmm5
        por       %xmm11, %xmm8
        paddd     %xmm6, %xmm3
        pxor      %xmm13, %xmm5
        movdqa    %xmm10, %xmm9
        movdqa    %xmm2, %xmm11
        paddd     %xmm5, %xmm3
        pxor      %xmm14, %xmm9
        pxor      %xmm7, %xmm11
        paddd     %xmm6, %xmm12
        paddd     160(%rsp), %xmm3
        pxor      %xmm8, %xmm9
        paddd     %xmm6, %xmm1
        pxor      %xmm4, %xmm11
        paddd     %xmm9, %xmm12
        paddd     %xmm11, %xmm1
        movdqa    %xmm3, %xmm9
        psrld     $21, %xmm3
        paddd     128(%rsp), %xmm1
        pslld     $11, %xmm9
        por       %xmm3, %xmm9
        movdqa    %xmm1, %xmm3
        paddd     144(%rsp), %xmm12
        pslld     $11, %xmm3
        psrld     $21, %xmm1
        movdqa    %xmm12, %xmm5
        por       %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        pslld     $11, %xmm5
        psrld     $21, %xmm12
        pxor      %xmm15, %xmm1
        por       %xmm12, %xmm5
        paddd     %xmm6, %xmm0
        pxor      %xmm9, %xmm1
        paddd     %xmm6, %xmm14
        movdqa    %xmm8, %xmm12
        paddd     %xmm6, %xmm7
        movdqa    %xmm4, %xmm6
        paddd     %xmm1, %xmm0
        pxor      %xmm10, %xmm12
        pxor      %xmm2, %xmm6
        pxor      %xmm5, %xmm12
        paddd     448(%rsp), %xmm0
        pxor      %xmm3, %xmm6
        paddd     %xmm12, %xmm14
        paddd     %xmm6, %xmm7
        movdqa    %xmm0, %xmm6
        psrld     $17, %xmm0
        paddd     816(%rsp), %xmm14
        pslld     $15, %xmm6
        paddd     768(%rsp), %xmm7
        por       %xmm0, %xmm6
        movdqa    %xmm14, %xmm1
        movdqa    %xmm7, %xmm0
        pslld     $15, %xmm1
        psrld     $17, %xmm14
        pslld     $15, %xmm0
        psrld     $17, %xmm7
        por       %xmm14, %xmm1
        por       %xmm7, %xmm0
        je        ..B8.6
..B8.5:
        movdqa    .L_2il0floatpacket.475(%rip), %xmm7
        movdqa    .L_2il0floatpacket.476(%rip), %xmm11
        paddd     %xmm7, %xmm15
        movdqa    .L_2il0floatpacket.477(%rip), %xmm12
        paddd     %xmm11, %xmm6
        movdqa    .L_2il0floatpacket.478(%rip), %xmm14
        paddd     %xmm12, %xmm9
        paddd     %xmm14, %xmm13
        paddd     %xmm7, %xmm10
        paddd     %xmm11, %xmm1
        paddd     %xmm12, %xmm5
        paddd     %xmm14, %xmm8
        paddd     %xmm7, %xmm2
        paddd     %xmm11, %xmm0
        paddd     %xmm12, %xmm3
        paddd     %xmm14, %xmm4
        movdqa    %xmm15, (%rsi)
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm13, 48(%rsi)
        movdqa    %xmm10, 64(%rsi)
        movdqa    %xmm1, 80(%rsi)
        movdqa    %xmm5, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm2, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm3, 160(%rsi)
        movdqa    %xmm4, 176(%rsi)
        addq      $840, %rsp
..___tag_value_SSEmd4body.214:
        ret       
..___tag_value_SSEmd4body.215:
..B8.6:
        paddd     (%rsp), %xmm15
        paddd     48(%rsp), %xmm6
        paddd     32(%rsp), %xmm9
        paddd     16(%rsp), %xmm13
        paddd     64(%rsi), %xmm10
        paddd     80(%rsi), %xmm1
        paddd     96(%rsi), %xmm5
        paddd     112(%rsi), %xmm8
        paddd     128(%rsi), %xmm2
        paddd     144(%rsi), %xmm0
        paddd     160(%rsi), %xmm3
        paddd     176(%rsi), %xmm4
        movdqa    %xmm15, (%rsi)
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm13, 48(%rsi)
        movdqa    %xmm10, 64(%rsi)
        movdqa    %xmm1, 80(%rsi)
        movdqa    %xmm5, 96(%rsi)
        movdqa    %xmm8, 112(%rsi)
        movdqa    %xmm2, 128(%rsi)
        movdqa    %xmm0, 144(%rsi)
        movdqa    %xmm3, 160(%rsi)
        movdqa    %xmm4, 176(%rsi)
..B8.7:
        addq      $840, %rsp
..___tag_value_SSEmd4body.216:
        ret       
        .align    16,0x90
..___tag_value_SSEmd4body.217:
	.type	SSEmd4body,@function
	.size	SSEmd4body,.-SSEmd4body
	.data
# -- End  SSEmd4body
	.text
# -- Begin  SSESHA1body
       .align    16,0x90
	.globl SSESHA1body
SSESHA1body:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %ecx
..B9.1:
..___tag_value_SSESHA1body.218:
        subq      $904, %rsp
..___tag_value_SSESHA1body.220:
        testq     %rdx, %rdx
        je        ..B9.10
..B9.2:
        movdqa    (%rdx), %xmm2
        movdqa    16(%rdx), %xmm1
        movdqa    32(%rdx), %xmm6
        movdqa    48(%rdx), %xmm4
        movdqa    64(%rdx), %xmm11
        movdqa    80(%rdx), %xmm13
        movdqa    96(%rdx), %xmm8
        movdqa    112(%rdx), %xmm12
        movdqa    128(%rdx), %xmm5
        movdqa    144(%rdx), %xmm3
..B9.3:
        movdqa    464(%rdi), %xmm0
        movdqa    %xmm6, %xmm10
        movdqa    %xmm0, 688(%rsp)
        pxor      %xmm4, %xmm10
        pxor      384(%rdi), %xmm0
        pand      %xmm1, %xmm10
        pxor      288(%rdi), %xmm0
        pxor      %xmm4, %xmm10
        pxor      256(%rdi), %xmm0
        paddd     %xmm10, %xmm11
        movdqa    %xmm0, %xmm9
        movdqa    %xmm13, %xmm10
        paddd     %xmm0, %xmm9
        psrld     $31, %xmm0
        movdqa    208(%rdi), %xmm7
        por       %xmm0, %xmm9
        movdqa    %xmm12, %xmm0
        pslld     $5, %xmm10
        movdqa    %xmm7, 656(%rsp)
        pxor      %xmm5, %xmm0
        pxor      128(%rdi), %xmm7
        pand      %xmm8, %xmm0
        pxor      32(%rdi), %xmm7
        pxor      %xmm5, %xmm0
        pxor      (%rdi), %xmm7
        paddd     %xmm0, %xmm3
        movdqa    %xmm9, 256(%rsp)
        movdqa    %xmm13, %xmm9
        movdqa    %xmm7, %xmm15
        psrld     $27, %xmm9
        movdqa    %xmm1, %xmm0
        paddd     %xmm7, %xmm15
        psrld     $31, %xmm7
        por       %xmm9, %xmm10
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        movdqa    400(%rdi), %xmm9
        por       %xmm7, %xmm15
        movdqa    %xmm2, %xmm7
        movdqa    %xmm2, %xmm14
        paddd     %xmm10, %xmm3
        por       %xmm1, %xmm0
        movdqa    480(%rdi), %xmm10
        movdqa    %xmm8, %xmm1
        movdqa    %xmm10, 672(%rsp)
        pslld     $5, %xmm7
        psrld     $27, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm8
        pxor      %xmm9, %xmm10
        pxor      304(%rdi), %xmm10
        por       %xmm14, %xmm7
        movdqa    144(%rdi), %xmm14
        por       %xmm8, %xmm1
        movdqa    224(%rdi), %xmm8
        paddd     %xmm7, %xmm11
        pxor      272(%rdi), %xmm10
        movdqa    %xmm8, 304(%rsp)
        pxor      %xmm14, %xmm8
        movdqa    %xmm9, 752(%rsp)
        movdqa    %xmm10, %xmm9
        pxor      48(%rdi), %xmm8
        paddd     %xmm10, %xmm9
        pxor      16(%rdi), %xmm8
        psrld     $31, %xmm10
        movdqa    .L_2il0floatpacket.506(%rip), %xmm7
        por       %xmm10, %xmm9
        movdqa    %xmm14, 832(%rsp)
        paddd     %xmm7, %xmm11
        movdqa    %xmm8, %xmm14
        movdqa    %xmm6, %xmm10
        paddd     (%rdi), %xmm11
        paddd     %xmm8, %xmm14
        psrld     $31, %xmm8
        pxor      %xmm0, %xmm10
        movdqa    %xmm9, 224(%rsp)
        por       %xmm8, %xmm14
        pand      %xmm2, %xmm10
        movdqa    %xmm11, %xmm8
        movdqa    %xmm11, %xmm9
        paddd     %xmm7, %xmm3
        movdqa    %xmm14, 240(%rsp)
        pxor      %xmm6, %xmm10
        pslld     $5, %xmm8
        psrld     $27, %xmm9
        movdqa    %xmm12, %xmm14
        paddd     %xmm10, %xmm4
        paddd     256(%rdi), %xmm3
        por       %xmm9, %xmm8
        pxor      %xmm1, %xmm14
        paddd     %xmm8, %xmm4
        pand      %xmm13, %xmm14
        movdqa    %xmm3, %xmm8
        movdqa    %xmm3, %xmm9
        pxor      %xmm12, %xmm14
        pslld     $5, %xmm8
        psrld     $27, %xmm9
        paddd     %xmm14, %xmm5
        por       %xmm9, %xmm8
        movdqa    160(%rdi), %xmm14
        paddd     %xmm8, %xmm5
        movdqa    240(%rdi), %xmm8
        movdqa    %xmm2, %xmm9
        movdqa    %xmm13, %xmm10
        pslld     $30, %xmm9
        movdqa    %xmm8, 288(%rsp)
        psrld     $2, %xmm2
        pslld     $30, %xmm10
        psrld     $2, %xmm13
        pxor      %xmm14, %xmm8
        por       %xmm2, %xmm9
        movdqa    416(%rdi), %xmm2
        por       %xmm13, %xmm10
        movdqa    496(%rdi), %xmm13
        paddd     %xmm7, %xmm4
        pxor      64(%rdi), %xmm8
        paddd     %xmm7, %xmm5
        pxor      32(%rdi), %xmm8
        movdqa    %xmm13, 704(%rsp)
        pxor      %xmm2, %xmm13
        movdqa    %xmm14, 768(%rsp)
        movdqa    %xmm8, %xmm14
        movdqa    %xmm2, 720(%rsp)
        movdqa    %xmm9, %xmm2
        pxor      320(%rdi), %xmm13
        paddd     %xmm8, %xmm14
        pxor      288(%rdi), %xmm13
        psrld     $31, %xmm8
        pxor      %xmm0, %xmm2
        por       %xmm8, %xmm14
        movdqa    %xmm13, %xmm8
        pand      %xmm11, %xmm2
        paddd     16(%rdi), %xmm4
        paddd     %xmm13, %xmm8
        psrld     $31, %xmm13
        pxor      %xmm0, %xmm2
        por       %xmm13, %xmm8
        paddd     %xmm2, %xmm6
        movdqa    %xmm4, %xmm2
        movdqa    %xmm4, %xmm13
        pslld     $5, %xmm2
        psrld     $27, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm10, %xmm13
        pxor      %xmm1, %xmm13
        paddd     %xmm2, %xmm6
        pand      %xmm3, %xmm13
        paddd     %xmm7, %xmm6
        paddd     272(%rdi), %xmm5
        pxor      %xmm1, %xmm13
        paddd     %xmm13, %xmm12
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm2
        pslld     $5, %xmm13
        psrld     $27, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm11, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        por       %xmm11, %xmm2
        movdqa    %xmm3, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm3
        por       %xmm3, %xmm11
        paddd     %xmm13, %xmm12
        movdqa    176(%rdi), %xmm3
        paddd     %xmm7, %xmm12
        movdqa    %xmm3, 736(%rsp)
        pxor      %xmm15, %xmm3
        movdqa    432(%rdi), %xmm13
        pxor      80(%rdi), %xmm3
        movdqa    %xmm13, 784(%rsp)
        pxor      48(%rdi), %xmm3
        pxor      256(%rsp), %xmm13
        movdqa    %xmm15, 272(%rsp)
        movdqa    %xmm3, %xmm15
        pxor      336(%rdi), %xmm13
        paddd     %xmm3, %xmm15
        pxor      304(%rdi), %xmm13
        psrld     $31, %xmm3
        por       %xmm3, %xmm15
        movdqa    %xmm13, %xmm3
        paddd     %xmm13, %xmm3
        psrld     $31, %xmm13
        paddd     32(%rdi), %xmm6
        por       %xmm13, %xmm3
        movdqa    %xmm15, 176(%rsp)
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, 160(%rsp)
        movdqa    %xmm6, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm3
        movdqa    %xmm2, %xmm13
        por       %xmm3, %xmm15
        movdqa    %xmm11, %xmm3
        pxor      %xmm9, %xmm13
        pxor      %xmm10, %xmm3
        pand      %xmm4, %xmm13
        pand      %xmm5, %xmm3
        pxor      %xmm9, %xmm13
        paddd     288(%rdi), %xmm12
        pxor      %xmm10, %xmm3
        paddd     %xmm13, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    %xmm12, %xmm3
        movdqa    %xmm12, %xmm13
        pslld     $5, %xmm3
        psrld     $27, %xmm13
        por       %xmm13, %xmm3
        paddd     %xmm15, %xmm0
        paddd     %xmm3, %xmm1
        movdqa    %xmm4, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        movdqa    192(%rdi), %xmm15
        por       %xmm4, %xmm3
        movdqa    %xmm5, %xmm4
        psrld     $2, %xmm5
        movdqa    %xmm15, 800(%rsp)
        pslld     $30, %xmm4
        pxor      240(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    448(%rdi), %xmm5
        paddd     %xmm7, %xmm0
        pxor      96(%rdi), %xmm15
        paddd     %xmm7, %xmm1
        movdqa    %xmm5, 816(%rsp)
        pxor      64(%rdi), %xmm15
        pxor      224(%rsp), %xmm5
        movdqa    %xmm15, %xmm13
        pxor      352(%rdi), %xmm5
        paddd     %xmm15, %xmm13
        pxor      320(%rdi), %xmm5
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm5, %xmm15
        paddd     %xmm5, %xmm15
        psrld     $31, %xmm5
        por       %xmm5, %xmm15
        movdqa    %xmm3, %xmm5
        pxor      %xmm2, %xmm5
        pand      %xmm6, %xmm5
        paddd     48(%rdi), %xmm0
        pxor      %xmm2, %xmm5
        movdqa    %xmm15, 608(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    %xmm0, %xmm5
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm4, %xmm15
        pxor      %xmm11, %xmm15
        paddd     %xmm5, %xmm9
        pand      %xmm12, %xmm15
        paddd     %xmm7, %xmm9
        paddd     304(%rdi), %xmm1
        pxor      %xmm11, %xmm15
        paddd     %xmm15, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm5
        pslld     $5, %xmm15
        psrld     $27, %xmm5
        por       %xmm5, %xmm15
        movdqa    %xmm6, %xmm5
        paddd     %xmm15, %xmm10
        pslld     $30, %xmm5
        movdqa    208(%rdi), %xmm15
        psrld     $2, %xmm6
        movdqa    %xmm14, 208(%rsp)
        pxor      %xmm14, %xmm15
        movdqa    464(%rdi), %xmm14
        por       %xmm6, %xmm5
        pxor      %xmm8, %xmm14
        movdqa    %xmm12, %xmm6
        pxor      368(%rdi), %xmm14
        pslld     $30, %xmm6
        pxor      112(%rdi), %xmm15
        psrld     $2, %xmm12
        pxor      336(%rdi), %xmm14
        por       %xmm12, %xmm6
        pxor      80(%rdi), %xmm15
        paddd     %xmm7, %xmm10
        movdqa    %xmm8, 192(%rsp)
        movdqa    %xmm14, %xmm8
        movdqa    %xmm15, %xmm12
        paddd     %xmm14, %xmm8
        psrld     $31, %xmm14
        paddd     %xmm15, %xmm12
        paddd     64(%rdi), %xmm9
        psrld     $31, %xmm15
        por       %xmm14, %xmm8
        por       %xmm15, %xmm12
        movdqa    %xmm8, 576(%rsp)
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm8
        pslld     $5, %xmm15
        psrld     $27, %xmm8
        movdqa    %xmm5, %xmm14
        por       %xmm8, %xmm15
        movdqa    %xmm6, %xmm8
        pxor      %xmm3, %xmm14
        pxor      %xmm4, %xmm8
        pand      %xmm0, %xmm14
        pand      %xmm1, %xmm8
        paddd     320(%rdi), %xmm10
        pxor      %xmm3, %xmm14
        pxor      %xmm4, %xmm8
        paddd     %xmm14, %xmm2
        paddd     %xmm8, %xmm11
        movdqa    %xmm10, %xmm8
        movdqa    %xmm10, %xmm14
        pslld     $5, %xmm8
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm2
        por       %xmm14, %xmm8
        paddd     %xmm7, %xmm2
        paddd     %xmm8, %xmm11
        movdqa    %xmm0, %xmm8
        pslld     $30, %xmm8
        psrld     $2, %xmm0
        movdqa    224(%rdi), %xmm15
        por       %xmm0, %xmm8
        movdqa    %xmm1, %xmm0
        psrld     $2, %xmm1
        pxor      176(%rsp), %xmm15
        pslld     $30, %xmm0
        pxor      128(%rdi), %xmm15
        por       %xmm1, %xmm0
        movdqa    480(%rdi), %xmm1
        paddd     %xmm7, %xmm11
        pxor      96(%rdi), %xmm15
        pxor      160(%rsp), %xmm1
        movdqa    %xmm15, %xmm14
        pxor      384(%rdi), %xmm1
        paddd     %xmm15, %xmm14
        pxor      352(%rdi), %xmm1
        psrld     $31, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm1, %xmm15
        paddd     %xmm1, %xmm15
        psrld     $31, %xmm1
        por       %xmm1, %xmm15
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        pand      %xmm9, %xmm1
        pxor      %xmm5, %xmm1
        paddd     %xmm1, %xmm3
        movdqa    %xmm0, %xmm1
        paddd     80(%rdi), %xmm2
        pxor      %xmm6, %xmm1
        movdqa    %xmm14, 560(%rsp)
        movdqa    %xmm2, %xmm14
        movdqa    %xmm15, 512(%rsp)
        movdqa    %xmm2, %xmm15
        pand      %xmm10, %xmm1
        pslld     $5, %xmm15
        paddd     336(%rdi), %xmm11
        psrld     $27, %xmm14
        pxor      %xmm6, %xmm1
        por       %xmm14, %xmm15
        paddd     %xmm1, %xmm4
        movdqa    %xmm11, %xmm1
        movdqa    %xmm11, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm3
        por       %xmm14, %xmm1
        paddd     %xmm7, %xmm3
        paddd     %xmm1, %xmm4
        movdqa    %xmm9, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm9
        por       %xmm9, %xmm1
        movdqa    %xmm10, %xmm9
        pslld     $30, %xmm9
        psrld     $2, %xmm10
        por       %xmm10, %xmm9
        paddd     %xmm7, %xmm4
        movdqa    240(%rdi), %xmm10
        pxor      %xmm13, %xmm10
        pxor      144(%rdi), %xmm10
        movdqa    496(%rdi), %xmm14
        pxor      112(%rdi), %xmm10
        pxor      608(%rsp), %xmm14
        movdqa    %xmm13, 640(%rsp)
        movdqa    %xmm10, %xmm13
        pxor      400(%rdi), %xmm14
        paddd     %xmm10, %xmm13
        pxor      368(%rdi), %xmm14
        psrld     $31, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm14, %xmm15
        movdqa    %xmm1, %xmm10
        paddd     %xmm14, %xmm15
        paddd     96(%rdi), %xmm3
        psrld     $31, %xmm14
        pxor      %xmm8, %xmm10
        por       %xmm14, %xmm15
        movdqa    %xmm13, 496(%rsp)
        pand      %xmm2, %xmm10
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm13
        paddd     352(%rdi), %xmm4
        pxor      %xmm8, %xmm10
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        movdqa    %xmm15, 448(%rsp)
        paddd     %xmm10, %xmm5
        por       %xmm13, %xmm14
        movdqa    %xmm9, %xmm10
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm0, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        pand      %xmm11, %xmm10
        por       %xmm13, %xmm15
        movdqa    %xmm11, %xmm13
        movdqa    %xmm12, 592(%rsp)
        pxor      %xmm0, %xmm10
        pxor      272(%rsp), %xmm12
        pslld     $30, %xmm13
        psrld     $2, %xmm11
        paddd     %xmm14, %xmm5
        pxor      160(%rdi), %xmm12
        paddd     %xmm10, %xmm6
        movdqa    128(%rdi), %xmm14
        movdqa    %xmm2, %xmm10
        por       %xmm11, %xmm13
        pslld     $30, %xmm10
        movdqa    576(%rsp), %xmm11
        psrld     $2, %xmm2
        pxor      256(%rsp), %xmm11
        pxor      %xmm14, %xmm12
        pxor      416(%rdi), %xmm11
        paddd     %xmm15, %xmm6
        por       %xmm2, %xmm10
        movdqa    %xmm12, %xmm15
        movdqa    384(%rdi), %xmm2
        paddd     %xmm12, %xmm15
        pxor      %xmm2, %xmm11
        psrld     $31, %xmm12
        por       %xmm12, %xmm15
        movdqa    %xmm11, %xmm12
        paddd     %xmm11, %xmm12
        psrld     $31, %xmm11
        paddd     %xmm7, %xmm5
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm11
        paddd     %xmm7, %xmm6
        paddd     112(%rdi), %xmm5
        pxor      %xmm1, %xmm11
        movdqa    %xmm15, 432(%rsp)
        pand      %xmm3, %xmm11
        movdqa    %xmm12, 320(%rsp)
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm12
        pxor      %xmm1, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm11, %xmm8
        por       %xmm12, %xmm15
        paddd     %xmm15, %xmm8
        paddd     %xmm7, %xmm8
        paddd     %xmm14, %xmm8
        movdqa    %xmm13, %xmm14
        paddd     368(%rdi), %xmm6
        pxor      %xmm9, %xmm14
        pand      %xmm4, %xmm14
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        paddd     %xmm14, %xmm0
        por       %xmm11, %xmm12
        paddd     %xmm12, %xmm0
        paddd     %xmm7, %xmm0
        paddd     %xmm2, %xmm0
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        por       %xmm4, %xmm3
        movdqa    560(%rsp), %xmm4
        pxor      240(%rsp), %xmm4
        movdqa    512(%rsp), %xmm12
        pxor      176(%rdi), %xmm4
        pxor      224(%rsp), %xmm12
        pxor      144(%rdi), %xmm4
        pxor      432(%rdi), %xmm12
        movdqa    %xmm4, %xmm11
        pxor      400(%rdi), %xmm12
        paddd     %xmm4, %xmm11
        psrld     $31, %xmm4
        movdqa    %xmm12, %xmm14
        por       %xmm4, %xmm11
        movdqa    %xmm2, %xmm4
        paddd     %xmm12, %xmm14
        psrld     $31, %xmm12
        pxor      %xmm10, %xmm4
        por       %xmm12, %xmm14
        movdqa    %xmm11, 464(%rsp)
        pand      %xmm5, %xmm4
        movdqa    %xmm14, 336(%rsp)
..B9.19:
        pxor      %xmm10, %xmm4
        movdqa    %xmm8, %xmm11
        paddd     %xmm4, %xmm1
        movdqa    %xmm8, %xmm4
        pslld     $5, %xmm4
        psrld     $27, %xmm11
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm14
        por       %xmm11, %xmm4
        movdqa    %xmm3, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm14
        paddd     %xmm4, %xmm1
        pxor      %xmm13, %xmm15
        por       %xmm14, %xmm12
        movdqa    %xmm5, %xmm11
        movdqa    496(%rsp), %xmm14
        movdqa    %xmm6, %xmm4
        pxor      208(%rsp), %xmm14
        pand      %xmm6, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm5
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        pxor      800(%rsp), %xmm14
        pxor      %xmm13, %xmm15
        por       %xmm5, %xmm11
        por       %xmm6, %xmm4
        movdqa    768(%rsp), %xmm6
        paddd     %xmm15, %xmm9
        movdqa    448(%rsp), %xmm5
        pxor      %xmm6, %xmm14
        pxor      192(%rsp), %xmm5
        paddd     %xmm12, %xmm9
        pxor      816(%rsp), %xmm5
        movdqa    %xmm14, %xmm12
        movdqa    720(%rsp), %xmm15
        paddd     %xmm14, %xmm12
        pxor      %xmm15, %xmm5
        psrld     $31, %xmm14
        por       %xmm14, %xmm12
        movdqa    %xmm5, %xmm14
        paddd     %xmm5, %xmm14
        psrld     $31, %xmm5
        paddd     %xmm7, %xmm1
        por       %xmm5, %xmm14
        movdqa    %xmm2, %xmm5
        paddd     %xmm7, %xmm9
        paddd     832(%rsp), %xmm1
        pxor      %xmm11, %xmm5
        movdqa    %xmm12, 480(%rsp)
        pand      %xmm8, %xmm5
        movdqa    %xmm14, 352(%rsp)
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm14
        pxor      %xmm2, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm14
        paddd     %xmm5, %xmm10
        por       %xmm14, %xmm12
        paddd     %xmm12, %xmm10
        movdqa    %xmm8, %xmm12
        paddd     %xmm7, %xmm10
        pslld     $30, %xmm12
        paddd     %xmm6, %xmm10
        movdqa    %xmm3, %xmm6
        paddd     752(%rsp), %xmm9
        pxor      %xmm4, %xmm6
        pand      %xmm0, %xmm6
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm5
        pxor      %xmm3, %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm5
        paddd     %xmm6, %xmm13
        por       %xmm5, %xmm14
        paddd     %xmm14, %xmm13
        movdqa    %xmm0, %xmm5
        paddd     %xmm7, %xmm13
        pslld     $30, %xmm5
        paddd     %xmm15, %xmm13
        psrld     $2, %xmm0
        movdqa    432(%rsp), %xmm15
        por       %xmm0, %xmm5
        pxor      176(%rsp), %xmm15
        psrld     $2, %xmm8
        pxor      656(%rsp), %xmm15
        por       %xmm8, %xmm12
        movdqa    736(%rsp), %xmm0
        movdqa    320(%rsp), %xmm6
        pxor      %xmm0, %xmm15
        pxor      160(%rsp), %xmm6
        movdqa    %xmm15, %xmm14
        pxor      688(%rsp), %xmm6
        paddd     %xmm15, %xmm14
        movdqa    784(%rsp), %xmm8
        psrld     $31, %xmm15
        pxor      %xmm8, %xmm6
        por       %xmm15, %xmm14
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm15
        psrld     $31, %xmm6
        por       %xmm6, %xmm15
        movdqa    %xmm12, %xmm6
        pxor      %xmm11, %xmm6
        movdqa    %xmm14, 528(%rsp)
        pand      %xmm1, %xmm6
        movdqa    %xmm15, 368(%rsp)
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        pxor      %xmm11, %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm6, %xmm2
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm2
        movdqa    %xmm13, %xmm15
        paddd     %xmm7, %xmm2
        movdqa    %xmm13, %xmm6
        paddd     %xmm0, %xmm2
        movdqa    %xmm5, %xmm0
        pxor      %xmm4, %xmm0
        pslld     $5, %xmm15
        pand      %xmm9, %xmm0
        psrld     $27, %xmm6
        pxor      %xmm4, %xmm0
        por       %xmm6, %xmm15
        paddd     %xmm0, %xmm3
        movdqa    %xmm1, %xmm6
        movdqa    464(%rsp), %xmm14
        paddd     %xmm15, %xmm3
        pxor      640(%rsp), %xmm14
        paddd     %xmm7, %xmm3
        pslld     $30, %xmm6
        psrld     $2, %xmm1
        pxor      304(%rsp), %xmm14
        paddd     %xmm8, %xmm3
        movdqa    336(%rsp), %xmm0
        por       %xmm1, %xmm6
        movdqa    800(%rsp), %xmm1
        movdqa    %xmm9, %xmm8
        pxor      608(%rsp), %xmm0
        pslld     $30, %xmm8
        psrld     $2, %xmm9
        pxor      %xmm1, %xmm14
        pxor      672(%rsp), %xmm0
        por       %xmm9, %xmm8
        movdqa    816(%rsp), %xmm9
        movdqa    %xmm14, %xmm15
        pxor      %xmm9, %xmm0
        paddd     %xmm14, %xmm15
        psrld     $31, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm0, %xmm14
        paddd     %xmm0, %xmm14
        psrld     $31, %xmm0
        por       %xmm0, %xmm14
        movdqa    %xmm6, %xmm0
        pxor      %xmm12, %xmm0
        movdqa    %xmm15, 544(%rsp)
        pand      %xmm10, %xmm0
        movdqa    %xmm14, 384(%rsp)
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm15
        pxor      %xmm12, %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm0, %xmm11
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm11
        movdqa    %xmm3, %xmm15
        paddd     %xmm7, %xmm11
        movdqa    %xmm3, %xmm0
        paddd     %xmm1, %xmm11
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        pslld     $5, %xmm15
        pand      %xmm13, %xmm1
        psrld     $27, %xmm0
        pxor      %xmm5, %xmm1
        por       %xmm0, %xmm15
        paddd     %xmm1, %xmm4
        movdqa    %xmm13, %xmm1
        pslld     $30, %xmm1
        psrld     $2, %xmm13
        paddd     %xmm15, %xmm4
        movdqa    %xmm10, %xmm0
        por       %xmm13, %xmm1
        paddd     %xmm7, %xmm4
        movdqa    592(%rsp), %xmm13
        pslld     $30, %xmm0
        pxor      480(%rsp), %xmm13
        psrld     $2, %xmm10
        pxor      288(%rsp), %xmm13
        paddd     %xmm9, %xmm4
        movdqa    656(%rsp), %xmm9
        por       %xmm10, %xmm0
        movdqa    576(%rsp), %xmm10
        pxor      %xmm9, %xmm13
        pxor      352(%rsp), %xmm10
        movdqa    %xmm13, %xmm15
        pxor      704(%rsp), %xmm10
        paddd     %xmm13, %xmm15
        movdqa    688(%rsp), %xmm14
        psrld     $31, %xmm13
        pxor      %xmm14, %xmm10
        por       %xmm13, %xmm15
        movdqa    %xmm10, %xmm13
        paddd     %xmm10, %xmm13
        psrld     $31, %xmm10
        por       %xmm10, %xmm13
        movdqa    %xmm0, %xmm10
        pxor      %xmm6, %xmm10
        movdqa    %xmm15, 624(%rsp)
        pand      %xmm2, %xmm10
        movdqa    %xmm13, 400(%rsp)
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm15
        pxor      %xmm6, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm12
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm12
        movdqa    %xmm4, %xmm15
        paddd     %xmm7, %xmm12
        movdqa    %xmm4, %xmm10
        paddd     %xmm9, %xmm12
        movdqa    %xmm1, %xmm9
        pxor      %xmm8, %xmm9
        pslld     $5, %xmm15
        pand      %xmm3, %xmm9
        psrld     $27, %xmm10
        pxor      %xmm8, %xmm9
        por       %xmm10, %xmm15
        paddd     %xmm9, %xmm5
        movdqa    %xmm2, %xmm10
        paddd     %xmm15, %xmm5
        pslld     $30, %xmm10
        paddd     %xmm7, %xmm5
        psrld     $2, %xmm2
        paddd     %xmm14, %xmm5
        por       %xmm2, %xmm10
        movdqa    560(%rsp), %xmm14
        movdqa    %xmm3, %xmm2
        pxor      528(%rsp), %xmm14
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        pxor      272(%rsp), %xmm14
        por       %xmm3, %xmm2
        movdqa    304(%rsp), %xmm3
        movdqa    512(%rsp), %xmm9
        pxor      %xmm3, %xmm14
        pxor      368(%rsp), %xmm9
        movdqa    %xmm14, %xmm13
        pxor      256(%rsp), %xmm9
        paddd     %xmm14, %xmm13
        movdqa    672(%rsp), %xmm15
        psrld     $31, %xmm14
        pxor      %xmm15, %xmm9
        por       %xmm14, %xmm13
        movdqa    %xmm9, %xmm14
        paddd     %xmm9, %xmm14
        psrld     $31, %xmm9
        por       %xmm9, %xmm14
        movdqa    %xmm10, %xmm9
        pxor      %xmm0, %xmm9
        movdqa    %xmm13, 848(%rsp)
        pand      %xmm11, %xmm9
        movdqa    %xmm14, 416(%rsp)
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm14
        pxor      %xmm0, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm9, %xmm6
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm6
        movdqa    %xmm5, %xmm14
        paddd     %xmm7, %xmm6
        movdqa    %xmm5, %xmm9
        paddd     %xmm3, %xmm6
        movdqa    %xmm2, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm9
        pxor      %xmm1, %xmm3
        por       %xmm9, %xmm14
        movdqa    %xmm11, %xmm9
        pand      %xmm4, %xmm3
        pslld     $30, %xmm9
        psrld     $2, %xmm11
        movdqa    496(%rsp), %xmm13
        pxor      %xmm1, %xmm3
        por       %xmm11, %xmm9
        movdqa    %xmm4, %xmm11
        pxor      544(%rsp), %xmm13
        paddd     %xmm3, %xmm8
        pslld     $30, %xmm11
        psrld     $2, %xmm4
        pxor      240(%rsp), %xmm13
        paddd     %xmm14, %xmm8
        movdqa    448(%rsp), %xmm3
        por       %xmm4, %xmm11
        movdqa    288(%rsp), %xmm4
        paddd     %xmm7, %xmm8
        pxor      384(%rsp), %xmm3
        pxor      %xmm4, %xmm13
        pxor      224(%rsp), %xmm3
        paddd     %xmm15, %xmm8
        movdqa    704(%rsp), %xmm15
        movdqa    %xmm13, %xmm14
        pxor      %xmm15, %xmm3
        paddd     %xmm13, %xmm14
        psrld     $31, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm3, %xmm13
        paddd     %xmm3, %xmm13
        psrld     $31, %xmm3
        por       %xmm3, %xmm13
        movdqa    %xmm9, %xmm3
        pxor      %xmm10, %xmm3
        movdqa    %xmm14, 144(%rsp)
        pand      %xmm12, %xmm3
        movdqa    %xmm13, 32(%rsp)
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm14
        pxor      %xmm10, %xmm3
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm3, %xmm0
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm0
        movdqa    %xmm8, %xmm14
        paddd     %xmm7, %xmm0
        movdqa    %xmm8, %xmm3
        paddd     %xmm4, %xmm0
        movdqa    %xmm11, %xmm4
        pxor      %xmm2, %xmm4
        pslld     $5, %xmm14
        pand      %xmm5, %xmm4
        psrld     $27, %xmm3
        pxor      %xmm2, %xmm4
        por       %xmm3, %xmm14
        movdqa    %xmm12, %xmm3
        paddd     %xmm4, %xmm1
        pslld     $30, %xmm3
        psrld     $2, %xmm12
        paddd     %xmm14, %xmm1
        por       %xmm12, %xmm3
        movdqa    432(%rsp), %xmm12
        movdqa    %xmm5, %xmm4
        pxor      624(%rsp), %xmm12
        paddd     %xmm7, %xmm1
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        pxor      208(%rsp), %xmm12
        paddd     %xmm15, %xmm1
        movdqa    272(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    320(%rsp), %xmm5
        pxor      %xmm15, %xmm12
        pxor      400(%rsp), %xmm5
        movdqa    %xmm12, %xmm13
        pxor      192(%rsp), %xmm5
        paddd     %xmm12, %xmm13
        movdqa    256(%rsp), %xmm14
        psrld     $31, %xmm12
        pxor      %xmm14, %xmm5
        por       %xmm12, %xmm13
        movdqa    %xmm5, %xmm12
        paddd     %xmm5, %xmm12
        psrld     $31, %xmm5
        por       %xmm5, %xmm12
        movdqa    %xmm3, %xmm5
        pxor      %xmm9, %xmm5
        movdqa    %xmm13, 128(%rsp)
        pand      %xmm6, %xmm5
        movdqa    %xmm12, 112(%rsp)
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm13
        pxor      %xmm9, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm5, %xmm10
        por       %xmm13, %xmm12
        paddd     %xmm12, %xmm10
        movdqa    %xmm1, %xmm13
        paddd     %xmm7, %xmm10
        movdqa    %xmm1, %xmm5
        paddd     %xmm15, %xmm10
        movdqa    %xmm4, %xmm15
        pxor      %xmm11, %xmm15
        pslld     $5, %xmm13
        pand      %xmm8, %xmm15
        psrld     $27, %xmm5
        pxor      %xmm11, %xmm15
        por       %xmm5, %xmm13
        paddd     %xmm15, %xmm2
        movdqa    %xmm6, %xmm5
        paddd     %xmm13, %xmm2
        pslld     $30, %xmm5
        paddd     %xmm7, %xmm2
        psrld     $2, %xmm6
        paddd     %xmm14, %xmm2
        por       %xmm6, %xmm5
        movdqa    464(%rsp), %xmm14
        movdqa    %xmm8, %xmm6
        pxor      848(%rsp), %xmm14
        pslld     $30, %xmm6
        psrld     $2, %xmm8
        pxor      176(%rsp), %xmm14
        por       %xmm8, %xmm6
        movdqa    240(%rsp), %xmm13
        movdqa    336(%rsp), %xmm8
        pxor      %xmm13, %xmm14
        pxor      416(%rsp), %xmm8
        movdqa    %xmm14, %xmm15
        pxor      160(%rsp), %xmm8
        paddd     %xmm14, %xmm15
        movdqa    224(%rsp), %xmm12
        psrld     $31, %xmm14
        pxor      %xmm12, %xmm8
        por       %xmm14, %xmm15
        movdqa    %xmm8, %xmm14
        paddd     %xmm8, %xmm14
        psrld     $31, %xmm8
        por       %xmm8, %xmm14
        movdqa    %xmm5, %xmm8
        pxor      %xmm3, %xmm8
        movdqa    %xmm15, 96(%rsp)
        pand      %xmm0, %xmm8
        movdqa    %xmm14, 48(%rsp)
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm15
        pxor      %xmm3, %xmm8
        pslld     $5, %xmm14
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm9
        por       %xmm15, %xmm14
        paddd     %xmm14, %xmm9
        movdqa    %xmm2, %xmm15
        paddd     %xmm7, %xmm9
        movdqa    %xmm2, %xmm8
        paddd     %xmm13, %xmm9
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        pand      %xmm1, %xmm13
        psrld     $27, %xmm8
        pxor      %xmm4, %xmm13
        por       %xmm8, %xmm15
        paddd     %xmm13, %xmm11
        movdqa    %xmm0, %xmm8
        paddd     %xmm15, %xmm11
        pslld     $30, %xmm8
        paddd     %xmm7, %xmm11
        psrld     $2, %xmm0
        paddd     %xmm12, %xmm11
        por       %xmm0, %xmm8
        movdqa    144(%rsp), %xmm12
        movdqa    %xmm1, %xmm0
        pxor      480(%rsp), %xmm12
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        pxor      640(%rsp), %xmm12
        por       %xmm1, %xmm0
        movdqa    208(%rsp), %xmm15
        movdqa    32(%rsp), %xmm1
        pxor      %xmm15, %xmm12
        pxor      352(%rsp), %xmm1
        movdqa    %xmm12, %xmm13
        pxor      608(%rsp), %xmm1
        paddd     %xmm12, %xmm13
        movdqa    192(%rsp), %xmm14
        psrld     $31, %xmm12
        pxor      %xmm14, %xmm1
        por       %xmm12, %xmm13
        movdqa    %xmm1, %xmm12
        paddd     %xmm1, %xmm12
        psrld     $31, %xmm1
        por       %xmm1, %xmm12
        movdqa    %xmm8, %xmm1
        pxor      %xmm5, %xmm1
        movdqa    %xmm13, 80(%rsp)
        pand      %xmm10, %xmm1
        movdqa    %xmm12, 16(%rsp)
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm13
        pxor      %xmm5, %xmm1
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm1, %xmm3
        por       %xmm13, %xmm12
        paddd     %xmm12, %xmm3
        movdqa    %xmm11, %xmm13
        paddd     %xmm7, %xmm3
        movdqa    %xmm11, %xmm1
        paddd     %xmm15, %xmm3
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm1
        pxor      %xmm6, %xmm15
        por       %xmm1, %xmm13
        movdqa    %xmm10, %xmm1
        pand      %xmm2, %xmm15
        pslld     $30, %xmm1
        psrld     $2, %xmm10
        pxor      %xmm6, %xmm15
        por       %xmm10, %xmm1
        movdqa    %xmm2, %xmm10
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm10
        psrld     $2, %xmm2
        paddd     %xmm13, %xmm4
        por       %xmm2, %xmm10
        movdqa    128(%rsp), %xmm2
        paddd     %xmm7, %xmm4
        pxor      528(%rsp), %xmm2
        paddd     %xmm14, %xmm4
        pxor      592(%rsp), %xmm2
        movdqa    176(%rsp), %xmm14
        movdqa    112(%rsp), %xmm13
        pxor      %xmm14, %xmm2
        pxor      368(%rsp), %xmm13
        movdqa    %xmm2, %xmm12
        pxor      576(%rsp), %xmm13
        paddd     %xmm2, %xmm12
        movdqa    160(%rsp), %xmm15
        psrld     $31, %xmm2
        pxor      %xmm15, %xmm13
        por       %xmm2, %xmm12
        movdqa    %xmm13, %xmm2
        paddd     %xmm13, %xmm2
        psrld     $31, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm1, %xmm13
        pxor      %xmm8, %xmm13
        movdqa    %xmm12, 64(%rsp)
        pand      %xmm9, %xmm13
        movdqa    %xmm2, (%rsp)
        movdqa    %xmm3, %xmm12
        movdqa    %xmm3, %xmm2
        pxor      %xmm8, %xmm13
        pslld     $5, %xmm12
        psrld     $27, %xmm2
        paddd     %xmm13, %xmm5
        por       %xmm2, %xmm12
        paddd     %xmm12, %xmm5
        movdqa    %xmm4, %xmm12
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm2
        paddd     %xmm14, %xmm5
        movdqa    %xmm10, %xmm14
        pxor      %xmm0, %xmm14
        pslld     $5, %xmm12
        pand      %xmm11, %xmm14
        psrld     $27, %xmm2
        pxor      %xmm0, %xmm14
        por       %xmm2, %xmm12
        paddd     %xmm14, %xmm6
        movdqa    %xmm9, %xmm13
        paddd     %xmm12, %xmm6
        pslld     $30, %xmm13
        paddd     %xmm7, %xmm6
        psrld     $2, %xmm9
        paddd     %xmm15, %xmm6
..B9.18:
        movdqa    96(%rsp), %xmm7
        por       %xmm9, %xmm13
        pxor      544(%rsp), %xmm7
        movdqa    %xmm11, %xmm14
        movdqa    48(%rsp), %xmm15
        pslld     $30, %xmm14
        pxor      560(%rsp), %xmm7
        psrld     $2, %xmm11
        movdqa    640(%rsp), %xmm9
        por       %xmm11, %xmm14
        pxor      384(%rsp), %xmm15
        pxor      %xmm9, %xmm7
        pxor      512(%rsp), %xmm15
        movdqa    %xmm7, %xmm12
        movdqa    608(%rsp), %xmm2
        paddd     %xmm7, %xmm12
        pxor      %xmm2, %xmm15
        psrld     $31, %xmm7
        movdqa    %xmm15, %xmm11
        por       %xmm7, %xmm12
        paddd     %xmm15, %xmm11
        psrld     $31, %xmm15
        movdqa    %xmm1, %xmm7
        por       %xmm15, %xmm11
        movdqa    %xmm12, 816(%rsp)
        pxor      %xmm13, %xmm7
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm12
        pxor      %xmm3, %xmm7
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm7, %xmm8
        por       %xmm12, %xmm15
        movdqa    %xmm6, %xmm12
        movdqa    .L_2il0floatpacket.507(%rip), %xmm7
        paddd     %xmm15, %xmm8
        paddd     %xmm7, %xmm8
        movdqa    %xmm6, %xmm15
        paddd     %xmm9, %xmm8
        movdqa    %xmm10, %xmm9
        pxor      %xmm14, %xmm9
        pslld     $5, %xmm15
        pxor      %xmm4, %xmm9
        psrld     $27, %xmm12
        paddd     %xmm9, %xmm0
        por       %xmm12, %xmm15
        paddd     %xmm15, %xmm0
        paddd     %xmm7, %xmm0
        paddd     %xmm2, %xmm0
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        movdqa    %xmm11, 768(%rsp)
        por       %xmm3, %xmm2
        movdqa    80(%rsp), %xmm11
        movdqa    %xmm4, %xmm3
        pxor      624(%rsp), %xmm11
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        pxor      496(%rsp), %xmm11
        por       %xmm4, %xmm3
        movdqa    592(%rsp), %xmm9
        movdqa    16(%rsp), %xmm4
        pxor      %xmm9, %xmm11
        pxor      400(%rsp), %xmm4
        movdqa    %xmm11, %xmm15
        pxor      448(%rsp), %xmm4
        paddd     %xmm11, %xmm15
        movdqa    576(%rsp), %xmm12
        psrld     $31, %xmm11
        pxor      %xmm12, %xmm4
        por       %xmm11, %xmm15
        movdqa    %xmm4, %xmm11
        paddd     %xmm4, %xmm11
        psrld     $31, %xmm4
        por       %xmm4, %xmm11
        movdqa    %xmm2, %xmm4
        movdqa    %xmm15, 800(%rsp)
        pxor      %xmm13, %xmm4
        movdqa    %xmm11, 752(%rsp)
        movdqa    %xmm8, %xmm11
        movdqa    %xmm8, %xmm15
        pxor      %xmm5, %xmm4
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm1
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm1
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm4
        paddd     %xmm7, %xmm1
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        paddd     %xmm9, %xmm1
        movdqa    %xmm3, %xmm9
        por       %xmm4, %xmm15
        movdqa    %xmm5, %xmm4
        pxor      %xmm14, %xmm9
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        pxor      %xmm6, %xmm9
        movdqa    64(%rsp), %xmm11
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        paddd     %xmm9, %xmm10
        pxor      848(%rsp), %xmm11
        pslld     $30, %xmm5
        psrld     $2, %xmm6
        paddd     %xmm15, %xmm10
        pxor      432(%rsp), %xmm11
        por       %xmm6, %xmm5
        movdqa    560(%rsp), %xmm9
        paddd     %xmm7, %xmm10
        movdqa    (%rsp), %xmm6
        pxor      %xmm9, %xmm11
        pxor      416(%rsp), %xmm6
        paddd     %xmm12, %xmm10
        pxor      320(%rsp), %xmm6
        movdqa    %xmm11, %xmm15
        movdqa    512(%rsp), %xmm12
        paddd     %xmm11, %xmm15
        pxor      %xmm12, %xmm6
        psrld     $31, %xmm11
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm6, %xmm11
        psrld     $31, %xmm6
        por       %xmm6, %xmm11
        movdqa    %xmm4, %xmm6
        movdqa    %xmm15, 784(%rsp)
        pxor      %xmm2, %xmm6
        movdqa    %xmm11, 720(%rsp)
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm15
        pxor      %xmm8, %xmm6
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm6, %xmm13
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm13
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm6
        paddd     %xmm7, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm6
        paddd     %xmm9, %xmm13
        movdqa    %xmm5, %xmm9
        por       %xmm6, %xmm15
        movdqa    %xmm8, %xmm6
        pxor      %xmm3, %xmm9
        pslld     $30, %xmm6
        psrld     $2, %xmm8
        pxor      %xmm0, %xmm9
        por       %xmm8, %xmm6
        movdqa    %xmm0, %xmm8
        paddd     %xmm9, %xmm14
        pslld     $30, %xmm8
        psrld     $2, %xmm0
        paddd     %xmm15, %xmm14
        por       %xmm0, %xmm8
        paddd     %xmm7, %xmm14
        movdqa    144(%rsp), %xmm0
        paddd     %xmm12, %xmm14
        pxor      816(%rsp), %xmm0
        pxor      464(%rsp), %xmm0
        movdqa    496(%rsp), %xmm12
        movdqa    32(%rsp), %xmm9
        pxor      %xmm12, %xmm0
        pxor      768(%rsp), %xmm9
        movdqa    %xmm0, %xmm11
        pxor      336(%rsp), %xmm9
        paddd     %xmm0, %xmm11
        movdqa    448(%rsp), %xmm15
        psrld     $31, %xmm0
        pxor      %xmm15, %xmm9
        por       %xmm0, %xmm11
        movdqa    %xmm9, %xmm0
        paddd     %xmm9, %xmm0
        psrld     $31, %xmm9
        por       %xmm9, %xmm0
        movdqa    %xmm6, %xmm9
        movdqa    %xmm11, 832(%rsp)
        pxor      %xmm4, %xmm9
        movdqa    %xmm0, 736(%rsp)
        movdqa    %xmm13, %xmm0
        movdqa    %xmm13, %xmm11
        pxor      %xmm1, %xmm9
        pslld     $5, %xmm0
        psrld     $27, %xmm11
        paddd     %xmm9, %xmm2
        por       %xmm11, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm14, %xmm11
        paddd     %xmm7, %xmm2
        movdqa    %xmm14, %xmm9
        paddd     %xmm12, %xmm2
        movdqa    %xmm8, %xmm12
        pxor      %xmm5, %xmm12
        pslld     $5, %xmm11
        pxor      %xmm10, %xmm12
        psrld     $27, %xmm9
        paddd     %xmm12, %xmm3
        por       %xmm9, %xmm11
        paddd     %xmm11, %xmm3
        movdqa    %xmm10, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        por       %xmm10, %xmm11
        movdqa    %xmm1, %xmm9
        movdqa    128(%rsp), %xmm10
        paddd     %xmm7, %xmm3
        pxor      800(%rsp), %xmm10
        pslld     $30, %xmm9
        pxor      480(%rsp), %xmm10
        psrld     $2, %xmm1
        movdqa    432(%rsp), %xmm0
        paddd     %xmm15, %xmm3
        movdqa    112(%rsp), %xmm12
        pxor      %xmm0, %xmm10
        pxor      752(%rsp), %xmm12
        por       %xmm1, %xmm9
        pxor      352(%rsp), %xmm12
        movdqa    %xmm10, %xmm15
        movdqa    320(%rsp), %xmm1
        paddd     %xmm10, %xmm15
        pxor      %xmm1, %xmm12
        psrld     $31, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm12, %xmm10
        paddd     %xmm12, %xmm10
        psrld     $31, %xmm12
        por       %xmm12, %xmm10
        movdqa    %xmm9, %xmm12
        movdqa    %xmm15, 704(%rsp)
        pxor      %xmm6, %xmm12
        movdqa    %xmm10, 672(%rsp)
        movdqa    %xmm2, %xmm10
        movdqa    %xmm2, %xmm15
        pxor      %xmm13, %xmm12
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm12, %xmm4
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm4
        movdqa    %xmm3, %xmm15
        paddd     %xmm7, %xmm4
        movdqa    %xmm3, %xmm12
        paddd     %xmm0, %xmm4
        movdqa    %xmm11, %xmm0
        pxor      %xmm8, %xmm0
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        pxor      %xmm14, %xmm0
        por       %xmm12, %xmm15
        movdqa    %xmm13, %xmm12
        paddd     %xmm0, %xmm5
        pslld     $30, %xmm12
        psrld     $2, %xmm13
        paddd     %xmm15, %xmm5
        por       %xmm13, %xmm12
        paddd     %xmm7, %xmm5
        movdqa    96(%rsp), %xmm13
        paddd     %xmm1, %xmm5
        pxor      784(%rsp), %xmm13
        movdqa    %xmm14, %xmm0
        pxor      528(%rsp), %xmm13
        pslld     $30, %xmm0
        movdqa    464(%rsp), %xmm15
        psrld     $2, %xmm14
        movdqa    48(%rsp), %xmm1
        pxor      %xmm15, %xmm13
        pxor      720(%rsp), %xmm1
        por       %xmm14, %xmm0
        pxor      368(%rsp), %xmm1
        movdqa    %xmm13, %xmm14
        movdqa    336(%rsp), %xmm10
        paddd     %xmm13, %xmm14
        pxor      %xmm10, %xmm1
        psrld     $31, %xmm13
        por       %xmm13, %xmm14
        movdqa    %xmm1, %xmm13
        paddd     %xmm1, %xmm13
        psrld     $31, %xmm1
        por       %xmm1, %xmm13
        movdqa    %xmm12, %xmm1
        movdqa    %xmm14, 688(%rsp)
        pxor      %xmm9, %xmm1
        movdqa    %xmm13, 656(%rsp)
        movdqa    %xmm4, %xmm14
        movdqa    %xmm4, %xmm13
        pxor      %xmm2, %xmm1
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm1, %xmm6
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm6
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm1
        paddd     %xmm7, %xmm6
        pslld     $5, %xmm13
        psrld     $27, %xmm1
        paddd     %xmm15, %xmm6
        movdqa    %xmm0, %xmm15
        por       %xmm1, %xmm13
        movdqa    %xmm2, %xmm1
        pxor      %xmm11, %xmm15
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        pxor      %xmm3, %xmm15
        movdqa    80(%rsp), %xmm14
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        paddd     %xmm15, %xmm8
        pxor      832(%rsp), %xmm14
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        paddd     %xmm13, %xmm8
        pxor      544(%rsp), %xmm14
        por       %xmm3, %xmm2
        movdqa    480(%rsp), %xmm15
        paddd     %xmm7, %xmm8
        movdqa    16(%rsp), %xmm3
        pxor      %xmm15, %xmm14
        pxor      736(%rsp), %xmm3
        paddd     %xmm10, %xmm8
        pxor      384(%rsp), %xmm3
        movdqa    %xmm14, %xmm13
        movdqa    352(%rsp), %xmm10
        paddd     %xmm14, %xmm13
        pxor      %xmm10, %xmm3
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm3, %xmm14
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm1, %xmm3
        movdqa    %xmm13, 256(%rsp)
        pxor      %xmm12, %xmm3
        movdqa    %xmm14, 272(%rsp)
        movdqa    %xmm6, %xmm14
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm3, %xmm9
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm9
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm3
        paddd     %xmm7, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm3
        paddd     %xmm15, %xmm9
        movdqa    %xmm2, %xmm15
        por       %xmm3, %xmm13
        movdqa    %xmm4, %xmm3
        pxor      %xmm0, %xmm15
        pslld     $30, %xmm3
        psrld     $2, %xmm4
        pxor      %xmm5, %xmm15
        movdqa    64(%rsp), %xmm14
        por       %xmm4, %xmm3
        movdqa    %xmm5, %xmm4
        paddd     %xmm15, %xmm11
        pxor      704(%rsp), %xmm14
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        paddd     %xmm13, %xmm11
        pxor      624(%rsp), %xmm14
        por       %xmm5, %xmm4
        movdqa    528(%rsp), %xmm15
        paddd     %xmm7, %xmm11
        movdqa    (%rsp), %xmm5
        pxor      %xmm15, %xmm14
        pxor      672(%rsp), %xmm5
        paddd     %xmm10, %xmm11
        pxor      400(%rsp), %xmm5
        movdqa    %xmm14, %xmm13
        movdqa    368(%rsp), %xmm10
        paddd     %xmm14, %xmm13
        pxor      %xmm10, %xmm5
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm5, %xmm14
        paddd     %xmm5, %xmm14
        psrld     $31, %xmm5
        por       %xmm5, %xmm14
        movdqa    %xmm3, %xmm5
        movdqa    %xmm13, 240(%rsp)
        pxor      %xmm1, %xmm5
        movdqa    %xmm14, 288(%rsp)
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm13
        pxor      %xmm6, %xmm5
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm5, %xmm12
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm12
        movdqa    %xmm11, %xmm13
        paddd     %xmm7, %xmm12
        movdqa    %xmm11, %xmm5
        paddd     %xmm15, %xmm12
        movdqa    %xmm4, %xmm15
        pxor      %xmm2, %xmm15
        pslld     $5, %xmm13
        pxor      %xmm8, %xmm15
        psrld     $27, %xmm5
        paddd     %xmm15, %xmm0
        por       %xmm5, %xmm13
        paddd     %xmm13, %xmm0
        movdqa    %xmm6, %xmm5
        paddd     %xmm7, %xmm0
        pslld     $30, %xmm5
        psrld     $2, %xmm6
        paddd     %xmm10, %xmm0
        movdqa    688(%rsp), %xmm10
        por       %xmm6, %xmm5
        movdqa    %xmm8, %xmm6
        psrld     $2, %xmm8
        pxor      816(%rsp), %xmm10
        pslld     $30, %xmm6
        pxor      848(%rsp), %xmm10
        por       %xmm8, %xmm6
        movdqa    544(%rsp), %xmm13
        movdqa    656(%rsp), %xmm8
        pxor      %xmm13, %xmm10
        pxor      768(%rsp), %xmm8
        movdqa    %xmm10, %xmm15
        pxor      416(%rsp), %xmm8
        paddd     %xmm10, %xmm15
        movdqa    384(%rsp), %xmm14
        psrld     $31, %xmm10
        pxor      %xmm14, %xmm8
        por       %xmm10, %xmm15
        movdqa    %xmm8, %xmm10
        paddd     %xmm8, %xmm10
        psrld     $31, %xmm8
        por       %xmm8, %xmm10
        movdqa    %xmm5, %xmm8
        movdqa    %xmm15, 224(%rsp)
        pxor      %xmm3, %xmm8
        movdqa    %xmm10, 304(%rsp)
        movdqa    %xmm12, %xmm10
        movdqa    %xmm12, %xmm15
        pxor      %xmm9, %xmm8
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm1
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm1
        movdqa    %xmm0, %xmm15
        paddd     %xmm7, %xmm1
        movdqa    %xmm0, %xmm8
        paddd     %xmm13, %xmm1
        movdqa    %xmm6, %xmm13
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        pxor      %xmm11, %xmm13
        psrld     $27, %xmm8
        paddd     %xmm13, %xmm2
        por       %xmm8, %xmm15
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, %xmm8
        paddd     %xmm7, %xmm2
        pslld     $30, %xmm8
        psrld     $2, %xmm9
        paddd     %xmm14, %xmm2
        movdqa    256(%rsp), %xmm14
        por       %xmm9, %xmm8
        movdqa    %xmm11, %xmm9
        psrld     $2, %xmm11
        pxor      800(%rsp), %xmm14
        pslld     $30, %xmm9
        pxor      144(%rsp), %xmm14
        por       %xmm11, %xmm9
        movdqa    624(%rsp), %xmm15
        movdqa    272(%rsp), %xmm11
        pxor      %xmm15, %xmm14
        pxor      752(%rsp), %xmm11
        movdqa    %xmm14, %xmm13
        pxor      32(%rsp), %xmm11
        paddd     %xmm14, %xmm13
        movdqa    400(%rsp), %xmm10
        psrld     $31, %xmm14
        pxor      %xmm10, %xmm11
        por       %xmm14, %xmm13
        movdqa    %xmm11, %xmm14
        paddd     %xmm11, %xmm14
        psrld     $31, %xmm11
        por       %xmm11, %xmm14
        movdqa    %xmm8, %xmm11
        movdqa    %xmm13, 208(%rsp)
        pxor      %xmm5, %xmm11
        movdqa    %xmm14, 176(%rsp)
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm13
        pxor      %xmm12, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        paddd     %xmm11, %xmm3
        por       %xmm13, %xmm14
        paddd     %xmm14, %xmm3
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm11
        paddd     %xmm7, %xmm3
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        paddd     %xmm15, %xmm3
        movdqa    %xmm9, %xmm15
        por       %xmm11, %xmm13
        movdqa    %xmm12, %xmm11
        pxor      %xmm6, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm12
        pxor      %xmm0, %xmm15
        por       %xmm12, %xmm11
        movdqa    %xmm0, %xmm12
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm12
        psrld     $2, %xmm0
        paddd     %xmm13, %xmm4
        por       %xmm0, %xmm12
        paddd     %xmm7, %xmm4
        movdqa    240(%rsp), %xmm0
        paddd     %xmm10, %xmm4
        pxor      784(%rsp), %xmm0
        pxor      128(%rsp), %xmm0
        movdqa    848(%rsp), %xmm10
        movdqa    288(%rsp), %xmm13
        pxor      %xmm10, %xmm0
        pxor      720(%rsp), %xmm13
        movdqa    %xmm0, %xmm14
        pxor      112(%rsp), %xmm13
        paddd     %xmm0, %xmm14
        movdqa    416(%rsp), %xmm15
        psrld     $31, %xmm0
        pxor      %xmm15, %xmm13
        por       %xmm0, %xmm14
        movdqa    %xmm13, %xmm0
        paddd     %xmm13, %xmm0
        psrld     $31, %xmm13
        por       %xmm13, %xmm0
        movdqa    %xmm11, %xmm13
        movdqa    %xmm14, 192(%rsp)
        pxor      %xmm8, %xmm13
        movdqa    %xmm0, 160(%rsp)
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm0
        pxor      %xmm1, %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm0
        paddd     %xmm13, %xmm5
        por       %xmm0, %xmm14
        paddd     %xmm14, %xmm5
        movdqa    %xmm4, %xmm13
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm0
        paddd     %xmm10, %xmm5
        movdqa    %xmm12, %xmm10
        pxor      %xmm9, %xmm10
        pslld     $5, %xmm13
        pxor      %xmm2, %xmm10
        psrld     $27, %xmm0
        paddd     %xmm10, %xmm6
        por       %xmm0, %xmm13
        movdqa    %xmm1, %xmm0
        paddd     %xmm13, %xmm6
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        paddd     %xmm7, %xmm6
        por       %xmm1, %xmm0
        movdqa    %xmm2, %xmm1
        paddd     %xmm15, %xmm6
        pslld     $30, %xmm1
        psrld     $2, %xmm2
..B9.17:
        movdqa    224(%rsp), %xmm13
        por       %xmm2, %xmm1
        pxor      832(%rsp), %xmm13
        pxor      96(%rsp), %xmm13
        movdqa    144(%rsp), %xmm10
        movdqa    304(%rsp), %xmm2
        pxor      %xmm10, %xmm13
        pxor      736(%rsp), %xmm2
        movdqa    %xmm13, %xmm15
        pxor      48(%rsp), %xmm2
        paddd     %xmm13, %xmm15
        movdqa    32(%rsp), %xmm14
        psrld     $31, %xmm13
        pxor      %xmm14, %xmm2
        por       %xmm13, %xmm15
        movdqa    %xmm2, %xmm13
        paddd     %xmm2, %xmm13
        psrld     $31, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm0, %xmm2
        movdqa    %xmm15, 624(%rsp)
        pxor      %xmm11, %xmm2
        movdqa    %xmm13, 544(%rsp)
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm13
        pxor      %xmm3, %xmm2
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm2, %xmm8
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm8
        movdqa    %xmm6, %xmm2
        paddd     %xmm7, %xmm8
        movdqa    %xmm6, %xmm13
        paddd     %xmm10, %xmm8
        movdqa    %xmm12, %xmm10
        pxor      %xmm1, %xmm10
        pslld     $5, %xmm2
        pxor      %xmm4, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm9
        por       %xmm13, %xmm2
        paddd     %xmm2, %xmm9
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        movdqa    208(%rsp), %xmm15
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        psrld     $2, %xmm4
        pxor      704(%rsp), %xmm15
        pslld     $30, %xmm3
        pxor      80(%rsp), %xmm15
        por       %xmm4, %xmm3
        movdqa    128(%rsp), %xmm10
        paddd     %xmm7, %xmm9
        movdqa    176(%rsp), %xmm4
        pxor      %xmm10, %xmm15
        pxor      672(%rsp), %xmm4
        paddd     %xmm14, %xmm9
        pxor      16(%rsp), %xmm4
        movdqa    %xmm15, %xmm13
        movdqa    112(%rsp), %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm14, %xmm4
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm15
        psrld     $31, %xmm4
        por       %xmm4, %xmm15
        movdqa    %xmm0, %xmm4
        movdqa    %xmm13, 640(%rsp)
        pxor      %xmm2, %xmm4
        movdqa    %xmm15, 560(%rsp)
        movdqa    %xmm8, %xmm15
        movdqa    %xmm8, %xmm13
        pxor      %xmm5, %xmm4
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm4, %xmm11
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm11
        movdqa    %xmm9, %xmm4
        paddd     %xmm7, %xmm11
        movdqa    %xmm9, %xmm13
        paddd     %xmm10, %xmm11
        movdqa    %xmm3, %xmm10
        pxor      %xmm1, %xmm10
        pslld     $5, %xmm4
        pxor      %xmm6, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm12
        por       %xmm13, %xmm4
        paddd     %xmm4, %xmm12
        movdqa    %xmm5, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        movdqa    192(%rsp), %xmm15
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        psrld     $2, %xmm6
        pxor      688(%rsp), %xmm15
        pslld     $30, %xmm5
        pxor      64(%rsp), %xmm15
        por       %xmm6, %xmm5
        movdqa    96(%rsp), %xmm10
        paddd     %xmm7, %xmm12
        movdqa    160(%rsp), %xmm6
        pxor      %xmm10, %xmm15
        pxor      656(%rsp), %xmm6
        paddd     %xmm14, %xmm12
        pxor      (%rsp), %xmm6
        movdqa    %xmm15, %xmm13
        movdqa    48(%rsp), %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm14, %xmm6
        psrld     $31, %xmm15
        por       %xmm15, %xmm13
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm15
        psrld     $31, %xmm6
        por       %xmm6, %xmm15
        movdqa    %xmm4, %xmm6
        movdqa    %xmm13, 848(%rsp)
        pxor      %xmm2, %xmm6
        movdqa    %xmm15, 576(%rsp)
        movdqa    %xmm11, %xmm15
        movdqa    %xmm11, %xmm13
        pxor      %xmm8, %xmm6
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm6, %xmm0
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm0
        movdqa    %xmm12, %xmm6
        paddd     %xmm7, %xmm0
        movdqa    %xmm12, %xmm13
        paddd     %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        pxor      %xmm3, %xmm10
        pslld     $5, %xmm6
        pxor      %xmm9, %xmm10
        psrld     $27, %xmm13
        paddd     %xmm10, %xmm1
        por       %xmm13, %xmm6
        paddd     %xmm6, %xmm1
        movdqa    %xmm8, %xmm6
        paddd     %xmm7, %xmm1
        pslld     $30, %xmm6
        paddd     %xmm14, %xmm1
        psrld     $2, %xmm8
        movdqa    256(%rsp), %xmm14
        por       %xmm8, %xmm6
        pxor      624(%rsp), %xmm14
        movdqa    %xmm9, %xmm8
        pxor      816(%rsp), %xmm14
        pslld     $30, %xmm8
        movdqa    80(%rsp), %xmm15
        psrld     $2, %xmm9
        movdqa    272(%rsp), %xmm10
        pxor      %xmm15, %xmm14
        pxor      544(%rsp), %xmm10
        por       %xmm9, %xmm8
        pxor      768(%rsp), %xmm10
        movdqa    %xmm14, %xmm13
        movdqa    16(%rsp), %xmm9
        paddd     %xmm14, %xmm13
        pxor      %xmm9, %xmm10
        psrld     $31, %xmm14
        por       %xmm14, %xmm13
        movdqa    %xmm10, %xmm14
        paddd     %xmm10, %xmm14
        psrld     $31, %xmm10
        por       %xmm10, %xmm14
        movdqa    %xmm6, %xmm10
        movdqa    %xmm13, 864(%rsp)
        pxor      %xmm4, %xmm10
        movdqa    %xmm14, 592(%rsp)
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm14
        pxor      %xmm11, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        paddd     %xmm10, %xmm2
        por       %xmm14, %xmm13
        paddd     %xmm13, %xmm2
        movdqa    %xmm1, %xmm14
        paddd     %xmm7, %xmm2
        movdqa    %xmm1, %xmm10
        paddd     %xmm15, %xmm2
        movdqa    %xmm8, %xmm15
        pxor      %xmm5, %xmm15
        pslld     $5, %xmm14
        pxor      %xmm12, %xmm15
        psrld     $27, %xmm10
        paddd     %xmm15, %xmm3
        por       %xmm10, %xmm14
        movdqa    240(%rsp), %xmm15
        paddd     %xmm14, %xmm3
        movdqa    %xmm11, %xmm10
        paddd     %xmm7, %xmm3
        pxor      640(%rsp), %xmm15
        pslld     $30, %xmm10
        psrld     $2, %xmm11
        paddd     %xmm9, %xmm3
        pxor      800(%rsp), %xmm15
        por       %xmm11, %xmm10
        movdqa    64(%rsp), %xmm13
        movdqa    %xmm12, %xmm11
        movdqa    288(%rsp), %xmm9
        pslld     $30, %xmm11
        pxor      560(%rsp), %xmm9
        psrld     $2, %xmm12
        pxor      %xmm13, %xmm15
        por       %xmm12, %xmm11
        pxor      752(%rsp), %xmm9
        movdqa    %xmm15, %xmm14
        movdqa    (%rsp), %xmm12
        paddd     %xmm15, %xmm14
        pxor      %xmm12, %xmm9
        psrld     $31, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm9, %xmm15
        paddd     %xmm9, %xmm15
        psrld     $31, %xmm9
        por       %xmm9, %xmm15
        movdqa    %xmm10, %xmm9
        movdqa    %xmm14, 880(%rsp)
        pxor      %xmm6, %xmm9
        movdqa    %xmm15, 608(%rsp)
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm14
        pxor      %xmm0, %xmm9
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     %xmm9, %xmm4
        por       %xmm14, %xmm15
        paddd     %xmm15, %xmm4
        movdqa    %xmm3, %xmm14
        paddd     %xmm7, %xmm4
        movdqa    %xmm3, %xmm9
        paddd     %xmm13, %xmm4
        movdqa    %xmm11, %xmm13
        pxor      %xmm8, %xmm13
        pslld     $5, %xmm14
        pxor      %xmm1, %xmm13
        psrld     $27, %xmm9
        paddd     %xmm13, %xmm5
        por       %xmm9, %xmm14
        paddd     %xmm14, %xmm5
        movdqa    %xmm1, %xmm9
        paddd     %xmm7, %xmm5
        pslld     $30, %xmm9
        movdqa    224(%rsp), %xmm15
        paddd     %xmm12, %xmm5
        movdqa    %xmm0, %xmm12
        psrld     $2, %xmm0
        pxor      848(%rsp), %xmm15
        pslld     $30, %xmm12
        psrld     $2, %xmm1
        por       %xmm0, %xmm12
        pxor      784(%rsp), %xmm15
        por       %xmm1, %xmm9
        movdqa    816(%rsp), %xmm1
        movdqa    304(%rsp), %xmm0
        pxor      %xmm1, %xmm15
        pxor      576(%rsp), %xmm0
        movdqa    %xmm15, %xmm13
        pxor      720(%rsp), %xmm0
        paddd     %xmm15, %xmm13
        movdqa    768(%rsp), %xmm14
        psrld     $31, %xmm15
        pxor      %xmm14, %xmm0
        por       %xmm15, %xmm13
        movdqa    %xmm0, %xmm15
        paddd     %xmm0, %xmm15
        psrld     $31, %xmm0
        por       %xmm0, %xmm15
        movdqa    %xmm12, %xmm0
        movdqa    %xmm13, 464(%rsp)
        pxor      %xmm10, %xmm0
        movdqa    %xmm15, 400(%rsp)
        movdqa    %xmm4, %xmm15
        movdqa    %xmm4, %xmm13
        pxor      %xmm2, %xmm0
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        paddd     %xmm0, %xmm6
        por       %xmm13, %xmm15
        paddd     %xmm15, %xmm6
        movdqa    %xmm5, %xmm13
        paddd     %xmm7, %xmm6
        movdqa    %xmm5, %xmm0
        paddd     %xmm1, %xmm6
        movdqa    %xmm9, %xmm1
        pxor      %xmm11, %xmm1
        pslld     $5, %xmm13
        pxor      %xmm3, %xmm1
        psrld     $27, %xmm0
        paddd     %xmm1, %xmm8
        movdqa    %xmm2, %xmm1
        por       %xmm0, %xmm13
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        paddd     %xmm13, %xmm8
        por       %xmm2, %xmm1
        paddd     %xmm7, %xmm8
        movdqa    208(%rsp), %xmm2
        paddd     %xmm14, %xmm8
        pxor      864(%rsp), %xmm2
        movdqa    %xmm3, %xmm0
        pxor      832(%rsp), %xmm2
        pslld     $30, %xmm0
        movdqa    800(%rsp), %xmm14
        psrld     $2, %xmm3
        movdqa    176(%rsp), %xmm13
        pxor      %xmm14, %xmm2
        pxor      592(%rsp), %xmm13
        por       %xmm3, %xmm0
        pxor      736(%rsp), %xmm13
        movdqa    %xmm2, %xmm15
        movdqa    752(%rsp), %xmm3
        paddd     %xmm2, %xmm15
        pxor      %xmm3, %xmm13
        psrld     $31, %xmm2
        por       %xmm2, %xmm15
        movdqa    %xmm13, %xmm2
        paddd     %xmm13, %xmm2
        psrld     $31, %xmm13
        por       %xmm13, %xmm2
        movdqa    %xmm1, %xmm13
        movdqa    %xmm15, 480(%rsp)
        pxor      %xmm12, %xmm13
        movdqa    %xmm2, 416(%rsp)
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm2
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm2
        paddd     %xmm13, %xmm10
        por       %xmm2, %xmm15
        paddd     %xmm15, %xmm10
        movdqa    %xmm8, %xmm2
        paddd     %xmm7, %xmm10
        movdqa    %xmm8, %xmm13
        paddd     %xmm14, %xmm10
        movdqa    %xmm0, %xmm14
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm13
        pxor      %xmm5, %xmm14
        por       %xmm13, %xmm2
        movdqa    %xmm5, %xmm13
        paddd     %xmm14, %xmm11
        pslld     $30, %xmm13
        psrld     $2, %xmm5
        paddd     %xmm2, %xmm11
        movdqa    %xmm4, %xmm14
        por       %xmm5, %xmm13
        movdqa    192(%rsp), %xmm5
        paddd     %xmm7, %xmm11
        pxor      880(%rsp), %xmm5
        pslld     $30, %xmm14
        psrld     $2, %xmm4
        paddd     %xmm3, %xmm11
        pxor      704(%rsp), %xmm5
        por       %xmm4, %xmm14
        movdqa    784(%rsp), %xmm3
        movdqa    160(%rsp), %xmm4
        pxor      %xmm3, %xmm5
        pxor      608(%rsp), %xmm4
        movdqa    %xmm5, %xmm15
        pxor      672(%rsp), %xmm4
        paddd     %xmm5, %xmm15
        movdqa    720(%rsp), %xmm2
        psrld     $31, %xmm5
        pxor      %xmm2, %xmm4
        por       %xmm5, %xmm15
        movdqa    %xmm4, %xmm5
        paddd     %xmm4, %xmm5
        psrld     $31, %xmm4
        por       %xmm4, %xmm5
        movdqa    %xmm14, %xmm4
        movdqa    %xmm15, 448(%rsp)
        pxor      %xmm1, %xmm4
        movdqa    %xmm5, 352(%rsp)
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm15
        pxor      %xmm6, %xmm4
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm12
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm12
        movdqa    %xmm11, %xmm15
        paddd     %xmm7, %xmm12
        movdqa    %xmm11, %xmm4
        paddd     %xmm3, %xmm12
        movdqa    %xmm13, %xmm3
        pxor      %xmm0, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        pxor      %xmm8, %xmm3
        por       %xmm4, %xmm15
        movdqa    %xmm6, %xmm4
        paddd     %xmm3, %xmm9
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        paddd     %xmm15, %xmm9
        por       %xmm6, %xmm4
        movdqa    %xmm8, %xmm3
        movdqa    464(%rsp), %xmm6
        paddd     %xmm7, %xmm9
        pxor      624(%rsp), %xmm6
        pslld     $30, %xmm3
        psrld     $2, %xmm8
        paddd     %xmm2, %xmm9
        pxor      688(%rsp), %xmm6
        por       %xmm8, %xmm3
        movdqa    832(%rsp), %xmm2
        movdqa    400(%rsp), %xmm8
        pxor      %xmm2, %xmm6
        pxor      544(%rsp), %xmm8
        movdqa    %xmm6, %xmm15
        pxor      656(%rsp), %xmm8
        paddd     %xmm6, %xmm15
        movdqa    736(%rsp), %xmm5
        psrld     $31, %xmm6
        pxor      %xmm5, %xmm8
        por       %xmm6, %xmm15
        movdqa    %xmm8, %xmm6
        paddd     %xmm8, %xmm6
        psrld     $31, %xmm8
        por       %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        movdqa    %xmm15, 368(%rsp)
        pxor      %xmm14, %xmm8
        movdqa    %xmm6, 320(%rsp)
        movdqa    %xmm12, %xmm15
        movdqa    %xmm12, %xmm6
        pxor      %xmm10, %xmm8
        pslld     $5, %xmm15
        psrld     $27, %xmm6
        paddd     %xmm8, %xmm1
        por       %xmm6, %xmm15
        paddd     %xmm15, %xmm1
        movdqa    %xmm9, %xmm6
        paddd     %xmm7, %xmm1
        movdqa    %xmm9, %xmm8
        paddd     %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        pxor      %xmm13, %xmm2
        pslld     $5, %xmm6
        pxor      %xmm11, %xmm2
        psrld     $27, %xmm8
        paddd     %xmm2, %xmm0
        movdqa    %xmm10, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm10
        por       %xmm10, %xmm2
        movdqa    %xmm11, %xmm10
        pslld     $30, %xmm10
        psrld     $2, %xmm11
        por       %xmm8, %xmm6
        por       %xmm11, %xmm10
        movdqa    480(%rsp), %xmm11
        paddd     %xmm6, %xmm0
        pxor      640(%rsp), %xmm11
        paddd     %xmm7, %xmm0
        pxor      256(%rsp), %xmm11
        paddd     %xmm5, %xmm0
        movdqa    704(%rsp), %xmm6
        movdqa    416(%rsp), %xmm7
        pxor      %xmm6, %xmm11
        pxor      560(%rsp), %xmm7
        movdqa    %xmm11, %xmm5
        pxor      272(%rsp), %xmm7
        paddd     %xmm11, %xmm5
        movdqa    672(%rsp), %xmm15
        psrld     $31, %xmm11
        pxor      %xmm15, %xmm7
        por       %xmm11, %xmm5
        movdqa    %xmm7, %xmm11
        paddd     %xmm7, %xmm11
        psrld     $31, %xmm7
        por       %xmm7, %xmm11
        movdqa    %xmm12, %xmm7
        movdqa    %xmm5, 432(%rsp)
        movdqa    %xmm12, %xmm5
        por       %xmm2, %xmm7
        pand      %xmm2, %xmm5
        pand      %xmm4, %xmm7
        movdqa    %xmm11, 336(%rsp)
        por       %xmm7, %xmm5
        movdqa    %xmm1, %xmm7
        movdqa    %xmm1, %xmm11
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        paddd     %xmm5, %xmm14
        por       %xmm11, %xmm7
        movdqa    .L_2il0floatpacket.508(%rip), %xmm8
        paddd     %xmm7, %xmm14
        paddd     %xmm8, %xmm14
        movdqa    %xmm9, %xmm7
        paddd     %xmm6, %xmm14
        movdqa    %xmm9, %xmm6
        por       %xmm10, %xmm6
        pand      %xmm10, %xmm7
        pand      %xmm3, %xmm6
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm5
        por       %xmm6, %xmm7
        pslld     $5, %xmm11
        psrld     $27, %xmm5
        paddd     %xmm7, %xmm13
        por       %xmm5, %xmm11
        movdqa    448(%rsp), %xmm5
        paddd     %xmm11, %xmm13
        movdqa    %xmm12, %xmm7
        paddd     %xmm8, %xmm13
        pxor      848(%rsp), %xmm5
        pslld     $30, %xmm7
        psrld     $2, %xmm12
        paddd     %xmm15, %xmm13
        pxor      240(%rsp), %xmm5
        por       %xmm12, %xmm7
        movdqa    688(%rsp), %xmm12
        movdqa    %xmm9, %xmm6
        movdqa    352(%rsp), %xmm15
        pslld     $30, %xmm6
        pxor      576(%rsp), %xmm15
        psrld     $2, %xmm9
        pxor      %xmm12, %xmm5
        por       %xmm9, %xmm6
        pxor      288(%rsp), %xmm15
        movdqa    %xmm5, %xmm11
        movdqa    656(%rsp), %xmm9
        paddd     %xmm5, %xmm11
        pxor      %xmm9, %xmm15
        psrld     $31, %xmm5
        por       %xmm5, %xmm11
        movdqa    %xmm15, %xmm5
        paddd     %xmm15, %xmm5
        psrld     $31, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm1, %xmm15
        movdqa    %xmm5, 384(%rsp)
        movdqa    %xmm1, %xmm5
        por       %xmm7, %xmm15
        pand      %xmm7, %xmm5
        pand      %xmm2, %xmm15
        por       %xmm15, %xmm5
        movdqa    %xmm13, %xmm15
        movdqa    %xmm11, 496(%rsp)
        paddd     %xmm5, %xmm4
        movdqa    %xmm14, %xmm5
        movdqa    %xmm14, %xmm11
        pslld     $5, %xmm5
        psrld     $27, %xmm11
        por       %xmm11, %xmm5
        movdqa    %xmm13, %xmm11
        paddd     %xmm5, %xmm4
        movdqa    %xmm0, %xmm5
        paddd     %xmm8, %xmm4
        pand      %xmm6, %xmm5
        paddd     %xmm12, %xmm4
        movdqa    %xmm0, %xmm12
        por       %xmm6, %xmm12
        pslld     $5, %xmm15
        pand      %xmm10, %xmm12
        psrld     $27, %xmm11
        por       %xmm12, %xmm5
        por       %xmm11, %xmm15
        paddd     %xmm5, %xmm3
        paddd     %xmm15, %xmm3
        paddd     %xmm8, %xmm3
        paddd     %xmm9, %xmm3
..B9.16:
        movdqa    %xmm1, %xmm5
        psrld     $2, %xmm1
        pslld     $30, %xmm5
        movdqa    368(%rsp), %xmm9
        por       %xmm1, %xmm5
        movdqa    %xmm0, %xmm1
        psrld     $2, %xmm0
        pxor      864(%rsp), %xmm9
        pslld     $30, %xmm1
        pxor      224(%rsp), %xmm9
        por       %xmm0, %xmm1
        movdqa    256(%rsp), %xmm12
        movdqa    320(%rsp), %xmm0
        pxor      %xmm12, %xmm9
        pxor      592(%rsp), %xmm0
        movdqa    %xmm9, %xmm15
        pxor      304(%rsp), %xmm0
        paddd     %xmm9, %xmm15
        movdqa    272(%rsp), %xmm11
        psrld     $31, %xmm9
        pxor      %xmm11, %xmm0
        por       %xmm9, %xmm15
        movdqa    %xmm0, %xmm9
        paddd     %xmm0, %xmm9
        psrld     $31, %xmm0
        por       %xmm0, %xmm9
        movdqa    %xmm14, %xmm0
        movdqa    %xmm9, 656(%rsp)
        movdqa    %xmm14, %xmm9
        por       %xmm5, %xmm0
        pand      %xmm5, %xmm9
        pand      %xmm7, %xmm0
        movdqa    %xmm15, 688(%rsp)
        por       %xmm0, %xmm9
        movdqa    %xmm4, %xmm0
        movdqa    %xmm4, %xmm15
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm9, %xmm2
        por       %xmm15, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm13, %xmm0
        paddd     %xmm8, %xmm2
        pand      %xmm1, %xmm0
        paddd     %xmm12, %xmm2
        movdqa    %xmm13, %xmm12
        por       %xmm1, %xmm12
        movdqa    %xmm3, %xmm15
        pand      %xmm6, %xmm12
        movdqa    %xmm3, %xmm9
        por       %xmm12, %xmm0
        pslld     $5, %xmm15
        paddd     %xmm0, %xmm10
        movdqa    %xmm14, %xmm0
        psrld     $27, %xmm9
        pslld     $30, %xmm0
        psrld     $2, %xmm14
        por       %xmm9, %xmm15
        movdqa    432(%rsp), %xmm9
        por       %xmm14, %xmm0
        movdqa    %xmm13, %xmm14
        psrld     $2, %xmm13
        pxor      880(%rsp), %xmm9
        pslld     $30, %xmm14
        pxor      208(%rsp), %xmm9
        paddd     %xmm15, %xmm10
        movdqa    240(%rsp), %xmm12
        por       %xmm13, %xmm14
        movdqa    336(%rsp), %xmm13
        paddd     %xmm8, %xmm10
        pxor      608(%rsp), %xmm13
        pxor      %xmm12, %xmm9
        pxor      176(%rsp), %xmm13
        paddd     %xmm11, %xmm10
        movdqa    288(%rsp), %xmm11
        movdqa    %xmm9, %xmm15
        pxor      %xmm11, %xmm13
        paddd     %xmm9, %xmm15
        psrld     $31, %xmm9
        por       %xmm9, %xmm15
        movdqa    %xmm13, %xmm9
        paddd     %xmm13, %xmm9
        psrld     $31, %xmm13
        por       %xmm13, %xmm9
        movdqa    %xmm4, %xmm13
        movdqa    %xmm9, 672(%rsp)
        movdqa    %xmm4, %xmm9
        por       %xmm0, %xmm13
        pand      %xmm0, %xmm9
        pand      %xmm5, %xmm13
        movdqa    %xmm15, 736(%rsp)
        por       %xmm13, %xmm9
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm9, %xmm7
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm7
        movdqa    %xmm3, %xmm13
        paddd     %xmm8, %xmm7
        pand      %xmm14, %xmm13
        paddd     %xmm12, %xmm7
        movdqa    %xmm3, %xmm12
        por       %xmm14, %xmm12
        movdqa    %xmm10, %xmm15
        pand      %xmm1, %xmm12
        movdqa    %xmm10, %xmm9
        por       %xmm12, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm9
        paddd     %xmm13, %xmm6
        por       %xmm9, %xmm15
        movdqa    %xmm4, %xmm13
        paddd     %xmm15, %xmm6
        pslld     $30, %xmm13
        paddd     %xmm8, %xmm6
        psrld     $2, %xmm4
        paddd     %xmm11, %xmm6
        por       %xmm4, %xmm13
        movdqa    496(%rsp), %xmm11
        movdqa    %xmm3, %xmm4
        pxor      464(%rsp), %xmm11
        pslld     $30, %xmm4
        pxor      192(%rsp), %xmm11
        psrld     $2, %xmm3
        movdqa    224(%rsp), %xmm15
        por       %xmm3, %xmm4
        movdqa    384(%rsp), %xmm9
        pxor      %xmm15, %xmm11
        pxor      400(%rsp), %xmm9
        movdqa    %xmm11, %xmm12
        pxor      160(%rsp), %xmm9
        paddd     %xmm11, %xmm12
        movdqa    304(%rsp), %xmm3
        psrld     $31, %xmm11
        pxor      %xmm3, %xmm9
        por       %xmm11, %xmm12
        movdqa    %xmm9, %xmm11
        paddd     %xmm9, %xmm11
        psrld     $31, %xmm9
        por       %xmm9, %xmm11
        movdqa    %xmm2, %xmm9
        movdqa    %xmm12, 752(%rsp)
        movdqa    %xmm2, %xmm12
        por       %xmm13, %xmm9
        pand      %xmm13, %xmm12
        pand      %xmm0, %xmm9
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        movdqa    %xmm11, 704(%rsp)
        paddd     %xmm12, %xmm5
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm11
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm6, %xmm11
        paddd     %xmm12, %xmm5
        movdqa    %xmm10, %xmm12
        paddd     %xmm8, %xmm5
        pand      %xmm4, %xmm12
        paddd     %xmm15, %xmm5
        movdqa    %xmm10, %xmm15
        por       %xmm4, %xmm15
        pslld     $5, %xmm9
        pand      %xmm14, %xmm15
        psrld     $27, %xmm11
        por       %xmm15, %xmm12
        por       %xmm11, %xmm9
        paddd     %xmm12, %xmm1
        paddd     %xmm9, %xmm1
        movdqa    %xmm10, %xmm9
        paddd     %xmm8, %xmm1
        pslld     $30, %xmm9
        movdqa    480(%rsp), %xmm15
        paddd     %xmm3, %xmm1
        movdqa    %xmm2, %xmm3
        psrld     $2, %xmm2
        pxor      688(%rsp), %xmm15
        pslld     $30, %xmm3
        psrld     $2, %xmm10
        por       %xmm2, %xmm3
        pxor      624(%rsp), %xmm15
        por       %xmm10, %xmm9
        movdqa    208(%rsp), %xmm2
        movdqa    416(%rsp), %xmm10
        pxor      %xmm2, %xmm15
        pxor      656(%rsp), %xmm10
        movdqa    %xmm15, %xmm12
        pxor      544(%rsp), %xmm10
        paddd     %xmm15, %xmm12
        movdqa    176(%rsp), %xmm11
        psrld     $31, %xmm15
        pxor      %xmm11, %xmm10
        por       %xmm15, %xmm12
        movdqa    %xmm10, %xmm15
        paddd     %xmm10, %xmm15
        psrld     $31, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm7, %xmm10
        movdqa    %xmm12, 768(%rsp)
        movdqa    %xmm7, %xmm12
        por       %xmm3, %xmm10
        pand      %xmm3, %xmm12
        pand      %xmm13, %xmm10
        movdqa    %xmm15, 720(%rsp)
        por       %xmm10, %xmm12
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm12, %xmm0
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm0
        movdqa    %xmm6, %xmm10
        paddd     %xmm8, %xmm0
        pand      %xmm9, %xmm10
        paddd     %xmm2, %xmm0
        movdqa    %xmm6, %xmm2
        por       %xmm9, %xmm2
        movdqa    %xmm1, %xmm15
        pand      %xmm4, %xmm2
        movdqa    %xmm1, %xmm12
        por       %xmm2, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        paddd     %xmm10, %xmm14
        por       %xmm12, %xmm15
        movdqa    %xmm7, %xmm10
        paddd     %xmm15, %xmm14
        pslld     $30, %xmm10
        paddd     %xmm8, %xmm14
        psrld     $2, %xmm7
        paddd     %xmm11, %xmm14
        por       %xmm7, %xmm10
        movdqa    448(%rsp), %xmm11
        movdqa    %xmm6, %xmm7
        pxor      736(%rsp), %xmm11
        pslld     $30, %xmm7
        psrld     $2, %xmm6
        pxor      640(%rsp), %xmm11
        por       %xmm6, %xmm7
        movdqa    192(%rsp), %xmm2
        movdqa    352(%rsp), %xmm6
        pxor      %xmm2, %xmm11
        pxor      672(%rsp), %xmm6
        movdqa    %xmm11, %xmm15
        pxor      560(%rsp), %xmm6
        paddd     %xmm11, %xmm15
        movdqa    160(%rsp), %xmm12
        psrld     $31, %xmm11
        pxor      %xmm12, %xmm6
        por       %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm6, %xmm11
        psrld     $31, %xmm6
        por       %xmm6, %xmm11
        movdqa    %xmm5, %xmm6
        movdqa    %xmm11, 128(%rsp)
        movdqa    %xmm5, %xmm11
        por       %xmm10, %xmm6
        pand      %xmm10, %xmm11
        pand      %xmm3, %xmm6
        movdqa    %xmm15, 512(%rsp)
        por       %xmm6, %xmm11
        movdqa    %xmm0, %xmm6
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm6
        psrld     $27, %xmm15
        paddd     %xmm11, %xmm13
        por       %xmm15, %xmm6
        paddd     %xmm6, %xmm13
        movdqa    %xmm1, %xmm6
        paddd     %xmm8, %xmm13
        pand      %xmm7, %xmm6
        paddd     %xmm2, %xmm13
        movdqa    %xmm1, %xmm2
        por       %xmm7, %xmm2
        movdqa    %xmm14, %xmm15
        pand      %xmm9, %xmm2
        movdqa    %xmm14, %xmm11
        por       %xmm2, %xmm6
        pslld     $5, %xmm15
        psrld     $27, %xmm11
        movdqa    %xmm1, %xmm2
        paddd     %xmm6, %xmm4
        por       %xmm11, %xmm15
        pslld     $30, %xmm2
        psrld     $2, %xmm1
        paddd     %xmm15, %xmm4
        por       %xmm1, %xmm2
        movdqa    368(%rsp), %xmm1
        paddd     %xmm8, %xmm4
        pxor      752(%rsp), %xmm1
        paddd     %xmm12, %xmm4
        pxor      848(%rsp), %xmm1
        movdqa    %xmm5, %xmm6
        movdqa    624(%rsp), %xmm12
        pslld     $30, %xmm6
        movdqa    320(%rsp), %xmm11
        psrld     $2, %xmm5
        pxor      704(%rsp), %xmm11
        pxor      %xmm12, %xmm1
        pxor      576(%rsp), %xmm11
        por       %xmm5, %xmm6
        movdqa    544(%rsp), %xmm5
        movdqa    %xmm1, %xmm15
        pxor      %xmm5, %xmm11
        paddd     %xmm1, %xmm15
        psrld     $31, %xmm1
        por       %xmm1, %xmm15
        movdqa    %xmm11, %xmm1
        paddd     %xmm11, %xmm1
        psrld     $31, %xmm11
        por       %xmm11, %xmm1
        movdqa    %xmm0, %xmm11
        movdqa    %xmm1, 144(%rsp)
        movdqa    %xmm0, %xmm1
        por       %xmm6, %xmm11
        pand      %xmm6, %xmm1
        pand      %xmm10, %xmm11
        movdqa    %xmm15, 528(%rsp)
        por       %xmm11, %xmm1
        movdqa    %xmm13, %xmm11
        movdqa    %xmm13, %xmm15
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm1, %xmm3
        por       %xmm15, %xmm11
        paddd     %xmm11, %xmm3
        movdqa    %xmm14, %xmm11
        paddd     %xmm8, %xmm3
        pand      %xmm2, %xmm11
        paddd     %xmm12, %xmm3
        movdqa    %xmm14, %xmm12
        por       %xmm2, %xmm12
        movdqa    %xmm4, %xmm15
        pand      %xmm7, %xmm12
        movdqa    %xmm4, %xmm1
        por       %xmm12, %xmm11
        pslld     $5, %xmm15
        paddd     %xmm11, %xmm9
        psrld     $27, %xmm1
        movdqa    %xmm14, %xmm11
        por       %xmm1, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm14
        paddd     %xmm15, %xmm9
        por       %xmm14, %xmm11
        movdqa    432(%rsp), %xmm14
        paddd     %xmm8, %xmm9
        pxor      768(%rsp), %xmm14
        paddd     %xmm5, %xmm9
        pxor      864(%rsp), %xmm14
        movdqa    %xmm0, %xmm12
        movdqa    640(%rsp), %xmm5
        pslld     $30, %xmm12
        movdqa    336(%rsp), %xmm1
        psrld     $2, %xmm0
        pxor      720(%rsp), %xmm1
        pxor      %xmm5, %xmm14
        pxor      592(%rsp), %xmm1
        por       %xmm0, %xmm12
        movdqa    560(%rsp), %xmm0
        movdqa    %xmm14, %xmm15
        pxor      %xmm0, %xmm1
        paddd     %xmm14, %xmm15
        psrld     $31, %xmm14
        por       %xmm14, %xmm15
        movdqa    %xmm1, %xmm14
        paddd     %xmm1, %xmm14
        psrld     $31, %xmm1
        por       %xmm1, %xmm14
        movdqa    %xmm13, %xmm1
        movdqa    %xmm15, 80(%rsp)
        movdqa    %xmm13, %xmm15
        por       %xmm12, %xmm1
        pand      %xmm12, %xmm15
        pand      %xmm6, %xmm1
        movdqa    %xmm14, 64(%rsp)
        por       %xmm1, %xmm15
        movdqa    %xmm3, %xmm1
        movdqa    %xmm3, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm14
        paddd     %xmm15, %xmm10
        por       %xmm14, %xmm1
        paddd     %xmm1, %xmm10
        movdqa    %xmm4, %xmm1
        paddd     %xmm8, %xmm10
        pand      %xmm11, %xmm1
        paddd     %xmm5, %xmm10
        movdqa    %xmm4, %xmm5
        por       %xmm11, %xmm5
        movdqa    %xmm9, %xmm14
        pand      %xmm2, %xmm5
        movdqa    %xmm9, %xmm15
        por       %xmm5, %xmm1
        pslld     $5, %xmm14
        paddd     %xmm1, %xmm7
        psrld     $27, %xmm15
        movdqa    %xmm4, %xmm1
        por       %xmm15, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm4
        paddd     %xmm14, %xmm7
        movdqa    %xmm13, %xmm5
        por       %xmm4, %xmm1
        paddd     %xmm8, %xmm7
        movdqa    496(%rsp), %xmm4
        pslld     $30, %xmm5
        pxor      512(%rsp), %xmm4
        psrld     $2, %xmm13
        pxor      880(%rsp), %xmm4
        paddd     %xmm0, %xmm7
        movdqa    848(%rsp), %xmm0
        por       %xmm13, %xmm5
        movdqa    384(%rsp), %xmm13
        pxor      %xmm0, %xmm4
        pxor      128(%rsp), %xmm13
        movdqa    %xmm4, %xmm15
        pxor      608(%rsp), %xmm13
        paddd     %xmm4, %xmm15
        movdqa    576(%rsp), %xmm14
        psrld     $31, %xmm4
        pxor      %xmm14, %xmm13
        por       %xmm4, %xmm15
        movdqa    %xmm13, %xmm4
        paddd     %xmm13, %xmm4
        psrld     $31, %xmm13
        por       %xmm13, %xmm4
        movdqa    %xmm3, %xmm13
        movdqa    %xmm4, 96(%rsp)
        movdqa    %xmm3, %xmm4
        por       %xmm5, %xmm13
        pand      %xmm5, %xmm4
        pand      %xmm12, %xmm13
        movdqa    %xmm15, 112(%rsp)
        por       %xmm13, %xmm4
        movdqa    %xmm10, %xmm13
        movdqa    %xmm10, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm4, %xmm6
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm6
        movdqa    %xmm9, %xmm13
        paddd     %xmm8, %xmm6
        pand      %xmm1, %xmm13
        paddd     %xmm0, %xmm6
        movdqa    %xmm9, %xmm0
        por       %xmm1, %xmm0
        movdqa    %xmm7, %xmm15
        pand      %xmm11, %xmm0
        movdqa    %xmm7, %xmm4
        por       %xmm0, %xmm13
        movdqa    %xmm3, %xmm0
        pslld     $30, %xmm0
        psrld     $2, %xmm3
        paddd     %xmm13, %xmm2
        pslld     $5, %xmm15
        psrld     $27, %xmm4
        por       %xmm3, %xmm0
        movdqa    528(%rsp), %xmm3
        movdqa    %xmm9, %xmm13
        pxor      688(%rsp), %xmm3
        por       %xmm4, %xmm15
        pslld     $30, %xmm13
        psrld     $2, %xmm9
        pxor      464(%rsp), %xmm3
        paddd     %xmm15, %xmm2
        movdqa    864(%rsp), %xmm4
        por       %xmm9, %xmm13
        movdqa    144(%rsp), %xmm9
        paddd     %xmm8, %xmm2
        pxor      656(%rsp), %xmm9
        pxor      %xmm4, %xmm3
        pxor      400(%rsp), %xmm9
        paddd     %xmm14, %xmm2
        movdqa    592(%rsp), %xmm15
        movdqa    %xmm3, %xmm14
        pxor      %xmm15, %xmm9
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm9, %xmm3
        paddd     %xmm9, %xmm3
        psrld     $31, %xmm9
        por       %xmm9, %xmm3
        movdqa    %xmm10, %xmm9
        movdqa    %xmm3, (%rsp)
        movdqa    %xmm10, %xmm3
        por       %xmm0, %xmm9
        pand      %xmm0, %xmm3
        pand      %xmm5, %xmm9
        movdqa    %xmm14, 16(%rsp)
        por       %xmm9, %xmm3
        movdqa    %xmm6, %xmm9
        movdqa    %xmm6, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        paddd     %xmm3, %xmm12
        por       %xmm14, %xmm9
        paddd     %xmm9, %xmm12
        movdqa    %xmm7, %xmm9
        paddd     %xmm8, %xmm12
        pand      %xmm13, %xmm9
        paddd     %xmm4, %xmm12
        movdqa    %xmm7, %xmm4
        por       %xmm13, %xmm4
        movdqa    %xmm2, %xmm14
        pand      %xmm1, %xmm4
        movdqa    %xmm2, %xmm3
        por       %xmm4, %xmm9
        pslld     $5, %xmm14
        psrld     $27, %xmm3
        paddd     %xmm9, %xmm11
        por       %xmm3, %xmm14
        movdqa    %xmm7, %xmm4
        movdqa    80(%rsp), %xmm3
        paddd     %xmm14, %xmm11
        pxor      736(%rsp), %xmm3
        paddd     %xmm8, %xmm11
        pslld     $30, %xmm4
        psrld     $2, %xmm7
        pxor      480(%rsp), %xmm3
        paddd     %xmm15, %xmm11
        movdqa    64(%rsp), %xmm15
        movdqa    %xmm10, %xmm9
        por       %xmm7, %xmm4
        pslld     $30, %xmm9
        movdqa    880(%rsp), %xmm7
        psrld     $2, %xmm10
        pxor      672(%rsp), %xmm15
        pxor      %xmm7, %xmm3
        pxor      416(%rsp), %xmm15
        por       %xmm10, %xmm9
        movdqa    608(%rsp), %xmm10
        movdqa    %xmm3, %xmm14
        pxor      %xmm10, %xmm15
        paddd     %xmm3, %xmm14
        psrld     $31, %xmm3
        por       %xmm3, %xmm14
        movdqa    %xmm15, %xmm3
        paddd     %xmm15, %xmm3
        psrld     $31, %xmm15
        por       %xmm15, %xmm3
        movdqa    %xmm6, %xmm15
        movdqa    %xmm3, 32(%rsp)
        movdqa    %xmm6, %xmm3
        por       %xmm9, %xmm15
        pand      %xmm9, %xmm3
        pand      %xmm0, %xmm15
        por       %xmm15, %xmm3
        movdqa    %xmm11, %xmm15
        movdqa    %xmm14, 48(%rsp)
        paddd     %xmm3, %xmm5
        movdqa    %xmm12, %xmm3
        movdqa    %xmm12, %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm14
        por       %xmm14, %xmm3
        movdqa    %xmm11, %xmm14
        paddd     %xmm3, %xmm5
        movdqa    %xmm2, %xmm3
        paddd     %xmm8, %xmm5
        pand      %xmm4, %xmm3
        paddd     %xmm7, %xmm5
        movdqa    %xmm2, %xmm7
        por       %xmm4, %xmm7
        pslld     $5, %xmm15
        pand      %xmm13, %xmm7
        psrld     $27, %xmm14
        por       %xmm7, %xmm3
        por       %xmm14, %xmm15
        paddd     %xmm3, %xmm1
        paddd     %xmm15, %xmm1
        paddd     %xmm8, %xmm1
        paddd     %xmm10, %xmm1
..B9.15:
        movdqa    %xmm6, %xmm3
        psrld     $2, %xmm6
        pslld     $30, %xmm3
        movdqa    112(%rsp), %xmm10
        por       %xmm6, %xmm3
        movdqa    %xmm2, %xmm6
        psrld     $2, %xmm2
        pxor      752(%rsp), %xmm10
        pslld     $30, %xmm6
        pxor      448(%rsp), %xmm10
        por       %xmm2, %xmm6
        movdqa    464(%rsp), %xmm7
        movdqa    96(%rsp), %xmm2
        pxor      %xmm7, %xmm10
        pxor      704(%rsp), %xmm2
        movdqa    %xmm10, %xmm15
        pxor      352(%rsp), %xmm2
        paddd     %xmm10, %xmm15
        movdqa    400(%rsp), %xmm14
        psrld     $31, %xmm10
        pxor      %xmm14, %xmm2
        por       %xmm10, %xmm15
        movdqa    %xmm2, %xmm10
        paddd     %xmm2, %xmm10
        psrld     $31, %xmm2
        por       %xmm2, %xmm10
        movdqa    %xmm12, %xmm2
        movdqa    %xmm10, 224(%rsp)
        movdqa    %xmm12, %xmm10
        por       %xmm3, %xmm2
        pand      %xmm3, %xmm10
        pand      %xmm9, %xmm2
        por       %xmm2, %xmm10
        movdqa    %xmm1, %xmm2
        movdqa    %xmm15, 256(%rsp)
        paddd     %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        movdqa    %xmm5, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        por       %xmm15, %xmm10
        movdqa    %xmm1, %xmm15
        paddd     %xmm10, %xmm0
        movdqa    %xmm11, %xmm10
        paddd     %xmm8, %xmm0
        pslld     $5, %xmm15
        paddd     %xmm7, %xmm0
        movdqa    %xmm11, %xmm7
        por       %xmm6, %xmm7
        psrld     $27, %xmm2
        pand      %xmm6, %xmm10
        pand      %xmm4, %xmm7
        por       %xmm2, %xmm15
        movdqa    %xmm12, %xmm2
        por       %xmm7, %xmm10
        pslld     $30, %xmm2
        psrld     $2, %xmm12
        paddd     %xmm10, %xmm13
        movdqa    16(%rsp), %xmm10
        por       %xmm12, %xmm2
        movdqa    %xmm11, %xmm12
        psrld     $2, %xmm11
        pxor      768(%rsp), %xmm10
        pslld     $30, %xmm12
        pxor      368(%rsp), %xmm10
        paddd     %xmm15, %xmm13
        movdqa    480(%rsp), %xmm7
        por       %xmm11, %xmm12
        movdqa    (%rsp), %xmm11
        paddd     %xmm8, %xmm13
        pxor      720(%rsp), %xmm11
        pxor      %xmm7, %xmm10
        pxor      320(%rsp), %xmm11
        paddd     %xmm14, %xmm13
        movdqa    416(%rsp), %xmm14
        movdqa    %xmm10, %xmm15
        pxor      %xmm14, %xmm11
        paddd     %xmm10, %xmm15
        psrld     $31, %xmm10
        por       %xmm10, %xmm15
        movdqa    %xmm11, %xmm10
        paddd     %xmm11, %xmm10
        psrld     $31, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm5, %xmm11
        movdqa    %xmm10, 288(%rsp)
        movdqa    %xmm5, %xmm10
        por       %xmm2, %xmm11
        pand      %xmm2, %xmm10
        pand      %xmm3, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm13, %xmm11
        movdqa    %xmm15, 304(%rsp)
        paddd     %xmm10, %xmm9
        movdqa    %xmm0, %xmm10
        movdqa    %xmm0, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        por       %xmm15, %xmm10
        movdqa    %xmm13, %xmm15
        paddd     %xmm10, %xmm9
        movdqa    %xmm1, %xmm10
        paddd     %xmm8, %xmm9
        pand      %xmm12, %xmm10
        paddd     %xmm7, %xmm9
        movdqa    %xmm1, %xmm7
        por       %xmm12, %xmm7
        pslld     $5, %xmm15
        pand      %xmm6, %xmm7
        psrld     $27, %xmm11
        por       %xmm7, %xmm10
        por       %xmm11, %xmm15
        paddd     %xmm10, %xmm4
        movdqa    %xmm5, %xmm11
        paddd     %xmm15, %xmm4
        pslld     $30, %xmm11
        paddd     %xmm8, %xmm4
        psrld     $2, %xmm5
        paddd     %xmm14, %xmm4
        por       %xmm5, %xmm11
        movdqa    48(%rsp), %xmm14
        movdqa    %xmm1, %xmm5
        pxor      512(%rsp), %xmm14
        pslld     $30, %xmm5
        pxor      432(%rsp), %xmm14
        psrld     $2, %xmm1
        movdqa    448(%rsp), %xmm15
        por       %xmm1, %xmm5
        movdqa    32(%rsp), %xmm7
        pxor      %xmm15, %xmm14
        pxor      128(%rsp), %xmm7
        movdqa    %xmm14, %xmm10
        pxor      336(%rsp), %xmm7
        paddd     %xmm14, %xmm10
        movdqa    352(%rsp), %xmm1
        psrld     $31, %xmm14
        pxor      %xmm1, %xmm7
        por       %xmm14, %xmm10
        movdqa    %xmm7, %xmm14
        paddd     %xmm7, %xmm14
        psrld     $31, %xmm7
        por       %xmm7, %xmm14
        movdqa    %xmm0, %xmm7
        movdqa    %xmm14, 576(%rsp)
        movdqa    %xmm0, %xmm14
        por       %xmm11, %xmm7
        pand      %xmm11, %xmm14
        pand      %xmm2, %xmm7
        movdqa    %xmm10, 624(%rsp)
        por       %xmm7, %xmm14
        movdqa    %xmm9, %xmm7
        movdqa    %xmm9, %xmm10
        pslld     $5, %xmm7
        psrld     $27, %xmm10
        paddd     %xmm14, %xmm3
        por       %xmm10, %xmm7
        paddd     %xmm7, %xmm3
        movdqa    %xmm13, %xmm7
        paddd     %xmm8, %xmm3
        pand      %xmm5, %xmm7
        paddd     %xmm15, %xmm3
        movdqa    %xmm13, %xmm15
        por       %xmm5, %xmm15
        movdqa    %xmm4, %xmm10
        pand      %xmm12, %xmm15
        movdqa    %xmm4, %xmm14
        por       %xmm15, %xmm7
        pslld     $5, %xmm10
        psrld     $27, %xmm14
        paddd     %xmm7, %xmm6
        por       %xmm14, %xmm10
        movdqa    %xmm13, %xmm7
        movdqa    528(%rsp), %xmm15
        paddd     %xmm10, %xmm6
        pxor      256(%rsp), %xmm15
        paddd     %xmm8, %xmm6
        pslld     $30, %xmm7
        psrld     $2, %xmm13
        pxor      496(%rsp), %xmm15
        paddd     %xmm1, %xmm6
        movdqa    368(%rsp), %xmm10
        movdqa    %xmm0, %xmm1
        por       %xmm13, %xmm7
        pslld     $30, %xmm1
        movdqa    144(%rsp), %xmm13
        psrld     $2, %xmm0
        pxor      224(%rsp), %xmm13
        pxor      %xmm10, %xmm15
        pxor      384(%rsp), %xmm13
        por       %xmm0, %xmm1
        movdqa    320(%rsp), %xmm0
        movdqa    %xmm15, %xmm14
        pxor      %xmm0, %xmm13
        paddd     %xmm15, %xmm14
        psrld     $31, %xmm15
        por       %xmm15, %xmm14
        movdqa    %xmm13, %xmm15
        paddd     %xmm13, %xmm15
        psrld     $31, %xmm13
        por       %xmm13, %xmm15
        movdqa    %xmm9, %xmm13
        movdqa    %xmm14, 784(%rsp)
        movdqa    %xmm9, %xmm14
        por       %xmm1, %xmm13
        pand      %xmm1, %xmm14
        pand      %xmm11, %xmm13
        movdqa    %xmm15, 640(%rsp)
        por       %xmm13, %xmm14
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm2
        por       %xmm15, %xmm13
        paddd     %xmm13, %xmm2
        movdqa    %xmm4, %xmm13
        paddd     %xmm8, %xmm2
        pand      %xmm7, %xmm13
        paddd     %xmm10, %xmm2
        movdqa    %xmm4, %xmm10
        por       %xmm7, %xmm10
        movdqa    %xmm6, %xmm15
        pand      %xmm5, %xmm10
        movdqa    %xmm6, %xmm14
        por       %xmm10, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     %xmm13, %xmm12
        por       %xmm14, %xmm15
        movdqa    %xmm4, %xmm13
        paddd     %xmm15, %xmm12
        pslld     $30, %xmm13
        paddd     %xmm8, %xmm12
        psrld     $2, %xmm4
        movdqa    80(%rsp), %xmm10
        paddd     %xmm0, %xmm12
        movdqa    %xmm9, %xmm0
        psrld     $2, %xmm9
        pxor      304(%rsp), %xmm10
        pslld     $30, %xmm0
        pxor      688(%rsp), %xmm10
        por       %xmm9, %xmm0
        movdqa    432(%rsp), %xmm9
        por       %xmm4, %xmm13
        movdqa    64(%rsp), %xmm4
        pxor      %xmm9, %xmm10
        pxor      288(%rsp), %xmm4
        movdqa    %xmm10, %xmm15
        pxor      656(%rsp), %xmm4
        paddd     %xmm10, %xmm15
        movdqa    336(%rsp), %xmm14
        psrld     $31, %xmm10
        pxor      %xmm14, %xmm4
        por       %xmm10, %xmm15
        movdqa    %xmm4, %xmm10
        paddd     %xmm4, %xmm10
        psrld     $31, %xmm4
        por       %xmm4, %xmm10
        movdqa    %xmm3, %xmm4
        movdqa    %xmm10, 192(%rsp)
        movdqa    %xmm3, %xmm10
        por       %xmm0, %xmm4
        pand      %xmm0, %xmm10
        pand      %xmm1, %xmm4
        movdqa    %xmm15, 208(%rsp)
        por       %xmm4, %xmm10
        movdqa    %xmm2, %xmm4
        movdqa    %xmm2, %xmm15
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm11
        por       %xmm15, %xmm4
        paddd     %xmm4, %xmm11
        movdqa    %xmm6, %xmm4
        paddd     %xmm8, %xmm11
        pand      %xmm13, %xmm4
        paddd     %xmm9, %xmm11
        movdqa    %xmm6, %xmm9
        por       %xmm13, %xmm9
        movdqa    %xmm12, %xmm15
        pand      %xmm7, %xmm9
        movdqa    %xmm12, %xmm10
        por       %xmm9, %xmm4
        pslld     $5, %xmm15
        psrld     $27, %xmm10
        movdqa    %xmm3, %xmm9
        paddd     %xmm4, %xmm5
        por       %xmm10, %xmm15
        pslld     $30, %xmm9
        psrld     $2, %xmm3
        paddd     %xmm15, %xmm5
        por       %xmm3, %xmm9
        movdqa    112(%rsp), %xmm3
        paddd     %xmm8, %xmm5
        pxor      624(%rsp), %xmm3
        paddd     %xmm14, %xmm5
        pxor      736(%rsp), %xmm3
        movdqa    %xmm6, %xmm4
        movdqa    496(%rsp), %xmm14
        pslld     $30, %xmm4
        movdqa    96(%rsp), %xmm10
        psrld     $2, %xmm6
        pxor      576(%rsp), %xmm10
        pxor      %xmm14, %xmm3
        pxor      672(%rsp), %xmm10
        por       %xmm6, %xmm4
        movdqa    384(%rsp), %xmm6
        movdqa    %xmm3, %xmm15
        pxor      %xmm6, %xmm10
        paddd     %xmm3, %xmm15
        psrld     $31, %xmm3
        por       %xmm3, %xmm15
        movdqa    %xmm10, %xmm3
        paddd     %xmm10, %xmm3
        psrld     $31, %xmm10
        por       %xmm10, %xmm3
        movdqa    %xmm2, %xmm10
        movdqa    %xmm3, 240(%rsp)
        movdqa    %xmm2, %xmm3
        por       %xmm9, %xmm10
        pand      %xmm9, %xmm3
        pand      %xmm0, %xmm10
        movdqa    %xmm15, 272(%rsp)
        por       %xmm10, %xmm3
        movdqa    %xmm11, %xmm10
        movdqa    %xmm11, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm3, %xmm1
        por       %xmm15, %xmm10
        paddd     %xmm10, %xmm1
        movdqa    %xmm12, %xmm10
        paddd     %xmm8, %xmm1
        pand      %xmm4, %xmm10
        paddd     %xmm14, %xmm1
        movdqa    %xmm12, %xmm14
        por       %xmm4, %xmm14
        movdqa    %xmm5, %xmm15
        pand      %xmm13, %xmm14
        movdqa    %xmm5, %xmm3
        por       %xmm14, %xmm10
        pslld     $5, %xmm15
        psrld     $27, %xmm3
        movdqa    %xmm2, %xmm14
        paddd     %xmm10, %xmm7
        por       %xmm3, %xmm15
        pslld     $30, %xmm14
        psrld     $2, %xmm2
        paddd     %xmm15, %xmm7
        por       %xmm2, %xmm14
        movdqa    16(%rsp), %xmm2
        paddd     %xmm8, %xmm7
        pxor      784(%rsp), %xmm2
        paddd     %xmm6, %xmm7
        pxor      752(%rsp), %xmm2
        movdqa    %xmm12, %xmm10
        movdqa    688(%rsp), %xmm6
        pslld     $30, %xmm10
        movdqa    (%rsp), %xmm3
        psrld     $2, %xmm12
        pxor      640(%rsp), %xmm3
        pxor      %xmm6, %xmm2
        pxor      704(%rsp), %xmm3
        por       %xmm12, %xmm10
        movdqa    656(%rsp), %xmm12
        movdqa    %xmm2, %xmm15
        pxor      %xmm12, %xmm3
        paddd     %xmm2, %xmm15
        psrld     $31, %xmm2
        por       %xmm2, %xmm15
        movdqa    %xmm3, %xmm2
        paddd     %xmm3, %xmm2
        psrld     $31, %xmm3
        por       %xmm3, %xmm2
        movdqa    %xmm11, %xmm3
        movdqa    %xmm2, 544(%rsp)
        movdqa    %xmm11, %xmm2
        por       %xmm14, %xmm3
        pand      %xmm14, %xmm2
        pand      %xmm9, %xmm3
        movdqa    %xmm15, 560(%rsp)
        por       %xmm3, %xmm2
        movdqa    %xmm1, %xmm3
        movdqa    %xmm1, %xmm15
        pslld     $5, %xmm3
        psrld     $27, %xmm15
        paddd     %xmm2, %xmm0
        por       %xmm15, %xmm3
        paddd     %xmm3, %xmm0
        movdqa    %xmm5, %xmm3
        paddd     %xmm8, %xmm0
        pand      %xmm10, %xmm3
        paddd     %xmm6, %xmm0
        movdqa    %xmm5, %xmm6
        por       %xmm10, %xmm6
        movdqa    %xmm7, %xmm15
        pand      %xmm4, %xmm6
        movdqa    %xmm7, %xmm2
        por       %xmm6, %xmm3
        pslld     $5, %xmm15
        paddd     %xmm3, %xmm13
        movdqa    %xmm5, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm5
        psrld     $27, %xmm2
        movdqa    %xmm11, %xmm6
        por       %xmm5, %xmm3
        por       %xmm2, %xmm15
        movdqa    48(%rsp), %xmm5
        pslld     $30, %xmm6
        pxor      208(%rsp), %xmm5
        psrld     $2, %xmm11
        pxor      768(%rsp), %xmm5
        paddd     %xmm15, %xmm13
        movdqa    736(%rsp), %xmm2
        por       %xmm11, %xmm6
        movdqa    32(%rsp), %xmm11
        paddd     %xmm8, %xmm13
        pxor      192(%rsp), %xmm11
        pxor      %xmm2, %xmm5
        pxor      720(%rsp), %xmm11
        paddd     %xmm12, %xmm13
        movdqa    672(%rsp), %xmm15
        movdqa    %xmm5, %xmm12
        pxor      %xmm15, %xmm11
        paddd     %xmm5, %xmm12
        psrld     $31, %xmm5
        por       %xmm5, %xmm12
        movdqa    %xmm11, %xmm5
        paddd     %xmm11, %xmm5
        psrld     $31, %xmm11
        por       %xmm11, %xmm5
        movdqa    %xmm1, %xmm11
        movdqa    %xmm5, 592(%rsp)
        movdqa    %xmm1, %xmm5
        por       %xmm6, %xmm11
        pand      %xmm6, %xmm5
        pand      %xmm14, %xmm11
        movdqa    %xmm12, 608(%rsp)
        por       %xmm11, %xmm5
        movdqa    %xmm0, %xmm11
        movdqa    %xmm0, %xmm12
        pslld     $5, %xmm11
        psrld     $27, %xmm12
        paddd     %xmm5, %xmm9
        por       %xmm12, %xmm11
        paddd     %xmm11, %xmm9
        movdqa    %xmm7, %xmm11
        paddd     %xmm8, %xmm9
        pand      %xmm3, %xmm11
        paddd     %xmm2, %xmm9
        movdqa    %xmm7, %xmm2
        por       %xmm3, %xmm2
        movdqa    %xmm13, %xmm12
        pand      %xmm10, %xmm2
        movdqa    %xmm13, %xmm5
        por       %xmm2, %xmm11
        pslld     $5, %xmm12
        psrld     $27, %xmm5
        paddd     %xmm11, %xmm4
        por       %xmm5, %xmm12
        movdqa    %xmm1, %xmm2
        paddd     %xmm12, %xmm4
        pslld     $30, %xmm2
        paddd     %xmm8, %xmm4
        psrld     $2, %xmm1
        movdqa    272(%rsp), %xmm8
        por       %xmm1, %xmm2
        pxor      256(%rsp), %xmm8
        movdqa    %xmm7, %xmm11
        movdqa    240(%rsp), %xmm1
        pslld     $30, %xmm11
        pxor      512(%rsp), %xmm8
        psrld     $2, %xmm7
        movdqa    752(%rsp), %xmm5
        por       %xmm7, %xmm11
        pxor      224(%rsp), %xmm1
        pxor      %xmm5, %xmm8
        pxor      128(%rsp), %xmm1
        paddd     %xmm15, %xmm4
        movdqa    704(%rsp), %xmm7
        movdqa    %xmm8, %xmm15
        pxor      %xmm7, %xmm1
        paddd     %xmm8, %xmm15
        psrld     $31, %xmm8
        movdqa    %xmm1, %xmm12
        por       %xmm8, %xmm15
        paddd     %xmm1, %xmm12
        psrld     $31, %xmm1
        movdqa    %xmm2, %xmm8
        movdqa    %xmm15, 816(%rsp)
        por       %xmm1, %xmm12
        pxor      %xmm6, %xmm8
        movdqa    %xmm9, %xmm1
        movdqa    %xmm9, %xmm15
        pxor      %xmm0, %xmm8
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm14
        por       %xmm15, %xmm1
        movdqa    .L_2il0floatpacket.509(%rip), %xmm8
        paddd     %xmm1, %xmm14
        paddd     %xmm8, %xmm14
        movdqa    %xmm4, %xmm1
        paddd     %xmm5, %xmm14
        movdqa    %xmm11, %xmm5
        pxor      %xmm3, %xmm5
        movdqa    %xmm4, %xmm15
        pxor      %xmm13, %xmm5
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm5, %xmm10
        por       %xmm15, %xmm1
        movdqa    %xmm13, %xmm5
        paddd     %xmm1, %xmm10
        pslld     $30, %xmm5
        paddd     %xmm8, %xmm10
        psrld     $2, %xmm13
        movdqa    %xmm12, 800(%rsp)
        paddd     %xmm7, %xmm10
        movdqa    560(%rsp), %xmm12
        movdqa    %xmm0, %xmm7
        pxor      304(%rsp), %xmm12
        pslld     $30, %xmm7
        psrld     $2, %xmm0
        por       %xmm13, %xmm5
        pxor      528(%rsp), %xmm12
        por       %xmm0, %xmm7
        movdqa    768(%rsp), %xmm0
        movdqa    544(%rsp), %xmm15
        pxor      %xmm0, %xmm12
        pxor      288(%rsp), %xmm15
        movdqa    %xmm12, %xmm1
        pxor      144(%rsp), %xmm15
        paddd     %xmm12, %xmm1
        movdqa    720(%rsp), %xmm13
        psrld     $31, %xmm12
        pxor      %xmm13, %xmm15
        por       %xmm12, %xmm1
        movdqa    %xmm15, %xmm12
        paddd     %xmm15, %xmm12
        psrld     $31, %xmm15
        por       %xmm15, %xmm12
        movdqa    %xmm7, %xmm15
        movdqa    %xmm1, 176(%rsp)
        pxor      %xmm2, %xmm15
        movdqa    %xmm12, 160(%rsp)
        movdqa    %xmm14, %xmm12
        movdqa    %xmm14, %xmm1
        pxor      %xmm9, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm1
        paddd     %xmm15, %xmm6
        por       %xmm1, %xmm12
        paddd     %xmm12, %xmm6
        movdqa    %xmm10, %xmm12
        paddd     %xmm8, %xmm6
        movdqa    %xmm10, %xmm1
        paddd     %xmm0, %xmm6
        movdqa    %xmm5, %xmm0
        pxor      %xmm11, %xmm0
        pslld     $5, %xmm12
        pxor      %xmm4, %xmm0
        psrld     $27, %xmm1
        paddd     %xmm0, %xmm3
        por       %xmm1, %xmm12
        paddd     %xmm12, %xmm3
        movdqa    %xmm9, %xmm1
        movdqa    %xmm4, %xmm0
        paddd     %xmm8, %xmm3
        movdqa    608(%rsp), %xmm12
        pslld     $30, %xmm1
        psrld     $2, %xmm9
        pslld     $30, %xmm0
        psrld     $2, %xmm4
        paddd     %xmm13, %xmm3
        pxor      624(%rsp), %xmm12
        por       %xmm9, %xmm1
        por       %xmm4, %xmm0
..B9.14:
        pxor      80(%rsp), %xmm12
        movdqa    512(%rsp), %xmm9
        movdqa    592(%rsp), %xmm4
        pxor      %xmm9, %xmm12
        pxor      576(%rsp), %xmm4
        movdqa    %xmm12, %xmm15
        pxor      64(%rsp), %xmm4
        paddd     %xmm12, %xmm15
        movdqa    128(%rsp), %xmm13
        psrld     $31, %xmm12
        pxor      %xmm13, %xmm4
        por       %xmm12, %xmm15
        movdqa    %xmm4, %xmm12
        paddd     %xmm4, %xmm12
        psrld     $31, %xmm4
        por       %xmm4, %xmm12
        movdqa    %xmm1, %xmm4
        pxor      %xmm7, %xmm4
        pxor      %xmm14, %xmm4
        movdqa    %xmm15, 320(%rsp)
        paddd     %xmm4, %xmm2
        movdqa    %xmm6, %xmm4
        movdqa    %xmm6, %xmm15
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        por       %xmm15, %xmm4
        paddd     %xmm4, %xmm2
        movdqa    %xmm3, %xmm4
        paddd     %xmm8, %xmm2
        psrld     $27, %xmm4
        paddd     %xmm9, %xmm2
        movdqa    %xmm0, %xmm9
        movdqa    %xmm12, 336(%rsp)
        pxor      %xmm5, %xmm9
        movdqa    %xmm3, %xmm12
        pxor      %xmm10, %xmm9
        pslld     $5, %xmm12
        paddd     %xmm9, %xmm11
        por       %xmm4, %xmm12
        movdqa    %xmm14, %xmm9
        paddd     %xmm12, %xmm11
        pslld     $30, %xmm9
        movdqa    816(%rsp), %xmm12
        paddd     %xmm8, %xmm11
        pxor      784(%rsp), %xmm12
        psrld     $2, %xmm14
        pxor      112(%rsp), %xmm12
        paddd     %xmm13, %xmm11
        movdqa    528(%rsp), %xmm15
        por       %xmm14, %xmm9
        movdqa    800(%rsp), %xmm13
        movdqa    %xmm10, %xmm14
        pxor      640(%rsp), %xmm13
        pslld     $30, %xmm14
        psrld     $2, %xmm10
        pxor      %xmm15, %xmm12
        pxor      96(%rsp), %xmm13
        por       %xmm10, %xmm14
        movdqa    144(%rsp), %xmm10
        movdqa    %xmm12, %xmm4
        pxor      %xmm10, %xmm13
        paddd     %xmm12, %xmm4
        psrld     $31, %xmm12
        por       %xmm12, %xmm4
        movdqa    %xmm13, %xmm12
        paddd     %xmm13, %xmm12
        psrld     $31, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        pxor      %xmm9, %xmm13
        pxor      %xmm6, %xmm13
        movdqa    %xmm12, 352(%rsp)
        paddd     %xmm13, %xmm7
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm12
        pslld     $5, %xmm13
        psrld     $27, %xmm12
        por       %xmm12, %xmm13
        movdqa    %xmm11, %xmm12
        paddd     %xmm13, %xmm7
        movdqa    %xmm11, %xmm13
        paddd     %xmm8, %xmm7
        pslld     $5, %xmm12
        paddd     %xmm15, %xmm7
        movdqa    %xmm0, %xmm15
        pxor      %xmm14, %xmm15
        psrld     $27, %xmm13
        pxor      %xmm3, %xmm15
        por       %xmm13, %xmm12
        paddd     %xmm15, %xmm5
        movdqa    %xmm7, %xmm13
        paddd     %xmm12, %xmm5
        movdqa    %xmm7, %xmm12
        paddd     %xmm8, %xmm5
        pslld     $5, %xmm12
        paddd     %xmm10, %xmm5
        movdqa    %xmm6, %xmm10
        pslld     $30, %xmm10
        psrld     $2, %xmm6
        por       %xmm6, %xmm10
        movdqa    %xmm3, %xmm6
        pslld     $30, %xmm6
        psrld     $2, %xmm3
        por       %xmm3, %xmm6
        movdqa    %xmm10, %xmm3
        pxor      %xmm9, %xmm3
        psrld     $27, %xmm13
        pxor      %xmm2, %xmm3
        por       %xmm13, %xmm12
        paddd     %xmm3, %xmm1
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm3
        pslld     $5, %xmm13
        psrld     $27, %xmm3
        movdqa    %xmm6, %xmm15
        por       %xmm3, %xmm13
        movdqa    %xmm2, %xmm3
        pxor      %xmm14, %xmm15
        pslld     $30, %xmm3
        psrld     $2, %xmm2
        paddd     %xmm12, %xmm1
        pxor      %xmm11, %xmm15
        por       %xmm2, %xmm3
        movdqa    %xmm11, %xmm2
        paddd     %xmm8, %xmm1
        paddd     %xmm15, %xmm0
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        paddd     %xmm13, %xmm0
        paddd     80(%rsp), %xmm1
        por       %xmm11, %xmm2
        movdqa    %xmm3, %xmm11
        paddd     %xmm8, %xmm0
        pxor      %xmm10, %xmm11
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm13
        pxor      %xmm7, %xmm11
        paddd     64(%rsp), %xmm0
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm11, %xmm9
        por       %xmm13, %xmm12
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        movdqa    %xmm2, %xmm15
        por       %xmm11, %xmm13
        movdqa    %xmm7, %xmm11
        pxor      %xmm6, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm7
        paddd     %xmm12, %xmm9
        pxor      %xmm5, %xmm15
        por       %xmm7, %xmm11
        movdqa    %xmm5, %xmm7
        paddd     %xmm8, %xmm9
        paddd     %xmm15, %xmm14
        pslld     $30, %xmm7
        psrld     $2, %xmm5
        paddd     %xmm13, %xmm14
        paddd     112(%rsp), %xmm9
        por       %xmm5, %xmm7
        movdqa    %xmm11, %xmm5
        paddd     %xmm8, %xmm14
        pxor      %xmm3, %xmm5
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm13
        pxor      %xmm1, %xmm5
        paddd     96(%rsp), %xmm14
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     %xmm5, %xmm10
        por       %xmm13, %xmm12
        movdqa    %xmm14, %xmm13
        movdqa    %xmm14, %xmm5
        paddd     %xmm12, %xmm10
        movdqa    %xmm7, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm5
        movdqa    %xmm1, %xmm12
        pxor      %xmm2, %xmm15
        por       %xmm5, %xmm13
        pslld     $30, %xmm12
        psrld     $2, %xmm1
        movdqa    %xmm0, %xmm5
        pxor      %xmm0, %xmm15
        por       %xmm1, %xmm12
        pslld     $30, %xmm5
        psrld     $2, %xmm0
        paddd     %xmm8, %xmm10
        por       %xmm0, %xmm5
        movdqa    %xmm12, %xmm0
        pxor      %xmm11, %xmm0
        paddd     %xmm15, %xmm6
        paddd     16(%rsp), %xmm10
        pxor      %xmm9, %xmm0
        paddd     %xmm13, %xmm6
        paddd     %xmm0, %xmm3
        movdqa    %xmm10, %xmm0
        movdqa    %xmm10, %xmm1
        paddd     %xmm8, %xmm6
        pslld     $5, %xmm0
        psrld     $27, %xmm1
        movdqa    %xmm5, %xmm13
        paddd     (%rsp), %xmm6
        por       %xmm1, %xmm0
        paddd     %xmm0, %xmm3
        pxor      %xmm7, %xmm13
        movdqa    %xmm6, %xmm0
        movdqa    %xmm6, %xmm15
        pxor      %xmm14, %xmm13
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm2
        por       %xmm15, %xmm0
        movdqa    %xmm9, %xmm1
        paddd     %xmm0, %xmm2
        pslld     $30, %xmm1
        psrld     $2, %xmm9
        movdqa    %xmm14, %xmm0
        por       %xmm9, %xmm1
        pslld     $30, %xmm0
        psrld     $2, %xmm14
        paddd     %xmm8, %xmm3
        por       %xmm14, %xmm0
        movdqa    %xmm1, %xmm14
        pxor      %xmm12, %xmm14
        paddd     %xmm8, %xmm2
        paddd     48(%rsp), %xmm3
        pxor      %xmm10, %xmm14
        paddd     %xmm14, %xmm11
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm9
        movdqa    %xmm10, %xmm14
        pslld     $5, %xmm13
        psrld     $27, %xmm9
        movdqa    %xmm0, %xmm15
        pslld     $30, %xmm14
        psrld     $2, %xmm10
        por       %xmm9, %xmm13
        paddd     32(%rsp), %xmm2
        pxor      %xmm5, %xmm15
        por       %xmm10, %xmm14
        movdqa    %xmm6, %xmm10
        paddd     %xmm13, %xmm11
        pxor      %xmm6, %xmm15
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm9
        pslld     $30, %xmm10
        psrld     $2, %xmm6
        paddd     %xmm8, %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm9
        por       %xmm6, %xmm10
        paddd     256(%rsp), %xmm11
        paddd     %xmm15, %xmm7
        por       %xmm9, %xmm13
        movdqa    %xmm14, %xmm6
        movdqa    %xmm10, %xmm15
        paddd     %xmm13, %xmm7
        pxor      %xmm1, %xmm6
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm9
        pxor      %xmm0, %xmm15
        pxor      %xmm3, %xmm6
        pslld     $5, %xmm13
        psrld     $27, %xmm9
        pxor      %xmm2, %xmm15
        paddd     %xmm6, %xmm12
        por       %xmm9, %xmm13
        paddd     %xmm15, %xmm5
        movdqa    %xmm3, %xmm15
        paddd     %xmm8, %xmm7
        paddd     %xmm13, %xmm12
        pslld     $30, %xmm15
        psrld     $2, %xmm3
        movdqa    %xmm2, %xmm13
        por       %xmm3, %xmm15
        paddd     224(%rsp), %xmm7
        pslld     $30, %xmm13
        psrld     $2, %xmm2
        movdqa    %xmm7, %xmm6
        movdqa    %xmm7, %xmm9
        por       %xmm2, %xmm13
        movdqa    %xmm15, %xmm2
        paddd     %xmm8, %xmm12
        pslld     $5, %xmm6
        psrld     $27, %xmm9
        pxor      %xmm14, %xmm2
        por       %xmm9, %xmm6
        paddd     304(%rsp), %xmm12
        pxor      %xmm11, %xmm2
        paddd     %xmm6, %xmm5
        paddd     %xmm2, %xmm1
        movdqa    %xmm12, %xmm2
        movdqa    %xmm12, %xmm3
        paddd     %xmm8, %xmm5
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        movdqa    %xmm13, %xmm9
        paddd     288(%rsp), %xmm5
        por       %xmm3, %xmm2
        paddd     %xmm2, %xmm1
        pxor      %xmm10, %xmm9
        movdqa    %xmm5, %xmm2
        movdqa    %xmm5, %xmm6
        pxor      %xmm7, %xmm9
        pslld     $5, %xmm2
        psrld     $27, %xmm6
        paddd     %xmm9, %xmm0
        por       %xmm6, %xmm2
        paddd     %xmm8, %xmm1
        paddd     %xmm2, %xmm0
        movdqa    %xmm11, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        por       %xmm11, %xmm2
        movdqa    %xmm7, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm7
        paddd     624(%rsp), %xmm1
        por       %xmm7, %xmm11
        movdqa    %xmm2, %xmm7
        movdqa    %xmm1, %xmm9
        pxor      %xmm15, %xmm7
        movdqa    %xmm1, %xmm3
        paddd     %xmm8, %xmm0
        pxor      %xmm12, %xmm7
        pslld     $5, %xmm9
        psrld     $27, %xmm3
        paddd     576(%rsp), %xmm0
        paddd     %xmm7, %xmm14
        por       %xmm3, %xmm9
        movdqa    %xmm11, %xmm6
        movdqa    %xmm12, %xmm7
        paddd     %xmm9, %xmm14
        pxor      %xmm13, %xmm6
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm3
        pslld     $30, %xmm7
        psrld     $2, %xmm12
        pxor      %xmm5, %xmm6
        pslld     $5, %xmm9
        psrld     $27, %xmm3
        por       %xmm12, %xmm7
        movdqa    %xmm5, %xmm12
        paddd     %xmm8, %xmm14
        paddd     %xmm6, %xmm10
        por       %xmm3, %xmm9
        pslld     $30, %xmm12
        psrld     $2, %xmm5
        paddd     %xmm9, %xmm10
        paddd     784(%rsp), %xmm14
        por       %xmm5, %xmm12
        movdqa    %xmm7, %xmm5
        paddd     %xmm8, %xmm10
        pxor      %xmm2, %xmm5
        movdqa    %xmm14, %xmm9
        movdqa    %xmm14, %xmm3
        pxor      %xmm1, %xmm5
        paddd     640(%rsp), %xmm10
        pslld     $5, %xmm9
        psrld     $27, %xmm3
        movdqa    %xmm12, %xmm6
        paddd     %xmm5, %xmm15
        por       %xmm3, %xmm9
        pxor      %xmm11, %xmm6
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm3
        pxor      %xmm0, %xmm6
        pslld     $5, %xmm5
        psrld     $27, %xmm3
        paddd     %xmm6, %xmm13
        por       %xmm3, %xmm5
        paddd     %xmm5, %xmm13
        movdqa    %xmm1, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm1
        movdqa    %xmm0, %xmm3
        por       %xmm1, %xmm5
        pslld     $30, %xmm3
        psrld     $2, %xmm0
        paddd     %xmm9, %xmm15
        por       %xmm0, %xmm3
        movdqa    %xmm5, %xmm0
        paddd     %xmm8, %xmm15
        pxor      %xmm7, %xmm0
        paddd     %xmm8, %xmm13
        paddd     208(%rsp), %xmm15
        pxor      %xmm14, %xmm0
        paddd     %xmm0, %xmm2
        movdqa    %xmm15, %xmm0
        movdqa    %xmm15, %xmm1
        pslld     $5, %xmm0
        psrld     $27, %xmm1
        movdqa    %xmm3, %xmm9
        paddd     192(%rsp), %xmm13
        por       %xmm1, %xmm0
        paddd     %xmm0, %xmm2
        pxor      %xmm12, %xmm9
        movdqa    %xmm13, %xmm0
        movdqa    %xmm13, %xmm6
        pxor      %xmm10, %xmm9
        pslld     $5, %xmm0
        psrld     $27, %xmm6
        paddd     %xmm9, %xmm11
        por       %xmm6, %xmm0
        movdqa    %xmm14, %xmm1
        paddd     %xmm0, %xmm11
        pslld     $30, %xmm1
        psrld     $2, %xmm14
        movdqa    %xmm10, %xmm0
        paddd     %xmm8, %xmm2
        por       %xmm14, %xmm1
        pslld     $30, %xmm0
        psrld     $2, %xmm10
        paddd     272(%rsp), %xmm2
        por       %xmm10, %xmm0
        movdqa    %xmm1, %xmm10
        movdqa    %xmm2, %xmm9
        pxor      %xmm5, %xmm10
        movdqa    %xmm2, %xmm14
        paddd     %xmm8, %xmm11
        pxor      %xmm15, %xmm10
        pslld     $5, %xmm9
        psrld     $27, %xmm14
        paddd     240(%rsp), %xmm11
        paddd     %xmm10, %xmm7
        por       %xmm14, %xmm9
        movdqa    %xmm0, %xmm10
        paddd     %xmm9, %xmm7
        pxor      %xmm3, %xmm10
        movdqa    %xmm11, %xmm9
        movdqa    %xmm11, %xmm6
        pxor      %xmm13, %xmm10
        pslld     $5, %xmm9
        psrld     $27, %xmm6
        paddd     %xmm10, %xmm12
        por       %xmm6, %xmm9
        movdqa    %xmm15, %xmm10
        paddd     %xmm9, %xmm12
        pslld     $30, %xmm10
        psrld     $2, %xmm15
        movdqa    %xmm13, %xmm9
        paddd     %xmm8, %xmm7
        por       %xmm15, %xmm10
        pslld     $30, %xmm9
        psrld     $2, %xmm13
        paddd     560(%rsp), %xmm7
        por       %xmm13, %xmm9
        movdqa    %xmm10, %xmm13
        movdqa    %xmm7, %xmm6
        pxor      %xmm1, %xmm13
        movdqa    %xmm7, %xmm15
        paddd     %xmm8, %xmm12
        pxor      %xmm2, %xmm13
        pslld     $5, %xmm6
        psrld     $27, %xmm15
        paddd     544(%rsp), %xmm12
        paddd     %xmm13, %xmm5
        por       %xmm15, %xmm6
        movdqa    %xmm9, %xmm13
        paddd     %xmm6, %xmm5
        pxor      %xmm0, %xmm13
        movdqa    %xmm12, %xmm6
        movdqa    %xmm12, %xmm14
        pxor      %xmm11, %xmm13
        pslld     $5, %xmm6
        psrld     $27, %xmm14
        paddd     %xmm13, %xmm3
        por       %xmm14, %xmm6
        paddd     %xmm8, %xmm5
        paddd     %xmm6, %xmm3
        movdqa    %xmm2, %xmm6
        pslld     $30, %xmm6
        psrld     $2, %xmm2
        por       %xmm2, %xmm6
        movdqa    %xmm11, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        paddd     608(%rsp), %xmm5
        por       %xmm11, %xmm2
        movdqa    %xmm6, %xmm11
        paddd     %xmm8, %xmm3
        pxor      %xmm10, %xmm11
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm13
        pxor      %xmm7, %xmm11
        paddd     592(%rsp), %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        movdqa    %xmm2, %xmm15
        paddd     %xmm11, %xmm1
        por       %xmm13, %xmm14
        pxor      %xmm9, %xmm15
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm11
        pxor      %xmm12, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        paddd     %xmm15, %xmm0
        por       %xmm11, %xmm13
        paddd     %xmm13, %xmm0
        movdqa    %xmm7, %xmm13
        paddd     %xmm14, %xmm1
        pslld     $30, %xmm13
        psrld     $2, %xmm7
        movdqa    %xmm12, %xmm11
        paddd     %xmm8, %xmm1
        por       %xmm7, %xmm13
        pslld     $30, %xmm11
        psrld     $2, %xmm12
        paddd     816(%rsp), %xmm1
        por       %xmm12, %xmm11
        movdqa    %xmm13, %xmm12
        paddd     %xmm8, %xmm0
        pxor      %xmm6, %xmm12
        movdqa    %xmm1, %xmm14
        movdqa    %xmm1, %xmm7
        pxor      %xmm5, %xmm12
        paddd     800(%rsp), %xmm0
        pslld     $5, %xmm14
        psrld     $27, %xmm7
        movdqa    %xmm11, %xmm15
        paddd     %xmm12, %xmm10
        por       %xmm7, %xmm14
        pxor      %xmm2, %xmm15
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm7
        pxor      %xmm3, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        paddd     %xmm14, %xmm10
        paddd     %xmm15, %xmm9
        por       %xmm7, %xmm12
        paddd     %xmm8, %xmm10
        paddd     %xmm12, %xmm9
        paddd     176(%rsp), %xmm10
        paddd     %xmm8, %xmm9
..B9.13:
        movdqa    %xmm5, %xmm7
        psrld     $2, %xmm5
        pslld     $30, %xmm7
        movdqa    %xmm10, %xmm14
        por       %xmm5, %xmm7
        movdqa    %xmm3, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm3
        por       %xmm3, %xmm5
        movdqa    %xmm13, %xmm3
        pxor      %xmm7, %xmm3
        movdqa    %xmm10, %xmm12
        paddd     160(%rsp), %xmm9
        pxor      %xmm1, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        movdqa    %xmm11, %xmm15
        paddd     %xmm3, %xmm6
        por       %xmm12, %xmm14
        pxor      %xmm5, %xmm15
        movdqa    %xmm9, %xmm12
        movdqa    %xmm9, %xmm3
        pxor      %xmm0, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm3
        paddd     %xmm15, %xmm2
        por       %xmm3, %xmm12
        movdqa    %xmm0, %xmm3
        paddd     %xmm12, %xmm2
        movdqa    %xmm1, %xmm12
        pslld     $30, %xmm12
        psrld     $2, %xmm1
        por       %xmm1, %xmm12
        pslld     $30, %xmm3
        psrld     $2, %xmm0
        paddd     %xmm14, %xmm6
        por       %xmm0, %xmm3
        movdqa    %xmm12, %xmm0
        paddd     %xmm8, %xmm6
        pxor      %xmm7, %xmm0
        paddd     320(%rsp), %xmm6
        pxor      %xmm10, %xmm0
        paddd     %xmm0, %xmm13
        movdqa    %xmm6, %xmm0
        movdqa    %xmm6, %xmm1
        pslld     $5, %xmm0
        psrld     $27, %xmm1
        paddd     %xmm8, %xmm2
        por       %xmm1, %xmm0
        paddd     %xmm0, %xmm13
        paddd     %xmm8, %xmm13
        paddd     336(%rsp), %xmm2
        paddd     %xmm4, %xmm13
        movdqa    %xmm3, %xmm4
        movdqa    %xmm2, %xmm1
        pxor      %xmm5, %xmm4
        movdqa    %xmm2, %xmm0
        pxor      %xmm9, %xmm4
        pslld     $5, %xmm1
        psrld     $27, %xmm0
        paddd     %xmm4, %xmm11
        por       %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        paddd     %xmm1, %xmm11
        movdqa    %xmm10, %xmm1
        paddd     %xmm8, %xmm11
        pslld     $30, %xmm1
        psrld     $2, %xmm10
        pslld     $30, %xmm0
        psrld     $2, %xmm9
        por       %xmm10, %xmm1
        paddd     352(%rsp), %xmm11
        por       %xmm9, %xmm0
        je        ..B9.9
..B9.4:
        movdqa    (%rdx), %xmm4
        movdqa    16(%rdx), %xmm8
        paddd     %xmm4, %xmm13
        movdqa    32(%rdx), %xmm9
        paddd     %xmm8, %xmm6
        movdqa    48(%rdx), %xmm10
        paddd     %xmm9, %xmm1
        movdqa    64(%rdx), %xmm14
        paddd     %xmm10, %xmm12
        movdqa    80(%rdx), %xmm15
        paddd     %xmm14, %xmm7
        movdqa    96(%rdx), %xmm4
        paddd     %xmm15, %xmm11
        movdqa    112(%rdx), %xmm8
        paddd     %xmm4, %xmm2
        movdqa    128(%rdx), %xmm9
        paddd     %xmm8, %xmm0
        movdqa    144(%rdx), %xmm10
        paddd     %xmm9, %xmm3
        paddd     %xmm10, %xmm5
..B9.5:
        movdqa    %xmm13, (%rsi)
        testl     %ecx, %ecx
        movdqa    %xmm6, 16(%rsi)
        movdqa    %xmm1, 32(%rsi)
        movdqa    %xmm12, 48(%rsi)
        movdqa    %xmm7, 64(%rsi)
        je        ..B9.7
..B9.6:
        movdqa    %xmm11, 256(%rsi)
        movdqa    %xmm2, 272(%rsi)
        movdqa    %xmm0, 288(%rsi)
        movdqa    %xmm3, 304(%rsi)
        movdqa    %xmm5, 320(%rsi)
        addq      $904, %rsp
..___tag_value_SSESHA1body.221:
        ret       
..___tag_value_SSESHA1body.222:
..B9.7:
        movdqa    %xmm11, 80(%rsi)
        movdqa    %xmm2, 96(%rsi)
        movdqa    %xmm0, 112(%rsi)
        movdqa    %xmm3, 128(%rsi)
        movdqa    %xmm5, 144(%rsi)
..B9.8:
        addq      $904, %rsp
..___tag_value_SSESHA1body.223:
        ret       
..___tag_value_SSESHA1body.224:
..B9.9:
        movdqa    .L_2il0floatpacket.501(%rip), %xmm4
        movdqa    .L_2il0floatpacket.502(%rip), %xmm8
        paddd     %xmm4, %xmm13
        movdqa    .L_2il0floatpacket.503(%rip), %xmm9
        paddd     %xmm8, %xmm6
        movdqa    .L_2il0floatpacket.504(%rip), %xmm10
        paddd     %xmm9, %xmm1
        movdqa    .L_2il0floatpacket.505(%rip), %xmm14
        paddd     %xmm10, %xmm12
        paddd     %xmm14, %xmm7
        paddd     %xmm4, %xmm11
        paddd     %xmm8, %xmm2
        paddd     %xmm9, %xmm0
        paddd     %xmm10, %xmm3
        paddd     %xmm14, %xmm5
        jmp       ..B9.5
..B9.10:
        movdqa    .L_2il0floatpacket.501(%rip), %xmm2
        movdqa    .L_2il0floatpacket.502(%rip), %xmm1
        movdqa    %xmm2, %xmm13
        movdqa    .L_2il0floatpacket.503(%rip), %xmm6
        movdqa    %xmm1, %xmm8
        movdqa    .L_2il0floatpacket.504(%rip), %xmm4
        movdqa    %xmm6, %xmm12
        movdqa    .L_2il0floatpacket.505(%rip), %xmm11
        movdqa    %xmm4, %xmm5
        movdqa    %xmm11, %xmm3
        jmp       ..B9.3
        .align    16,0x90
..___tag_value_SSESHA1body.225:
	.type	SSESHA1body,@function
	.size	SSESHA1body,.-SSESHA1body
	.data
# -- End  SSESHA1body
	.bss
	.align 4
	.align 4
	.globl debug
debug:
	.type	debug,@object
	.size	debug,4
	.space 4	# pad
	.section .rodata, "a"
	.space 8, 0x00 	# pad
	.align 16
.L_2il0floatpacket.61:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.61,@object
	.size	.L_2il0floatpacket.61,16
	.align 16
.L_2il0floatpacket.62:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.62,@object
	.size	.L_2il0floatpacket.62,16
	.align 16
.L_2il0floatpacket.63:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.63,@object
	.size	.L_2il0floatpacket.63,16
	.align 16
.L_2il0floatpacket.64:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.64,@object
	.size	.L_2il0floatpacket.64,16
	.align 16
.L_2il0floatpacket.65:
	.long	0xd76aa478,0xd76aa478,0xd76aa478,0xd76aa478
	.type	.L_2il0floatpacket.65,@object
	.size	.L_2il0floatpacket.65,16
	.align 16
.L_2il0floatpacket.66:
	.long	0xe8c7b756,0xe8c7b756,0xe8c7b756,0xe8c7b756
	.type	.L_2il0floatpacket.66,@object
	.size	.L_2il0floatpacket.66,16
	.align 16
.L_2il0floatpacket.67:
	.long	0x242070db,0x242070db,0x242070db,0x242070db
	.type	.L_2il0floatpacket.67,@object
	.size	.L_2il0floatpacket.67,16
	.align 16
.L_2il0floatpacket.68:
	.long	0xc1bdceee,0xc1bdceee,0xc1bdceee,0xc1bdceee
	.type	.L_2il0floatpacket.68,@object
	.size	.L_2il0floatpacket.68,16
	.align 16
.L_2il0floatpacket.69:
	.long	0xf57c0faf,0xf57c0faf,0xf57c0faf,0xf57c0faf
	.type	.L_2il0floatpacket.69,@object
	.size	.L_2il0floatpacket.69,16
	.align 16
.L_2il0floatpacket.70:
	.long	0x4787c62a,0x4787c62a,0x4787c62a,0x4787c62a
	.type	.L_2il0floatpacket.70,@object
	.size	.L_2il0floatpacket.70,16
	.align 16
.L_2il0floatpacket.71:
	.long	0xa8304613,0xa8304613,0xa8304613,0xa8304613
	.type	.L_2il0floatpacket.71,@object
	.size	.L_2il0floatpacket.71,16
	.align 16
.L_2il0floatpacket.72:
	.long	0xfd469501,0xfd469501,0xfd469501,0xfd469501
	.type	.L_2il0floatpacket.72,@object
	.size	.L_2il0floatpacket.72,16
	.align 16
.L_2il0floatpacket.73:
	.long	0x698098d8,0x698098d8,0x698098d8,0x698098d8
	.type	.L_2il0floatpacket.73,@object
	.size	.L_2il0floatpacket.73,16
	.align 16
.L_2il0floatpacket.74:
	.long	0x8b44f7af,0x8b44f7af,0x8b44f7af,0x8b44f7af
	.type	.L_2il0floatpacket.74,@object
	.size	.L_2il0floatpacket.74,16
	.align 16
.L_2il0floatpacket.75:
	.long	0xffff5bb1,0xffff5bb1,0xffff5bb1,0xffff5bb1
	.type	.L_2il0floatpacket.75,@object
	.size	.L_2il0floatpacket.75,16
	.align 16
.L_2il0floatpacket.76:
	.long	0x895cd7be,0x895cd7be,0x895cd7be,0x895cd7be
	.type	.L_2il0floatpacket.76,@object
	.size	.L_2il0floatpacket.76,16
	.align 16
.L_2il0floatpacket.77:
	.long	0x6b901122,0x6b901122,0x6b901122,0x6b901122
	.type	.L_2il0floatpacket.77,@object
	.size	.L_2il0floatpacket.77,16
	.align 16
.L_2il0floatpacket.78:
	.long	0xfd987193,0xfd987193,0xfd987193,0xfd987193
	.type	.L_2il0floatpacket.78,@object
	.size	.L_2il0floatpacket.78,16
	.align 16
.L_2il0floatpacket.79:
	.long	0xa679438e,0xa679438e,0xa679438e,0xa679438e
	.type	.L_2il0floatpacket.79,@object
	.size	.L_2il0floatpacket.79,16
	.align 16
.L_2il0floatpacket.80:
	.long	0x49b40821,0x49b40821,0x49b40821,0x49b40821
	.type	.L_2il0floatpacket.80,@object
	.size	.L_2il0floatpacket.80,16
	.align 16
.L_2il0floatpacket.81:
	.long	0xf61e2562,0xf61e2562,0xf61e2562,0xf61e2562
	.type	.L_2il0floatpacket.81,@object
	.size	.L_2il0floatpacket.81,16
	.align 16
.L_2il0floatpacket.82:
	.long	0xc040b340,0xc040b340,0xc040b340,0xc040b340
	.type	.L_2il0floatpacket.82,@object
	.size	.L_2il0floatpacket.82,16
	.align 16
.L_2il0floatpacket.83:
	.long	0x265e5a51,0x265e5a51,0x265e5a51,0x265e5a51
	.type	.L_2il0floatpacket.83,@object
	.size	.L_2il0floatpacket.83,16
	.align 16
.L_2il0floatpacket.84:
	.long	0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa,0xe9b6c7aa
	.type	.L_2il0floatpacket.84,@object
	.size	.L_2il0floatpacket.84,16
	.align 16
.L_2il0floatpacket.85:
	.long	0xd62f105d,0xd62f105d,0xd62f105d,0xd62f105d
	.type	.L_2il0floatpacket.85,@object
	.size	.L_2il0floatpacket.85,16
	.align 16
.L_2il0floatpacket.86:
	.long	0x02441453,0x02441453,0x02441453,0x02441453
	.type	.L_2il0floatpacket.86,@object
	.size	.L_2il0floatpacket.86,16
	.align 16
.L_2il0floatpacket.87:
	.long	0xd8a1e681,0xd8a1e681,0xd8a1e681,0xd8a1e681
	.type	.L_2il0floatpacket.87,@object
	.size	.L_2il0floatpacket.87,16
	.align 16
.L_2il0floatpacket.88:
	.long	0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8,0xe7d3fbc8
	.type	.L_2il0floatpacket.88,@object
	.size	.L_2il0floatpacket.88,16
	.align 16
.L_2il0floatpacket.89:
	.long	0x21e1cde6,0x21e1cde6,0x21e1cde6,0x21e1cde6
	.type	.L_2il0floatpacket.89,@object
	.size	.L_2il0floatpacket.89,16
	.align 16
.L_2il0floatpacket.90:
	.long	0xc33707d6,0xc33707d6,0xc33707d6,0xc33707d6
	.type	.L_2il0floatpacket.90,@object
	.size	.L_2il0floatpacket.90,16
	.align 16
.L_2il0floatpacket.91:
	.long	0xf4d50d87,0xf4d50d87,0xf4d50d87,0xf4d50d87
	.type	.L_2il0floatpacket.91,@object
	.size	.L_2il0floatpacket.91,16
	.align 16
.L_2il0floatpacket.92:
	.long	0x455a14ed,0x455a14ed,0x455a14ed,0x455a14ed
	.type	.L_2il0floatpacket.92,@object
	.size	.L_2il0floatpacket.92,16
	.align 16
.L_2il0floatpacket.93:
	.long	0xa9e3e905,0xa9e3e905,0xa9e3e905,0xa9e3e905
	.type	.L_2il0floatpacket.93,@object
	.size	.L_2il0floatpacket.93,16
	.align 16
.L_2il0floatpacket.94:
	.long	0xfcefa3f8,0xfcefa3f8,0xfcefa3f8,0xfcefa3f8
	.type	.L_2il0floatpacket.94,@object
	.size	.L_2il0floatpacket.94,16
	.align 16
.L_2il0floatpacket.95:
	.long	0x676f02d9,0x676f02d9,0x676f02d9,0x676f02d9
	.type	.L_2il0floatpacket.95,@object
	.size	.L_2il0floatpacket.95,16
	.align 16
.L_2il0floatpacket.96:
	.long	0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a,0x8d2a4c8a
	.type	.L_2il0floatpacket.96,@object
	.size	.L_2il0floatpacket.96,16
	.align 16
.L_2il0floatpacket.97:
	.long	0xfffa3942,0xfffa3942,0xfffa3942,0xfffa3942
	.type	.L_2il0floatpacket.97,@object
	.size	.L_2il0floatpacket.97,16
	.align 16
.L_2il0floatpacket.98:
	.long	0x8771f681,0x8771f681,0x8771f681,0x8771f681
	.type	.L_2il0floatpacket.98,@object
	.size	.L_2il0floatpacket.98,16
	.align 16
.L_2il0floatpacket.99:
	.long	0x6d9d6122,0x6d9d6122,0x6d9d6122,0x6d9d6122
	.type	.L_2il0floatpacket.99,@object
	.size	.L_2il0floatpacket.99,16
	.align 16
.L_2il0floatpacket.100:
	.long	0xfde5380c,0xfde5380c,0xfde5380c,0xfde5380c
	.type	.L_2il0floatpacket.100,@object
	.size	.L_2il0floatpacket.100,16
	.align 16
.L_2il0floatpacket.101:
	.long	0xa4beea44,0xa4beea44,0xa4beea44,0xa4beea44
	.type	.L_2il0floatpacket.101,@object
	.size	.L_2il0floatpacket.101,16
	.align 16
.L_2il0floatpacket.102:
	.long	0x4bdecfa9,0x4bdecfa9,0x4bdecfa9,0x4bdecfa9
	.type	.L_2il0floatpacket.102,@object
	.size	.L_2il0floatpacket.102,16
	.align 16
.L_2il0floatpacket.103:
	.long	0xf6bb4b60,0xf6bb4b60,0xf6bb4b60,0xf6bb4b60
	.type	.L_2il0floatpacket.103,@object
	.size	.L_2il0floatpacket.103,16
	.align 16
.L_2il0floatpacket.104:
	.long	0xbebfbc70,0xbebfbc70,0xbebfbc70,0xbebfbc70
	.type	.L_2il0floatpacket.104,@object
	.size	.L_2il0floatpacket.104,16
	.align 16
.L_2il0floatpacket.105:
	.long	0x289b7ec6,0x289b7ec6,0x289b7ec6,0x289b7ec6
	.type	.L_2il0floatpacket.105,@object
	.size	.L_2il0floatpacket.105,16
	.align 16
.L_2il0floatpacket.106:
	.long	0xeaa127fa,0xeaa127fa,0xeaa127fa,0xeaa127fa
	.type	.L_2il0floatpacket.106,@object
	.size	.L_2il0floatpacket.106,16
	.align 16
.L_2il0floatpacket.107:
	.long	0xd4ef3085,0xd4ef3085,0xd4ef3085,0xd4ef3085
	.type	.L_2il0floatpacket.107,@object
	.size	.L_2il0floatpacket.107,16
	.align 16
.L_2il0floatpacket.108:
	.long	0x04881d05,0x04881d05,0x04881d05,0x04881d05
	.type	.L_2il0floatpacket.108,@object
	.size	.L_2il0floatpacket.108,16
	.align 16
.L_2il0floatpacket.109:
	.long	0xd9d4d039,0xd9d4d039,0xd9d4d039,0xd9d4d039
	.type	.L_2il0floatpacket.109,@object
	.size	.L_2il0floatpacket.109,16
	.align 16
.L_2il0floatpacket.110:
	.long	0xe6db99e5,0xe6db99e5,0xe6db99e5,0xe6db99e5
	.type	.L_2il0floatpacket.110,@object
	.size	.L_2il0floatpacket.110,16
	.align 16
.L_2il0floatpacket.111:
	.long	0x1fa27cf8,0x1fa27cf8,0x1fa27cf8,0x1fa27cf8
	.type	.L_2il0floatpacket.111,@object
	.size	.L_2il0floatpacket.111,16
	.align 16
.L_2il0floatpacket.112:
	.long	0xc4ac5665,0xc4ac5665,0xc4ac5665,0xc4ac5665
	.type	.L_2il0floatpacket.112,@object
	.size	.L_2il0floatpacket.112,16
	.align 16
.L_2il0floatpacket.113:
	.long	0xf4292244,0xf4292244,0xf4292244,0xf4292244
	.type	.L_2il0floatpacket.113,@object
	.size	.L_2il0floatpacket.113,16
	.align 16
.L_2il0floatpacket.114:
	.long	0x432aff97,0x432aff97,0x432aff97,0x432aff97
	.type	.L_2il0floatpacket.114,@object
	.size	.L_2il0floatpacket.114,16
	.align 16
.L_2il0floatpacket.115:
	.long	0xab9423a7,0xab9423a7,0xab9423a7,0xab9423a7
	.type	.L_2il0floatpacket.115,@object
	.size	.L_2il0floatpacket.115,16
	.align 16
.L_2il0floatpacket.116:
	.long	0xfc93a039,0xfc93a039,0xfc93a039,0xfc93a039
	.type	.L_2il0floatpacket.116,@object
	.size	.L_2il0floatpacket.116,16
	.align 16
.L_2il0floatpacket.117:
	.long	0x655b59c3,0x655b59c3,0x655b59c3,0x655b59c3
	.type	.L_2il0floatpacket.117,@object
	.size	.L_2il0floatpacket.117,16
	.align 16
.L_2il0floatpacket.118:
	.long	0x8f0ccc92,0x8f0ccc92,0x8f0ccc92,0x8f0ccc92
	.type	.L_2il0floatpacket.118,@object
	.size	.L_2il0floatpacket.118,16
	.align 16
.L_2il0floatpacket.119:
	.long	0xffeff47d,0xffeff47d,0xffeff47d,0xffeff47d
	.type	.L_2il0floatpacket.119,@object
	.size	.L_2il0floatpacket.119,16
	.align 16
.L_2il0floatpacket.120:
	.long	0x85845dd1,0x85845dd1,0x85845dd1,0x85845dd1
	.type	.L_2il0floatpacket.120,@object
	.size	.L_2il0floatpacket.120,16
	.align 16
.L_2il0floatpacket.121:
	.long	0x6fa87e4f,0x6fa87e4f,0x6fa87e4f,0x6fa87e4f
	.type	.L_2il0floatpacket.121,@object
	.size	.L_2il0floatpacket.121,16
	.align 16
.L_2il0floatpacket.122:
	.long	0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0,0xfe2ce6e0
	.type	.L_2il0floatpacket.122,@object
	.size	.L_2il0floatpacket.122,16
	.align 16
.L_2il0floatpacket.123:
	.long	0xa3014314,0xa3014314,0xa3014314,0xa3014314
	.type	.L_2il0floatpacket.123,@object
	.size	.L_2il0floatpacket.123,16
	.align 16
.L_2il0floatpacket.124:
	.long	0x4e0811a1,0x4e0811a1,0x4e0811a1,0x4e0811a1
	.type	.L_2il0floatpacket.124,@object
	.size	.L_2il0floatpacket.124,16
	.align 16
.L_2il0floatpacket.125:
	.long	0xf7537e82,0xf7537e82,0xf7537e82,0xf7537e82
	.type	.L_2il0floatpacket.125,@object
	.size	.L_2il0floatpacket.125,16
	.align 16
.L_2il0floatpacket.126:
	.long	0xbd3af235,0xbd3af235,0xbd3af235,0xbd3af235
	.type	.L_2il0floatpacket.126,@object
	.size	.L_2il0floatpacket.126,16
	.align 16
.L_2il0floatpacket.127:
	.long	0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb,0x2ad7d2bb
	.type	.L_2il0floatpacket.127,@object
	.size	.L_2il0floatpacket.127,16
	.align 16
.L_2il0floatpacket.128:
	.long	0xeb86d391,0xeb86d391,0xeb86d391,0xeb86d391
	.type	.L_2il0floatpacket.128,@object
	.size	.L_2il0floatpacket.128,16
	.align 16
.L_2il0floatpacket.129:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.129,@object
	.size	.L_2il0floatpacket.129,16
	.align 16
.L_2il0floatpacket.475:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.475,@object
	.size	.L_2il0floatpacket.475,16
	.align 16
.L_2il0floatpacket.476:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.476,@object
	.size	.L_2il0floatpacket.476,16
	.align 16
.L_2il0floatpacket.477:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.477,@object
	.size	.L_2il0floatpacket.477,16
	.align 16
.L_2il0floatpacket.478:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.478,@object
	.size	.L_2il0floatpacket.478,16
	.align 16
.L_2il0floatpacket.479:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.479,@object
	.size	.L_2il0floatpacket.479,16
	.align 16
.L_2il0floatpacket.480:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.480,@object
	.size	.L_2il0floatpacket.480,16
	.align 16
.L_2il0floatpacket.501:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.501,@object
	.size	.L_2il0floatpacket.501,16
	.align 16
.L_2il0floatpacket.502:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.502,@object
	.size	.L_2il0floatpacket.502,16
	.align 16
.L_2il0floatpacket.503:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.503,@object
	.size	.L_2il0floatpacket.503,16
	.align 16
.L_2il0floatpacket.504:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.504,@object
	.size	.L_2il0floatpacket.504,16
	.align 16
.L_2il0floatpacket.505:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.505,@object
	.size	.L_2il0floatpacket.505,16
	.align 16
.L_2il0floatpacket.506:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.506,@object
	.size	.L_2il0floatpacket.506,16
	.align 16
.L_2il0floatpacket.507:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.507,@object
	.size	.L_2il0floatpacket.507,16
	.align 16
.L_2il0floatpacket.508:
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.type	.L_2il0floatpacket.508,@object
	.size	.L_2il0floatpacket.508,16
	.align 16
.L_2il0floatpacket.509:
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	.type	.L_2il0floatpacket.509,@object
	.size	.L_2il0floatpacket.509,16
	.align 4
.L_2__STRING.3:
	.byte	0
	.byte	0
	.type	.L_2__STRING.3,@object
	.size	.L_2__STRING.3,2
	.section .rodata.str1.4, "aMS",@progbits,1
	.align 4
	.align 4
.L_2__STRING.2:
	.byte	36
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.2,@object
	.size	.L_2__STRING.2,4
	.align 4
.L_2__STRING.1:
	.byte	36
	.byte	97
	.byte	112
	.byte	114
	.byte	49
	.byte	36
	.byte	0
	.type	.L_2__STRING.1,@object
	.size	.L_2__STRING.1,7
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 8
	.4byte 0x00000014
	.8byte 0x7801000100000000
	.8byte 0x0000019008070c10
	.4byte 0x00000000
	.4byte 0x00000014
	.4byte 0x0000001c
	.8byte ..___tag_value_sse_debug.1
	.8byte ..___tag_value_sse_debug.3-..___tag_value_sse_debug.1
	.4byte 0x0000003c
	.4byte 0x00000034
	.8byte ..___tag_value_mmxput.4
	.8byte ..___tag_value_mmxput.12-..___tag_value_mmxput.4
	.byte 0x04
	.4byte ..___tag_value_mmxput.6-..___tag_value_mmxput.4
	.2byte 0x048f
	.byte 0x04
	.4byte ..___tag_value_mmxput.7-..___tag_value_mmxput.6
	.2byte 0x0383
	.byte 0x04
	.4byte ..___tag_value_mmxput.8-..___tag_value_mmxput.7
	.2byte 0x0286
	.byte 0x04
	.4byte ..___tag_value_mmxput.9-..___tag_value_mmxput.8
	.2byte 0x04cf
	.4byte ..___tag_value_mmxput.10-..___tag_value_mmxput.9
	.2byte 0x04c3
	.4byte ..___tag_value_mmxput.11-..___tag_value_mmxput.10
	.2byte 0x00c6
	.4byte 0x00000074
	.4byte 0x00000074
	.8byte ..___tag_value_mmxput2.13
	.8byte ..___tag_value_mmxput2.37-..___tag_value_mmxput2.13
	.byte 0x04
	.4byte ..___tag_value_mmxput2.15-..___tag_value_mmxput2.13
	.4byte 0x100e028c
	.byte 0x04
	.4byte ..___tag_value_mmxput2.17-..___tag_value_mmxput2.15
	.4byte 0x180e038d
	.byte 0x04
	.4byte ..___tag_value_mmxput2.19-..___tag_value_mmxput2.17
	.4byte 0x200e048e
	.byte 0x04
	.4byte ..___tag_value_mmxput2.21-..___tag_value_mmxput2.19
	.4byte 0x280e058f
	.byte 0x04
	.4byte ..___tag_value_mmxput2.23-..___tag_value_mmxput2.21
	.4byte 0x300e0683
	.byte 0x04
	.4byte ..___tag_value_mmxput2.27-..___tag_value_mmxput2.23
	.2byte 0x04c3
	.4byte ..___tag_value_mmxput2.28-..___tag_value_mmxput2.27
	.4byte 0x04cf280e
	.4byte ..___tag_value_mmxput2.30-..___tag_value_mmxput2.28
	.4byte 0x04ce200e
	.4byte ..___tag_value_mmxput2.32-..___tag_value_mmxput2.30
	.4byte 0x04cd180e
	.4byte ..___tag_value_mmxput2.34-..___tag_value_mmxput2.32
	.4byte 0x04cc100e
	.4byte ..___tag_value_mmxput2.36-..___tag_value_mmxput2.34
	.8byte 0x000000000000080e
	.4byte 0x0000008c
	.4byte 0x000000ec
	.8byte ..___tag_value_dispatch.38
	.8byte ..___tag_value_dispatch.84-..___tag_value_dispatch.38
	.byte 0x04
	.4byte ..___tag_value_dispatch.40-..___tag_value_dispatch.38
	.4byte 0x100e028c
	.byte 0x04
	.4byte ..___tag_value_dispatch.42-..___tag_value_dispatch.40
	.4byte 0x180e038d
	.byte 0x04
	.4byte ..___tag_value_dispatch.44-..___tag_value_dispatch.42
	.4byte 0x200e048e
	.byte 0x04
	.4byte ..___tag_value_dispatch.46-..___tag_value_dispatch.44
	.4byte 0x280e058f
	.byte 0x04
	.4byte ..___tag_value_dispatch.48-..___tag_value_dispatch.46
	.4byte 0x300e0683
	.byte 0x04
	.4byte ..___tag_value_dispatch.50-..___tag_value_dispatch.48
	.4byte 0x380e0786
	.byte 0x04
	.4byte ..___tag_value_dispatch.52-..___tag_value_dispatch.50
	.2byte 0x600e
	.byte 0x04
	.4byte ..___tag_value_dispatch.71-..___tag_value_dispatch.52
	.4byte 0x04c6380e
	.4byte ..___tag_value_dispatch.73-..___tag_value_dispatch.71
	.4byte 0x04c3300e
	.4byte ..___tag_value_dispatch.75-..___tag_value_dispatch.73
	.4byte 0x04cf280e
	.4byte ..___tag_value_dispatch.77-..___tag_value_dispatch.75
	.4byte 0x04ce200e
	.4byte ..___tag_value_dispatch.79-..___tag_value_dispatch.77
	.4byte 0x04cd180e
	.4byte ..___tag_value_dispatch.81-..___tag_value_dispatch.79
	.4byte 0x04cc100e
	.4byte ..___tag_value_dispatch.83-..___tag_value_dispatch.81
	.4byte 0x0000080e
	.2byte 0x0000
	.4byte 0x00000084
	.4byte 0x0000017c
	.8byte ..___tag_value_mmxput3.85
	.8byte ..___tag_value_mmxput3.111-..___tag_value_mmxput3.85
	.byte 0x04
	.4byte ..___tag_value_mmxput3.87-..___tag_value_mmxput3.85
	.4byte 0x100e028c
	.byte 0x04
	.4byte ..___tag_value_mmxput3.89-..___tag_value_mmxput3.87
	.4byte 0x180e038d
	.byte 0x04
	.4byte ..___tag_value_mmxput3.91-..___tag_value_mmxput3.89
	.4byte 0x200e048e
	.byte 0x04
	.4byte ..___tag_value_mmxput3.93-..___tag_value_mmxput3.91
	.4byte 0x280e058f
	.byte 0x04
	.4byte ..___tag_value_mmxput3.95-..___tag_value_mmxput3.93
	.4byte 0x300e0683
	.byte 0x04
	.4byte ..___tag_value_mmxput3.97-..___tag_value_mmxput3.95
	.4byte 0x380e0786
	.byte 0x04
	.4byte ..___tag_value_mmxput3.99-..___tag_value_mmxput3.97
	.2byte 0x04c6
	.4byte ..___tag_value_mmxput3.100-..___tag_value_mmxput3.99
	.4byte 0x04c3300e
	.4byte ..___tag_value_mmxput3.102-..___tag_value_mmxput3.100
	.4byte 0x04cf280e
	.4byte ..___tag_value_mmxput3.104-..___tag_value_mmxput3.102
	.4byte 0x04ce200e
	.4byte ..___tag_value_mmxput3.106-..___tag_value_mmxput3.104
	.4byte 0x04cd180e
	.4byte ..___tag_value_mmxput3.108-..___tag_value_mmxput3.106
	.4byte 0x04cc100e
	.4byte ..___tag_value_mmxput3.110-..___tag_value_mmxput3.108
	.4byte 0x0000080e
	.2byte 0x0000
	.byte 0x00
	.4byte 0x00000034
	.4byte 0x00000204
	.8byte ..___tag_value_SSEmd5body.112
	.8byte ..___tag_value_SSEmd5body.118-..___tag_value_SSEmd5body.112
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.114-..___tag_value_SSEmd5body.112
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd5body.115-..___tag_value_SSEmd5body.114
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.116-..___tag_value_SSEmd5body.115
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd5body.117-..___tag_value_SSEmd5body.116
	.4byte 0x0000080e
	.4byte 0x000000a4
	.4byte 0x0000023c
	.8byte ..___tag_value_md5cryptsse.119
	.8byte ..___tag_value_md5cryptsse.210-..___tag_value_md5cryptsse.119
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.121-..___tag_value_md5cryptsse.119
	.4byte 0x100e028c
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.123-..___tag_value_md5cryptsse.121
	.4byte 0x180e038d
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.125-..___tag_value_md5cryptsse.123
	.4byte 0x200e048e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.127-..___tag_value_md5cryptsse.125
	.4byte 0x280e058f
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.129-..___tag_value_md5cryptsse.127
	.4byte 0x300e0683
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.131-..___tag_value_md5cryptsse.129
	.4byte 0x380e0786
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.133-..___tag_value_md5cryptsse.131
	.4byte 0x0435d00e
	.4byte ..___tag_value_md5cryptsse.188-..___tag_value_md5cryptsse.133
	.4byte 0x04c6380e
	.4byte ..___tag_value_md5cryptsse.190-..___tag_value_md5cryptsse.188
	.4byte 0x04c3300e
	.4byte ..___tag_value_md5cryptsse.192-..___tag_value_md5cryptsse.190
	.4byte 0x04cf280e
	.4byte ..___tag_value_md5cryptsse.194-..___tag_value_md5cryptsse.192
	.4byte 0x04ce200e
	.4byte ..___tag_value_md5cryptsse.196-..___tag_value_md5cryptsse.194
	.4byte 0x04cd180e
	.4byte ..___tag_value_md5cryptsse.198-..___tag_value_md5cryptsse.196
	.4byte 0x04cc100e
	.4byte ..___tag_value_md5cryptsse.200-..___tag_value_md5cryptsse.198
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.201-..___tag_value_md5cryptsse.200
	.8byte 0x8c0786068335d00e
	.8byte 0x00058f048e038d02
	.4byte 0x00000000
	.2byte 0x0000
	.4byte 0x00000034
	.4byte 0x000002e4
	.8byte ..___tag_value_SSEmd4body.211
	.8byte ..___tag_value_SSEmd4body.217-..___tag_value_SSEmd4body.211
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.213-..___tag_value_SSEmd4body.211
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd4body.214-..___tag_value_SSEmd4body.213
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.215-..___tag_value_SSEmd4body.214
	.4byte 0x0406d00e
	.4byte ..___tag_value_SSEmd4body.216-..___tag_value_SSEmd4body.215
	.4byte 0x0000080e
	.4byte 0x0000003c
	.4byte 0x0000031c
	.8byte ..___tag_value_SSESHA1body.218
	.8byte ..___tag_value_SSESHA1body.225-..___tag_value_SSESHA1body.218
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.220-..___tag_value_SSESHA1body.218
	.4byte 0x0407900e
	.4byte ..___tag_value_SSESHA1body.221-..___tag_value_SSESHA1body.220
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.222-..___tag_value_SSESHA1body.221
	.4byte 0x0407900e
	.4byte ..___tag_value_SSESHA1body.223-..___tag_value_SSESHA1body.222
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_SSESHA1body.224-..___tag_value_SSESHA1body.223
	.4byte 0x0007900e
	.byte 0x00
# End
