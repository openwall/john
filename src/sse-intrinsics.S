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
        subq      $24, %rsp
..___tag_value_dispatch.52:
        xorl      %eax, %eax
        movl      %eax, %r13d
        movq      %rdx, %r15
        movl      %ecx, %r14d
        movq      %rsi, %r12
        movq      %rdi, %rbx
..B4.2:
        movl      %r13d, %ebp
        movl      $818089009, %eax
        shrl      $1, %ebp
        mull      %ebp
        shrl      $2, %edx
        imull     $42, %edx, %ebp
        negl      %ebp
        addl      %r13d, %ebp
        cmpl      $40, %ebp
        ja        ..B4.54
..B4.3:
        jmp       *..1..TPKT.6_0.0.6(,%rbp,8)
..1.6_0.TAG.015.0.6:
..B4.19:
        movl      $1, %esi
        movq      %rbx, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %r12, %r9
        movl      $1, %ebp
..___tag_value_dispatch.53:
        call      mmxput3
..___tag_value_dispatch.54:
        jmp       ..B4.55
..1.6_0.TAG.01c.0.6:
..1.6_0.TAG.0e.0.6:
..B4.25:
        xorl      %ecx, %ecx
        movl      $5, %ebp
        movl      %r13d, (%rsp)
        movl      %ecx, %r13d
        movq      %r15, 8(%rsp)
        movl      %ecx, %r15d
        movl      %r14d, 16(%rsp)
        movl      %ecx, %r14d
..B4.26:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r12, %rsi
        lea       3840(%rbx,%r13), %rdi
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
        movl      (%rsp), %r13d
        movq      8(%rsp), %r15
        movl      16(%rsp), %r14d
        jmp       ..B4.55
..1.6_0.TAG.023.0.6:
..1.6_0.TAG.07.0.6:
..B4.34:
        movq      %rbx, %rdi
        movl      $4, %esi
        movq      %r15, %rdx
        movl      $1, %ecx
        movl      %r14d, %r8d
        movq      %r12, %r9
        movl      $4, %ebp
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
        movl      $3, %ebp
        movl      %r13d, (%rsp)
        movl      %ecx, %r13d
        movq      %r15, 8(%rsp)
        movl      %ecx, %r15d
        movl      %r14d, 16(%rsp)
        movl      %ecx, %r14d
..B4.37:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r12, %rsi
        lea       2304(%rbx,%r13), %rdi
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
        movl      (%rsp), %r13d
        movq      8(%rsp), %r15
        movl      16(%rsp), %r14d
        jmp       ..B4.55
..1.6_0.TAG.027.0.6:
..1.6_0.TAG.021.0.6:
..1.6_0.TAG.01b.0.6:
..1.6_0.TAG.0f.0.6:
..1.6_0.TAG.09.0.6:
..1.6_0.TAG.03.0.6:
..B4.42:
        movl      $2, %esi
        movq      %rbx, %rdi
        movq      %r15, %rdx
        movl      %esi, %ecx
        xorl      %r8d, %r8d
        movq      %r12, %r9
        movl      $2, %ebp
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
        movl      $6, %ebp
        movl      %r13d, (%rsp)
        movl      %ecx, %r13d
        movq      %r15, 8(%rsp)
        movl      %ecx, %r15d
        movl      %r14d, 16(%rsp)
        movl      %ecx, %r14d
..B4.45:
        movl      $64, %edx
        movl      %r14d, %esi
        addq      %r12, %rsi
        lea       4608(%rbx,%r13), %rdi
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
        movl      (%rsp), %r13d
        movq      8(%rsp), %r15
        movl      16(%rsp), %r14d
        jmp       ..B4.55
..1.6_0.TAG.00.0.6:
..B4.50:
        xorl      %ecx, %ecx
        xorl      %ebp, %ebp
        movl      %r13d, (%rsp)
        movl      %ecx, %r13d
        movq      %r15, 8(%rsp)
        movl      %ecx, %r15d
        movl      %r14d, 16(%rsp)
        movl      %ecx, %r14d
..B4.51:
        movl      %r14d, %edi
        movl      $64, %edx
        movl      %r15d, %esi
        addq      %rbx, %rdi
        addq      %r12, %rsi
..___tag_value_dispatch.65:
        call      memcpy
..___tag_value_dispatch.66:
..B4.52:
        incl      %r13d
        addl      $64, %r15d
        addl      $256, %r14d
        cmpl      $3, %r13d
        jb        ..B4.51
..B4.53:
        movl      (%rsp), %r13d
        movq      8(%rsp), %r15
        movl      16(%rsp), %r14d
        jmp       ..B4.55
..1.6_0.TAG.DEFAULT.0.6:
..B4.54:
        movq      %rbx, %rdi
        movl      $7, %esi
        movq      %r15, %rdx
        movl      $2, %ecx
        movl      %r14d, %r8d
        movq      %r12, %r9
        movl      $7, %ebp
..___tag_value_dispatch.67:
        call      mmxput3
..___tag_value_dispatch.68:
..B4.55:
        movq      %r12, %rsi
        lea       (%rbp,%rbp,2), %rdi
        shlq      $8, %rdi
        movl      $1, %edx
        addq      %rbx, %rdi
..___tag_value_dispatch.69:
        call      SSEmd5body
..___tag_value_dispatch.70:
..B4.56:
        incl      %r13d
        cmpl      $1000, %r13d
        jb        ..B4.2
..B4.57:
        addq      $24, %rsp
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
        subq      $776, %rsp
..___tag_value_SSEmd5body.114:
        testl     %edx, %edx
        je        ..B6.3
..B6.2:
        movdqa    .L_2il0floatpacket.61(%rip), %xmm1
        movdqa    .L_2il0floatpacket.62(%rip), %xmm15
        movdqa    %xmm1, %xmm11
        movdqa    .L_2il0floatpacket.63(%rip), %xmm10
        movdqa    %xmm15, %xmm9
        movdqa    .L_2il0floatpacket.64(%rip), %xmm3
        movdqa    %xmm10, %xmm2
        movdqa    %xmm3, %xmm5
        movdqa    %xmm1, %xmm13
        movdqa    %xmm15, %xmm0
        movdqa    %xmm10, %xmm4
        movdqa    %xmm3, %xmm6
        jmp       ..B6.4
..B6.3:
        movdqa    (%rsi), %xmm1
        movdqa    16(%rsi), %xmm15
        movdqa    32(%rsi), %xmm10
        movdqa    48(%rsi), %xmm3
        movdqa    64(%rsi), %xmm11
        movdqa    80(%rsi), %xmm9
        movdqa    96(%rsi), %xmm2
        movdqa    112(%rsi), %xmm5
        movdqa    128(%rsi), %xmm13
        movdqa    144(%rsi), %xmm0
        movdqa    160(%rsi), %xmm4
        movdqa    176(%rsi), %xmm6
..B6.4:
        movdqa    %xmm10, %xmm8
        movdqa    %xmm2, %xmm14
        pxor      %xmm3, %xmm8
        pxor      %xmm5, %xmm14
        movdqa    .L_2il0floatpacket.65(%rip), %xmm12
        pand      %xmm15, %xmm8
        paddd     %xmm12, %xmm1
        pxor      %xmm3, %xmm8
        movdqa    (%rdi), %xmm7
        paddd     %xmm8, %xmm1
        movdqa    %xmm7, 704(%rsp)
        paddd     %xmm7, %xmm1
        movdqa    %xmm4, %xmm7
        pand      %xmm9, %xmm14
        pxor      %xmm6, %xmm7
        paddd     %xmm12, %xmm11
        pand      %xmm0, %xmm7
        pxor      %xmm5, %xmm14
        paddd     %xmm12, %xmm13
        pxor      %xmm6, %xmm7
        paddd     %xmm14, %xmm11
        paddd     %xmm7, %xmm13
        movdqa    512(%rdi), %xmm14
        movdqa    256(%rdi), %xmm8
        paddd     %xmm14, %xmm13
        movdqa    %xmm8, 688(%rsp)
        paddd     %xmm8, %xmm11
        movdqa    %xmm14, 384(%rsp)
        movdqa    %xmm1, %xmm8
        movdqa    %xmm13, %xmm14
        pslld     $7, %xmm8
        psrld     $25, %xmm1
        pslld     $7, %xmm14
        psrld     $25, %xmm13
        por       %xmm1, %xmm8
        movdqa    %xmm11, %xmm7
        por       %xmm13, %xmm14
        movdqa    %xmm15, %xmm13
        paddd     %xmm15, %xmm8
        pslld     $7, %xmm7
        psrld     $25, %xmm11
        pxor      %xmm10, %xmm13
        por       %xmm11, %xmm7
        movdqa    .L_2il0floatpacket.66(%rip), %xmm11
        pand      %xmm8, %xmm13
        paddd     %xmm11, %xmm3
        pxor      %xmm10, %xmm13
        paddd     %xmm13, %xmm3
        paddd     %xmm11, %xmm5
        movdqa    %xmm9, %xmm13
        paddd     %xmm11, %xmm6
        movdqa    %xmm0, %xmm11
        paddd     %xmm9, %xmm7
        paddd     %xmm0, %xmm14
        pxor      %xmm2, %xmm13
        pxor      %xmm4, %xmm11
        pand      %xmm7, %xmm13
        pand      %xmm14, %xmm11
        pxor      %xmm2, %xmm13
        pxor      %xmm4, %xmm11
        paddd     %xmm13, %xmm5
        movdqa    16(%rdi), %xmm1
        paddd     %xmm11, %xmm6
        movdqa    272(%rdi), %xmm12
        paddd     %xmm1, %xmm3
        movdqa    528(%rdi), %xmm13
        paddd     %xmm12, %xmm5
        paddd     %xmm13, %xmm6
        movdqa    %xmm3, %xmm11
        movdqa    %xmm1, 144(%rsp)
        movdqa    %xmm6, %xmm1
        movdqa    %xmm12, 112(%rsp)
        movdqa    %xmm5, %xmm12
        pslld     $12, %xmm11
        psrld     $20, %xmm3
        pslld     $12, %xmm12
        psrld     $20, %xmm5
        pslld     $12, %xmm1
        psrld     $20, %xmm6
        por       %xmm3, %xmm11
        por       %xmm5, %xmm12
        movdqa    .L_2il0floatpacket.67(%rip), %xmm5
        por       %xmm6, %xmm1
        movdqa    %xmm15, %xmm6
        paddd     %xmm8, %xmm11
        movdqa    %xmm13, 96(%rsp)
        paddd     %xmm5, %xmm10
        pxor      %xmm8, %xmm6
        paddd     %xmm5, %xmm2
        movdqa    %xmm9, %xmm13
        paddd     %xmm5, %xmm4
        movdqa    %xmm0, %xmm5
        paddd     %xmm7, %xmm12
        paddd     %xmm14, %xmm1
        pand      %xmm11, %xmm6
        pxor      %xmm7, %xmm13
        pxor      %xmm14, %xmm5
        pxor      %xmm15, %xmm6
        pand      %xmm12, %xmm13
        pand      %xmm1, %xmm5
        paddd     %xmm6, %xmm10
        movdqa    32(%rdi), %xmm3
        pxor      %xmm9, %xmm13
        pxor      %xmm0, %xmm5
        paddd     %xmm3, %xmm10
        movdqa    %xmm3, (%rsp)
        paddd     %xmm13, %xmm2
        movdqa    288(%rdi), %xmm6
        paddd     %xmm5, %xmm4
        movdqa    544(%rdi), %xmm3
        paddd     %xmm6, %xmm2
        paddd     %xmm3, %xmm4
        movdqa    %xmm10, %xmm13
        movdqa    %xmm3, 32(%rsp)
        movdqa    %xmm2, %xmm5
        movdqa    %xmm4, %xmm3
        pslld     $17, %xmm13
        psrld     $15, %xmm10
        pslld     $17, %xmm5
        psrld     $15, %xmm2
        pslld     $17, %xmm3
        psrld     $15, %xmm4
        por       %xmm10, %xmm13
        movdqa    %xmm6, 16(%rsp)
        por       %xmm2, %xmm5
        movdqa    .L_2il0floatpacket.68(%rip), %xmm6
        por       %xmm4, %xmm3
        movdqa    %xmm11, %xmm4
        movdqa    %xmm12, %xmm2
        paddd     %xmm11, %xmm13
        paddd     %xmm12, %xmm5
        paddd     %xmm6, %xmm15
        pxor      %xmm8, %xmm4
        paddd     %xmm6, %xmm9
        pxor      %xmm7, %xmm2
        paddd     %xmm6, %xmm0
        movdqa    %xmm1, %xmm6
        paddd     %xmm1, %xmm3
        pand      %xmm13, %xmm4
        pand      %xmm5, %xmm2
        pxor      %xmm14, %xmm6
        pxor      %xmm8, %xmm4
        pxor      %xmm7, %xmm2
        pand      %xmm3, %xmm6
        paddd     %xmm4, %xmm15
        movdqa    48(%rdi), %xmm10
        paddd     %xmm2, %xmm9
        movdqa    304(%rdi), %xmm4
        pxor      %xmm14, %xmm6
        movdqa    %xmm10, 256(%rsp)
        paddd     %xmm10, %xmm15
        movdqa    560(%rdi), %xmm10
        paddd     %xmm4, %xmm9
        paddd     %xmm6, %xmm0
        movdqa    %xmm15, %xmm6
        movdqa    %xmm10, 288(%rsp)
        paddd     %xmm10, %xmm0
        movdqa    %xmm9, %xmm10
        psrld     $10, %xmm9
        pslld     $22, %xmm10
        pslld     $22, %xmm6
        por       %xmm9, %xmm10
        movdqa    %xmm0, %xmm9
        psrld     $10, %xmm15
        pslld     $22, %xmm9
        psrld     $10, %xmm0
        por       %xmm15, %xmm6
        por       %xmm0, %xmm9
        movdqa    %xmm13, %xmm0
        paddd     %xmm13, %xmm6
        pxor      %xmm11, %xmm0
        movdqa    %xmm4, 272(%rsp)
        pand      %xmm6, %xmm0
        movdqa    .L_2il0floatpacket.69(%rip), %xmm4
        pxor      %xmm11, %xmm0
        paddd     %xmm4, %xmm8
        paddd     %xmm4, %xmm7
        paddd     %xmm0, %xmm8
        movdqa    %xmm5, %xmm0
        paddd     %xmm4, %xmm14
        movdqa    %xmm3, %xmm4
        paddd     %xmm5, %xmm10
        paddd     %xmm3, %xmm9
        pxor      %xmm12, %xmm0
        pxor      %xmm1, %xmm4
        movdqa    64(%rdi), %xmm15
        pand      %xmm10, %xmm0
        pand      %xmm9, %xmm4
        paddd     %xmm15, %xmm8
        pxor      %xmm12, %xmm0
        pxor      %xmm1, %xmm4
        movdqa    %xmm15, 48(%rsp)
        paddd     %xmm0, %xmm7
        movdqa    320(%rdi), %xmm15
        paddd     %xmm4, %xmm14
        movdqa    %xmm8, %xmm4
        paddd     %xmm15, %xmm7
        pslld     $7, %xmm4
        psrld     $25, %xmm8
        por       %xmm8, %xmm4
        movdqa    %xmm7, %xmm8
        movdqa    576(%rdi), %xmm2
        pslld     $7, %xmm8
        psrld     $25, %xmm7
        paddd     %xmm2, %xmm14
        por       %xmm7, %xmm8
        movdqa    %xmm6, %xmm7
        movdqa    %xmm15, 80(%rsp)
        paddd     %xmm6, %xmm4
        movdqa    %xmm14, %xmm15
        pxor      %xmm13, %xmm7
        movdqa    .L_2il0floatpacket.70(%rip), %xmm0
        pslld     $7, %xmm15
        psrld     $25, %xmm14
        pand      %xmm4, %xmm7
        por       %xmm14, %xmm15
        paddd     %xmm0, %xmm11
        pxor      %xmm13, %xmm7
        paddd     %xmm0, %xmm12
        paddd     %xmm0, %xmm1
        movdqa    %xmm9, %xmm0
        paddd     %xmm9, %xmm15
        paddd     %xmm7, %xmm11
        movdqa    %xmm10, %xmm7
        pxor      %xmm3, %xmm0
        paddd     %xmm10, %xmm8
        pxor      %xmm5, %xmm7
        pand      %xmm15, %xmm0
        pand      %xmm8, %xmm7
        pxor      %xmm3, %xmm0
        pxor      %xmm5, %xmm7
        movdqa    %xmm2, 64(%rsp)
        paddd     %xmm0, %xmm1
        movdqa    80(%rdi), %xmm14
        paddd     %xmm7, %xmm12
        movdqa    592(%rdi), %xmm2
        paddd     %xmm14, %xmm11
        movdqa    %xmm14, 432(%rsp)
        paddd     %xmm2, %xmm1
        movdqa    336(%rdi), %xmm14
        movdqa    %xmm11, %xmm0
        movdqa    %xmm14, 448(%rsp)
        paddd     %xmm14, %xmm12
        movdqa    %xmm1, %xmm14
        pslld     $12, %xmm0
        psrld     $20, %xmm11
        movdqa    %xmm12, %xmm7
        pslld     $12, %xmm14
        psrld     $20, %xmm1
        por       %xmm11, %xmm0
        pslld     $12, %xmm7
        psrld     $20, %xmm12
        por       %xmm1, %xmm14
        movdqa    %xmm4, %xmm1
        paddd     %xmm4, %xmm0
        movdqa    %xmm2, 416(%rsp)
        por       %xmm12, %xmm7
        pxor      %xmm6, %xmm1
        movdqa    %xmm8, %xmm12
        movdqa    .L_2il0floatpacket.71(%rip), %xmm2
        paddd     %xmm8, %xmm7
        pand      %xmm0, %xmm1
        pxor      %xmm10, %xmm12
        paddd     %xmm2, %xmm13
        paddd     %xmm2, %xmm5
        paddd     %xmm2, %xmm3
        movdqa    %xmm15, %xmm2
        pxor      %xmm6, %xmm1
        pand      %xmm7, %xmm12
        paddd     %xmm15, %xmm14
        pxor      %xmm9, %xmm2
        movdqa    96(%rdi), %xmm11
        paddd     %xmm1, %xmm13
        pxor      %xmm10, %xmm12
        pand      %xmm14, %xmm2
        movdqa    352(%rdi), %xmm1
        paddd     %xmm11, %xmm13
        paddd     %xmm12, %xmm5
        pxor      %xmm9, %xmm2
        movdqa    %xmm11, 192(%rsp)
        paddd     %xmm1, %xmm5
        movdqa    %xmm1, 176(%rsp)
        movdqa    %xmm13, %xmm1
        movdqa    608(%rdi), %xmm11
        paddd     %xmm2, %xmm3
        pslld     $17, %xmm1
        psrld     $15, %xmm13
        paddd     %xmm11, %xmm3
        por       %xmm13, %xmm1
        movdqa    %xmm5, %xmm13
        movdqa    %xmm3, %xmm2
        pslld     $17, %xmm13
        psrld     $15, %xmm5
        pslld     $17, %xmm2
        psrld     $15, %xmm3
        por       %xmm5, %xmm13
        movdqa    %xmm0, %xmm5
        por       %xmm3, %xmm2
        movdqa    %xmm7, %xmm12
        movdqa    .L_2il0floatpacket.72(%rip), %xmm3
        paddd     %xmm0, %xmm1
        pxor      %xmm4, %xmm5
        paddd     %xmm7, %xmm13
        paddd     %xmm3, %xmm6
        paddd     %xmm3, %xmm10
        pxor      %xmm8, %xmm12
        paddd     %xmm3, %xmm9
        movdqa    %xmm14, %xmm3
        pand      %xmm1, %xmm5
        paddd     %xmm14, %xmm2
        pand      %xmm13, %xmm12
        pxor      %xmm15, %xmm3
        pxor      %xmm4, %xmm5
        pxor      %xmm8, %xmm12
        pand      %xmm2, %xmm3
        movdqa    %xmm11, 160(%rsp)
        paddd     %xmm5, %xmm6
        movdqa    368(%rdi), %xmm5
        paddd     %xmm12, %xmm10
        movdqa    112(%rdi), %xmm11
        pxor      %xmm15, %xmm3
        movdqa    %xmm5, 560(%rsp)
        paddd     %xmm11, %xmm6
        paddd     %xmm5, %xmm10
        paddd     %xmm3, %xmm9
        movdqa    624(%rdi), %xmm5
        movdqa    %xmm10, %xmm3
        movdqa    %xmm5, 544(%rsp)
        paddd     %xmm5, %xmm9
        movdqa    %xmm6, %xmm5
        psrld     $10, %xmm6
        pslld     $22, %xmm5
        pslld     $22, %xmm3
        por       %xmm6, %xmm5
        psrld     $10, %xmm10
        movdqa    %xmm9, %xmm6
        por       %xmm10, %xmm3
        pslld     $22, %xmm6
        psrld     $10, %xmm9
        movdqa    %xmm1, %xmm10
        paddd     %xmm1, %xmm5
        por       %xmm9, %xmm6
        pxor      %xmm0, %xmm10
        movdqa    .L_2il0floatpacket.73(%rip), %xmm9
        pand      %xmm5, %xmm10
        paddd     %xmm9, %xmm4
        paddd     %xmm9, %xmm8
        movdqa    %xmm13, %xmm12
        paddd     %xmm9, %xmm15
        movdqa    %xmm2, %xmm9
        paddd     %xmm13, %xmm3
        paddd     %xmm2, %xmm6
        pxor      %xmm0, %xmm10
        pxor      %xmm7, %xmm12
        pxor      %xmm14, %xmm9
        movdqa    %xmm11, 592(%rsp)
        paddd     %xmm10, %xmm4
        movdqa    128(%rdi), %xmm11
        pand      %xmm3, %xmm12
        pand      %xmm6, %xmm9
        paddd     %xmm11, %xmm4
        pxor      %xmm7, %xmm12
        pxor      %xmm14, %xmm9
        movdqa    384(%rdi), %xmm10
        paddd     %xmm12, %xmm8
        paddd     %xmm9, %xmm15
        movdqa    %xmm4, %xmm9
        paddd     %xmm10, %xmm8
        pslld     $7, %xmm9
        psrld     $25, %xmm4
        movdqa    %xmm10, 352(%rsp)
        por       %xmm4, %xmm9
        movdqa    640(%rdi), %xmm10
        movdqa    %xmm8, %xmm4
        paddd     %xmm10, %xmm15
        pslld     $7, %xmm4
        psrld     $25, %xmm8
        paddd     %xmm5, %xmm9
        por       %xmm8, %xmm4
        movdqa    %xmm15, %xmm8
        movdqa    %xmm11, 368(%rsp)
        pslld     $7, %xmm8
        psrld     $25, %xmm15
        movdqa    %xmm5, %xmm11
        por       %xmm15, %xmm8
        pxor      %xmm1, %xmm11
        movdqa    .L_2il0floatpacket.74(%rip), %xmm15
        pand      %xmm9, %xmm11
        movdqa    %xmm10, 336(%rsp)
        paddd     %xmm15, %xmm0
        paddd     %xmm15, %xmm7
        movdqa    %xmm3, %xmm10
        paddd     %xmm15, %xmm14
        movdqa    %xmm6, %xmm15
        paddd     %xmm3, %xmm4
        paddd     %xmm6, %xmm8
        pxor      %xmm1, %xmm11
        pxor      %xmm13, %xmm10
        pxor      %xmm2, %xmm15
        paddd     %xmm11, %xmm0
        movdqa    144(%rdi), %xmm12
        pand      %xmm4, %xmm10
        pand      %xmm8, %xmm15
        paddd     %xmm12, %xmm0
        pxor      %xmm13, %xmm10
        pxor      %xmm2, %xmm15
        movdqa    400(%rdi), %xmm11
        paddd     %xmm10, %xmm7
        paddd     %xmm15, %xmm14
        movdqa    %xmm0, %xmm15
        paddd     %xmm11, %xmm7
        pslld     $12, %xmm15
        psrld     $20, %xmm0
        movdqa    %xmm12, 128(%rsp)
        por       %xmm0, %xmm15
        movdqa    656(%rdi), %xmm12
        movdqa    %xmm7, %xmm0
        paddd     %xmm12, %xmm14
        pslld     $12, %xmm0
        psrld     $20, %xmm7
        paddd     %xmm9, %xmm15
        por       %xmm7, %xmm0
        movdqa    %xmm14, %xmm7
        pslld     $12, %xmm7
        psrld     $20, %xmm14
        por       %xmm14, %xmm7
        movdqa    %xmm9, %xmm14
        movdqa    %xmm12, 224(%rsp)
        movdqa    %xmm4, %xmm12
        movdqa    .L_2il0floatpacket.75(%rip), %xmm10
        pxor      %xmm5, %xmm14
        paddd     %xmm4, %xmm0
        paddd     %xmm10, %xmm1
        paddd     %xmm10, %xmm13
        pxor      %xmm3, %xmm12
        paddd     %xmm10, %xmm2
        movdqa    %xmm8, %xmm10
        pand      %xmm15, %xmm14
        paddd     %xmm8, %xmm7
        pand      %xmm0, %xmm12
        pxor      %xmm6, %xmm10
        pxor      %xmm5, %xmm14
        pxor      %xmm3, %xmm12
        pand      %xmm7, %xmm10
        paddd     %xmm14, %xmm1
        movdqa    %xmm11, 208(%rsp)
        paddd     %xmm12, %xmm13
        movdqa    416(%rdi), %xmm14
        pxor      %xmm6, %xmm10
        movdqa    160(%rdi), %xmm11
        paddd     %xmm14, %xmm13
        movdqa    %xmm14, 496(%rsp)
        paddd     %xmm11, %xmm1
        movdqa    672(%rdi), %xmm14
        paddd     %xmm10, %xmm2
        movdqa    %xmm14, 512(%rsp)
        paddd     %xmm14, %xmm2
        movdqa    %xmm1, %xmm14
        psrld     $15, %xmm1
        pslld     $17, %xmm14
        por       %xmm1, %xmm14
        movdqa    %xmm13, %xmm1
        pslld     $17, %xmm1
        psrld     $15, %xmm13
        por       %xmm13, %xmm1
        movdqa    %xmm2, %xmm13
        pslld     $17, %xmm13
        psrld     $15, %xmm2
        por       %xmm2, %xmm13
        movdqa    %xmm15, %xmm2
        paddd     %xmm15, %xmm14
        pxor      %xmm9, %xmm2
        movdqa    .L_2il0floatpacket.76(%rip), %xmm10
        pand      %xmm14, %xmm2
        paddd     %xmm10, %xmm5
        pxor      %xmm9, %xmm2
        paddd     %xmm2, %xmm5
        paddd     %xmm0, %xmm1
        movdqa    432(%rdi), %xmm2
        paddd     %xmm7, %xmm13
        movdqa    %xmm2, 304(%rsp)
        movdqa    %xmm0, %xmm2
        pxor      %xmm4, %xmm2
        paddd     %xmm10, %xmm3
        movdqa    %xmm11, 528(%rsp)
        pand      %xmm1, %xmm2
        movdqa    176(%rdi), %xmm11
        pxor      %xmm4, %xmm2
        movdqa    %xmm11, 240(%rsp)
        paddd     %xmm11, %xmm5
..B6.11:
        movdqa    %xmm7, %xmm12
        paddd     %xmm10, %xmm6
        pxor      %xmm8, %xmm12
        paddd     %xmm2, %xmm3
        pand      %xmm13, %xmm12
        pxor      %xmm8, %xmm12
        movdqa    304(%rsp), %xmm2
        paddd     %xmm12, %xmm6
        movdqa    %xmm5, %xmm12
        paddd     %xmm2, %xmm3
        pslld     $22, %xmm12
        psrld     $10, %xmm5
        movdqa    688(%rdi), %xmm11
        por       %xmm5, %xmm12
        movdqa    %xmm3, %xmm5
        paddd     %xmm11, %xmm6
        pslld     $22, %xmm5
        psrld     $10, %xmm3
        por       %xmm3, %xmm5
        movdqa    %xmm6, %xmm3
        pslld     $22, %xmm3
        psrld     $10, %xmm6
        por       %xmm6, %xmm3
        movdqa    %xmm14, %xmm6
        paddd     %xmm14, %xmm12
        pxor      %xmm15, %xmm6
        movdqa    %xmm11, 320(%rsp)
        pand      %xmm12, %xmm6
        movdqa    .L_2il0floatpacket.77(%rip), %xmm11
        pxor      %xmm15, %xmm6
        paddd     %xmm11, %xmm9
        paddd     %xmm1, %xmm5
        paddd     %xmm6, %xmm9
        movdqa    %xmm1, %xmm6
        pxor      %xmm0, %xmm6
        paddd     %xmm11, %xmm4
        pand      %xmm5, %xmm6
        paddd     %xmm11, %xmm8
        movdqa    %xmm13, %xmm11
        paddd     %xmm13, %xmm3
        movdqa    192(%rdi), %xmm10
        pxor      %xmm0, %xmm6
        pxor      %xmm7, %xmm11
        paddd     %xmm10, %xmm9
        movdqa    %xmm10, 624(%rsp)
        paddd     %xmm6, %xmm4
        movdqa    448(%rdi), %xmm10
        pand      %xmm3, %xmm11
        paddd     %xmm10, %xmm4
        pxor      %xmm7, %xmm11
        movdqa    %xmm10, 608(%rsp)
        paddd     %xmm11, %xmm8
        movdqa    %xmm9, %xmm11
        movdqa    %xmm4, %xmm10
        pslld     $7, %xmm11
        psrld     $25, %xmm9
        pslld     $7, %xmm10
        psrld     $25, %xmm4
        movdqa    704(%rdi), %xmm6
        por       %xmm9, %xmm11
        por       %xmm4, %xmm10
        movdqa    %xmm14, %xmm4
        paddd     %xmm6, %xmm8
        paddd     %xmm12, %xmm11
        pxor      %xmm12, %xmm4
        paddd     %xmm5, %xmm10
        movdqa    %xmm6, 640(%rsp)
        movdqa    %xmm8, %xmm6
        movdqa    .L_2il0floatpacket.78(%rip), %xmm9
        pand      %xmm11, %xmm4
        pslld     $7, %xmm6
        psrld     $25, %xmm8
        paddd     %xmm9, %xmm15
        pxor      %xmm14, %xmm4
        por       %xmm8, %xmm6
        paddd     %xmm4, %xmm15
        paddd     %xmm9, %xmm0
        movdqa    %xmm1, %xmm4
        paddd     %xmm9, %xmm7
        movdqa    %xmm13, %xmm9
        paddd     %xmm3, %xmm6
        pxor      %xmm5, %xmm4
        pxor      %xmm3, %xmm9
        pand      %xmm10, %xmm4
        movdqa    208(%rdi), %xmm8
        pand      %xmm6, %xmm9
        paddd     %xmm8, %xmm15
        pxor      %xmm1, %xmm4
        pxor      %xmm13, %xmm9
        paddd     %xmm4, %xmm0
        movdqa    %xmm8, 400(%rsp)
        paddd     %xmm9, %xmm7
        movdqa    464(%rdi), %xmm8
        movdqa    %xmm15, %xmm9
        movdqa    720(%rdi), %xmm4
        paddd     %xmm8, %xmm0
        pslld     $12, %xmm9
        psrld     $20, %xmm15
        movdqa    %xmm4, 480(%rsp)
        paddd     %xmm4, %xmm7
        por       %xmm15, %xmm9
        movdqa    %xmm0, %xmm4
        movdqa    %xmm11, %xmm15
        paddd     %xmm11, %xmm9
        pslld     $12, %xmm4
        psrld     $20, %xmm0
        pxor      %xmm12, %xmm15
        por       %xmm0, %xmm4
        movdqa    %xmm8, 464(%rsp)
        movdqa    %xmm7, %xmm0
        movdqa    .L_2il0floatpacket.79(%rip), %xmm8
        pand      %xmm9, %xmm15
        pslld     $12, %xmm0
        psrld     $20, %xmm7
        paddd     %xmm8, %xmm14
        pxor      %xmm12, %xmm15
        por       %xmm7, %xmm0
        paddd     %xmm15, %xmm14
        paddd     %xmm8, %xmm1
        movdqa    %xmm10, %xmm15
        paddd     %xmm8, %xmm13
        movdqa    %xmm6, %xmm8
        paddd     %xmm10, %xmm4
        paddd     %xmm6, %xmm0
        pxor      %xmm5, %xmm15
        pxor      %xmm3, %xmm8
        movdqa    224(%rdi), %xmm7
        pand      %xmm4, %xmm15
        pand      %xmm0, %xmm8
        paddd     %xmm7, %xmm14
        pxor      %xmm5, %xmm15
        pxor      %xmm3, %xmm8
        movdqa    %xmm7, 672(%rsp)
        paddd     %xmm15, %xmm1
        movdqa    480(%rdi), %xmm7
        paddd     %xmm8, %xmm13
        movdqa    %xmm14, %xmm8
        paddd     %xmm7, %xmm1
        pslld     $17, %xmm8
        psrld     $15, %xmm14
        movdqa    %xmm7, 656(%rsp)
        por       %xmm14, %xmm8
        movdqa    %xmm1, %xmm7
        movdqa    %xmm9, %xmm14
        paddd     736(%rdi), %xmm13
        paddd     %xmm9, %xmm8
        pslld     $17, %xmm7
        psrld     $15, %xmm1
        pxor      %xmm11, %xmm14
        por       %xmm1, %xmm7
        movdqa    .L_2il0floatpacket.80(%rip), %xmm1
        movdqa    %xmm13, %xmm15
        pand      %xmm8, %xmm14
        pslld     $17, %xmm15
        psrld     $15, %xmm13
        paddd     %xmm1, %xmm12
        pxor      %xmm11, %xmm14
        por       %xmm13, %xmm15
        paddd     %xmm14, %xmm12
        paddd     %xmm1, %xmm5
        movdqa    %xmm4, %xmm14
        paddd     %xmm1, %xmm3
        movdqa    %xmm0, %xmm1
        paddd     %xmm4, %xmm7
        paddd     %xmm0, %xmm15
        pxor      %xmm10, %xmm14
        pxor      %xmm6, %xmm1
        pand      %xmm7, %xmm14
        movdqa    240(%rdi), %xmm13
        pand      %xmm15, %xmm1
        paddd     %xmm13, %xmm12
        pxor      %xmm10, %xmm14
        pxor      %xmm6, %xmm1
        paddd     %xmm14, %xmm5
        paddd     %xmm1, %xmm3
        movdqa    %xmm12, %xmm1
        paddd     496(%rdi), %xmm5
        pslld     $22, %xmm1
        psrld     $10, %xmm12
        por       %xmm12, %xmm1
        movdqa    %xmm5, %xmm12
        paddd     752(%rdi), %xmm3
        pslld     $22, %xmm12
        psrld     $10, %xmm5
        paddd     %xmm8, %xmm1
        por       %xmm5, %xmm12
        movdqa    %xmm3, %xmm5
        pslld     $22, %xmm5
        psrld     $10, %xmm3
        por       %xmm3, %xmm5
        movdqa    %xmm8, %xmm3
        pxor      %xmm1, %xmm3
        paddd     %xmm15, %xmm5
        movdqa    .L_2il0floatpacket.81(%rip), %xmm14
        pand      %xmm9, %xmm3
        paddd     %xmm14, %xmm11
        pxor      %xmm8, %xmm3
        paddd     %xmm14, %xmm10
        paddd     %xmm14, %xmm6
        movdqa    %xmm15, %xmm14
        paddd     %xmm7, %xmm12
        paddd     %xmm3, %xmm11
        movdqa    %xmm7, %xmm3
        pxor      %xmm5, %xmm14
        pxor      %xmm12, %xmm3
        pand      %xmm0, %xmm14
        pand      %xmm4, %xmm3
        pxor      %xmm15, %xmm14
        pxor      %xmm7, %xmm3
        paddd     144(%rsp), %xmm11
        paddd     %xmm14, %xmm6
        paddd     96(%rsp), %xmm6
        paddd     %xmm3, %xmm10
        movdqa    %xmm11, %xmm3
        psrld     $27, %xmm11
        pslld     $5, %xmm3
        movdqa    %xmm6, %xmm14
        paddd     112(%rsp), %xmm10
        por       %xmm11, %xmm3
        pslld     $5, %xmm14
        psrld     $27, %xmm6
        paddd     %xmm1, %xmm3
        movdqa    %xmm10, %xmm11
        por       %xmm6, %xmm14
        movdqa    %xmm1, %xmm6
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pxor      %xmm3, %xmm6
        por       %xmm10, %xmm11
        movdqa    .L_2il0floatpacket.82(%rip), %xmm10
        pand      %xmm8, %xmm6
        paddd     %xmm10, %xmm9
        pxor      %xmm1, %xmm6
        paddd     %xmm12, %xmm11
        paddd     %xmm5, %xmm14
        paddd     %xmm6, %xmm9
        paddd     %xmm10, %xmm4
        movdqa    %xmm12, %xmm6
        paddd     %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        pxor      %xmm11, %xmm6
        pxor      %xmm14, %xmm10
        pand      %xmm7, %xmm6
        pand      %xmm15, %xmm10
        pxor      %xmm12, %xmm6
        paddd     192(%rsp), %xmm9
        pxor      %xmm5, %xmm10
        paddd     %xmm6, %xmm4
        paddd     %xmm10, %xmm0
        movdqa    %xmm9, %xmm10
        psrld     $23, %xmm9
        paddd     176(%rsp), %xmm4
        pslld     $9, %xmm10
        por       %xmm9, %xmm10
        movdqa    %xmm4, %xmm9
        paddd     160(%rsp), %xmm0
        pslld     $9, %xmm9
        psrld     $23, %xmm4
        paddd     %xmm3, %xmm10
        por       %xmm4, %xmm9
        movdqa    %xmm0, %xmm4
        movdqa    %xmm3, %xmm6
        pslld     $9, %xmm4
        psrld     $23, %xmm0
        pxor      %xmm10, %xmm6
        por       %xmm0, %xmm4
        pand      %xmm1, %xmm6
        movdqa    .L_2il0floatpacket.83(%rip), %xmm0
        pxor      %xmm3, %xmm6
        paddd     %xmm0, %xmm8
        paddd     %xmm11, %xmm9
        paddd     %xmm6, %xmm8
        movdqa    %xmm11, %xmm6
        pxor      %xmm9, %xmm6
        paddd     %xmm0, %xmm7
        pand      %xmm12, %xmm6
        paddd     %xmm14, %xmm4
        pxor      %xmm11, %xmm6
        paddd     %xmm0, %xmm15
        paddd     %xmm6, %xmm7
        paddd     %xmm2, %xmm7
        movdqa    %xmm14, %xmm2
        pxor      %xmm4, %xmm2
        paddd     240(%rsp), %xmm8
        pand      %xmm5, %xmm2
        pxor      %xmm14, %xmm2
        movdqa    %xmm8, %xmm0
        paddd     %xmm2, %xmm15
        pslld     $14, %xmm0
        psrld     $18, %xmm8
        movdqa    %xmm7, %xmm2
        paddd     688(%rdi), %xmm15
        por       %xmm8, %xmm0
        pslld     $14, %xmm2
        psrld     $18, %xmm7
        paddd     %xmm10, %xmm0
        por       %xmm7, %xmm2
        movdqa    %xmm15, %xmm6
        movdqa    %xmm10, %xmm7
        pslld     $14, %xmm6
        psrld     $18, %xmm15
        pxor      %xmm0, %xmm7
        paddd     %xmm9, %xmm2
        movdqa    .L_2il0floatpacket.84(%rip), %xmm8
        por       %xmm15, %xmm6
        pand      %xmm3, %xmm7
        movdqa    %xmm9, %xmm15
        paddd     %xmm8, %xmm1
        pxor      %xmm10, %xmm7
        pxor      %xmm2, %xmm15
        paddd     %xmm4, %xmm6
        paddd     %xmm7, %xmm1
        pand      %xmm11, %xmm15
        movdqa    %xmm4, %xmm7
        paddd     %xmm8, %xmm12
        paddd     704(%rsp), %xmm1
        pxor      %xmm9, %xmm15
        pxor      %xmm6, %xmm7
        paddd     %xmm15, %xmm12
        paddd     %xmm8, %xmm5
        pand      %xmm14, %xmm7
        movdqa    %xmm1, %xmm8
        pxor      %xmm4, %xmm7
        paddd     688(%rsp), %xmm12
        pslld     $20, %xmm8
        psrld     $12, %xmm1
        paddd     %xmm7, %xmm5
        por       %xmm1, %xmm8
        movdqa    %xmm12, %xmm1
        paddd     384(%rsp), %xmm5
        pslld     $20, %xmm1
        psrld     $12, %xmm12
        paddd     %xmm0, %xmm8
        por       %xmm12, %xmm1
        movdqa    %xmm5, %xmm12
        pslld     $20, %xmm12
        psrld     $12, %xmm5
        por       %xmm5, %xmm12
        movdqa    %xmm0, %xmm5
        pxor      %xmm8, %xmm5
        paddd     %xmm2, %xmm1
        movdqa    .L_2il0floatpacket.85(%rip), %xmm15
        pand      %xmm10, %xmm5
        paddd     %xmm15, %xmm3
        pxor      %xmm0, %xmm5
        paddd     %xmm6, %xmm12
        paddd     %xmm5, %xmm3
        movdqa    %xmm2, %xmm7
        movdqa    %xmm6, %xmm5
        pxor      %xmm1, %xmm7
        pxor      %xmm12, %xmm5
        pand      %xmm9, %xmm7
        pand      %xmm4, %xmm5
        paddd     432(%rsp), %xmm3
        paddd     %xmm15, %xmm11
        pxor      %xmm2, %xmm7
        paddd     %xmm15, %xmm14
        pxor      %xmm6, %xmm5
        paddd     %xmm7, %xmm11
        paddd     %xmm5, %xmm14
        movdqa    %xmm3, %xmm5
        paddd     448(%rsp), %xmm11
        pslld     $5, %xmm5
        psrld     $27, %xmm3
        movdqa    %xmm1, %xmm7
        por       %xmm3, %xmm5
        movdqa    %xmm11, %xmm3
        paddd     416(%rsp), %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm11
        paddd     %xmm8, %xmm5
        por       %xmm11, %xmm3
        movdqa    %xmm14, %xmm11
        pslld     $5, %xmm11
        psrld     $27, %xmm14
        por       %xmm14, %xmm11
        movdqa    %xmm8, %xmm14
        pxor      %xmm5, %xmm14
        paddd     %xmm1, %xmm3
        movdqa    .L_2il0floatpacket.86(%rip), %xmm15
        pand      %xmm0, %xmm14
        paddd     %xmm15, %xmm10
        pxor      %xmm8, %xmm14
        paddd     %xmm12, %xmm11
        paddd     %xmm14, %xmm10
        movdqa    %xmm12, %xmm14
        pxor      %xmm3, %xmm7
        pxor      %xmm11, %xmm14
        pand      %xmm2, %xmm7
        pand      %xmm6, %xmm14
        paddd     %xmm15, %xmm9
        paddd     528(%rsp), %xmm10
        pxor      %xmm1, %xmm7
        paddd     %xmm15, %xmm4
        pxor      %xmm12, %xmm14
        paddd     %xmm7, %xmm9
        paddd     %xmm14, %xmm4
        movdqa    %xmm10, %xmm14
        psrld     $23, %xmm10
        paddd     496(%rsp), %xmm9
        pslld     $9, %xmm14
        por       %xmm10, %xmm14
        movdqa    %xmm9, %xmm10
        paddd     512(%rsp), %xmm4
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        paddd     %xmm5, %xmm14
        por       %xmm9, %xmm10
        movdqa    %xmm4, %xmm9
        pslld     $9, %xmm9
        psrld     $23, %xmm4
        por       %xmm4, %xmm9
        movdqa    %xmm5, %xmm4
        pxor      %xmm14, %xmm4
        paddd     %xmm3, %xmm10
        movdqa    .L_2il0floatpacket.87(%rip), %xmm7
        pand      %xmm8, %xmm4
        paddd     %xmm7, %xmm0
        pxor      %xmm5, %xmm4
        paddd     %xmm4, %xmm0
        paddd     %xmm11, %xmm9
        movdqa    %xmm13, 576(%rsp)
        paddd     %xmm13, %xmm0
        movdqa    %xmm3, %xmm13
        paddd     %xmm7, %xmm2
        pxor      %xmm10, %xmm13
        paddd     %xmm7, %xmm6
        pand      %xmm1, %xmm13
        movdqa    %xmm11, %xmm7
        pxor      %xmm3, %xmm13
        pxor      %xmm9, %xmm7
        paddd     %xmm13, %xmm2
        pand      %xmm12, %xmm7
        movdqa    496(%rdi), %xmm13
        movdqa    %xmm0, %xmm4
        paddd     %xmm13, %xmm2
        pxor      %xmm11, %xmm7
        pslld     $14, %xmm4
        psrld     $18, %xmm0
        paddd     %xmm7, %xmm6
        por       %xmm0, %xmm4
        movdqa    752(%rdi), %xmm7
        movdqa    %xmm2, %xmm0
        paddd     %xmm7, %xmm6
        pslld     $14, %xmm0
        psrld     $18, %xmm2
        paddd     %xmm14, %xmm4
        por       %xmm2, %xmm0
        movdqa    %xmm6, %xmm2
        pslld     $14, %xmm2
        psrld     $18, %xmm6
        por       %xmm6, %xmm2
        movdqa    %xmm14, %xmm6
        pxor      %xmm4, %xmm6
        paddd     %xmm10, %xmm0
        movdqa    .L_2il0floatpacket.88(%rip), %xmm15
        pand      %xmm5, %xmm6
        paddd     %xmm15, %xmm8
        pxor      %xmm14, %xmm6
        paddd     %xmm6, %xmm8
        movdqa    %xmm10, %xmm6
        pxor      %xmm0, %xmm6
        paddd     %xmm9, %xmm2
        pand      %xmm3, %xmm6
        paddd     %xmm15, %xmm1
        paddd     48(%rsp), %xmm8
        pxor      %xmm10, %xmm6
        paddd     %xmm15, %xmm12
        movdqa    %xmm9, %xmm15
        paddd     %xmm6, %xmm1
        pxor      %xmm2, %xmm15
        movdqa    %xmm8, %xmm6
        pand      %xmm11, %xmm15
        paddd     80(%rsp), %xmm1
        pslld     $20, %xmm6
        psrld     $12, %xmm8
        pxor      %xmm9, %xmm15
        por       %xmm8, %xmm6
        movdqa    %xmm1, %xmm8
        paddd     %xmm15, %xmm12
        pslld     $20, %xmm8
        psrld     $12, %xmm1
        paddd     %xmm4, %xmm6
        paddd     64(%rsp), %xmm12
        por       %xmm1, %xmm8
        movdqa    736(%rdi), %xmm1
..B6.10:
        movdqa    %xmm7, 752(%rsp)
        movdqa    %xmm12, %xmm7
        pslld     $20, %xmm7
        psrld     $12, %xmm12
        por       %xmm12, %xmm7
        movdqa    %xmm4, %xmm12
        pxor      %xmm6, %xmm12
        paddd     %xmm0, %xmm8
        movdqa    %xmm13, 736(%rsp)
        pand      %xmm14, %xmm12
        movdqa    .L_2il0floatpacket.89(%rip), %xmm13
        pxor      %xmm4, %xmm12
        paddd     %xmm13, %xmm5
        paddd     %xmm2, %xmm7
        paddd     %xmm12, %xmm5
        movdqa    %xmm0, %xmm15
        movdqa    %xmm2, %xmm12
        pxor      %xmm8, %xmm15
        pxor      %xmm7, %xmm12
        pand      %xmm10, %xmm15
        pand      %xmm9, %xmm12
        paddd     %xmm13, %xmm3
        paddd     128(%rsp), %xmm5
        pxor      %xmm0, %xmm15
        paddd     %xmm13, %xmm11
        pxor      %xmm2, %xmm12
        paddd     %xmm15, %xmm3
        paddd     %xmm12, %xmm11
        movdqa    %xmm5, %xmm12
        psrld     $27, %xmm5
        paddd     208(%rsp), %xmm3
        pslld     $5, %xmm12
        por       %xmm5, %xmm12
        movdqa    %xmm3, %xmm5
        paddd     224(%rsp), %xmm11
        pslld     $5, %xmm5
        psrld     $27, %xmm3
        paddd     %xmm6, %xmm12
        por       %xmm3, %xmm5
        movdqa    %xmm11, %xmm3
        pslld     $5, %xmm3
        psrld     $27, %xmm11
        por       %xmm11, %xmm3
        movdqa    %xmm6, %xmm11
        pxor      %xmm12, %xmm11
        paddd     %xmm8, %xmm5
        movdqa    .L_2il0floatpacket.90(%rip), %xmm15
        pand      %xmm4, %xmm11
        paddd     %xmm15, %xmm14
        pxor      %xmm6, %xmm11
        movdqa    %xmm8, %xmm13
        paddd     %xmm7, %xmm3
        paddd     %xmm11, %xmm14
        pxor      %xmm5, %xmm13
        movdqa    %xmm7, %xmm11
        pand      %xmm0, %xmm13
        pxor      %xmm3, %xmm11
        paddd     %xmm15, %xmm10
        pxor      %xmm8, %xmm13
        pand      %xmm2, %xmm11
        paddd     %xmm13, %xmm10
        paddd     %xmm15, %xmm9
        pxor      %xmm7, %xmm11
        movdqa    %xmm3, %xmm15
        paddd     656(%rsp), %xmm10
        paddd     %xmm11, %xmm9
        paddd     672(%rsp), %xmm14
        paddd     %xmm1, %xmm9
        movdqa    %xmm1, 720(%rsp)
        movdqa    %xmm10, %xmm1
        movdqa    %xmm14, %xmm11
        pslld     $9, %xmm1
        psrld     $23, %xmm10
        pslld     $9, %xmm11
        psrld     $23, %xmm14
        por       %xmm10, %xmm1
        movdqa    %xmm9, %xmm10
        por       %xmm14, %xmm11
        pslld     $9, %xmm10
        psrld     $23, %xmm9
        paddd     %xmm12, %xmm11
        paddd     %xmm5, %xmm1
        por       %xmm9, %xmm10
        movdqa    %xmm12, %xmm14
        movdqa    %xmm5, %xmm9
        pxor      %xmm11, %xmm14
        pxor      %xmm1, %xmm9
        paddd     %xmm3, %xmm10
        movdqa    .L_2il0floatpacket.91(%rip), %xmm13
        pand      %xmm6, %xmm14
        pand      %xmm8, %xmm9
        paddd     %xmm13, %xmm4
        pxor      %xmm12, %xmm14
        paddd     %xmm13, %xmm0
        pxor      %xmm5, %xmm9
        pxor      %xmm10, %xmm15
        paddd     %xmm14, %xmm4
        paddd     %xmm9, %xmm0
        pand      %xmm7, %xmm15
        paddd     %xmm13, %xmm2
        paddd     256(%rsp), %xmm4
        pxor      %xmm3, %xmm15
        paddd     272(%rsp), %xmm0
        paddd     %xmm15, %xmm2
        movdqa    %xmm4, %xmm15
        movdqa    %xmm0, %xmm14
        paddd     288(%rsp), %xmm2
        pslld     $14, %xmm15
        psrld     $18, %xmm4
        pslld     $14, %xmm14
        psrld     $18, %xmm0
        por       %xmm4, %xmm15
        por       %xmm0, %xmm14
        movdqa    %xmm2, %xmm0
        paddd     %xmm11, %xmm15
        pslld     $14, %xmm0
        psrld     $18, %xmm2
        movdqa    %xmm11, %xmm4
        movdqa    .L_2il0floatpacket.92(%rip), %xmm9
        por       %xmm2, %xmm0
        pxor      %xmm15, %xmm4
        paddd     %xmm1, %xmm14
        paddd     %xmm10, %xmm0
        paddd     %xmm9, %xmm6
        pand      %xmm12, %xmm4
        paddd     %xmm9, %xmm8
        movdqa    %xmm1, %xmm2
        paddd     %xmm9, %xmm7
        movdqa    %xmm10, %xmm9
        pxor      %xmm11, %xmm4
        pxor      %xmm14, %xmm2
        pxor      %xmm0, %xmm9
        paddd     %xmm4, %xmm6
        pand      %xmm5, %xmm2
        movdqa    368(%rsp), %xmm4
        pand      %xmm3, %xmm9
        paddd     %xmm4, %xmm6
        pxor      %xmm1, %xmm2
        pxor      %xmm10, %xmm9
        paddd     %xmm2, %xmm8
        movdqa    352(%rsp), %xmm2
        paddd     %xmm9, %xmm7
        movdqa    %xmm6, %xmm9
        paddd     %xmm2, %xmm8
        pslld     $20, %xmm9
        psrld     $12, %xmm6
        por       %xmm6, %xmm9
        movdqa    %xmm8, %xmm6
        paddd     336(%rsp), %xmm7
        pslld     $20, %xmm6
        psrld     $12, %xmm8
        paddd     %xmm15, %xmm9
        por       %xmm8, %xmm6
        movdqa    %xmm7, %xmm8
        pslld     $20, %xmm8
        psrld     $12, %xmm7
        por       %xmm7, %xmm8
        movdqa    %xmm15, %xmm7
        pxor      %xmm9, %xmm7
        paddd     %xmm14, %xmm6
        movdqa    .L_2il0floatpacket.93(%rip), %xmm13
        pand      %xmm11, %xmm7
        paddd     %xmm13, %xmm12
        pxor      %xmm15, %xmm7
        paddd     %xmm7, %xmm12
        movdqa    %xmm14, %xmm7
        pxor      %xmm6, %xmm7
        paddd     %xmm0, %xmm8
        paddd     %xmm13, %xmm5
        pand      %xmm1, %xmm7
        paddd     %xmm13, %xmm3
        movdqa    %xmm0, %xmm13
        pxor      %xmm14, %xmm7
        pxor      %xmm8, %xmm13
        paddd     400(%rsp), %xmm12
        paddd     %xmm7, %xmm5
        pand      %xmm10, %xmm13
        movdqa    %xmm12, %xmm7
        paddd     464(%rsp), %xmm5
        pxor      %xmm0, %xmm13
        paddd     %xmm13, %xmm3
        pslld     $5, %xmm7
        psrld     $27, %xmm12
        movdqa    %xmm5, %xmm13
        paddd     480(%rsp), %xmm3
        por       %xmm12, %xmm7
        pslld     $5, %xmm13
        psrld     $27, %xmm5
        paddd     %xmm9, %xmm7
        por       %xmm5, %xmm13
        movdqa    %xmm3, %xmm5
        movdqa    %xmm9, %xmm12
        pslld     $5, %xmm5
        psrld     $27, %xmm3
        pxor      %xmm7, %xmm12
        por       %xmm3, %xmm5
        movdqa    .L_2il0floatpacket.94(%rip), %xmm3
        pand      %xmm15, %xmm12
        paddd     %xmm3, %xmm11
        pxor      %xmm9, %xmm12
        paddd     %xmm6, %xmm13
        paddd     %xmm8, %xmm5
        paddd     %xmm12, %xmm11
        paddd     %xmm3, %xmm1
        movdqa    %xmm6, %xmm12
        paddd     %xmm3, %xmm10
        movdqa    %xmm8, %xmm3
        pxor      %xmm13, %xmm12
        pxor      %xmm5, %xmm3
        pand      %xmm14, %xmm12
        pand      %xmm0, %xmm3
        pxor      %xmm6, %xmm12
        paddd     (%rsp), %xmm11
        pxor      %xmm8, %xmm3
        paddd     %xmm12, %xmm1
        paddd     %xmm3, %xmm10
        movdqa    %xmm11, %xmm3
        psrld     $23, %xmm11
        paddd     16(%rsp), %xmm1
        pslld     $9, %xmm3
        por       %xmm11, %xmm3
        movdqa    %xmm1, %xmm11
        paddd     32(%rsp), %xmm10
        pslld     $9, %xmm11
        psrld     $23, %xmm1
        paddd     %xmm7, %xmm3
        por       %xmm1, %xmm11
        movdqa    %xmm10, %xmm12
        movdqa    %xmm7, %xmm1
        pslld     $9, %xmm12
        psrld     $23, %xmm10
        pxor      %xmm3, %xmm1
        por       %xmm10, %xmm12
        pand      %xmm9, %xmm1
        movdqa    .L_2il0floatpacket.95(%rip), %xmm10
        pxor      %xmm7, %xmm1
        paddd     %xmm10, %xmm15
        paddd     %xmm13, %xmm11
        paddd     %xmm1, %xmm15
        movdqa    %xmm13, %xmm1
        paddd     %xmm5, %xmm12
        paddd     %xmm10, %xmm14
        pxor      %xmm11, %xmm1
        paddd     %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        pand      %xmm6, %xmm1
        pxor      %xmm12, %xmm10
        pxor      %xmm13, %xmm1
        pand      %xmm8, %xmm10
        paddd     %xmm1, %xmm14
        paddd     592(%rsp), %xmm15
        pxor      %xmm5, %xmm10
        paddd     560(%rsp), %xmm14
        paddd     %xmm10, %xmm0
        movdqa    %xmm15, %xmm10
        psrld     $18, %xmm15
        pslld     $14, %xmm10
        movdqa    %xmm14, %xmm1
        paddd     544(%rsp), %xmm0
        por       %xmm15, %xmm10
        pslld     $14, %xmm1
        psrld     $18, %xmm14
        paddd     %xmm3, %xmm10
        por       %xmm14, %xmm1
        movdqa    %xmm0, %xmm15
        movdqa    %xmm3, %xmm14
        pslld     $14, %xmm15
        psrld     $18, %xmm0
        pxor      %xmm10, %xmm14
        por       %xmm0, %xmm15
        movdqa    .L_2il0floatpacket.96(%rip), %xmm0
        pand      %xmm7, %xmm14
        paddd     %xmm0, %xmm9
        pxor      %xmm3, %xmm14
        paddd     %xmm11, %xmm1
        paddd     %xmm14, %xmm9
        movdqa    %xmm11, %xmm14
        paddd     %xmm12, %xmm15
        pxor      %xmm1, %xmm14
        paddd     %xmm0, %xmm6
        pand      %xmm13, %xmm14
        paddd     %xmm0, %xmm8
        movdqa    %xmm12, %xmm0
        pxor      %xmm11, %xmm14
        paddd     624(%rsp), %xmm9
        pxor      %xmm15, %xmm0
        paddd     %xmm14, %xmm6
        pand      %xmm5, %xmm0
        movdqa    %xmm9, %xmm14
        pxor      %xmm12, %xmm0
        paddd     608(%rsp), %xmm6
        pslld     $20, %xmm14
        psrld     $12, %xmm9
        paddd     %xmm0, %xmm8
        por       %xmm9, %xmm14
        movdqa    %xmm6, %xmm9
        paddd     640(%rsp), %xmm8
        pslld     $20, %xmm9
        psrld     $12, %xmm6
        movdqa    %xmm10, %xmm0
        por       %xmm6, %xmm9
        movdqa    %xmm8, %xmm6
        pslld     $20, %xmm6
        psrld     $12, %xmm8
        paddd     %xmm10, %xmm14
        por       %xmm8, %xmm6
        movdqa    .L_2il0floatpacket.97(%rip), %xmm8
        pxor      %xmm3, %xmm0
        paddd     %xmm8, %xmm7
        pxor      %xmm14, %xmm0
        paddd     %xmm0, %xmm7
        paddd     %xmm8, %xmm13
        movdqa    %xmm1, %xmm0
        paddd     %xmm8, %xmm5
        movdqa    %xmm15, %xmm8
        paddd     %xmm1, %xmm9
        paddd     %xmm15, %xmm6
        pxor      %xmm11, %xmm0
        pxor      %xmm12, %xmm8
        pxor      %xmm9, %xmm0
        paddd     432(%rsp), %xmm7
        pxor      %xmm6, %xmm8
        paddd     %xmm0, %xmm13
        paddd     %xmm8, %xmm5
        movdqa    %xmm7, %xmm8
        psrld     $28, %xmm7
        paddd     448(%rsp), %xmm13
        pslld     $4, %xmm8
        por       %xmm7, %xmm8
        movdqa    %xmm13, %xmm7
        paddd     416(%rsp), %xmm5
        pslld     $4, %xmm7
        psrld     $28, %xmm13
        paddd     %xmm14, %xmm8
        por       %xmm13, %xmm7
        movdqa    %xmm5, %xmm13
        pslld     $4, %xmm13
        psrld     $28, %xmm5
        por       %xmm5, %xmm13
        movdqa    %xmm14, %xmm5
        movdqa    .L_2il0floatpacket.98(%rip), %xmm0
        pxor      %xmm10, %xmm5
        paddd     %xmm0, %xmm3
        pxor      %xmm8, %xmm5
        paddd     %xmm5, %xmm3
        paddd     %xmm9, %xmm7
        paddd     %xmm4, %xmm3
        movdqa    %xmm9, %xmm4
        pxor      %xmm1, %xmm4
        paddd     %xmm0, %xmm11
        pxor      %xmm7, %xmm4
        paddd     %xmm0, %xmm12
        movdqa    %xmm6, %xmm0
        paddd     %xmm6, %xmm13
        paddd     %xmm4, %xmm11
        pxor      %xmm15, %xmm0
        paddd     %xmm2, %xmm11
        pxor      %xmm13, %xmm0
        paddd     %xmm0, %xmm12
        movdqa    %xmm3, %xmm0
        movdqa    %xmm11, %xmm4
        pslld     $11, %xmm0
        paddd     336(%rsp), %xmm12
        psrld     $21, %xmm3
        pslld     $11, %xmm4
        psrld     $21, %xmm11
        por       %xmm3, %xmm0
        por       %xmm11, %xmm4
        movdqa    %xmm12, %xmm3
        movdqa    %xmm8, %xmm11
        movdqa    .L_2il0floatpacket.99(%rip), %xmm5
        paddd     %xmm8, %xmm0
        pslld     $11, %xmm3
        psrld     $21, %xmm12
        pxor      %xmm14, %xmm11
        movdqa    %xmm7, %xmm2
        paddd     %xmm7, %xmm4
        por       %xmm12, %xmm3
        paddd     %xmm5, %xmm10
        pxor      %xmm0, %xmm11
        pxor      %xmm9, %xmm2
        movdqa    %xmm13, %xmm12
        paddd     %xmm13, %xmm3
        paddd     %xmm11, %xmm10
        paddd     %xmm5, %xmm1
        pxor      %xmm4, %xmm2
        pxor      %xmm6, %xmm12
        paddd     %xmm2, %xmm1
        paddd     240(%rsp), %xmm10
        paddd     %xmm5, %xmm15
        pxor      %xmm3, %xmm12
        movdqa    %xmm10, %xmm2
        paddd     304(%rsp), %xmm1
        paddd     %xmm12, %xmm15
        paddd     320(%rsp), %xmm15
        pslld     $16, %xmm2
        psrld     $16, %xmm10
        movdqa    %xmm1, %xmm11
        por       %xmm10, %xmm2
        pslld     $16, %xmm11
        psrld     $16, %xmm1
        movdqa    %xmm15, %xmm10
        por       %xmm1, %xmm11
        pslld     $16, %xmm10
        psrld     $16, %xmm15
        movdqa    %xmm0, %xmm1
        movdqa    .L_2il0floatpacket.100(%rip), %xmm5
        paddd     %xmm0, %xmm2
        por       %xmm15, %xmm10
        pxor      %xmm8, %xmm1
        movdqa    %xmm4, %xmm15
        paddd     %xmm4, %xmm11
        paddd     %xmm5, %xmm14
        pxor      %xmm2, %xmm1
        pxor      %xmm7, %xmm15
        paddd     %xmm1, %xmm14
        paddd     %xmm5, %xmm9
        pxor      %xmm11, %xmm15
        movdqa    %xmm3, %xmm1
        paddd     %xmm3, %xmm10
        paddd     %xmm15, %xmm9
        pxor      %xmm13, %xmm1
        paddd     656(%rsp), %xmm9
        paddd     %xmm5, %xmm6
        pxor      %xmm10, %xmm1
        movdqa    %xmm9, %xmm12
        paddd     %xmm1, %xmm6
        pslld     $23, %xmm12
        movdqa    720(%rsp), %xmm1
        psrld     $9, %xmm9
        paddd     672(%rsp), %xmm14
        paddd     %xmm1, %xmm6
        movdqa    %xmm14, %xmm5
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        pslld     $23, %xmm5
        psrld     $9, %xmm14
        pslld     $23, %xmm9
        psrld     $9, %xmm6
        por       %xmm14, %xmm5
        por       %xmm6, %xmm9
        movdqa    %xmm2, %xmm6
        movdqa    .L_2il0floatpacket.101(%rip), %xmm15
        paddd     %xmm2, %xmm5
        pxor      %xmm0, %xmm6
        paddd     %xmm15, %xmm8
        pxor      %xmm5, %xmm6
        movdqa    %xmm11, %xmm14
        paddd     %xmm6, %xmm8
        movdqa    %xmm10, %xmm6
        paddd     %xmm11, %xmm12
        paddd     %xmm10, %xmm9
        pxor      %xmm4, %xmm14
        pxor      %xmm3, %xmm6
        paddd     144(%rsp), %xmm8
        paddd     %xmm15, %xmm7
        pxor      %xmm12, %xmm14
        paddd     %xmm15, %xmm13
        pxor      %xmm9, %xmm6
        paddd     %xmm14, %xmm7
        paddd     %xmm6, %xmm13
        movdqa    %xmm8, %xmm6
        paddd     112(%rsp), %xmm7
        pslld     $4, %xmm6
        psrld     $28, %xmm8
        paddd     96(%rsp), %xmm13
        por       %xmm8, %xmm6
        movdqa    %xmm7, %xmm8
        psrld     $28, %xmm7
        pslld     $4, %xmm8
        movdqa    %xmm13, %xmm14
        por       %xmm7, %xmm8
        pslld     $4, %xmm14
        psrld     $28, %xmm13
        movdqa    %xmm5, %xmm7
        paddd     %xmm5, %xmm6
        por       %xmm13, %xmm14
        movdqa    .L_2il0floatpacket.102(%rip), %xmm13
        pxor      %xmm2, %xmm7
        paddd     %xmm13, %xmm0
        pxor      %xmm6, %xmm7
        paddd     %xmm7, %xmm0
        paddd     %xmm12, %xmm8
        paddd     48(%rsp), %xmm0
        paddd     %xmm9, %xmm14
        movdqa    752(%rsp), %xmm7
        paddd     %xmm13, %xmm4
        movdqa    736(%rsp), %xmm13
..B6.9:
        movdqa    %xmm1, 720(%rsp)
        movdqa    %xmm12, %xmm1
        pxor      %xmm11, %xmm1
        movdqa    %xmm9, %xmm15
        pxor      %xmm8, %xmm1
        pxor      %xmm10, %xmm15
        paddd     %xmm1, %xmm4
        movdqa    %xmm0, %xmm1
        paddd     80(%rsp), %xmm4
        pxor      %xmm14, %xmm15
        paddd     .L_2il0floatpacket.102(%rip), %xmm3
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        paddd     %xmm15, %xmm3
        por       %xmm0, %xmm1
        movdqa    %xmm4, %xmm0
        paddd     64(%rsp), %xmm3
        pslld     $11, %xmm0
        psrld     $21, %xmm4
        movdqa    %xmm6, %xmm15
        por       %xmm4, %xmm0
        movdqa    %xmm3, %xmm4
        pslld     $11, %xmm4
        psrld     $21, %xmm3
        paddd     %xmm6, %xmm1
        por       %xmm3, %xmm4
        movdqa    .L_2il0floatpacket.103(%rip), %xmm3
        pxor      %xmm5, %xmm15
        paddd     %xmm3, %xmm2
        pxor      %xmm1, %xmm15
        paddd     %xmm15, %xmm2
        paddd     %xmm3, %xmm11
        movdqa    %xmm8, %xmm15
        paddd     %xmm3, %xmm10
        movdqa    %xmm14, %xmm3
        paddd     %xmm8, %xmm0
        paddd     %xmm14, %xmm4
        pxor      %xmm12, %xmm15
        pxor      %xmm9, %xmm3
        pxor      %xmm0, %xmm15
        paddd     592(%rsp), %xmm2
        pxor      %xmm4, %xmm3
        paddd     %xmm15, %xmm11
        paddd     %xmm3, %xmm10
        movdqa    %xmm2, %xmm3
        psrld     $16, %xmm2
        paddd     560(%rsp), %xmm11
        pslld     $16, %xmm3
        por       %xmm2, %xmm3
        movdqa    %xmm11, %xmm2
        paddd     544(%rsp), %xmm10
        pslld     $16, %xmm2
        psrld     $16, %xmm11
        movdqa    %xmm6, %xmm15
        por       %xmm11, %xmm2
        movdqa    %xmm10, %xmm11
        pslld     $16, %xmm11
        psrld     $16, %xmm10
        paddd     %xmm1, %xmm3
        por       %xmm10, %xmm11
        movdqa    .L_2il0floatpacket.104(%rip), %xmm10
        pxor      %xmm1, %xmm15
        paddd     %xmm10, %xmm5
        pxor      %xmm3, %xmm15
        paddd     %xmm15, %xmm5
        paddd     %xmm10, %xmm12
        movdqa    %xmm8, %xmm15
        paddd     %xmm10, %xmm9
        movdqa    %xmm14, %xmm10
        paddd     %xmm0, %xmm2
        paddd     %xmm4, %xmm11
        pxor      %xmm0, %xmm15
        pxor      %xmm4, %xmm10
        pxor      %xmm2, %xmm15
        paddd     528(%rsp), %xmm5
        pxor      %xmm11, %xmm10
        paddd     %xmm15, %xmm12
        paddd     %xmm10, %xmm9
        movdqa    %xmm5, %xmm10
        psrld     $9, %xmm5
        paddd     496(%rsp), %xmm12
        pslld     $23, %xmm10
        por       %xmm5, %xmm10
        movdqa    %xmm12, %xmm5
        paddd     512(%rsp), %xmm9
        pslld     $23, %xmm5
        psrld     $9, %xmm12
        movdqa    %xmm3, %xmm15
        por       %xmm12, %xmm5
        movdqa    %xmm9, %xmm12
        pslld     $23, %xmm12
        psrld     $9, %xmm9
        paddd     %xmm3, %xmm10
        por       %xmm9, %xmm12
        movdqa    .L_2il0floatpacket.105(%rip), %xmm9
        pxor      %xmm1, %xmm15
        paddd     %xmm9, %xmm6
        pxor      %xmm10, %xmm15
        paddd     %xmm15, %xmm6
        paddd     %xmm9, %xmm8
        movdqa    %xmm2, %xmm15
        paddd     %xmm9, %xmm14
        movdqa    %xmm11, %xmm9
        paddd     %xmm2, %xmm5
        paddd     %xmm11, %xmm12
        pxor      %xmm0, %xmm15
        pxor      %xmm4, %xmm9
        pxor      %xmm5, %xmm15
        paddd     400(%rsp), %xmm6
        pxor      %xmm12, %xmm9
        paddd     %xmm15, %xmm8
        paddd     %xmm9, %xmm14
        movdqa    %xmm6, %xmm9
        psrld     $28, %xmm6
        paddd     464(%rsp), %xmm8
        pslld     $4, %xmm9
        por       %xmm6, %xmm9
        movdqa    %xmm8, %xmm6
        paddd     480(%rsp), %xmm14
        pslld     $4, %xmm6
        psrld     $28, %xmm8
        movdqa    %xmm10, %xmm15
        por       %xmm8, %xmm6
        movdqa    %xmm14, %xmm8
        pslld     $4, %xmm8
        psrld     $28, %xmm14
        paddd     %xmm10, %xmm9
        por       %xmm14, %xmm8
        movdqa    .L_2il0floatpacket.106(%rip), %xmm14
        pxor      %xmm3, %xmm15
        paddd     %xmm14, %xmm1
        pxor      %xmm9, %xmm15
        paddd     %xmm14, %xmm0
        paddd     %xmm14, %xmm4
        movdqa    %xmm12, %xmm14
        paddd     %xmm12, %xmm8
        paddd     %xmm15, %xmm1
        movdqa    %xmm5, %xmm15
        pxor      %xmm11, %xmm14
        paddd     %xmm5, %xmm6
        pxor      %xmm2, %xmm15
        pxor      %xmm8, %xmm14
        paddd     704(%rsp), %xmm1
        pxor      %xmm6, %xmm15
        paddd     %xmm14, %xmm4
        paddd     %xmm15, %xmm0
        paddd     384(%rsp), %xmm4
        movdqa    %xmm1, %xmm14
        paddd     688(%rsp), %xmm0
        pslld     $11, %xmm14
        psrld     $21, %xmm1
        movdqa    %xmm4, %xmm15
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        pslld     $11, %xmm15
        psrld     $21, %xmm4
        pslld     $11, %xmm1
        psrld     $21, %xmm0
        por       %xmm4, %xmm15
        movdqa    %xmm9, %xmm4
        paddd     %xmm9, %xmm14
        por       %xmm0, %xmm1
        movdqa    .L_2il0floatpacket.107(%rip), %xmm0
        pxor      %xmm10, %xmm4
        paddd     %xmm0, %xmm3
        pxor      %xmm14, %xmm4
        paddd     %xmm4, %xmm3
        paddd     %xmm0, %xmm2
        movdqa    %xmm6, %xmm4
        paddd     %xmm0, %xmm11
        movdqa    %xmm8, %xmm0
        paddd     %xmm6, %xmm1
        paddd     %xmm8, %xmm15
        pxor      %xmm5, %xmm4
        pxor      %xmm12, %xmm0
        pxor      %xmm1, %xmm4
        paddd     256(%rsp), %xmm3
        pxor      %xmm15, %xmm0
        paddd     %xmm4, %xmm2
        paddd     %xmm0, %xmm11
        movdqa    %xmm3, %xmm0
        psrld     $16, %xmm3
        paddd     272(%rsp), %xmm2
        pslld     $16, %xmm0
        por       %xmm3, %xmm0
        movdqa    %xmm2, %xmm3
        paddd     288(%rsp), %xmm11
        pslld     $16, %xmm3
        psrld     $16, %xmm2
        paddd     %xmm14, %xmm0
        por       %xmm2, %xmm3
        movdqa    %xmm11, %xmm2
        pslld     $16, %xmm2
        psrld     $16, %xmm11
        por       %xmm11, %xmm2
        movdqa    %xmm14, %xmm11
        movdqa    .L_2il0floatpacket.108(%rip), %xmm4
        pxor      %xmm9, %xmm11
        paddd     %xmm4, %xmm10
        pxor      %xmm0, %xmm11
        paddd     %xmm11, %xmm10
        movdqa    %xmm1, %xmm11
        paddd     %xmm1, %xmm3
        pxor      %xmm6, %xmm11
        paddd     192(%rsp), %xmm10
        paddd     %xmm4, %xmm5
        pxor      %xmm3, %xmm11
        paddd     %xmm4, %xmm12
        movdqa    %xmm15, %xmm4
        paddd     %xmm15, %xmm2
        paddd     %xmm11, %xmm5
        pxor      %xmm8, %xmm4
        movdqa    %xmm10, %xmm11
        pxor      %xmm2, %xmm4
        paddd     176(%rsp), %xmm5
        pslld     $23, %xmm11
        psrld     $9, %xmm10
        paddd     %xmm4, %xmm12
        por       %xmm10, %xmm11
        movdqa    %xmm5, %xmm10
        paddd     160(%rsp), %xmm12
        pslld     $23, %xmm10
        psrld     $9, %xmm5
        movdqa    %xmm0, %xmm4
        por       %xmm5, %xmm10
        movdqa    %xmm12, %xmm5
        pslld     $23, %xmm5
        psrld     $9, %xmm12
        paddd     %xmm0, %xmm11
        por       %xmm12, %xmm5
        movdqa    .L_2il0floatpacket.109(%rip), %xmm12
        pxor      %xmm14, %xmm4
        paddd     %xmm12, %xmm9
        pxor      %xmm11, %xmm4
        paddd     %xmm4, %xmm9
        paddd     %xmm12, %xmm6
        movdqa    %xmm3, %xmm4
        paddd     %xmm12, %xmm8
        movdqa    %xmm2, %xmm12
        paddd     %xmm3, %xmm10
        paddd     %xmm2, %xmm5
        pxor      %xmm1, %xmm4
        pxor      %xmm15, %xmm12
        pxor      %xmm10, %xmm4
        paddd     128(%rsp), %xmm9
        pxor      %xmm5, %xmm12
        paddd     %xmm4, %xmm6
        paddd     %xmm12, %xmm8
        movdqa    %xmm9, %xmm12
        psrld     $28, %xmm9
        paddd     208(%rsp), %xmm6
        pslld     $4, %xmm12
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        paddd     224(%rsp), %xmm8
        pslld     $4, %xmm9
        psrld     $28, %xmm6
        movdqa    %xmm11, %xmm4
        por       %xmm6, %xmm9
        movdqa    %xmm8, %xmm6
        pslld     $4, %xmm6
        psrld     $28, %xmm8
        paddd     %xmm11, %xmm12
        por       %xmm8, %xmm6
        movdqa    .L_2il0floatpacket.110(%rip), %xmm8
        pxor      %xmm0, %xmm4
        paddd     %xmm8, %xmm14
        pxor      %xmm12, %xmm4
        paddd     %xmm4, %xmm14
        movdqa    %xmm10, %xmm4
        paddd     %xmm10, %xmm9
        paddd     %xmm8, %xmm1
        pxor      %xmm3, %xmm4
        paddd     %xmm8, %xmm15
        movdqa    %xmm5, %xmm8
        paddd     %xmm5, %xmm6
        pxor      %xmm9, %xmm4
        pxor      %xmm2, %xmm8
        paddd     624(%rsp), %xmm14
        paddd     %xmm4, %xmm1
        pxor      %xmm6, %xmm8
        paddd     608(%rsp), %xmm1
        paddd     %xmm8, %xmm15
        movdqa    %xmm14, %xmm8
        psrld     $21, %xmm14
        paddd     640(%rsp), %xmm15
        pslld     $11, %xmm8
        movdqa    %xmm1, %xmm4
        por       %xmm14, %xmm8
        pslld     $11, %xmm4
        psrld     $21, %xmm1
        movdqa    %xmm15, %xmm14
        por       %xmm1, %xmm4
        pslld     $11, %xmm14
        psrld     $21, %xmm15
        movdqa    %xmm12, %xmm1
        paddd     %xmm12, %xmm8
        por       %xmm15, %xmm14
        pxor      %xmm11, %xmm1
        movdqa    .L_2il0floatpacket.111(%rip), %xmm15
        pxor      %xmm8, %xmm1
        paddd     %xmm15, %xmm0
        paddd     %xmm9, %xmm4
        paddd     %xmm1, %xmm0
        movdqa    %xmm9, %xmm1
        paddd     %xmm15, %xmm3
        pxor      %xmm10, %xmm1
        paddd     %xmm15, %xmm2
        movdqa    %xmm6, %xmm15
        paddd     %xmm6, %xmm14
        pxor      %xmm4, %xmm1
        pxor      %xmm5, %xmm15
        paddd     %xmm1, %xmm3
        pxor      %xmm14, %xmm15
        paddd     %xmm13, %xmm3
        paddd     %xmm15, %xmm2
        movdqa    %xmm7, 752(%rsp)
        paddd     %xmm7, %xmm2
        movdqa    %xmm3, %xmm7
        psrld     $16, %xmm3
        paddd     576(%rsp), %xmm0
        pslld     $16, %xmm7
        movdqa    %xmm0, %xmm1
        por       %xmm3, %xmm7
        movdqa    %xmm2, %xmm3
        pslld     $16, %xmm1
        psrld     $16, %xmm0
        pslld     $16, %xmm3
        psrld     $16, %xmm2
        por       %xmm0, %xmm1
        movdqa    %xmm4, %xmm0
        por       %xmm2, %xmm3
        movdqa    %xmm8, %xmm2
        paddd     %xmm4, %xmm7
        movdqa    .L_2il0floatpacket.112(%rip), %xmm15
        pxor      %xmm9, %xmm0
        paddd     %xmm8, %xmm1
        pxor      %xmm12, %xmm2
        paddd     %xmm15, %xmm10
        pxor      %xmm7, %xmm0
        paddd     %xmm15, %xmm11
        pxor      %xmm1, %xmm2
        paddd     %xmm0, %xmm10
        movdqa    %xmm14, %xmm0
        paddd     %xmm2, %xmm11
        paddd     %xmm14, %xmm3
        pxor      %xmm6, %xmm0
        paddd     %xmm15, %xmm5
        paddd     (%rsp), %xmm11
        pxor      %xmm3, %xmm0
        paddd     16(%rsp), %xmm10
        movdqa    %xmm11, %xmm2
        paddd     %xmm0, %xmm5
        movdqa    %xmm10, %xmm0
        pslld     $23, %xmm2
        psrld     $9, %xmm11
        paddd     32(%rsp), %xmm5
        pslld     $23, %xmm0
        psrld     $9, %xmm10
        por       %xmm11, %xmm2
        por       %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        movdqa    %xmm8, %xmm15
        pcmpeqd   %xmm11, %xmm11
        paddd     %xmm1, %xmm2
        pslld     $23, %xmm10
        psrld     $9, %xmm5
        pandn     %xmm11, %xmm15
        por       %xmm5, %xmm10
        por       %xmm2, %xmm15
        movdqa    .L_2il0floatpacket.113(%rip), %xmm5
        pxor      %xmm1, %xmm15
        paddd     %xmm5, %xmm12
        paddd     %xmm5, %xmm9
        paddd     %xmm15, %xmm12
        movdqa    %xmm4, %xmm15
        paddd     %xmm5, %xmm6
        movdqa    %xmm14, %xmm5
        paddd     %xmm7, %xmm0
        paddd     %xmm3, %xmm10
        pandn     %xmm11, %xmm15
        pandn     %xmm11, %xmm5
        por       %xmm0, %xmm15
        por       %xmm10, %xmm5
        paddd     704(%rsp), %xmm12
        pxor      %xmm7, %xmm15
        pxor      %xmm3, %xmm5
        paddd     %xmm15, %xmm9
        paddd     %xmm5, %xmm6
        movdqa    %xmm12, %xmm5
        paddd     688(%rsp), %xmm9
        pslld     $6, %xmm5
        psrld     $26, %xmm12
        movdqa    %xmm1, %xmm15
        por       %xmm12, %xmm5
        movdqa    %xmm9, %xmm12
        paddd     384(%rsp), %xmm6
        pslld     $6, %xmm12
        psrld     $26, %xmm9
        paddd     %xmm2, %xmm5
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        pslld     $6, %xmm9
        psrld     $26, %xmm6
        pandn     %xmm11, %xmm15
        por       %xmm6, %xmm9
        movdqa    .L_2il0floatpacket.114(%rip), %xmm6
        por       %xmm5, %xmm15
        paddd     %xmm6, %xmm8
        pxor      %xmm2, %xmm15
        paddd     %xmm15, %xmm8
        paddd     %xmm6, %xmm4
        movdqa    %xmm7, %xmm15
        paddd     %xmm6, %xmm14
        movdqa    %xmm3, %xmm6
        paddd     %xmm0, %xmm12
        paddd     %xmm10, %xmm9
        pandn     %xmm11, %xmm15
        pandn     %xmm11, %xmm6
        por       %xmm12, %xmm15
        por       %xmm9, %xmm6
        pxor      %xmm0, %xmm15
        paddd     592(%rsp), %xmm8
        pxor      %xmm10, %xmm6
        paddd     %xmm15, %xmm4
        paddd     %xmm6, %xmm14
        movdqa    %xmm8, %xmm6
        psrld     $22, %xmm8
        paddd     560(%rsp), %xmm4
        pslld     $10, %xmm6
        por       %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        paddd     544(%rsp), %xmm14
        pslld     $10, %xmm8
        psrld     $22, %xmm4
        movdqa    %xmm2, %xmm15
        por       %xmm4, %xmm8
        movdqa    %xmm14, %xmm4
        paddd     %xmm5, %xmm6
        pslld     $10, %xmm4
        psrld     $22, %xmm14
        pandn     %xmm11, %xmm15
        por       %xmm14, %xmm4
        por       %xmm6, %xmm15
        movdqa    .L_2il0floatpacket.115(%rip), %xmm14
        pxor      %xmm5, %xmm15
        paddd     %xmm14, %xmm1
        paddd     %xmm14, %xmm7
        paddd     %xmm15, %xmm1
        movdqa    %xmm0, %xmm15
        paddd     %xmm14, %xmm3
        movdqa    %xmm10, %xmm14
        paddd     %xmm12, %xmm8
        paddd     %xmm9, %xmm4
        pandn     %xmm11, %xmm15
        pandn     %xmm11, %xmm14
        por       %xmm8, %xmm15
        por       %xmm4, %xmm14
        paddd     672(%rsp), %xmm1
        pxor      %xmm12, %xmm15
        pxor      %xmm9, %xmm14
        paddd     %xmm15, %xmm7
        paddd     %xmm14, %xmm3
        movdqa    %xmm1, %xmm14
        paddd     656(%rsp), %xmm7
        pslld     $15, %xmm14
        psrld     $17, %xmm1
        por       %xmm1, %xmm14
        movdqa    %xmm7, %xmm1
        paddd     720(%rsp), %xmm3
        pslld     $15, %xmm1
        psrld     $17, %xmm7
        movdqa    %xmm3, %xmm15
        por       %xmm7, %xmm1
        movdqa    %xmm5, %xmm7
        paddd     %xmm6, %xmm14
        pslld     $15, %xmm15
        psrld     $17, %xmm3
        pandn     %xmm11, %xmm7
        por       %xmm3, %xmm15
        por       %xmm14, %xmm7
        movdqa    .L_2il0floatpacket.116(%rip), %xmm3
        pxor      %xmm6, %xmm7
        paddd     %xmm3, %xmm2
        paddd     %xmm8, %xmm1
        paddd     %xmm4, %xmm15
        paddd     %xmm7, %xmm2
        movdqa    752(%rsp), %xmm7
..B6.8:
        movdqa    %xmm7, 752(%rsp)
        paddd     %xmm3, %xmm0
        movdqa    %xmm12, %xmm11
        pcmpeqd   %xmm7, %xmm7
        paddd     %xmm3, %xmm10
        movdqa    %xmm9, %xmm3
        pandn     %xmm7, %xmm11
        pandn     %xmm7, %xmm3
        por       %xmm1, %xmm11
        por       %xmm15, %xmm3
        paddd     432(%rsp), %xmm2
        pxor      %xmm8, %xmm11
        pxor      %xmm4, %xmm3
        paddd     %xmm11, %xmm0
        paddd     %xmm3, %xmm10
        movdqa    %xmm2, %xmm3
        paddd     448(%rsp), %xmm0
        pslld     $21, %xmm3
        psrld     $11, %xmm2
        movdqa    %xmm6, %xmm11
        por       %xmm2, %xmm3
        movdqa    %xmm0, %xmm2
        paddd     416(%rsp), %xmm10
        pslld     $21, %xmm2
        psrld     $11, %xmm0
        paddd     %xmm14, %xmm3
        por       %xmm0, %xmm2
        movdqa    %xmm10, %xmm0
        pslld     $21, %xmm0
        psrld     $11, %xmm10
        pandn     %xmm7, %xmm11
        por       %xmm10, %xmm0
        movdqa    .L_2il0floatpacket.117(%rip), %xmm10
        por       %xmm3, %xmm11
        paddd     %xmm10, %xmm5
        pxor      %xmm14, %xmm11
        paddd     %xmm11, %xmm5
        paddd     %xmm10, %xmm12
        movdqa    %xmm8, %xmm11
        paddd     %xmm10, %xmm9
        movdqa    %xmm4, %xmm10
        paddd     %xmm1, %xmm2
        paddd     %xmm15, %xmm0
        pandn     %xmm7, %xmm11
        pandn     %xmm7, %xmm10
        por       %xmm2, %xmm11
        por       %xmm0, %xmm10
        pxor      %xmm1, %xmm11
        paddd     624(%rsp), %xmm5
        pxor      %xmm15, %xmm10
        paddd     %xmm11, %xmm12
        paddd     %xmm10, %xmm9
        movdqa    %xmm5, %xmm10
        psrld     $26, %xmm5
        paddd     608(%rsp), %xmm12
        pslld     $6, %xmm10
        por       %xmm5, %xmm10
        movdqa    %xmm12, %xmm5
        paddd     640(%rsp), %xmm9
        pslld     $6, %xmm5
        psrld     $26, %xmm12
        paddd     %xmm3, %xmm10
        por       %xmm12, %xmm5
        movdqa    %xmm9, %xmm12
        pslld     $6, %xmm12
        psrld     $26, %xmm9
        por       %xmm9, %xmm12
        movdqa    %xmm14, %xmm9
        pandn     %xmm7, %xmm9
        paddd     %xmm2, %xmm5
        movdqa    .L_2il0floatpacket.118(%rip), %xmm11
        por       %xmm10, %xmm9
        paddd     %xmm11, %xmm6
        pxor      %xmm3, %xmm9
        paddd     %xmm9, %xmm6
        movdqa    %xmm1, %xmm9
        pandn     %xmm7, %xmm9
        paddd     %xmm11, %xmm8
        por       %xmm5, %xmm9
        paddd     %xmm11, %xmm4
        movdqa    %xmm15, %xmm11
        paddd     %xmm0, %xmm12
        paddd     256(%rsp), %xmm6
        pxor      %xmm2, %xmm9
        pandn     %xmm7, %xmm11
        paddd     %xmm9, %xmm8
        por       %xmm12, %xmm11
        movdqa    %xmm6, %xmm9
        paddd     272(%rsp), %xmm8
        pxor      %xmm0, %xmm11
        pslld     $10, %xmm9
        psrld     $22, %xmm6
        paddd     %xmm11, %xmm4
        por       %xmm6, %xmm9
        movdqa    %xmm8, %xmm6
        psrld     $22, %xmm8
        paddd     288(%rsp), %xmm4
        pslld     $10, %xmm6
        por       %xmm8, %xmm6
        movdqa    %xmm4, %xmm8
        movdqa    %xmm3, %xmm11
        paddd     %xmm10, %xmm9
        pslld     $10, %xmm8
        psrld     $22, %xmm4
        pandn     %xmm7, %xmm11
        por       %xmm4, %xmm8
        movdqa    .L_2il0floatpacket.119(%rip), %xmm4
        por       %xmm9, %xmm11
        paddd     %xmm4, %xmm14
        pxor      %xmm10, %xmm11
        paddd     %xmm11, %xmm14
        paddd     %xmm4, %xmm1
        movdqa    %xmm2, %xmm11
        paddd     %xmm4, %xmm15
        movdqa    %xmm0, %xmm4
        paddd     %xmm5, %xmm6
        paddd     %xmm12, %xmm8
        pandn     %xmm7, %xmm11
        pandn     %xmm7, %xmm4
        por       %xmm6, %xmm11
        por       %xmm8, %xmm4
        pxor      %xmm5, %xmm11
        paddd     528(%rsp), %xmm14
        pxor      %xmm12, %xmm4
        paddd     %xmm11, %xmm1
        paddd     %xmm4, %xmm15
        movdqa    %xmm14, %xmm4
        psrld     $17, %xmm14
        paddd     496(%rsp), %xmm1
        pslld     $15, %xmm4
        por       %xmm14, %xmm4
        movdqa    %xmm1, %xmm14
        paddd     512(%rsp), %xmm15
        pslld     $15, %xmm14
        psrld     $17, %xmm1
        movdqa    %xmm10, %xmm11
        por       %xmm1, %xmm14
        movdqa    %xmm15, %xmm1
        paddd     %xmm9, %xmm4
        pslld     $15, %xmm1
        psrld     $17, %xmm15
        pandn     %xmm7, %xmm11
        por       %xmm15, %xmm1
        por       %xmm4, %xmm11
        movdqa    .L_2il0floatpacket.120(%rip), %xmm15
        pxor      %xmm9, %xmm11
        paddd     %xmm15, %xmm3
        paddd     %xmm6, %xmm14
        paddd     %xmm11, %xmm3
        movdqa    %xmm5, %xmm11
        pandn     %xmm7, %xmm11
        paddd     %xmm15, %xmm2
        por       %xmm14, %xmm11
        paddd     %xmm15, %xmm0
        movdqa    %xmm12, %xmm15
        paddd     %xmm8, %xmm1
        pxor      %xmm6, %xmm11
        pandn     %xmm7, %xmm15
        paddd     %xmm11, %xmm2
        por       %xmm1, %xmm15
        paddd     144(%rsp), %xmm3
        pxor      %xmm8, %xmm15
        paddd     112(%rsp), %xmm2
        paddd     %xmm15, %xmm0
        movdqa    %xmm3, %xmm11
        movdqa    %xmm2, %xmm15
        paddd     96(%rsp), %xmm0
        pslld     $21, %xmm11
        psrld     $11, %xmm3
        pslld     $21, %xmm15
        psrld     $11, %xmm2
        por       %xmm3, %xmm11
        por       %xmm2, %xmm15
        movdqa    %xmm0, %xmm2
        movdqa    %xmm9, %xmm3
        paddd     %xmm4, %xmm11
        pslld     $21, %xmm2
        psrld     $11, %xmm0
        pandn     %xmm7, %xmm3
        por       %xmm0, %xmm2
        movdqa    .L_2il0floatpacket.121(%rip), %xmm0
        por       %xmm11, %xmm3
        paddd     %xmm0, %xmm10
        pxor      %xmm4, %xmm3
        paddd     %xmm3, %xmm10
        paddd     %xmm0, %xmm5
        movdqa    %xmm6, %xmm3
        paddd     %xmm0, %xmm12
        movdqa    %xmm8, %xmm0
        paddd     %xmm14, %xmm15
        paddd     %xmm1, %xmm2
        pandn     %xmm7, %xmm3
        pandn     %xmm7, %xmm0
        por       %xmm15, %xmm3
        por       %xmm2, %xmm0
        pxor      %xmm14, %xmm3
        paddd     368(%rsp), %xmm10
        pxor      %xmm1, %xmm0
        paddd     %xmm3, %xmm5
        paddd     %xmm0, %xmm12
        movdqa    %xmm10, %xmm0
        psrld     $26, %xmm10
        paddd     352(%rsp), %xmm5
        pslld     $6, %xmm0
        por       %xmm10, %xmm0
        movdqa    %xmm5, %xmm10
        paddd     336(%rsp), %xmm12
        pslld     $6, %xmm10
        psrld     $26, %xmm5
        paddd     %xmm11, %xmm0
        por       %xmm5, %xmm10
        movdqa    %xmm12, %xmm5
        pslld     $6, %xmm5
        psrld     $26, %xmm12
        por       %xmm12, %xmm5
        movdqa    %xmm4, %xmm12
        pandn     %xmm7, %xmm12
        paddd     %xmm15, %xmm10
        movdqa    .L_2il0floatpacket.122(%rip), %xmm3
        por       %xmm0, %xmm12
        paddd     %xmm3, %xmm9
        pxor      %xmm11, %xmm12
        paddd     %xmm12, %xmm9
        movdqa    %xmm14, %xmm12
        pandn     %xmm7, %xmm12
        paddd     %xmm3, %xmm6
        por       %xmm10, %xmm12
        paddd     %xmm2, %xmm5
        pxor      %xmm15, %xmm12
        paddd     %xmm3, %xmm8
        paddd     576(%rsp), %xmm9
        paddd     %xmm12, %xmm6
        paddd     %xmm13, %xmm6
        movdqa    %xmm1, %xmm13
        movdqa    %xmm9, %xmm12
        pandn     %xmm7, %xmm13
        pslld     $10, %xmm12
        psrld     $22, %xmm9
        por       %xmm5, %xmm13
        por       %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        pxor      %xmm2, %xmm13
        pslld     $10, %xmm9
        psrld     $22, %xmm6
        paddd     %xmm13, %xmm8
        por       %xmm6, %xmm9
        movdqa    %xmm11, %xmm6
        paddd     %xmm0, %xmm12
        paddd     752(%rsp), %xmm8
        pandn     %xmm7, %xmm6
        movdqa    .L_2il0floatpacket.123(%rip), %xmm3
        movdqa    %xmm8, %xmm13
        por       %xmm12, %xmm6
        pslld     $10, %xmm13
        psrld     $22, %xmm8
        paddd     %xmm3, %xmm4
        pxor      %xmm0, %xmm6
        por       %xmm8, %xmm13
        paddd     %xmm6, %xmm4
        movdqa    %xmm15, %xmm8
        movdqa    %xmm2, %xmm6
        paddd     %xmm10, %xmm9
        paddd     %xmm5, %xmm13
        pandn     %xmm7, %xmm8
        pandn     %xmm7, %xmm6
        por       %xmm9, %xmm8
        por       %xmm13, %xmm6
        paddd     %xmm3, %xmm14
        paddd     192(%rsp), %xmm4
        pxor      %xmm10, %xmm8
        paddd     %xmm3, %xmm1
        pxor      %xmm5, %xmm6
        paddd     %xmm8, %xmm14
        paddd     %xmm6, %xmm1
        movdqa    %xmm4, %xmm6
        psrld     $17, %xmm4
        paddd     176(%rsp), %xmm14
        pslld     $15, %xmm6
        por       %xmm4, %xmm6
        movdqa    %xmm14, %xmm4
        paddd     160(%rsp), %xmm1
        pslld     $15, %xmm4
        psrld     $17, %xmm14
        paddd     %xmm12, %xmm6
        por       %xmm14, %xmm4
        movdqa    %xmm1, %xmm14
        pslld     $15, %xmm14
        psrld     $17, %xmm1
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        pandn     %xmm7, %xmm1
        paddd     %xmm13, %xmm14
        movdqa    .L_2il0floatpacket.124(%rip), %xmm8
        por       %xmm6, %xmm1
        paddd     %xmm8, %xmm11
        pxor      %xmm12, %xmm1
        paddd     %xmm1, %xmm11
        movdqa    %xmm5, %xmm1
        pandn     %xmm7, %xmm1
        paddd     %xmm8, %xmm2
        por       %xmm14, %xmm1
        movdqa    %xmm10, %xmm3
        pxor      %xmm13, %xmm1
        paddd     %xmm9, %xmm4
        paddd     %xmm1, %xmm2
        pandn     %xmm7, %xmm3
        paddd     400(%rsp), %xmm11
        paddd     %xmm8, %xmm15
        paddd     480(%rsp), %xmm2
        por       %xmm4, %xmm3
        movdqa    %xmm11, %xmm8
        movdqa    %xmm2, %xmm1
        pxor      %xmm9, %xmm3
        pslld     $21, %xmm8
        psrld     $11, %xmm11
        pslld     $21, %xmm1
        psrld     $11, %xmm2
        paddd     %xmm3, %xmm15
        por       %xmm11, %xmm8
        por       %xmm2, %xmm1
        movdqa    %xmm12, %xmm2
        paddd     %xmm6, %xmm8
        paddd     464(%rsp), %xmm15
        pandn     %xmm7, %xmm2
        movdqa    .L_2il0floatpacket.125(%rip), %xmm11
        movdqa    %xmm15, %xmm3
        por       %xmm8, %xmm2
        pslld     $21, %xmm3
        psrld     $11, %xmm15
        paddd     %xmm11, %xmm0
        pxor      %xmm6, %xmm2
        por       %xmm15, %xmm3
        paddd     %xmm2, %xmm0
        movdqa    %xmm9, %xmm15
        movdqa    %xmm13, %xmm2
        paddd     %xmm4, %xmm3
        paddd     %xmm14, %xmm1
        pandn     %xmm7, %xmm15
        pandn     %xmm7, %xmm2
        por       %xmm3, %xmm15
        por       %xmm1, %xmm2
        paddd     %xmm11, %xmm10
        paddd     48(%rsp), %xmm0
        pxor      %xmm4, %xmm15
        paddd     %xmm11, %xmm5
        pxor      %xmm14, %xmm2
        paddd     %xmm15, %xmm10
        paddd     %xmm2, %xmm5
        movdqa    %xmm0, %xmm15
        psrld     $26, %xmm0
        paddd     64(%rsp), %xmm5
        pslld     $6, %xmm15
        por       %xmm0, %xmm15
        movdqa    %xmm5, %xmm0
        paddd     80(%rsp), %xmm10
        pslld     $6, %xmm0
        psrld     $26, %xmm5
        movdqa    %xmm10, %xmm2
        por       %xmm5, %xmm0
        movdqa    %xmm6, %xmm5
        paddd     %xmm8, %xmm15
        pslld     $6, %xmm2
        psrld     $26, %xmm10
        pandn     %xmm7, %xmm5
        movdqa    .L_2il0floatpacket.126(%rip), %xmm11
        por       %xmm10, %xmm2
        por       %xmm15, %xmm5
        movdqa    %xmm4, %xmm10
        paddd     %xmm3, %xmm2
        paddd     %xmm11, %xmm12
        pxor      %xmm8, %xmm5
        pandn     %xmm7, %xmm10
        paddd     %xmm5, %xmm12
        por       %xmm2, %xmm10
        movdqa    %xmm14, %xmm5
        paddd     %xmm1, %xmm0
        paddd     %xmm11, %xmm9
        pxor      %xmm3, %xmm10
        pandn     %xmm7, %xmm5
        paddd     %xmm10, %xmm9
        por       %xmm0, %xmm5
        paddd     %xmm11, %xmm13
        paddd     240(%rsp), %xmm12
        pxor      %xmm1, %xmm5
        paddd     304(%rsp), %xmm9
        paddd     %xmm5, %xmm13
        movdqa    %xmm12, %xmm11
        movdqa    %xmm9, %xmm10
        paddd     320(%rsp), %xmm13
        pslld     $10, %xmm11
        psrld     $22, %xmm12
        pslld     $10, %xmm10
        psrld     $22, %xmm9
        por       %xmm12, %xmm11
        por       %xmm9, %xmm10
        movdqa    %xmm13, %xmm5
        movdqa    %xmm8, %xmm9
        paddd     %xmm15, %xmm11
        pslld     $10, %xmm5
        psrld     $22, %xmm13
        pandn     %xmm7, %xmm9
        por       %xmm13, %xmm5
        movdqa    .L_2il0floatpacket.127(%rip), %xmm13
        por       %xmm11, %xmm9
        paddd     %xmm13, %xmm6
        pxor      %xmm15, %xmm9
        paddd     %xmm9, %xmm6
        movdqa    %xmm3, %xmm12
        movdqa    %xmm1, %xmm9
        paddd     %xmm2, %xmm10
        paddd     %xmm0, %xmm5
        pandn     %xmm7, %xmm12
        pandn     %xmm7, %xmm9
        por       %xmm10, %xmm12
        por       %xmm5, %xmm9
        paddd     %xmm13, %xmm4
        paddd     (%rsp), %xmm6
        pxor      %xmm2, %xmm12
        paddd     %xmm13, %xmm14
        pxor      %xmm0, %xmm9
        paddd     %xmm12, %xmm4
        paddd     %xmm9, %xmm14
        movdqa    %xmm6, %xmm9
        psrld     $17, %xmm6
        paddd     16(%rsp), %xmm4
        pslld     $15, %xmm9
        por       %xmm6, %xmm9
        movdqa    %xmm4, %xmm6
        paddd     32(%rsp), %xmm14
        pslld     $15, %xmm6
        psrld     $17, %xmm4
        paddd     %xmm11, %xmm9
        por       %xmm4, %xmm6
        movdqa    %xmm14, %xmm4
        pslld     $15, %xmm4
        psrld     $17, %xmm14
        por       %xmm14, %xmm4
        movdqa    %xmm15, %xmm14
        pandn     %xmm7, %xmm14
        movdqa    %xmm2, %xmm12
        movdqa    .L_2il0floatpacket.128(%rip), %xmm13
        paddd     %xmm10, %xmm6
        por       %xmm9, %xmm14
        pandn     %xmm7, %xmm12
        paddd     %xmm13, %xmm8
        pxor      %xmm11, %xmm14
        por       %xmm6, %xmm12
        paddd     %xmm14, %xmm8
        paddd     %xmm13, %xmm3
        pxor      %xmm10, %xmm12
        paddd     128(%rsp), %xmm8
        paddd     %xmm12, %xmm3
        movdqa    %xmm0, %xmm12
        paddd     %xmm5, %xmm4
        pandn     %xmm7, %xmm12
        movdqa    %xmm8, %xmm7
        pslld     $21, %xmm7
        psrld     $11, %xmm8
        por       %xmm8, %xmm7
        por       %xmm4, %xmm12
        paddd     %xmm9, %xmm7
        paddd     %xmm13, %xmm1
        pxor      %xmm5, %xmm12
        paddd     208(%rsp), %xmm3
        paddd     %xmm12, %xmm1
        paddd     .L_2il0floatpacket.62(%rip), %xmm7
        movdqa    .L_2il0floatpacket.61(%rip), %xmm12
        paddd     .L_2il0floatpacket.63(%rip), %xmm9
        paddd     %xmm12, %xmm15
        paddd     .L_2il0floatpacket.64(%rip), %xmm11
        paddd     %xmm12, %xmm2
        movdqa    %xmm7, 16(%rsi)
        movdqa    %xmm3, %xmm7
        paddd     224(%rsp), %xmm1
        pslld     $21, %xmm7
        movdqa    %xmm15, (%rsi)
        psrld     $11, %xmm3
        movdqa    %xmm9, 32(%rsi)
        movdqa    %xmm11, 48(%rsi)
..B6.7:
        movdqa    %xmm2, 64(%rsi)
        movdqa    %xmm1, %xmm2
        pslld     $21, %xmm2
        psrld     $11, %xmm1
        por       %xmm3, %xmm7
        por       %xmm1, %xmm2
        movdqa    .L_2il0floatpacket.62(%rip), %xmm3
        paddd     %xmm6, %xmm7
        movdqa    .L_2il0floatpacket.63(%rip), %xmm8
        paddd     %xmm4, %xmm2
        movdqa    .L_2il0floatpacket.64(%rip), %xmm9
        paddd     %xmm3, %xmm7
        paddd     .L_2il0floatpacket.61(%rip), %xmm0
        paddd     %xmm8, %xmm6
        paddd     %xmm9, %xmm10
        paddd     %xmm3, %xmm2
        paddd     %xmm8, %xmm4
        paddd     %xmm9, %xmm5
        movdqa    %xmm7, 80(%rsi)
        movdqa    %xmm6, 96(%rsi)
        movdqa    %xmm10, 112(%rsi)
        movdqa    %xmm0, 128(%rsi)
        movdqa    %xmm2, 144(%rsi)
        movdqa    %xmm4, 160(%rsi)
        movdqa    %xmm5, 176(%rsi)
        addq      $776, %rsp
..___tag_value_SSEmd5body.115:
        ret       
        .align    16,0x90
..___tag_value_SSEmd5body.116:
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
..___tag_value_md5cryptsse.117:
        pushq     %r12
..___tag_value_md5cryptsse.119:
        pushq     %r13
..___tag_value_md5cryptsse.121:
        pushq     %r14
..___tag_value_md5cryptsse.123:
        pushq     %r15
..___tag_value_md5cryptsse.125:
        pushq     %rbx
..___tag_value_md5cryptsse.127:
        pushq     %rbp
..___tag_value_md5cryptsse.129:
        subq      $6808, %rsp
..___tag_value_md5cryptsse.131:
        movq      %rsi, %r15
        movq      %rdx, 6488(%rsp)
        lea       6144(%rsp), %r14
        movq      %rdi, %r13
        movq      %r14, %rdi
        xorl      %esi, %esi
        movl      $192, %edx
        movl      %ecx, %ebx
..___tag_value_md5cryptsse.132:
        call      memset
..___tag_value_md5cryptsse.133:
..B7.2:
        xorl      %esi, %esi
        lea       (%rsp), %rbp
        movq      %rbp, %rdi
        movl      $6144, %edx
..___tag_value_md5cryptsse.134:
        call      memset
..___tag_value_md5cryptsse.135:
..B7.3:
        movq      %r15, %rdi
..___tag_value_md5cryptsse.136:
        call      strlen
..___tag_value_md5cryptsse.137:
..B7.202:
        movq      %rax, %rcx
..B7.4:
        movl      %ecx, %eax
        xorl      %edx, %edx
        movl      %ecx, %esi
        movl      %eax, %ecx
        shrl      $1, %ecx
        movl      %eax, %r12d
        movl      %ecx, 6696(%rsp)
        movq      %rsi, 6704(%rsp)
        lea       (,%rax,8), %edi
        movl      %edi, 6712(%rsp)
        movq      %r13, 6720(%rsp)
        movq      %r15, 6728(%rsp)
        movl      %ebx, 6736(%rsp)
        movl      %edx, %ebx
..B7.5:
        movl      %ebx, %r14d
        shlq      $4, %r14
        addq      6720(%rsp), %r14
        movq      %r14, %rdi
..___tag_value_md5cryptsse.138:
        call      strlen
..___tag_value_md5cryptsse.139:
..B7.6:
        movl      %ebx, %r15d
        movl      %eax, %edi
        shrl      $2, %r15d
        movl      %r15d, %esi
        shll      $8, %esi
        movl      %ebx, %r13d
        testl     %edi, %edi
        movl      %edi, 6752(%rsp,%r13,4)
        lea       (%rsp,%rsi), %r8
        jbe       ..B7.13
..B7.7:
        movl      %edi, %eax
        movl      %ebx, %ebp
        shrl      $1, %eax
        andl      $3, %ebp
        movl      $1, %ecx
        xorl      %r11d, %r11d
        testl     %eax, %eax
        jbe       ..B7.11
..B7.9:
        lea       16(%r11,%r11), %r10d
        movl      %r10d, %ecx
        lea       (%r11,%r11), %r9d
        andl      $-4, %ecx
        andl      $3, %r10d
        shll      $2, %ecx
        lea       1(%r11,%r11), %edx
        lea       (%rcx,%rbp,4), %ecx
        addl      %r10d, %ecx
        movb      (%r9,%r14), %r9b
        movb      %r9b, (%rcx,%r8)
        lea       17(%r11,%r11), %ecx
        movl      %ecx, %r10d
        andl      $3, %ecx
        andl      $-4, %r10d
        incl      %r11d
        shll      $2, %r10d
        lea       (%r10,%rbp,4), %r9d
        addl      %ecx, %r9d
        cmpl      %eax, %r11d
        movb      (%rdx,%r14), %cl
        movb      %cl, (%r9,%r8)
        jb        ..B7.9
..B7.10:
        lea       1(%r11,%r11), %ecx
..B7.11:
        cmpl      %edi, %ecx
        ja        ..B7.14
..B7.12:
        lea       15(%rcx), %r9d
        decl      %ecx
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %ebp, %r10d
        movb      (%rcx,%r14), %cl
        lea       (%r9,%r10,4), %r11d
        movb      %cl, (%r11,%r8)
        jmp       ..B7.14
..B7.13:
        movl      %ebx, %ebp
        andl      $3, %ebp
..B7.14:
        lea       16(%rdi), %ecx
        movl      %ecx, %r9d
        andl      $3, %ecx
        andl      $-4, %r9d
        addl      %ebp, %r9d
        testl     %edi, %edi
        lea       (%rcx,%r9,4), %ecx
        movb      $128, (%rcx,%r8)
        jbe       ..B7.21
..B7.15:
        movl      %edi, %eax
        movl      $1, %r9d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.19
..B7.17:
        lea       (%rdx,%rdx), %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r9d, %r11d
        andl      $3, %r9d
        lea       (%r10,%rbp,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%r14), %r11b
        movb      %r11b, 768(%r10,%r8)
        lea       1(%rdx,%rdx), %r10d
        movl      %r10d, %r11d
        incl      %edx
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %r9d
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %eax, %edx
        movb      (%r9,%r14), %r9b
        movb      %r9b, 768(%r11,%r8)
        jb        ..B7.17
..B7.18:
        lea       1(%rdx,%rdx), %r9d
..B7.19:
        cmpl      %edi, %r9d
        ja        ..B7.211
..B7.20:
        decl      %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        movl      %r9d, %r11d
        addl      %ebp, %r10d
        andl      $3, %r9d
        lea       (%r9,%r10,4), %r9d
        movb      (%r11,%r14), %r10b
        movb      %r10b, 768(%r9,%r8)
        movb      $128, 768(%rcx,%r8)
        lea       1536(%rsp,%rsi), %rcx
        jmp       ..B7.22
..B7.21:
        movb      $128, 768(%rcx,%r8)
        lea       1536(%rsp,%rsi), %rcx
        jbe       ..B7.34
..B7.22:
        movl      %edi, %eax
        movl      $1, %r9d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.26
..B7.24:
        lea       (%rdx,%rdx), %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r9d, %r11d
        andl      $3, %r9d
        lea       (%r10,%rbp,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%r14), %r11b
        movb      %r11b, (%r10,%rcx)
        lea       1(%rdx,%rdx), %r10d
        movl      %r10d, %r11d
        incl      %edx
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %r9d
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %eax, %edx
        movb      (%r9,%r14), %r9b
        movb      %r9b, (%r11,%rcx)
        jb        ..B7.24
..B7.25:
        lea       1(%rdx,%rdx), %r9d
..B7.26:
        cmpl      %edi, %r9d
        ja        ..B7.28
..B7.27:
        decl      %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        movl      %r9d, %r11d
        addl      %ebp, %r10d
        andl      $3, %r9d
        lea       (%r9,%r10,4), %r9d
        movb      (%r11,%r14), %r10b
        movb      %r10b, (%r9,%rcx)
..B7.28:
        movl      %edi, %r10d
        movl      $1, %r9d
        shrl      $1, %r10d
        xorl      %r11d, %r11d
        testl     %r10d, %r10d
        jbe       ..B7.32
..B7.29:
        movl      %r12d, 6800(%rsp)
..B7.30:
        lea       (%rdi,%r11,2), %r9d
        movl      %r9d, %r12d
        movl      %r9d, %eax
        andl      $-4, %r12d
        lea       (%r11,%r11), %edx
        shll      $2, %r12d
        andl      $3, %eax
        incl      %r9d
        lea       (%r12,%rbp,4), %r12d
        addl      %eax, %r12d
        movb      (%rdx,%r14), %al
        movb      %al, (%r12,%rcx)
        movl      %r9d, %r12d
        andl      $-4, %r12d
        lea       1(%r11,%r11), %eax
        shll      $2, %r12d
        andl      $3, %r9d
        incl      %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %r9d, %r12d
        cmpl      %r10d, %r11d
        movb      (%rax,%r14), %r9b
        movb      %r9b, (%r12,%rcx)
        jb        ..B7.30
..B7.31:
        movl      6800(%rsp), %r12d
        lea       1(%r11,%r11), %r9d
..B7.32:
        cmpl      %edi, %r9d
        ja        ..B7.34
..B7.33:
        lea       -1(%rdi,%r9), %r10d
        decl      %r9d
        movl      %r10d, %r11d
        andl      $3, %r10d
        andl      $-4, %r11d
        addl      %ebp, %r11d
        lea       (%r10,%r11,4), %r10d
        movb      (%r9,%r14), %r9b
        movb      %r9b, (%r10,%rcx)
..B7.34:
        lea       16(%rdi,%rdi), %r9d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        lea       (%rdi,%rdi), %ecx
        addl      %ebp, %r10d
        testl     %edi, %edi
        lea       (%r9,%r10,4), %r9d
        movb      $128, 1536(%r9,%r8)
        jbe       ..B7.47
..B7.35:
        movl      %edi, %eax
        movl      $1, %r10d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.39
..B7.36:
        movl      %r12d, 6800(%rsp)
..B7.37:
        lea       16(%rdx,%rdx), %r10d
        movl      %r10d, %r11d
        lea       (%rdx,%rdx), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%r14), %r10b
        movb      %r10b, 2304(%r11,%r8)
        lea       17(%rdx,%rdx), %r11d
        movl      %r11d, %r12d
        lea       1(%rdx,%rdx), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %edx
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %eax, %edx
        movb      (%r10,%r14), %r10b
        movb      %r10b, 2304(%r12,%r8)
        jb        ..B7.37
..B7.38:
        movl      6800(%rsp), %r12d
        lea       1(%rdx,%rdx), %r10d
..B7.39:
        cmpl      %edi, %r10d
        ja        ..B7.41
..B7.40:
        lea       15(%r10), %r11d
        decl      %r10d
        movl      %r11d, %eax
        andl      $3, %r11d
        andl      $-4, %eax
        addl      %ebp, %eax
        lea       (%r11,%rax,4), %r11d
        movb      (%r10,%r14), %r10b
        movb      %r10b, 2304(%r11,%r8)
..B7.41:
        movl      %edi, %eax
        movl      $1, %r10d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.45
..B7.42:
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
..B7.43:
        lea       (%rdx,%rdx), %r10d
        lea       16(%r10,%rdi), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %ebx
        andl      $-4, %r12d
        andl      $3, %ebx
        shll      $2, %r12d
        incl      %r11d
        movb      (%r10,%r14), %r10b
        lea       (%r12,%rbp,4), %r12d
        addl      %ebx, %r12d
        lea       1(%rdx,%rdx), %ebx
        incl      %edx
        movb      %r10b, 2304(%r12,%r8)
        movl      %r11d, %r10d
        andl      $-4, %r10d
        andl      $3, %r11d
        shll      $2, %r10d
        lea       (%r10,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %eax, %edx
        movb      (%rbx,%r14), %r11b
        movb      %r11b, 2304(%r12,%r8)
        jb        ..B7.43
..B7.44:
        movl      6664(%rsp), %ebx
        lea       1(%rdx,%rdx), %r10d
        movl      6800(%rsp), %r12d
..B7.45:
        cmpl      %edi, %r10d
        ja        ..B7.210
..B7.46:
        lea       15(%r10,%rdi), %r11d
        decl      %r10d
        movl      %r11d, %eax
        andl      $3, %r11d
        andl      $-4, %eax
        addl      %ebp, %eax
        lea       (%r11,%rax,4), %r11d
        movb      (%r10,%r14), %r10b
        movb      %r10b, 2304(%r11,%r8)
        movb      $128, 2304(%r9,%r8)
        lea       3072(%rsp,%rsi), %r9
        jmp       ..B7.48
..B7.47:
        movb      $128, 2304(%r9,%r8)
        lea       3072(%rsp,%rsi), %r9
        jbe       ..B7.54
..B7.48:
        movl      %edi, %eax
        movl      $1, %r10d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.52
..B7.49:
        movl      %r12d, 6800(%rsp)
..B7.50:
        lea       (%rdx,%rdx), %r10d
        movl      %r10d, %r11d
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %r12d
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%r14), %r12b
        movb      %r12b, (%r11,%r9)
        lea       1(%rdx,%rdx), %r11d
        movl      %r11d, %r12d
        incl      %edx
        andl      $-4, %r12d
        shll      $2, %r12d
        movl      %r11d, %r10d
        andl      $3, %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %eax, %edx
        movb      (%r10,%r14), %r10b
        movb      %r10b, (%r12,%r9)
        jb        ..B7.50
..B7.51:
        movl      6800(%rsp), %r12d
        lea       1(%rdx,%rdx), %r10d
..B7.52:
        cmpl      %edi, %r10d
        ja        ..B7.54
..B7.53:
        decl      %r10d
        movl      %r10d, %r11d
        andl      $-4, %r11d
        movl      %r10d, %edx
        addl      %ebp, %r11d
        andl      $3, %r10d
        lea       (%r10,%r11,4), %r10d
        movb      (%rdx,%r14), %r11b
        movb      %r11b, (%r10,%r9)
..B7.54:
        testl     %r12d, %r12d
        jbe       ..B7.61
..B7.55:
        movl      $1, %edx
        xorl      %eax, %eax
        cmpl      $0, 6696(%rsp)
        jbe       ..B7.59
..B7.56:
        movq      %r14, 6672(%rsp)
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
        movl      6696(%rsp), %r10d
        movq      6728(%rsp), %r11
..B7.57:
        lea       (%rdi,%rax,2), %r12d
        movl      %r12d, %r14d
        movl      %r12d, %edx
        andl      $-4, %r14d
        lea       (%rax,%rax), %ebx
        shll      $2, %r14d
        andl      $3, %edx
        incl      %r12d
        lea       (%r14,%rbp,4), %r14d
        addl      %edx, %r14d
        lea       1(%rax,%rax), %edx
        incl      %eax
        movb      (%rbx,%r11), %bl
        movb      %bl, (%r14,%r9)
        movl      %r12d, %ebx
        andl      $-4, %ebx
        andl      $3, %r12d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %r10d, %eax
        movb      (%rdx,%r11), %r12b
        movb      %r12b, (%r14,%r9)
        jb        ..B7.57
..B7.58:
        movq      6672(%rsp), %r14
        lea       1(%rax,%rax), %edx
        movl      6664(%rsp), %ebx
        movl      6800(%rsp), %r12d
..B7.59:
        cmpl      %r12d, %edx
        ja        ..B7.61
..B7.60:
        lea       -1(%rdi,%rdx), %r10d
        decl      %edx
        movl      %r10d, %r11d
        andl      $3, %r10d
        andl      $-4, %r11d
        addl      %ebp, %r11d
        lea       (%r10,%r11,4), %r10d
        movq      6728(%rsp), %r11
        movb      (%rdx,%r11), %r11b
        movb      %r11b, (%r10,%r9)
..B7.61:
        lea       16(%r12,%rdi), %edx
        movl      %edx, %r11d
        movl      %edx, %r10d
        andl      $-4, %r11d
        andl      $3, %r10d
        addl      %ebp, %r11d
        lea       (%r12,%rdi), %r9d
        movl      %r9d, 6744(%rsp)
        testl     %r12d, %r12d
        lea       (%r10,%r11,4), %eax
        movb      $128, 3072(%rax,%r8)
        jbe       ..B7.71
..B7.62:
        movl      $1, %r11d
        xorl      %r10d, %r10d
        cmpl      $0, 6696(%rsp)
        jbe       ..B7.66
..B7.63:
        movl      %ebx, 6664(%rsp)
        movq      %r14, 6672(%rsp)
        movl      %r12d, 6800(%rsp)
        movl      6696(%rsp), %ebx
        movq      6728(%rsp), %r9
..B7.64:
        lea       16(%r10,%r10), %r11d
        movl      %r11d, %r12d
        lea       (%r10,%r10), %r14d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        movb      (%r14,%r9), %r11b
        movb      %r11b, 3840(%r12,%r8)
        lea       17(%r10,%r10), %r12d
        movl      %r12d, %r14d
        lea       1(%r10,%r10), %r11d
        andl      $-4, %r14d
        andl      $3, %r12d
        shll      $2, %r14d
        incl      %r10d
        lea       (%r14,%rbp,4), %r14d
        addl      %r12d, %r14d
        cmpl      %ebx, %r10d
        movb      (%r11,%r9), %r11b
        movb      %r11b, 3840(%r14,%r8)
        jb        ..B7.64
..B7.65:
        movq      6672(%rsp), %r14
        lea       1(%r10,%r10), %r11d
        movl      6664(%rsp), %ebx
        movl      6800(%rsp), %r12d
..B7.66:
        cmpl      %r12d, %r11d
        ja        ..B7.69
..B7.67:
        lea       15(%r11), %r10d
        decl      %r11d
        movl      %r10d, %r9d
        andl      $3, %r10d
        andl      $-4, %r9d
        addl      %ebp, %r9d
        testl     %edi, %edi
        lea       (%r10,%r9,4), %r9d
        movq      6728(%rsp), %r10
        movb      (%r11,%r10), %r11b
        movb      %r11b, 3840(%r9,%r8)
        ja        ..B7.72
..B7.68:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rsi), %rax
        jmp       ..B7.79
..B7.69:
        testl     %edi, %edi
        ja        ..B7.72
..B7.70:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rsi), %rax
        jmp       ..B7.79
..B7.71:
        testl     %edi, %edi
        jbe       ..B7.85
..B7.72:
        movl      %edi, %r9d
        movl      $1, %r11d
        shrl      $1, %r9d
        xorl      %r10d, %r10d
        testl     %r9d, %r9d
        jbe       ..B7.76
..B7.73:
        movl      %edi, 6680(%rsp)
        movq      %r13, 6688(%rsp)
        movl      %ebx, 6664(%rsp)
..B7.74:
        lea       (%r12,%r10,2), %r13d
        lea       16(%r13), %r11d
        addl      $17, %r13d
        movl      %r11d, %ebx
        lea       (%r10,%r10), %edi
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %ebx
        addl      %r11d, %ebx
        movb      (%rdi,%r14), %r11b
        movl      %r13d, %edi
        andl      $-4, %edi
        andl      $3, %r13d
        shll      $2, %edi
        movb      %r11b, 3840(%rbx,%r8)
        lea       1(%r10,%r10), %ebx
        lea       (%rdi,%rbp,4), %r11d
        addl      %r13d, %r11d
        incl      %r10d
        cmpl      %r9d, %r10d
        movb      (%rbx,%r14), %r13b
        movb      %r13b, 3840(%r11,%r8)
        jb        ..B7.74
..B7.75:
        movl      6680(%rsp), %edi
        lea       1(%r10,%r10), %r11d
        movq      6688(%rsp), %r13
        movl      6664(%rsp), %ebx
..B7.76:
        cmpl      %edi, %r11d
        ja        ..B7.78
..B7.77:
        lea       15(%r12,%r11), %r9d
        decl      %r11d
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %ebp, %r10d
        lea       (%r9,%r10,4), %r9d
        movb      (%r11,%r14), %r11b
        movb      %r11b, 3840(%r9,%r8)
..B7.78:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rsi), %rax
        testl     %r12d, %r12d
        jbe       ..B7.208
..B7.79:
        movl      $1, %esi
        xorl      %r9d, %r9d
        cmpl      $0, 6696(%rsp)
        jbe       ..B7.83
..B7.80:
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
        movl      6696(%rsp), %ebx
        movq      6728(%rsp), %rsi
..B7.81:
        lea       16(%r9,%r9), %r10d
        movl      %r10d, %r11d
        lea       (%r9,%r9), %r12d
        andl      $-4, %r11d
        andl      $3, %r10d
        shll      $2, %r11d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        movb      (%r12,%rsi), %r10b
        movb      %r10b, (%r11,%rax)
        lea       17(%r9,%r9), %r11d
        movl      %r11d, %r12d
        lea       1(%r9,%r9), %r10d
        andl      $-4, %r12d
        andl      $3, %r11d
        shll      $2, %r12d
        incl      %r9d
        lea       (%r12,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %ebx, %r9d
        movb      (%r10,%rsi), %r10b
        movb      %r10b, (%r12,%rax)
        jb        ..B7.81
..B7.82:
        movl      6664(%rsp), %ebx
        lea       1(%r9,%r9), %esi
        movl      6800(%rsp), %r12d
..B7.83:
        cmpl      %r12d, %esi
        ja        ..B7.208
..B7.84:
        lea       15(%rsi), %r9d
        decl      %esi
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %ebp, %r10d
        testl     %edi, %edi
        lea       (%r9,%r10,4), %r11d
        movq      6728(%rsp), %r9
        movb      (%rsi,%r9), %sil
        movb      %sil, (%r11,%rax)
        ja        ..B7.87
        jmp       ..B7.99
..B7.85:
        movb      $128, 3840(%rax,%r8)
        lea       4608(%rsp,%rsi), %rax
..B7.86:
        jbe       ..B7.99
..B7.87:
        movl      %edi, %esi
        movl      $1, %r10d
        shrl      $1, %esi
        xorl      %r9d, %r9d
        testl     %esi, %esi
        jbe       ..B7.91
..B7.88:
        movq      %r13, 6688(%rsp)
        movl      %ebx, 6664(%rsp)
..B7.89:
        lea       (%r12,%r9,2), %r13d
        lea       16(%r13), %r11d
        addl      $17, %r13d
        movl      %r11d, %ebx
        lea       (%r9,%r9), %r10d
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %ebx
        addl      %r11d, %ebx
        movb      (%r10,%r14), %r11b
        movl      %r13d, %r10d
        andl      $-4, %r10d
        andl      $3, %r13d
        shll      $2, %r10d
        movb      %r11b, (%rbx,%rax)
        lea       1(%r9,%r9), %ebx
        lea       (%r10,%rbp,4), %r11d
        addl      %r13d, %r11d
        incl      %r9d
        cmpl      %esi, %r9d
        movb      (%rbx,%r14), %r13b
        movb      %r13b, (%r11,%rax)
        jb        ..B7.89
..B7.90:
        movq      6688(%rsp), %r13
        lea       1(%r9,%r9), %r10d
        movl      6664(%rsp), %ebx
..B7.91:
        cmpl      %edi, %r10d
        ja        ..B7.93
..B7.92:
        lea       15(%r12,%r10), %esi
        decl      %r10d
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addl      %ebp, %r9d
        movb      (%r10,%r14), %r10b
        lea       (%rsi,%r9,4), %r11d
        movb      %r10b, (%r11,%rax)
..B7.93:
        movl      %edi, %esi
        movl      $1, %r10d
        shrl      $1, %esi
        xorl      %r9d, %r9d
        testl     %esi, %esi
        jbe       ..B7.97
..B7.94:
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
..B7.95:
        lea       (%rdx,%r9,2), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %ebx
        andl      $-4, %r12d
        lea       (%r9,%r9), %r10d
        shll      $2, %r12d
        andl      $3, %ebx
        incl      %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %ebx, %r12d
        lea       1(%r9,%r9), %ebx
        incl      %r9d
        movb      (%r10,%r14), %r10b
        movb      %r10b, (%r12,%rax)
        movl      %r11d, %r10d
        andl      $-4, %r10d
        andl      $3, %r11d
        shll      $2, %r10d
        lea       (%r10,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %esi, %r9d
        movb      (%rbx,%r14), %r11b
        movb      %r11b, (%r12,%rax)
        jb        ..B7.95
..B7.96:
        movl      6664(%rsp), %ebx
        lea       1(%r9,%r9), %r10d
        movl      6800(%rsp), %r12d
..B7.97:
        cmpl      %edi, %r10d
        ja        ..B7.99
..B7.98:
        lea       -1(%rdx,%r10), %esi
        decl      %r10d
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addl      %ebp, %r9d
        lea       (%rsi,%r9,4), %r11d
        movb      (%r10,%r14), %sil
        movb      %sil, (%r11,%rax)
..B7.99:
        lea       16(%r12,%rdi,2), %esi
        movl      %esi, %r9d
        andl      $3, %esi
        andl      $-4, %r9d
        addl      %ebp, %r9d
        testl     %edi, %edi
        lea       (%rsi,%r9,4), %esi
        movb      $128, 4608(%rsi,%r8)
        jbe       ..B7.107
..B7.100:
        movl      %edi, %edx
        movl      $1, %r9d
        shrl      $1, %edx
        xorl      %eax, %eax
        testl     %edx, %edx
        jbe       ..B7.104
..B7.102:
        lea       (%rax,%rax), %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        shll      $2, %r10d
        movl      %r9d, %r11d
        andl      $3, %r9d
        lea       (%r10,%rbp,4), %r10d
        addl      %r9d, %r10d
        movb      (%r11,%r14), %r11b
        movb      %r11b, 5376(%r10,%r8)
        lea       1(%rax,%rax), %r10d
        movl      %r10d, %r11d
        incl      %eax
        andl      $-4, %r11d
        shll      $2, %r11d
        movl      %r10d, %r9d
        andl      $3, %r10d
        lea       (%r11,%rbp,4), %r11d
        addl      %r10d, %r11d
        cmpl      %edx, %eax
        movb      (%r9,%r14), %r9b
        movb      %r9b, 5376(%r11,%r8)
        jb        ..B7.102
..B7.103:
        lea       1(%rax,%rax), %r9d
..B7.104:
        cmpl      %edi, %r9d
        ja        ..B7.106
..B7.105:
        decl      %r9d
        movl      %r9d, %r10d
        andl      $-4, %r10d
        movl      %r9d, %r11d
        addl      %ebp, %r10d
        andl      $3, %r9d
        testl     %r12d, %r12d
        lea       (%r9,%r10,4), %r9d
        movb      (%r11,%r14), %r10b
        movb      %r10b, 5376(%r9,%r8)
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
        movl      $1, %edx
        xorl      %eax, %eax
        cmpl      $0, 6696(%rsp)
        jbe       ..B7.112
..B7.109:
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
        movl      6696(%rsp), %r9d
        movq      6728(%rsp), %r10
..B7.110:
        lea       (%rdi,%rax,2), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %edx
        andl      $-4, %r12d
        lea       (%rax,%rax), %ebx
        shll      $2, %r12d
        andl      $3, %edx
        incl      %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %edx, %r12d
        lea       1(%rax,%rax), %edx
        incl      %eax
        movb      (%rbx,%r10), %bl
        movb      %bl, 5376(%r12,%r8)
        movl      %r11d, %ebx
        andl      $-4, %ebx
        andl      $3, %r11d
        shll      $2, %ebx
        lea       (%rbx,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %r9d, %eax
        movb      (%rdx,%r10), %r11b
        movb      %r11b, 5376(%r12,%r8)
        jb        ..B7.110
..B7.111:
        movl      6664(%rsp), %ebx
        lea       1(%rax,%rax), %edx
        movl      6800(%rsp), %r12d
..B7.112:
        cmpl      %r12d, %edx
        ja        ..B7.114
..B7.113:
        lea       -1(%rdi,%rdx), %r9d
        decl      %edx
        movl      %r9d, %r10d
        andl      $3, %r9d
        andl      $-4, %r10d
        addl      %ebp, %r10d
        lea       (%r9,%r10,4), %r11d
        movq      6728(%rsp), %r9
        movb      (%rdx,%r9), %r9b
        movb      %r9b, 5376(%r11,%r8)
..B7.114:
        testl     %edi, %edi
        jbe       ..B7.121
..B7.115:
        movl      %edi, %eax
        movl      $1, %r10d
        shrl      $1, %eax
        xorl      %edx, %edx
        testl     %eax, %eax
        jbe       ..B7.119
..B7.116:
        movl      %ebx, 6664(%rsp)
        movl      %r12d, 6800(%rsp)
        movl      6744(%rsp), %r10d
..B7.117:
        lea       (%r10,%rdx,2), %r11d
        movl      %r11d, %r12d
        movl      %r11d, %ebx
        andl      $-4, %r12d
        lea       (%rdx,%rdx), %r9d
        shll      $2, %r12d
        andl      $3, %ebx
        incl      %r11d
        lea       (%r12,%rbp,4), %r12d
        addl      %ebx, %r12d
        lea       1(%rdx,%rdx), %ebx
        incl      %edx
        movb      (%r9,%r14), %r9b
        movb      %r9b, 5376(%r12,%r8)
        movl      %r11d, %r9d
        andl      $-4, %r9d
        andl      $3, %r11d
        shll      $2, %r9d
        lea       (%r9,%rbp,4), %r12d
        addl      %r11d, %r12d
        cmpl      %eax, %edx
        movb      (%rbx,%r14), %r11b
        movb      %r11b, 5376(%r12,%r8)
        jb        ..B7.117
..B7.118:
        movl      6664(%rsp), %ebx
        lea       1(%rdx,%rdx), %r10d
        movl      6800(%rsp), %r12d
..B7.119:
        cmpl      %edi, %r10d
        ja        ..B7.121
..B7.120:
        movl      6744(%rsp), %r9d
        lea       -1(%r9,%r10), %r11d
        decl      %r10d
        movl      %r11d, %r9d
        andl      $3, %r11d
        andl      $-4, %r9d
        addl      %ebp, %r9d
        lea       (%r11,%r9,4), %r9d
        movb      (%r10,%r14), %r10b
        movb      %r10b, 5376(%r9,%r8)
..B7.121:
        movb      $128, 5376(%rsi,%r8)
        movl      %r15d, %esi
        shll      $6, %esi
        lea       128(,%rdi,8), %r9d
        lea       128(,%rcx,8), %r10d
        lea       56(%rbp,%rsi), %r8d
        movl      6712(%rsp), %esi
        lea       128(%rsi,%rdi,8), %r11d
        lea       6496(%rsp), %rdi
        movl      %r9d, (%rsp,%r8,4)
        lea       128(%rsi,%rcx,8), %ecx
        movl      %r9d, 768(%rsp,%r8,4)
        movl      %r10d, 1536(%rsp,%r8,4)
        movl      %r10d, 2304(%rsp,%r8,4)
        movl      %r11d, 3072(%rsp,%r8,4)
        movl      %r11d, 3840(%rsp,%r8,4)
        movl      %ecx, 4608(%rsp,%r8,4)
        movl      %ecx, 5376(%rsp,%r8,4)
..___tag_value_md5cryptsse.140:
        call      MD5_Init
..___tag_value_md5cryptsse.141:
..B7.122:
        movq      %r14, %rsi
        lea       6496(%rsp), %rdi
        movl      6752(%rsp,%r13,4), %edx
..___tag_value_md5cryptsse.142:
        call      MD5_Update
..___tag_value_md5cryptsse.143:
..B7.123:
        cmpl      $1, 6736(%rsp)
        je        ..B7.199
..B7.124:
        movl      $.L_2__STRING.2, %esi
        lea       6496(%rsp), %rdi
        movl      $3, %edx
..___tag_value_md5cryptsse.144:
        call      MD5_Update
..___tag_value_md5cryptsse.145:
..B7.125:
        movq      6728(%rsp), %rsi
        lea       6496(%rsp), %rdi
        movq      6704(%rsp), %rdx
..___tag_value_md5cryptsse.146:
        call      MD5_Update
..___tag_value_md5cryptsse.147:
..B7.126:
        lea       6336(%rsp), %rdi
..___tag_value_md5cryptsse.148:
        call      MD5_Init
..___tag_value_md5cryptsse.149:
..B7.127:
        movq      %r14, %rsi
        lea       6336(%rsp), %rdi
        movl      6752(%rsp,%r13,4), %edx
..___tag_value_md5cryptsse.150:
        call      MD5_Update
..___tag_value_md5cryptsse.151:
..B7.128:
        movq      6728(%rsp), %rsi
        lea       6336(%rsp), %rdi
        movq      6704(%rsp), %rdx
..___tag_value_md5cryptsse.152:
        call      MD5_Update
..___tag_value_md5cryptsse.153:
..B7.129:
        movq      %r14, %rsi
        lea       6336(%rsp), %rdi
        movl      6752(%rsp,%r13,4), %edx
..___tag_value_md5cryptsse.154:
        call      MD5_Update
..___tag_value_md5cryptsse.155:
..B7.130:
        lea       6648(%rsp), %rdi
        lea       6336(%rsp), %rsi
..___tag_value_md5cryptsse.156:
        call      MD5_Final
..___tag_value_md5cryptsse.157:
..B7.131:
        movl      6752(%rsp,%r13,4), %edx
        lea       6496(%rsp), %rdi
        lea       6648(%rsp), %rsi
..___tag_value_md5cryptsse.158:
        call      MD5_Update
..___tag_value_md5cryptsse.159:
..B7.132:
        movl      6752(%rsp,%r13,4), %r13d
        testl     %r13d, %r13d
        je        ..B7.139
..B7.134:
        testl     $1, %r13d
        je        ..B7.136
..B7.135:
        movl      $.L_2__STRING.3, %esi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.160:
        call      MD5_Update
..___tag_value_md5cryptsse.161:
        jmp       ..B7.137
..B7.136:
        movq      %r14, %rsi
        lea       6496(%rsp), %rdi
        movl      $1, %edx
..___tag_value_md5cryptsse.162:
        call      MD5_Update
..___tag_value_md5cryptsse.163:
..B7.137:
        shrl      $1, %r13d
        testl     %r13d, %r13d
        jne       ..B7.134
..B7.139:
        lea       6648(%rsp), %rdi
        lea       6496(%rsp), %rsi
..___tag_value_md5cryptsse.164:
        call      MD5_Final
..___tag_value_md5cryptsse.165:
..B7.140:
        shll      $4, %r15d
        incl      %ebx
        movl      6648(%rsp), %esi
        cmpl      $12, %ebx
        movl      6652(%rsp), %r8d
        movl      6656(%rsp), %r10d
        movl      6660(%rsp), %r11d
        lea       (%rbp,%r15), %ecx
        lea       4(%r15,%rbp), %edi
        lea       8(%r15,%rbp), %r9d
        lea       12(%r15,%rbp), %ebp
        movl      %esi, 6144(%rsp,%rcx,4)
        movl      %r8d, 6144(%rsp,%rdi,4)
        movl      %r10d, 6144(%rsp,%r9,4)
        movl      %r11d, 6144(%rsp,%rbp,4)
        jb        ..B7.5
..B7.141:
        movl      %r12d, %eax
        lea       (%rsp), %rbp
        xorl      %r13d, %r13d
        lea       6144(%rsp), %r14
        movl      %eax, %r12d
        lea       2304(%rsp), %rdx
        lea       4608(%rsp), %rbx
..B7.142:
        movl      %r13d, %ecx
        movl      $818089009, %eax
        shrl      $1, %ecx
        mull      %ecx
        shrl      $2, %edx
        imull     $42, %edx, %edx
        negl      %edx
        addl      %r13d, %edx
        cmpl      $40, %edx
        ja        ..B7.194
..B7.143:
        jmp       *..1..TPKT.6_0.0.6.38(,%rdx,8)
..1.6_0.TAG.015.0.6.38:
..B7.159:
        movl      $1, %esi
        movq      %rbp, %rdi
        movl      %esi, %ecx
        lea       6752(%rsp), %rdx
        xorl      %r8d, %r8d
        movq      %r14, %r9
        movl      $1, %r15d
..___tag_value_md5cryptsse.166:
        call      mmxput3
..___tag_value_md5cryptsse.167:
        jmp       ..B7.195
..1.6_0.TAG.01c.0.6.38:
..1.6_0.TAG.0e.0.6.38:
..B7.165:
        xorl      %ecx, %ecx
        movl      $5, %r15d
        lea       3840(%rsp), %rbx
        movl      %ecx, %ebp
        movl      %r13d, 6664(%rsp)
        movl      %ecx, %r13d
        movl      %r12d, 6800(%rsp)
        movl      %ecx, %r12d
..B7.166:
        movl      %r13d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %rbx, %rdi
        addq      %r14, %rsi
..___tag_value_md5cryptsse.168:
        call      memcpy
..___tag_value_md5cryptsse.169:
..B7.167:
        incl      %r12d
        addl      $64, %ebp
        addl      $256, %r13d
        cmpl      $3, %r12d
        jb        ..B7.166
..B7.168:
        movl      6664(%rsp), %r13d
        lea       4608(%rsp), %rbx
        movl      6800(%rsp), %r12d
        lea       (%rsp), %rbp
        jmp       ..B7.195
..1.6_0.TAG.023.0.6.38:
..1.6_0.TAG.07.0.6.38:
..B7.174:
        movq      %rbp, %rdi
        movl      $4, %esi
        movl      $1, %ecx
        lea       6752(%rsp), %rdx
        movl      %r12d, %r8d
        movq      %r14, %r9
        movl      $4, %r15d
..___tag_value_md5cryptsse.170:
        call      mmxput3
..___tag_value_md5cryptsse.171:
        jmp       ..B7.195
..1.6_0.TAG.024.0.6.38:
..1.6_0.TAG.01e.0.6.38:
..1.6_0.TAG.018.0.6.38:
..1.6_0.TAG.012.0.6.38:
..1.6_0.TAG.0c.0.6.38:
..1.6_0.TAG.06.0.6.38:
..B7.176:
        xorl      %ecx, %ecx
        movl      $3, %r15d
        lea       2304(%rsp), %rbx
        movl      %ecx, %ebp
        movl      %r13d, 6664(%rsp)
        movl      %ecx, %r13d
        movl      %r12d, 6800(%rsp)
        movl      %ecx, %r12d
..B7.177:
        movl      %r13d, %edi
        movl      $64, %edx
        movl      %ebp, %esi
        addq      %rbx, %rdi
        addq      %r14, %rsi
..___tag_value_md5cryptsse.172:
        call      memcpy
..___tag_value_md5cryptsse.173:
..B7.178:
        incl      %r12d
        addl      $64, %ebp
        addl      $256, %r13d
        cmpl      $3, %r12d
        jb        ..B7.177
..B7.179:
        movl      6664(%rsp), %r13d
        lea       4608(%rsp), %rbx
        movl      6800(%rsp), %r12d
        lea       (%rsp), %rbp
        jmp       ..B7.195
..1.6_0.TAG.027.0.6.38:
..1.6_0.TAG.021.0.6.38:
..1.6_0.TAG.01b.0.6.38:
..1.6_0.TAG.0f.0.6.38:
..1.6_0.TAG.09.0.6.38:
..1.6_0.TAG.03.0.6.38:
..B7.182:
        movl      $2, %esi
        movq      %rbp, %rdi
        movl      %esi, %ecx
        lea       6752(%rsp), %rdx
        xorl      %r8d, %r8d
        movq      %r14, %r9
        movl      $2, %r15d
..___tag_value_md5cryptsse.174:
        call      mmxput3
..___tag_value_md5cryptsse.175:
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
        xorl      %ecx, %ecx
        movl      $6, %r15d
        movl      %ecx, %ebp
        movl      %r13d, 6664(%rsp)
        movl      %ecx, %r13d
        movl      %r12d, 6800(%rsp)
        movl      %ecx, %r12d
..B7.185:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %r13d, %esi
        addq      %rbx, %rdi
        addq      %r14, %rsi
..___tag_value_md5cryptsse.176:
        call      memcpy
..___tag_value_md5cryptsse.177:
..B7.186:
        incl      %ebp
        addl      $64, %r13d
        addl      $256, %r12d
        cmpl      $3, %ebp
        jb        ..B7.185
..B7.187:
        movl      6664(%rsp), %r13d
        lea       (%rsp), %rbp
        movl      6800(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.00.0.6.38:
..B7.190:
        xorl      %ecx, %ecx
        xorl      %r15d, %r15d
        movl      %ecx, %ebx
        movl      %r13d, 6664(%rsp)
        movl      %ecx, %r13d
        movl      %r12d, 6800(%rsp)
        movl      %ecx, %r12d
..B7.191:
        movl      %r12d, %edi
        movl      $64, %edx
        movl      %r13d, %esi
        addq      %rbp, %rdi
        addq      %r14, %rsi
..___tag_value_md5cryptsse.178:
        call      memcpy
..___tag_value_md5cryptsse.179:
..B7.192:
        incl      %ebx
        addl      $64, %r13d
        addl      $256, %r12d
        cmpl      $3, %ebx
        jb        ..B7.191
..B7.193:
        movl      6664(%rsp), %r13d
        lea       4608(%rsp), %rbx
        movl      6800(%rsp), %r12d
        jmp       ..B7.195
..1.6_0.TAG.DEFAULT.0.6.38:
..B7.194:
        movq      %rbp, %rdi
        movl      $7, %esi
        movl      $2, %ecx
        lea       6752(%rsp), %rdx
        movl      %r12d, %r8d
        movq      %r14, %r9
        movl      $7, %r15d
..___tag_value_md5cryptsse.180:
        call      mmxput3
..___tag_value_md5cryptsse.181:
..B7.195:
        movq      %r14, %rsi
        lea       (%r15,%r15,2), %rdi
        shlq      $8, %rdi
        movl      $1, %edx
        addq      %rbp, %rdi
..___tag_value_md5cryptsse.182:
        call      SSEmd5body
..___tag_value_md5cryptsse.183:
..B7.196:
        incl      %r13d
        cmpl      $1000, %r13d
        jb        ..B7.142
..B7.197:
        movq      %r14, %rsi
        movl      $192, %edx
        movq      6488(%rsp), %rdi
..___tag_value_md5cryptsse.184:
        call      memcpy
..___tag_value_md5cryptsse.185:
..B7.198:
        addq      $6808, %rsp
..___tag_value_md5cryptsse.186:
        popq      %rbp
..___tag_value_md5cryptsse.188:
        popq      %rbx
..___tag_value_md5cryptsse.190:
        popq      %r15
..___tag_value_md5cryptsse.192:
        popq      %r14
..___tag_value_md5cryptsse.194:
        popq      %r13
..___tag_value_md5cryptsse.196:
        popq      %r12
..___tag_value_md5cryptsse.198:
        ret       
..___tag_value_md5cryptsse.199:
..B7.199:
        movl      $.L_2__STRING.1, %esi
        lea       6496(%rsp), %rdi
        movl      $6, %edx
..___tag_value_md5cryptsse.206:
        call      MD5_Update
..___tag_value_md5cryptsse.207:
        jmp       ..B7.125
..B7.208:
        testl     %edi, %edi
        ja        ..B7.87
        jmp       ..B7.99
..B7.210:
        testl     %edi, %edi
        jmp       ..B7.47
..B7.211:
        testl     %edi, %edi
        jmp       ..B7.21
        .align    16,0x90
..___tag_value_md5cryptsse.208:
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
..___tag_value_SSEmd4body.209:
        subq      $776, %rsp
..___tag_value_SSEmd4body.211:
        testl     %edx, %edx
        je        ..B8.3
..B8.2:
        movdqa    .L_2il0floatpacket.474(%rip), %xmm1
        movdqa    .L_2il0floatpacket.475(%rip), %xmm3
        movdqa    %xmm1, %xmm4
        movdqa    .L_2il0floatpacket.476(%rip), %xmm2
        movdqa    %xmm3, %xmm5
        movdqa    .L_2il0floatpacket.477(%rip), %xmm9
        movdqa    %xmm2, %xmm14
        movdqa    %xmm9, %xmm10
        movdqa    %xmm1, %xmm7
        movdqa    %xmm3, %xmm13
        movdqa    %xmm2, %xmm15
        movdqa    %xmm9, %xmm11
        jmp       ..B8.4
..B8.3:
        movdqa    (%rsi), %xmm1
        movdqa    16(%rsi), %xmm3
        movdqa    32(%rsi), %xmm2
        movdqa    48(%rsi), %xmm9
        movdqa    64(%rsi), %xmm4
        movdqa    80(%rsi), %xmm5
        movdqa    96(%rsi), %xmm14
        movdqa    112(%rsi), %xmm10
        movdqa    128(%rsi), %xmm7
        movdqa    144(%rsi), %xmm13
        movdqa    160(%rsi), %xmm15
        movdqa    176(%rsi), %xmm11
..B8.4:
        movdqa    %xmm2, %xmm6
        movdqa    %xmm14, %xmm12
        pxor      %xmm9, %xmm6
        pxor      %xmm0, %xmm0
        pand      %xmm3, %xmm6
        paddd     %xmm0, %xmm1
        pxor      %xmm9, %xmm6
        pxor      %xmm10, %xmm12
        movdqa    (%rdi), %xmm8
        paddd     %xmm6, %xmm1
        movdqa    %xmm8, 720(%rsp)
        paddd     %xmm8, %xmm1
        movdqa    %xmm15, %xmm8
        pand      %xmm5, %xmm12
        pxor      %xmm11, %xmm8
        paddd     %xmm0, %xmm4
        pxor      %xmm10, %xmm12
        pand      %xmm13, %xmm8
        movdqa    256(%rdi), %xmm6
        paddd     %xmm12, %xmm4
        paddd     %xmm0, %xmm7
        pxor      %xmm11, %xmm8
        movdqa    512(%rdi), %xmm12
        paddd     %xmm6, %xmm4
        paddd     %xmm8, %xmm7
        movdqa    %xmm1, %xmm8
        movdqa    %xmm12, 752(%rsp)
        paddd     %xmm12, %xmm7
        movdqa    %xmm4, %xmm12
        psrld     $29, %xmm4
        pslld     $3, %xmm12
        pslld     $3, %xmm8
        psrld     $29, %xmm1
        por       %xmm4, %xmm12
        movdqa    %xmm3, %xmm4
        por       %xmm1, %xmm8
        pxor      %xmm2, %xmm4
        paddd     %xmm0, %xmm9
        movdqa    %xmm6, 736(%rsp)
        movdqa    %xmm7, %xmm6
        pand      %xmm8, %xmm4
        pslld     $3, %xmm6
        psrld     $29, %xmm7
        pxor      %xmm2, %xmm4
        movdqa    %xmm5, %xmm1
        por       %xmm7, %xmm6
        movdqa    16(%rdi), %xmm7
        paddd     %xmm4, %xmm9
        pxor      %xmm14, %xmm1
        paddd     %xmm7, %xmm9
        movdqa    %xmm7, 48(%rsp)
        pand      %xmm12, %xmm1
        movdqa    %xmm13, %xmm7
        paddd     %xmm0, %xmm10
        pxor      %xmm14, %xmm1
        pxor      %xmm15, %xmm7
        movdqa    272(%rdi), %xmm4
        paddd     %xmm1, %xmm10
        pand      %xmm6, %xmm7
        paddd     %xmm4, %xmm10
        movdqa    %xmm4, 112(%rsp)
        paddd     %xmm0, %xmm11
        pxor      %xmm15, %xmm7
        movdqa    %xmm9, %xmm4
        movdqa    528(%rdi), %xmm1
        paddd     %xmm7, %xmm11
        pslld     $7, %xmm4
        psrld     $25, %xmm9
        paddd     %xmm1, %xmm11
        por       %xmm9, %xmm4
        movdqa    %xmm3, %xmm9
        movdqa    %xmm10, %xmm7
        movdqa    %xmm1, 128(%rsp)
        movdqa    %xmm11, %xmm1
        pxor      %xmm8, %xmm9
        pslld     $7, %xmm1
        psrld     $25, %xmm11
        pand      %xmm4, %xmm9
        pslld     $7, %xmm7
        psrld     $25, %xmm10
        por       %xmm11, %xmm1
        paddd     %xmm0, %xmm2
        pxor      %xmm3, %xmm9
        movdqa    %xmm5, %xmm11
        por       %xmm10, %xmm7
        paddd     %xmm9, %xmm2
        movdqa    32(%rdi), %xmm10
        pxor      %xmm12, %xmm11
        movdqa    %xmm10, 208(%rsp)
        paddd     %xmm10, %xmm2
        pand      %xmm7, %xmm11
        movdqa    %xmm13, %xmm10
        paddd     %xmm0, %xmm14
        pxor      %xmm5, %xmm11
        pxor      %xmm6, %xmm10
        paddd     %xmm11, %xmm14
        movdqa    288(%rdi), %xmm9
        pand      %xmm1, %xmm10
        paddd     %xmm9, %xmm14
        paddd     %xmm0, %xmm15
        pxor      %xmm13, %xmm10
        paddd     %xmm0, %xmm3
        paddd     %xmm10, %xmm15
        movdqa    %xmm14, %xmm10
        movdqa    %xmm9, 224(%rsp)
        movdqa    %xmm2, %xmm9
        pslld     $11, %xmm10
        psrld     $21, %xmm14
        movdqa    544(%rdi), %xmm11
        pslld     $11, %xmm9
        psrld     $21, %xmm2
        por       %xmm14, %xmm10
        movdqa    %xmm4, %xmm14
        paddd     %xmm11, %xmm15
        por       %xmm2, %xmm9
        pxor      %xmm8, %xmm14
        movdqa    %xmm11, 240(%rsp)
        movdqa    %xmm15, %xmm11
        pand      %xmm9, %xmm14
        pslld     $11, %xmm11
        psrld     $21, %xmm15
        pxor      %xmm8, %xmm14
        por       %xmm15, %xmm11
        paddd     %xmm14, %xmm3
        movdqa    48(%rdi), %xmm15
        movdqa    %xmm7, %xmm2
        movdqa    %xmm15, (%rsp)
        paddd     %xmm15, %xmm3
        pxor      %xmm12, %xmm2
        movdqa    %xmm1, %xmm15
        pand      %xmm10, %xmm2
        pxor      %xmm6, %xmm15
        paddd     %xmm0, %xmm5
        pxor      %xmm12, %xmm2
        pand      %xmm11, %xmm15
        paddd     %xmm2, %xmm5
        movdqa    304(%rdi), %xmm14
        paddd     %xmm0, %xmm13
        pxor      %xmm6, %xmm15
        paddd     %xmm14, %xmm5
        movdqa    560(%rdi), %xmm2
        paddd     %xmm15, %xmm13
        paddd     %xmm2, %xmm13
        movdqa    %xmm5, %xmm15
        movdqa    %xmm14, 16(%rsp)
        movdqa    %xmm3, %xmm14
        movdqa    %xmm2, 32(%rsp)
        pslld     $19, %xmm15
        psrld     $13, %xmm5
        movdqa    %xmm13, %xmm2
        pslld     $19, %xmm14
        psrld     $13, %xmm3
        por       %xmm5, %xmm15
        pslld     $19, %xmm2
        psrld     $13, %xmm13
        movdqa    %xmm9, %xmm5
        por       %xmm3, %xmm14
        por       %xmm13, %xmm2
        pxor      %xmm4, %xmm5
        movdqa    %xmm10, %xmm13
        pand      %xmm14, %xmm5
        pxor      %xmm7, %xmm13
        paddd     %xmm0, %xmm8
        pxor      %xmm4, %xmm5
        pand      %xmm15, %xmm13
        paddd     %xmm5, %xmm8
        movdqa    64(%rdi), %xmm3
        paddd     %xmm0, %xmm12
        pxor      %xmm7, %xmm13
        paddd     %xmm3, %xmm8
        movdqa    320(%rdi), %xmm5
        paddd     %xmm13, %xmm12
        movdqa    %xmm5, 432(%rsp)
        paddd     %xmm5, %xmm12
        movdqa    %xmm8, %xmm5
        psrld     $29, %xmm8
        movdqa    %xmm3, 416(%rsp)
        movdqa    %xmm11, %xmm3
        pslld     $3, %xmm5
        pxor      %xmm1, %xmm3
        por       %xmm8, %xmm5
        movdqa    %xmm12, %xmm8
        pand      %xmm2, %xmm3
        pslld     $3, %xmm8
        psrld     $29, %xmm12
        paddd     %xmm0, %xmm6
        pxor      %xmm1, %xmm3
        por       %xmm12, %xmm8
        movdqa    %xmm14, %xmm12
        paddd     %xmm3, %xmm6
        movdqa    576(%rdi), %xmm13
        pxor      %xmm9, %xmm12
        paddd     %xmm13, %xmm6
        pand      %xmm5, %xmm12
        movdqa    %xmm6, %xmm3
        paddd     %xmm0, %xmm4
        pxor      %xmm9, %xmm12
        pslld     $3, %xmm3
        movdqa    %xmm13, 448(%rsp)
        psrld     $29, %xmm6
        paddd     %xmm12, %xmm4
        movdqa    %xmm15, %xmm12
        movdqa    %xmm2, %xmm13
        por       %xmm6, %xmm3
        pxor      %xmm10, %xmm12
        pxor      %xmm11, %xmm13
        pand      %xmm8, %xmm12
        pand      %xmm3, %xmm13
        movdqa    80(%rdi), %xmm6
        paddd     %xmm0, %xmm7
        pxor      %xmm10, %xmm12
        paddd     %xmm0, %xmm1
        pxor      %xmm11, %xmm13
        paddd     %xmm6, %xmm4
        paddd     %xmm12, %xmm7
        paddd     %xmm13, %xmm1
        movdqa    592(%rdi), %xmm12
        paddd     %xmm0, %xmm9
        movdqa    %xmm6, 144(%rsp)
        paddd     %xmm12, %xmm1
        movdqa    336(%rdi), %xmm6
        movdqa    %xmm3, %xmm13
        movdqa    %xmm12, 176(%rsp)
        movdqa    %xmm4, %xmm12
        paddd     %xmm6, %xmm7
        pslld     $7, %xmm12
        psrld     $25, %xmm4
        pxor      %xmm2, %xmm13
        por       %xmm4, %xmm12
        movdqa    %xmm7, %xmm4
        pslld     $7, %xmm4
        psrld     $25, %xmm7
        por       %xmm7, %xmm4
        movdqa    %xmm5, %xmm7
        pxor      %xmm14, %xmm7
        paddd     %xmm0, %xmm10
        pand      %xmm12, %xmm7
        paddd     %xmm0, %xmm11
        movdqa    %xmm6, 160(%rsp)
        movdqa    %xmm1, %xmm6
        pxor      %xmm14, %xmm7
        pslld     $7, %xmm6
        psrld     $25, %xmm1
        paddd     %xmm7, %xmm9
        movdqa    %xmm8, %xmm7
        por       %xmm1, %xmm6
        pxor      %xmm15, %xmm7
        pand      %xmm6, %xmm13
        pand      %xmm4, %xmm7
        pxor      %xmm2, %xmm13
        movdqa    96(%rdi), %xmm1
        pxor      %xmm15, %xmm7
        paddd     %xmm1, %xmm9
        paddd     %xmm7, %xmm10
        movdqa    608(%rdi), %xmm7
        paddd     %xmm13, %xmm11
        movdqa    %xmm1, 336(%rsp)
        paddd     %xmm7, %xmm11
        movdqa    352(%rdi), %xmm1
        paddd     %xmm0, %xmm14
        movdqa    %xmm7, 368(%rsp)
        movdqa    %xmm9, %xmm7
        paddd     %xmm1, %xmm10
        pslld     $11, %xmm7
        psrld     $21, %xmm9
        movdqa    %xmm6, %xmm13
        por       %xmm9, %xmm7
        movdqa    %xmm10, %xmm9
        pslld     $11, %xmm9
        psrld     $21, %xmm10
        por       %xmm10, %xmm9
        movdqa    %xmm12, %xmm10
        pxor      %xmm5, %xmm10
        pxor      %xmm3, %xmm13
        pand      %xmm7, %xmm10
        paddd     %xmm0, %xmm15
        movdqa    %xmm1, 352(%rsp)
        movdqa    %xmm11, %xmm1
        pxor      %xmm5, %xmm10
        pslld     $11, %xmm1
        psrld     $21, %xmm11
        paddd     %xmm10, %xmm14
        movdqa    %xmm4, %xmm10
        por       %xmm11, %xmm1
        pxor      %xmm8, %xmm10
        pand      %xmm1, %xmm13
        pand      %xmm9, %xmm10
        paddd     %xmm0, %xmm2
        movdqa    112(%rdi), %xmm11
        pxor      %xmm8, %xmm10
        pxor      %xmm3, %xmm13
        paddd     %xmm11, %xmm14
        paddd     %xmm10, %xmm15
        paddd     %xmm13, %xmm2
        movdqa    624(%rdi), %xmm10
        paddd     %xmm0, %xmm5
        movdqa    %xmm10, 64(%rsp)
        paddd     %xmm10, %xmm2
        movdqa    %xmm14, %xmm10
        psrld     $13, %xmm14
        pslld     $19, %xmm10
        movdqa    %xmm2, %xmm13
        movdqa    %xmm11, 96(%rsp)
        por       %xmm14, %xmm10
        movdqa    368(%rdi), %xmm11
        movdqa    %xmm7, %xmm14
        paddd     %xmm11, %xmm15
        pxor      %xmm12, %xmm14
        movdqa    %xmm11, 80(%rsp)
        movdqa    %xmm15, %xmm11
        pand      %xmm10, %xmm14
        pslld     $19, %xmm11
        psrld     $13, %xmm15
        pxor      %xmm12, %xmm14
        por       %xmm15, %xmm11
        pslld     $19, %xmm13
        movdqa    128(%rdi), %xmm15
        psrld     $13, %xmm2
        paddd     %xmm14, %xmm5
        por       %xmm2, %xmm13
        movdqa    %xmm15, 624(%rsp)
        paddd     %xmm15, %xmm5
        movdqa    %xmm9, %xmm2
        movdqa    %xmm1, %xmm15
        pxor      %xmm4, %xmm2
        pxor      %xmm6, %xmm15
        pand      %xmm11, %xmm2
        pand      %xmm13, %xmm15
        paddd     %xmm0, %xmm8
        pxor      %xmm4, %xmm2
        paddd     %xmm0, %xmm3
        pxor      %xmm6, %xmm15
        paddd     %xmm2, %xmm8
        paddd     %xmm15, %xmm3
        movdqa    640(%rdi), %xmm2
        paddd     %xmm0, %xmm12
        movdqa    384(%rdi), %xmm14
        paddd     %xmm2, %xmm3
        movdqa    %xmm2, 592(%rsp)
        movdqa    %xmm5, %xmm2
        paddd     %xmm14, %xmm8
        pslld     $3, %xmm2
        psrld     $29, %xmm5
        movdqa    %xmm11, %xmm15
        por       %xmm5, %xmm2
        movdqa    %xmm8, %xmm5
        pslld     $3, %xmm5
        psrld     $29, %xmm8
        por       %xmm8, %xmm5
        movdqa    %xmm3, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm3
        por       %xmm3, %xmm8
        movdqa    %xmm10, %xmm3
        pxor      %xmm7, %xmm3
        pxor      %xmm9, %xmm15
        pand      %xmm2, %xmm3
        pand      %xmm5, %xmm15
        pxor      %xmm7, %xmm3
        paddd     %xmm0, %xmm4
        movdqa    %xmm14, 576(%rsp)
        paddd     %xmm3, %xmm12
        movdqa    144(%rdi), %xmm14
        pxor      %xmm9, %xmm15
        movdqa    %xmm14, 320(%rsp)
        paddd     %xmm14, %xmm12
        movdqa    %xmm13, %xmm14
        paddd     %xmm15, %xmm4
        pxor      %xmm1, %xmm14
        paddd     %xmm0, %xmm6
        pand      %xmm8, %xmm14
        paddd     %xmm0, %xmm7
        movdqa    400(%rdi), %xmm3
        pxor      %xmm1, %xmm14
        movdqa    %xmm3, 304(%rsp)
        paddd     %xmm3, %xmm4
        movdqa    656(%rdi), %xmm3
        paddd     %xmm14, %xmm6
        movdqa    %xmm3, 288(%rsp)
        paddd     %xmm3, %xmm6
        movdqa    %xmm12, %xmm3
        psrld     $25, %xmm12
        pslld     $7, %xmm3
        movdqa    %xmm5, %xmm15
        por       %xmm12, %xmm3
        movdqa    %xmm4, %xmm12
        pslld     $7, %xmm12
        psrld     $25, %xmm4
        por       %xmm4, %xmm12
        movdqa    %xmm6, %xmm4
        pslld     $7, %xmm4
        psrld     $25, %xmm6
        por       %xmm6, %xmm4
        movdqa    %xmm2, %xmm6
        pxor      %xmm10, %xmm6
        pxor      %xmm11, %xmm15
        pand      %xmm3, %xmm6
        pand      %xmm12, %xmm15
        pxor      %xmm10, %xmm6
        paddd     %xmm0, %xmm9
        movdqa    160(%rdi), %xmm14
        paddd     %xmm6, %xmm7
        movdqa    %xmm14, 496(%rsp)
        paddd     %xmm14, %xmm7
        movdqa    %xmm8, %xmm14
        pxor      %xmm11, %xmm15
        pxor      %xmm13, %xmm14
        paddd     %xmm15, %xmm9
        pand      %xmm4, %xmm14
        paddd     %xmm0, %xmm1
        movdqa    416(%rdi), %xmm6
        pxor      %xmm13, %xmm14
        movdqa    %xmm6, 528(%rsp)
        paddd     %xmm6, %xmm9
        movdqa    672(%rdi), %xmm6
        paddd     %xmm14, %xmm1
        movdqa    %xmm6, 512(%rsp)
        paddd     %xmm6, %xmm1
        movdqa    %xmm7, %xmm6
        psrld     $21, %xmm7
        pslld     $11, %xmm6
        paddd     %xmm0, %xmm10
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        pslld     $11, %xmm7
        psrld     $21, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm1, %xmm9
        pslld     $11, %xmm9
        psrld     $21, %xmm1
        por       %xmm1, %xmm9
        movdqa    %xmm3, %xmm1
        pxor      %xmm2, %xmm1
        movdqa    %xmm12, %xmm15
        pand      %xmm6, %xmm1
        pxor      %xmm5, %xmm15
        pxor      %xmm2, %xmm1
        pand      %xmm7, %xmm15
        movdqa    176(%rdi), %xmm14
        paddd     %xmm1, %xmm10
        movdqa    %xmm14, 192(%rsp)
        paddd     %xmm14, %xmm10
        movdqa    %xmm4, %xmm14
        paddd     %xmm0, %xmm11
        pxor      %xmm8, %xmm14
        pxor      %xmm5, %xmm15
        pand      %xmm9, %xmm14
        paddd     %xmm15, %xmm11
        movdqa    432(%rdi), %xmm1
        paddd     %xmm0, %xmm13
        pxor      %xmm8, %xmm14
        paddd     %xmm1, %xmm11
        movdqa    %xmm1, 256(%rsp)
        paddd     %xmm14, %xmm13
        movdqa    688(%rdi), %xmm1
        movdqa    %xmm7, %xmm15
        movdqa    %xmm1, 272(%rsp)
        paddd     %xmm1, %xmm13
        movdqa    %xmm10, %xmm1
        psrld     $13, %xmm10
        pslld     $19, %xmm1
        paddd     %xmm0, %xmm2
        por       %xmm10, %xmm1
        movdqa    %xmm11, %xmm10
        pslld     $19, %xmm10
        psrld     $13, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm13, %xmm11
        pslld     $19, %xmm11
        psrld     $13, %xmm13
        por       %xmm13, %xmm11
        movdqa    %xmm6, %xmm13
        pxor      %xmm3, %xmm13
        paddd     %xmm0, %xmm5
        pand      %xmm1, %xmm13
        pxor      %xmm12, %xmm15
        paddd     %xmm0, %xmm8
        movdqa    %xmm9, %xmm0
        pxor      %xmm3, %xmm13
        pand      %xmm10, %xmm15
        pxor      %xmm4, %xmm0
        paddd     %xmm13, %xmm2
        movdqa    192(%rdi), %xmm14
        pxor      %xmm12, %xmm15
        pand      %xmm11, %xmm0
        paddd     %xmm14, %xmm2
        movdqa    448(%rdi), %xmm13
        paddd     %xmm15, %xmm5
        pxor      %xmm4, %xmm0
        paddd     %xmm13, %xmm5
        movdqa    %xmm13, 672(%rsp)
        paddd     %xmm0, %xmm8
        movdqa    704(%rdi), %xmm13
        movdqa    %xmm2, %xmm0
        movdqa    %xmm13, 656(%rsp)
        paddd     %xmm13, %xmm8
        pslld     $3, %xmm0
        psrld     $29, %xmm2
        movdqa    %xmm5, %xmm13
        por       %xmm2, %xmm0
        movdqa    %xmm14, 640(%rsp)
        pslld     $3, %xmm13
        psrld     $29, %xmm5
..B8.9:
        movdqa    %xmm8, %xmm2
        movdqa    %xmm10, %xmm15
        pslld     $3, %xmm2
        psrld     $29, %xmm8
        por       %xmm5, %xmm13
        pxor      %xmm7, %xmm15
        por       %xmm8, %xmm2
        pand      %xmm13, %xmm15
        pxor      %xmm8, %xmm8
        movdqa    %xmm1, %xmm14
        paddd     %xmm8, %xmm12
        pxor      %xmm7, %xmm15
        pxor      %xmm6, %xmm14
        paddd     %xmm15, %xmm12
        movdqa    %xmm11, %xmm15
        pand      %xmm0, %xmm14
        pxor      %xmm9, %xmm15
        paddd     %xmm8, %xmm3
        pxor      %xmm6, %xmm14
        pand      %xmm2, %xmm15
        paddd     %xmm14, %xmm3
        paddd     %xmm8, %xmm4
        movdqa    464(%rdi), %xmm14
        pxor      %xmm9, %xmm15
        movdqa    %xmm14, 480(%rsp)
        paddd     %xmm14, %xmm12
        movdqa    720(%rdi), %xmm14
        paddd     %xmm15, %xmm4
        movdqa    208(%rdi), %xmm5
        paddd     %xmm14, %xmm4
        movdqa    %xmm14, 400(%rsp)
        paddd     %xmm5, %xmm3
        movdqa    %xmm4, %xmm14
        movdqa    %xmm3, %xmm15
        pslld     $7, %xmm14
        psrld     $25, %xmm4
        pslld     $7, %xmm15
        psrld     $25, %xmm3
        por       %xmm4, %xmm14
        movdqa    %xmm0, %xmm4
        por       %xmm3, %xmm15
        pxor      %xmm1, %xmm4
        pand      %xmm15, %xmm4
        movdqa    %xmm12, %xmm3
        paddd     %xmm8, %xmm6
        pxor      %xmm1, %xmm4
        pslld     $7, %xmm3
        psrld     $25, %xmm12
        paddd     %xmm4, %xmm6
        movdqa    %xmm10, %xmm4
        por       %xmm12, %xmm3
        pxor      %xmm13, %xmm4
        pand      %xmm3, %xmm4
        paddd     %xmm8, %xmm7
        pxor      %xmm10, %xmm4
        paddd     %xmm8, %xmm9
        paddd     %xmm4, %xmm7
        movdqa    %xmm11, %xmm4
        pxor      %xmm2, %xmm4
        paddd     %xmm8, %xmm1
        movdqa    224(%rdi), %xmm12
        pand      %xmm14, %xmm4
        paddd     %xmm12, %xmm6
        pxor      %xmm11, %xmm4
        movdqa    %xmm12, 608(%rsp)
        paddd     %xmm4, %xmm9
        movdqa    480(%rdi), %xmm12
        movdqa    %xmm6, %xmm4
        paddd     %xmm12, %xmm7
        pslld     $11, %xmm4
        psrld     $21, %xmm6
        paddd     %xmm8, %xmm10
        movdqa    %xmm12, 544(%rsp)
        por       %xmm6, %xmm4
        movdqa    736(%rdi), %xmm12
        movdqa    %xmm7, %xmm6
        paddd     %xmm12, %xmm9
        pslld     $11, %xmm6
        psrld     $21, %xmm7
        paddd     %xmm8, %xmm11
        por       %xmm7, %xmm6
        movdqa    %xmm9, %xmm7
        pslld     $11, %xmm7
        psrld     $21, %xmm9
        por       %xmm9, %xmm7
        movdqa    %xmm0, %xmm9
        pxor      %xmm15, %xmm9
        movdqa    %xmm14, %xmm8
        pand      %xmm4, %xmm9
        pxor      %xmm2, %xmm8
        pxor      %xmm0, %xmm9
        pand      %xmm7, %xmm8
        paddd     %xmm9, %xmm1
        movdqa    %xmm3, %xmm9
        pxor      %xmm13, %xmm9
        pxor      %xmm2, %xmm8
        movdqa    %xmm12, 560(%rsp)
        pand      %xmm6, %xmm9
        movdqa    240(%rdi), %xmm12
        pxor      %xmm13, %xmm9
        paddd     %xmm12, %xmm1
        paddd     %xmm9, %xmm10
        movdqa    752(%rdi), %xmm9
        paddd     %xmm8, %xmm11
        movdqa    %xmm1, %xmm8
        paddd     %xmm9, %xmm11
        movdqa    %xmm12, 384(%rsp)
        pslld     $19, %xmm8
        movdqa    496(%rdi), %xmm12
        psrld     $13, %xmm1
        paddd     %xmm12, %xmm10
        por       %xmm1, %xmm8
        movdqa    %xmm11, %xmm1
        psrld     $13, %xmm11
        movdqa    %xmm12, 688(%rsp)
        pslld     $19, %xmm1
        movdqa    %xmm9, 704(%rsp)
        movdqa    %xmm10, %xmm9
        movdqa    %xmm4, %xmm12
        pslld     $19, %xmm9
        psrld     $13, %xmm10
        por       %xmm11, %xmm1
        por       %xmm15, %xmm12
        movdqa    %xmm4, %xmm11
        por       %xmm10, %xmm9
        pand      %xmm8, %xmm12
        movdqa    .L_2il0floatpacket.478(%rip), %xmm10
        pand      %xmm15, %xmm11
        paddd     %xmm10, %xmm0
        por       %xmm11, %xmm12
        paddd     %xmm12, %xmm0
        movdqa    %xmm6, %xmm12
        por       %xmm3, %xmm12
        movdqa    %xmm6, %xmm11
        pand      %xmm9, %xmm12
        pand      %xmm3, %xmm11
        paddd     %xmm10, %xmm13
        por       %xmm11, %xmm12
        paddd     %xmm12, %xmm13
        movdqa    %xmm7, %xmm12
        por       %xmm14, %xmm12
        movdqa    %xmm7, %xmm11
        pand      %xmm1, %xmm12
        pand      %xmm14, %xmm11
        paddd     736(%rsp), %xmm13
        paddd     %xmm10, %xmm2
        por       %xmm11, %xmm12
        paddd     %xmm10, %xmm15
        paddd     %xmm12, %xmm2
        movdqa    %xmm13, %xmm12
        paddd     752(%rsp), %xmm2
        pslld     $3, %xmm12
        psrld     $29, %xmm13
        paddd     %xmm10, %xmm3
        paddd     720(%rsp), %xmm0
        por       %xmm13, %xmm12
        movdqa    %xmm2, %xmm13
        movdqa    %xmm0, %xmm11
        pslld     $3, %xmm13
        psrld     $29, %xmm2
        pslld     $3, %xmm11
        psrld     $29, %xmm0
        por       %xmm2, %xmm13
        movdqa    %xmm8, %xmm2
        por       %xmm0, %xmm11
        por       %xmm4, %xmm2
        movdqa    %xmm8, %xmm0
        pand      %xmm11, %xmm2
        pand      %xmm4, %xmm0
        paddd     %xmm10, %xmm14
        por       %xmm0, %xmm2
        movdqa    %xmm9, %xmm0
        paddd     %xmm2, %xmm15
        movdqa    %xmm9, %xmm2
        por       %xmm6, %xmm2
        pand      %xmm6, %xmm0
        pand      %xmm12, %xmm2
        paddd     %xmm10, %xmm4
        por       %xmm0, %xmm2
        movdqa    %xmm1, %xmm0
        paddd     %xmm2, %xmm3
        movdqa    %xmm1, %xmm2
        por       %xmm7, %xmm2
        pand      %xmm7, %xmm0
        pand      %xmm13, %xmm2
        paddd     %xmm10, %xmm6
        paddd     416(%rsp), %xmm15
        por       %xmm0, %xmm2
        paddd     %xmm2, %xmm14
        movdqa    %xmm15, %xmm0
        paddd     448(%rsp), %xmm14
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm10, %xmm7
        paddd     432(%rsp), %xmm3
        por       %xmm15, %xmm0
        movdqa    %xmm14, %xmm15
        movdqa    %xmm3, %xmm2
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        por       %xmm14, %xmm15
        movdqa    %xmm11, %xmm14
        por       %xmm3, %xmm2
        por       %xmm8, %xmm14
        movdqa    %xmm11, %xmm3
        pand      %xmm0, %xmm14
        pand      %xmm8, %xmm3
        paddd     %xmm10, %xmm8
        por       %xmm3, %xmm14
        movdqa    %xmm12, %xmm3
        paddd     %xmm14, %xmm4
        movdqa    %xmm12, %xmm14
        por       %xmm9, %xmm14
        pand      %xmm9, %xmm3
        pand      %xmm2, %xmm14
        paddd     %xmm10, %xmm9
        por       %xmm3, %xmm14
        movdqa    %xmm13, %xmm3
        paddd     %xmm14, %xmm6
        movdqa    %xmm13, %xmm14
        por       %xmm1, %xmm14
        pand      %xmm1, %xmm3
        paddd     624(%rsp), %xmm4
        pand      %xmm15, %xmm14
        por       %xmm3, %xmm14
        movdqa    %xmm4, %xmm3
        paddd     576(%rsp), %xmm6
        pslld     $9, %xmm3
        psrld     $23, %xmm4
        paddd     %xmm14, %xmm7
        por       %xmm4, %xmm3
        movdqa    %xmm6, %xmm4
        paddd     592(%rsp), %xmm7
        pslld     $9, %xmm4
        psrld     $23, %xmm6
        movdqa    %xmm0, %xmm14
        por       %xmm6, %xmm4
        movdqa    %xmm7, %xmm6
        pslld     $9, %xmm6
        psrld     $23, %xmm7
        por       %xmm7, %xmm6
        por       %xmm11, %xmm14
        movdqa    %xmm0, %xmm7
        pand      %xmm3, %xmm14
        pand      %xmm11, %xmm7
        paddd     %xmm10, %xmm1
        por       %xmm7, %xmm14
        movdqa    %xmm2, %xmm7
        paddd     %xmm14, %xmm8
        movdqa    %xmm2, %xmm14
        por       %xmm12, %xmm14
        pand      %xmm12, %xmm7
        pand      %xmm4, %xmm14
        paddd     %xmm10, %xmm11
        por       %xmm7, %xmm14
        movdqa    %xmm15, %xmm7
        paddd     %xmm14, %xmm9
        movdqa    %xmm15, %xmm14
        por       %xmm13, %xmm14
        pand      %xmm13, %xmm7
        pand      %xmm6, %xmm14
        paddd     %xmm10, %xmm12
        paddd     640(%rsp), %xmm8
        por       %xmm7, %xmm14
        paddd     672(%rsp), %xmm9
        paddd     %xmm14, %xmm1
        movdqa    %xmm8, %xmm14
        psrld     $19, %xmm8
        paddd     656(%rsp), %xmm1
        pslld     $13, %xmm14
        movdqa    %xmm9, %xmm7
        por       %xmm8, %xmm14
        pslld     $13, %xmm7
        psrld     $19, %xmm9
        movdqa    %xmm1, %xmm8
        por       %xmm9, %xmm7
        pslld     $13, %xmm8
        psrld     $19, %xmm1
        movdqa    %xmm3, %xmm9
        por       %xmm1, %xmm8
        por       %xmm0, %xmm9
        movdqa    %xmm3, %xmm1
        pand      %xmm14, %xmm9
        pand      %xmm0, %xmm1
        por       %xmm1, %xmm9
        movdqa    %xmm4, %xmm1
        paddd     %xmm9, %xmm11
        movdqa    %xmm4, %xmm9
        por       %xmm2, %xmm9
        pand      %xmm2, %xmm1
        pand      %xmm7, %xmm9
        paddd     %xmm10, %xmm13
        por       %xmm1, %xmm9
        movdqa    %xmm6, %xmm1
        paddd     %xmm9, %xmm12
        movdqa    %xmm6, %xmm9
        por       %xmm15, %xmm9
        pand      %xmm15, %xmm1
        pand      %xmm8, %xmm9
        paddd     %xmm10, %xmm0
        paddd     48(%rsp), %xmm11
        por       %xmm1, %xmm9
        paddd     %xmm9, %xmm13
        movdqa    %xmm11, %xmm9
        paddd     112(%rsp), %xmm12
        pslld     $3, %xmm9
        psrld     $29, %xmm11
        movdqa    %xmm14, %xmm1
        por       %xmm11, %xmm9
        movdqa    %xmm12, %xmm11
        paddd     128(%rsp), %xmm13
        pslld     $3, %xmm11
        psrld     $29, %xmm12
        por       %xmm3, %xmm1
        por       %xmm12, %xmm11
        movdqa    %xmm13, %xmm12
        pslld     $3, %xmm12
        psrld     $29, %xmm13
        por       %xmm13, %xmm12
        movdqa    %xmm14, %xmm13
        pand      %xmm9, %xmm1
        pand      %xmm3, %xmm13
        por       %xmm13, %xmm1
        movdqa    %xmm7, %xmm13
        paddd     %xmm1, %xmm0
        movdqa    %xmm7, %xmm1
        por       %xmm4, %xmm1
        pand      %xmm4, %xmm13
        pand      %xmm11, %xmm1
        paddd     %xmm10, %xmm2
        por       %xmm13, %xmm1
        movdqa    %xmm8, %xmm13
        paddd     %xmm1, %xmm2
        movdqa    %xmm8, %xmm1
        por       %xmm6, %xmm1
        pand      %xmm6, %xmm13
        paddd     144(%rsp), %xmm0
        pand      %xmm12, %xmm1
        paddd     %xmm10, %xmm15
        por       %xmm13, %xmm1
        movdqa    %xmm0, %xmm13
        paddd     %xmm1, %xmm15
        paddd     160(%rsp), %xmm2
        pslld     $5, %xmm13
        psrld     $27, %xmm0
        paddd     %xmm10, %xmm3
        paddd     176(%rsp), %xmm15
        por       %xmm0, %xmm13
        movdqa    %xmm2, %xmm0
        psrld     $27, %xmm2
        pslld     $5, %xmm0
        movdqa    %xmm15, %xmm1
        por       %xmm2, %xmm0
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        movdqa    %xmm9, %xmm2
        por       %xmm15, %xmm1
        por       %xmm14, %xmm2
        movdqa    %xmm9, %xmm15
        pand      %xmm13, %xmm2
        pand      %xmm14, %xmm15
        paddd     %xmm10, %xmm4
        por       %xmm15, %xmm2
        movdqa    %xmm11, %xmm15
        paddd     %xmm2, %xmm3
        movdqa    %xmm11, %xmm2
        por       %xmm7, %xmm2
        pand      %xmm7, %xmm15
        pand      %xmm0, %xmm2
        paddd     %xmm10, %xmm6
        por       %xmm15, %xmm2
        movdqa    %xmm12, %xmm15
        paddd     %xmm2, %xmm4
        movdqa    %xmm12, %xmm2
        por       %xmm8, %xmm2
        pand      %xmm8, %xmm15
        pand      %xmm1, %xmm2
        paddd     %xmm10, %xmm14
        paddd     320(%rsp), %xmm3
        por       %xmm15, %xmm2
        paddd     %xmm2, %xmm6
        movdqa    %xmm3, %xmm2
        paddd     304(%rsp), %xmm4
        pslld     $9, %xmm2
        psrld     $23, %xmm3
        movdqa    %xmm13, %xmm15
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        paddd     288(%rsp), %xmm6
        pslld     $9, %xmm3
        psrld     $23, %xmm4
        por       %xmm9, %xmm15
        por       %xmm4, %xmm3
        movdqa    %xmm6, %xmm4
        pslld     $9, %xmm4
        psrld     $23, %xmm6
        por       %xmm6, %xmm4
        movdqa    %xmm13, %xmm6
        pand      %xmm2, %xmm15
        pand      %xmm9, %xmm6
        por       %xmm6, %xmm15
        movdqa    %xmm0, %xmm6
        paddd     %xmm15, %xmm14
        por       %xmm11, %xmm6
        movdqa    %xmm5, 464(%rsp)
        paddd     %xmm5, %xmm14
        movdqa    %xmm0, %xmm5
        pand      %xmm3, %xmm6
        pand      %xmm11, %xmm5
        paddd     %xmm10, %xmm7
        por       %xmm5, %xmm6
        movdqa    %xmm1, %xmm5
        por       %xmm12, %xmm5
        movdqa    %xmm1, %xmm15
        paddd     %xmm6, %xmm7
        pand      %xmm4, %xmm5
        pand      %xmm12, %xmm15
        paddd     %xmm10, %xmm8
        paddd     464(%rdi), %xmm7
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm8
        movdqa    %xmm7, %xmm6
        paddd     720(%rdi), %xmm8
        movdqa    %xmm14, %xmm5
        pslld     $13, %xmm6
        psrld     $19, %xmm7
        pslld     $13, %xmm5
        psrld     $19, %xmm14
        por       %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        por       %xmm14, %xmm5
        pslld     $13, %xmm7
        psrld     $19, %xmm8
        movdqa    %xmm2, %xmm14
        por       %xmm8, %xmm7
        por       %xmm13, %xmm14
        movdqa    %xmm2, %xmm8
        pand      %xmm5, %xmm14
        pand      %xmm13, %xmm8
        movdqa    %xmm3, %xmm15
        paddd     %xmm10, %xmm9
        por       %xmm8, %xmm14
        por       %xmm0, %xmm15
        movdqa    %xmm3, %xmm8
        paddd     %xmm14, %xmm9
        pand      %xmm6, %xmm15
        pand      %xmm0, %xmm8
        movdqa    %xmm4, %xmm14
        por       %xmm8, %xmm15
        por       %xmm1, %xmm14
        movdqa    %xmm4, %xmm8
        pand      %xmm7, %xmm14
        pand      %xmm1, %xmm8
        paddd     %xmm10, %xmm12
        por       %xmm8, %xmm14
        paddd     %xmm10, %xmm11
        paddd     208(%rsp), %xmm9
        paddd     %xmm14, %xmm12
        paddd     240(%rsp), %xmm12
        paddd     %xmm15, %xmm11
        movdqa    %xmm9, %xmm8
        psrld     $29, %xmm9
        paddd     224(%rsp), %xmm11
        pslld     $3, %xmm8
        movdqa    %xmm12, %xmm14
        por       %xmm9, %xmm8
        movdqa    %xmm11, %xmm9
        pslld     $3, %xmm14
        psrld     $29, %xmm12
        pslld     $3, %xmm9
        psrld     $29, %xmm11
        por       %xmm12, %xmm14
        movdqa    %xmm5, %xmm12
        por       %xmm11, %xmm9
        por       %xmm2, %xmm12
        movdqa    %xmm5, %xmm11
        pand      %xmm8, %xmm12
        pand      %xmm2, %xmm11
        movdqa    %xmm6, %xmm15
        paddd     %xmm10, %xmm13
        por       %xmm11, %xmm12
        por       %xmm3, %xmm15
        movdqa    %xmm6, %xmm11
        paddd     %xmm12, %xmm13
        pand      %xmm9, %xmm15
        pand      %xmm3, %xmm11
        movdqa    %xmm7, %xmm12
        por       %xmm11, %xmm15
        por       %xmm4, %xmm12
        movdqa    %xmm7, %xmm11
        pand      %xmm14, %xmm12
        pand      %xmm4, %xmm11
        paddd     336(%rsp), %xmm13
        paddd     %xmm10, %xmm1
        por       %xmm11, %xmm12
        paddd     %xmm10, %xmm0
        paddd     %xmm12, %xmm1
        movdqa    %xmm13, %xmm12
        paddd     368(%rsp), %xmm1
        paddd     %xmm15, %xmm0
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        paddd     352(%rsp), %xmm0
        por       %xmm13, %xmm12
        movdqa    %xmm1, %xmm13
        movdqa    %xmm0, %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm1
        pslld     $5, %xmm11
        psrld     $27, %xmm0
        por       %xmm1, %xmm13
        movdqa    %xmm8, %xmm1
        por       %xmm0, %xmm11
        por       %xmm5, %xmm1
        movdqa    %xmm8, %xmm0
        pand      %xmm12, %xmm1
        pand      %xmm5, %xmm0
        paddd     %xmm10, %xmm2
        por       %xmm0, %xmm1
..B8.8:
        movdqa    %xmm9, %xmm15
        movdqa    %xmm9, %xmm0
        por       %xmm6, %xmm15
        pand      %xmm6, %xmm0
        pand      %xmm11, %xmm15
        paddd     %xmm10, %xmm3
        por       %xmm0, %xmm15
        paddd     %xmm1, %xmm2
        paddd     %xmm15, %xmm3
        movdqa    %xmm14, %xmm15
        movdqa    496(%rsp), %xmm1
        por       %xmm7, %xmm15
        movdqa    %xmm14, %xmm0
        paddd     %xmm1, %xmm2
        pand      %xmm13, %xmm15
        pand      %xmm7, %xmm0
        por       %xmm0, %xmm15
        movdqa    %xmm2, %xmm0
        paddd     528(%rsp), %xmm3
        paddd     %xmm10, %xmm4
        pslld     $9, %xmm0
        psrld     $23, %xmm2
        paddd     %xmm15, %xmm4
        por       %xmm2, %xmm0
        movdqa    %xmm3, %xmm2
        psrld     $23, %xmm3
        paddd     512(%rsp), %xmm4
        pslld     $9, %xmm2
        por       %xmm3, %xmm2
        movdqa    %xmm4, %xmm3
        pslld     $9, %xmm3
        psrld     $23, %xmm4
        movdqa    %xmm12, %xmm15
        por       %xmm4, %xmm3
        por       %xmm8, %xmm15
        movdqa    %xmm12, %xmm4
        pand      %xmm0, %xmm15
        pand      %xmm8, %xmm4
        paddd     %xmm10, %xmm5
        por       %xmm4, %xmm15
        paddd     %xmm15, %xmm5
        movdqa    %xmm11, %xmm15
        por       %xmm9, %xmm15
        movdqa    %xmm11, %xmm4
        pand      %xmm2, %xmm15
        pand      %xmm9, %xmm4
        paddd     %xmm10, %xmm6
        por       %xmm4, %xmm15
        paddd     %xmm15, %xmm6
        movdqa    %xmm13, %xmm15
        por       %xmm14, %xmm15
        movdqa    %xmm13, %xmm4
        paddd     608(%rsp), %xmm5
        pand      %xmm3, %xmm15
        pand      %xmm14, %xmm4
        paddd     %xmm10, %xmm7
        por       %xmm4, %xmm15
        movdqa    %xmm5, %xmm4
        paddd     544(%rsp), %xmm6
        pslld     $13, %xmm4
        psrld     $19, %xmm5
        paddd     %xmm15, %xmm7
        por       %xmm5, %xmm4
        movdqa    %xmm6, %xmm5
        paddd     560(%rsp), %xmm7
        pslld     $13, %xmm5
        psrld     $19, %xmm6
        movdqa    %xmm12, %xmm15
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        pslld     $13, %xmm6
        psrld     $19, %xmm7
        por       %xmm7, %xmm6
        por       %xmm0, %xmm15
        movdqa    %xmm12, %xmm7
        pand      %xmm4, %xmm15
        pand      %xmm0, %xmm7
        paddd     %xmm10, %xmm8
        por       %xmm7, %xmm15
        movdqa    %xmm11, %xmm7
        paddd     %xmm15, %xmm8
        movdqa    %xmm11, %xmm15
        por       %xmm2, %xmm15
        pand      %xmm2, %xmm7
        pand      %xmm5, %xmm15
        paddd     %xmm10, %xmm9
        por       %xmm7, %xmm15
        movdqa    %xmm13, %xmm7
        paddd     %xmm15, %xmm9
        movdqa    %xmm13, %xmm15
        por       %xmm3, %xmm15
        pand      %xmm3, %xmm7
        paddd     (%rsp), %xmm8
        pand      %xmm6, %xmm15
        por       %xmm7, %xmm15
        movdqa    %xmm8, %xmm7
        paddd     16(%rsp), %xmm9
        paddd     %xmm10, %xmm14
        pslld     $3, %xmm7
        psrld     $29, %xmm8
        paddd     %xmm15, %xmm14
        por       %xmm8, %xmm7
        movdqa    %xmm9, %xmm8
        psrld     $29, %xmm9
        paddd     32(%rsp), %xmm14
        pslld     $3, %xmm8
        por       %xmm9, %xmm8
        movdqa    %xmm14, %xmm9
        pslld     $3, %xmm9
        psrld     $29, %xmm14
        movdqa    %xmm4, %xmm15
        por       %xmm14, %xmm9
        por       %xmm0, %xmm15
        movdqa    %xmm4, %xmm14
        pand      %xmm7, %xmm15
        pand      %xmm0, %xmm14
        paddd     %xmm10, %xmm12
        por       %xmm14, %xmm15
        paddd     %xmm15, %xmm12
        movdqa    %xmm5, %xmm15
        por       %xmm2, %xmm15
        movdqa    %xmm5, %xmm14
        pand      %xmm8, %xmm15
        pand      %xmm2, %xmm14
        paddd     %xmm10, %xmm11
        por       %xmm14, %xmm15
        paddd     %xmm15, %xmm11
        movdqa    %xmm6, %xmm15
        por       %xmm3, %xmm15
        movdqa    %xmm6, %xmm14
        paddd     96(%rsp), %xmm12
        pand      %xmm9, %xmm15
        pand      %xmm3, %xmm14
        paddd     %xmm10, %xmm13
        por       %xmm14, %xmm15
        movdqa    %xmm12, %xmm14
        paddd     80(%rsp), %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        paddd     %xmm15, %xmm13
        por       %xmm12, %xmm14
        movdqa    %xmm11, %xmm12
        paddd     64(%rsp), %xmm13
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        movdqa    %xmm7, %xmm15
        por       %xmm11, %xmm12
        movdqa    %xmm13, %xmm11
        pslld     $5, %xmm11
        psrld     $27, %xmm13
        por       %xmm13, %xmm11
        por       %xmm4, %xmm15
        movdqa    %xmm7, %xmm13
        pand      %xmm14, %xmm15
        pand      %xmm4, %xmm13
        paddd     %xmm10, %xmm0
        por       %xmm13, %xmm15
        movdqa    %xmm8, %xmm13
        paddd     %xmm15, %xmm0
        movdqa    %xmm8, %xmm15
        por       %xmm5, %xmm15
        pand      %xmm5, %xmm13
        pand      %xmm12, %xmm15
        paddd     %xmm10, %xmm2
        por       %xmm13, %xmm15
        movdqa    %xmm9, %xmm13
        paddd     %xmm15, %xmm2
        movdqa    %xmm9, %xmm15
        por       %xmm6, %xmm15
        pand      %xmm6, %xmm13
        paddd     192(%rsp), %xmm0
        pand      %xmm11, %xmm15
        paddd     %xmm10, %xmm3
        por       %xmm13, %xmm15
        movdqa    %xmm0, %xmm13
        paddd     %xmm15, %xmm3
        paddd     256(%rsp), %xmm2
        pslld     $9, %xmm13
        psrld     $23, %xmm0
        paddd     %xmm10, %xmm4
        paddd     272(%rsp), %xmm3
        por       %xmm0, %xmm13
        movdqa    %xmm2, %xmm0
        psrld     $23, %xmm2
        pslld     $9, %xmm0
        movdqa    %xmm3, %xmm15
        por       %xmm2, %xmm0
        pslld     $9, %xmm15
        psrld     $23, %xmm3
        movdqa    %xmm14, %xmm2
        por       %xmm3, %xmm15
        por       %xmm7, %xmm2
        movdqa    %xmm14, %xmm3
        pand      %xmm13, %xmm2
        pand      %xmm7, %xmm3
        paddd     %xmm10, %xmm5
        por       %xmm3, %xmm2
        movdqa    %xmm12, %xmm3
        paddd     %xmm2, %xmm4
        movdqa    %xmm12, %xmm2
        por       %xmm8, %xmm2
        pand      %xmm8, %xmm3
        pand      %xmm0, %xmm2
        paddd     %xmm10, %xmm6
        por       %xmm3, %xmm2
        movdqa    %xmm11, %xmm3
        por       %xmm9, %xmm3
        movdqa    %xmm11, %xmm10
        paddd     %xmm2, %xmm5
        pand      %xmm15, %xmm3
        pand      %xmm9, %xmm10
        paddd     688(%rsp), %xmm5
        por       %xmm10, %xmm3
        paddd     %xmm3, %xmm6
        movdqa    %xmm5, %xmm10
        paddd     704(%rsp), %xmm6
        pslld     $13, %xmm10
        psrld     $19, %xmm5
        paddd     384(%rsp), %xmm4
        por       %xmm5, %xmm10
        movdqa    %xmm6, %xmm5
        movdqa    %xmm4, %xmm2
        pslld     $13, %xmm5
        psrld     $19, %xmm6
        pslld     $13, %xmm2
        psrld     $19, %xmm4
        por       %xmm6, %xmm5
        movdqa    %xmm13, %xmm6
        movdqa    .L_2il0floatpacket.479(%rip), %xmm3
        por       %xmm4, %xmm2
        pxor      %xmm14, %xmm6
        paddd     %xmm3, %xmm7
        pxor      %xmm2, %xmm6
        movdqa    %xmm0, %xmm4
        paddd     %xmm6, %xmm7
        movdqa    %xmm15, %xmm6
        pxor      %xmm12, %xmm4
        pxor      %xmm11, %xmm6
        paddd     720(%rsp), %xmm7
        paddd     %xmm3, %xmm8
        pxor      %xmm10, %xmm4
        paddd     %xmm3, %xmm9
        pxor      %xmm5, %xmm6
        paddd     %xmm4, %xmm8
        paddd     %xmm6, %xmm9
        movdqa    %xmm7, %xmm6
        paddd     736(%rsp), %xmm8
        pslld     $3, %xmm6
        psrld     $29, %xmm7
        paddd     %xmm3, %xmm14
        por       %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        paddd     752(%rsp), %xmm9
        pslld     $3, %xmm7
        psrld     $29, %xmm8
        movdqa    %xmm10, %xmm4
        por       %xmm8, %xmm7
        movdqa    %xmm9, %xmm8
        pslld     $3, %xmm8
        psrld     $29, %xmm9
        por       %xmm9, %xmm8
        movdqa    %xmm2, %xmm9
        pxor      %xmm13, %xmm9
        pxor      %xmm0, %xmm4
        pxor      %xmm6, %xmm9
        paddd     %xmm3, %xmm12
        paddd     %xmm9, %xmm14
        movdqa    %xmm5, %xmm9
        pxor      %xmm15, %xmm9
        pxor      %xmm7, %xmm4
        paddd     624(%rsp), %xmm14
        paddd     %xmm3, %xmm11
        pxor      %xmm8, %xmm9
        paddd     %xmm4, %xmm12
        paddd     %xmm9, %xmm11
        movdqa    %xmm14, %xmm9
        paddd     576(%rsp), %xmm12
        pslld     $9, %xmm9
        psrld     $23, %xmm14
        paddd     %xmm3, %xmm13
        por       %xmm14, %xmm9
        movdqa    %xmm12, %xmm14
        paddd     592(%rsp), %xmm11
        pslld     $9, %xmm14
        psrld     $23, %xmm12
        movdqa    %xmm7, %xmm4
        por       %xmm12, %xmm14
        movdqa    %xmm11, %xmm12
        pslld     $9, %xmm12
        psrld     $23, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm6, %xmm11
        pxor      %xmm2, %xmm11
        pxor      %xmm10, %xmm4
        pxor      %xmm9, %xmm11
        paddd     %xmm3, %xmm0
        paddd     %xmm11, %xmm13
        movdqa    %xmm8, %xmm11
        pxor      %xmm5, %xmm11
        pxor      %xmm14, %xmm4
        paddd     416(%rsp), %xmm13
        paddd     %xmm3, %xmm15
        pxor      %xmm12, %xmm11
        paddd     %xmm4, %xmm0
        paddd     %xmm11, %xmm15
        movdqa    %xmm13, %xmm11
        paddd     432(%rsp), %xmm0
        pslld     $11, %xmm11
        psrld     $21, %xmm13
        movdqa    %xmm14, %xmm4
        por       %xmm13, %xmm11
        movdqa    %xmm0, %xmm13
        paddd     448(%rsp), %xmm15
        pslld     $11, %xmm13
        psrld     $21, %xmm0
        paddd     %xmm3, %xmm2
        por       %xmm0, %xmm13
        movdqa    %xmm15, %xmm0
        pslld     $11, %xmm0
        psrld     $21, %xmm15
        por       %xmm15, %xmm0
        movdqa    %xmm9, %xmm15
        pxor      %xmm6, %xmm15
        pxor      %xmm7, %xmm4
        pxor      %xmm11, %xmm15
        paddd     %xmm3, %xmm10
        paddd     %xmm15, %xmm2
        pxor      %xmm13, %xmm4
        movdqa    %xmm12, %xmm15
        paddd     %xmm4, %xmm10
        pxor      %xmm8, %xmm15
        paddd     %xmm3, %xmm5
        paddd     672(%rsp), %xmm10
        pxor      %xmm0, %xmm15
        paddd     %xmm15, %xmm5
        movdqa    %xmm10, %xmm15
        paddd     656(%rsp), %xmm5
        pslld     $15, %xmm15
        psrld     $17, %xmm10
        paddd     %xmm3, %xmm6
        paddd     640(%rsp), %xmm2
        por       %xmm10, %xmm15
        movdqa    %xmm5, %xmm10
        movdqa    %xmm2, %xmm4
        pslld     $15, %xmm10
        psrld     $17, %xmm5
        pslld     $15, %xmm4
        psrld     $17, %xmm2
        por       %xmm5, %xmm10
        movdqa    %xmm11, %xmm5
        por       %xmm2, %xmm4
        pxor      %xmm9, %xmm5
        pxor      %xmm4, %xmm5
        movdqa    %xmm13, %xmm2
        paddd     %xmm5, %xmm6
        movdqa    %xmm0, %xmm5
        pxor      %xmm14, %xmm2
        pxor      %xmm12, %xmm5
        paddd     208(%rsp), %xmm6
        paddd     %xmm3, %xmm7
        pxor      %xmm15, %xmm2
        paddd     %xmm3, %xmm8
        pxor      %xmm10, %xmm5
        paddd     %xmm2, %xmm7
        paddd     %xmm5, %xmm8
        movdqa    %xmm6, %xmm5
        paddd     224(%rsp), %xmm7
        pslld     $3, %xmm5
        psrld     $29, %xmm6
        paddd     %xmm3, %xmm9
        por       %xmm6, %xmm5
        movdqa    %xmm7, %xmm6
        paddd     240(%rsp), %xmm8
        pslld     $3, %xmm6
        psrld     $29, %xmm7
        paddd     %xmm3, %xmm14
        por       %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        pslld     $3, %xmm7
        psrld     $29, %xmm8
        por       %xmm8, %xmm7
        movdqa    %xmm4, %xmm8
        pxor      %xmm11, %xmm8
        movdqa    %xmm10, %xmm2
        pxor      %xmm5, %xmm8
        pxor      %xmm0, %xmm2
        paddd     %xmm8, %xmm9
        paddd     %xmm3, %xmm12
        paddd     %xmm1, %xmm9
        movdqa    %xmm15, %xmm1
        pxor      %xmm13, %xmm1
        pxor      %xmm7, %xmm2
        pxor      %xmm6, %xmm1
        paddd     %xmm2, %xmm12
        paddd     %xmm1, %xmm14
        movdqa    %xmm9, %xmm2
        paddd     528(%rsp), %xmm14
        pslld     $9, %xmm2
        movdqa    %xmm14, %xmm1
        psrld     $23, %xmm14
        paddd     512(%rsp), %xmm12
        pslld     $9, %xmm1
        psrld     $23, %xmm9
        por       %xmm14, %xmm1
        movdqa    %xmm12, %xmm14
        por       %xmm9, %xmm2
        pslld     $9, %xmm14
        psrld     $23, %xmm12
        movdqa    %xmm7, %xmm9
        por       %xmm12, %xmm14
        movdqa    %xmm5, %xmm12
        movdqa    %xmm6, %xmm8
        pxor      %xmm10, %xmm9
        pxor      %xmm4, %xmm12
        pxor      %xmm15, %xmm8
        paddd     %xmm3, %xmm0
        pxor      %xmm14, %xmm9
        paddd     %xmm3, %xmm11
        pxor      %xmm2, %xmm12
        paddd     %xmm3, %xmm13
        pxor      %xmm1, %xmm8
        paddd     %xmm9, %xmm0
        paddd     368(%rsp), %xmm0
        paddd     %xmm12, %xmm11
        paddd     %xmm8, %xmm13
        movdqa    %xmm0, %xmm12
        paddd     336(%rsp), %xmm11
        pslld     $11, %xmm12
        paddd     352(%rsp), %xmm13
        movdqa    %xmm11, %xmm9
        movdqa    %xmm13, %xmm8
        psrld     $21, %xmm0
        pslld     $11, %xmm9
        psrld     $21, %xmm11
        pslld     $11, %xmm8
        psrld     $21, %xmm13
        por       %xmm0, %xmm12
        movdqa    %xmm2, %xmm0
        por       %xmm11, %xmm9
        por       %xmm13, %xmm8
        pxor      %xmm5, %xmm0
        movdqa    %xmm1, %xmm13
        paddd     %xmm3, %xmm4
        pxor      %xmm9, %xmm0
        pxor      %xmm6, %xmm13
        paddd     %xmm0, %xmm4
        paddd     %xmm3, %xmm15
        pxor      %xmm8, %xmm13
        movdqa    %xmm14, %xmm0
        paddd     %xmm13, %xmm15
        paddd     608(%rsp), %xmm4
        pxor      %xmm7, %xmm0
        paddd     544(%rsp), %xmm15
        paddd     %xmm3, %xmm10
        pxor      %xmm12, %xmm0
        movdqa    %xmm4, %xmm11
        paddd     %xmm0, %xmm10
        pslld     $15, %xmm11
        psrld     $17, %xmm4
        movdqa    %xmm15, %xmm0
        paddd     560(%rsp), %xmm10
        por       %xmm4, %xmm11
        pslld     $15, %xmm0
        psrld     $17, %xmm15
        movdqa    %xmm8, %xmm4
        por       %xmm15, %xmm0
        movdqa    %xmm10, %xmm13
        pxor      %xmm1, %xmm4
        pslld     $15, %xmm13
        psrld     $17, %xmm10
        paddd     %xmm3, %xmm6
        pxor      %xmm0, %xmm4
        movdqa    %xmm12, %xmm15
        por       %xmm10, %xmm13
        movdqa    %xmm9, %xmm10
        paddd     %xmm4, %xmm6
        pxor      %xmm14, %xmm15
        pxor      %xmm2, %xmm10
        paddd     112(%rsp), %xmm6
        paddd     %xmm3, %xmm7
        pxor      %xmm13, %xmm15
        paddd     %xmm3, %xmm5
        pxor      %xmm11, %xmm10
        paddd     %xmm15, %xmm7
        movdqa    %xmm6, %xmm4
        paddd     %xmm10, %xmm5
        paddd     128(%rsp), %xmm7
        pslld     $3, %xmm4
        psrld     $29, %xmm6
        paddd     %xmm3, %xmm2
        paddd     48(%rsp), %xmm5
        por       %xmm6, %xmm4
        movdqa    %xmm7, %xmm6
        movdqa    %xmm5, %xmm10
        pslld     $3, %xmm6
        psrld     $29, %xmm7
        pslld     $3, %xmm10
        psrld     $29, %xmm5
        por       %xmm7, %xmm6
        movdqa    %xmm11, %xmm7
        por       %xmm5, %xmm10
        pxor      %xmm9, %xmm7
        pxor      %xmm10, %xmm7
        movdqa    %xmm0, %xmm5
        paddd     %xmm7, %xmm2
        pxor      %xmm8, %xmm5
        paddd     320(%rsp), %xmm2
        paddd     %xmm3, %xmm1
        pxor      %xmm4, %xmm5
..B8.7:
        movdqa    %xmm13, %xmm7
        paddd     %xmm5, %xmm1
        pxor      %xmm12, %xmm7
        movdqa    %xmm2, %xmm5
        paddd     304(%rsp), %xmm1
        paddd     %xmm3, %xmm14
        pxor      %xmm6, %xmm7
        pslld     $9, %xmm5
        psrld     $23, %xmm2
        paddd     %xmm7, %xmm14
        por       %xmm2, %xmm5
        movdqa    %xmm1, %xmm2
        paddd     288(%rsp), %xmm14
        pslld     $9, %xmm2
        psrld     $23, %xmm1
        paddd     %xmm3, %xmm9
        por       %xmm1, %xmm2
        movdqa    %xmm14, %xmm1
        pslld     $9, %xmm1
        psrld     $23, %xmm14
        por       %xmm14, %xmm1
        movdqa    %xmm10, %xmm14
        pxor      %xmm11, %xmm14
        movdqa    %xmm4, %xmm15
        pxor      %xmm5, %xmm14
        pxor      %xmm0, %xmm15
        paddd     %xmm14, %xmm9
        paddd     %xmm3, %xmm8
        paddd     144(%rsp), %xmm9
        pxor      %xmm2, %xmm15
        movdqa    %xmm6, %xmm7
        paddd     %xmm15, %xmm8
        pxor      %xmm13, %xmm7
        movdqa    %xmm9, %xmm14
        paddd     160(%rsp), %xmm8
        paddd     %xmm3, %xmm12
        pxor      %xmm1, %xmm7
        pslld     $11, %xmm14
        psrld     $21, %xmm9
        paddd     %xmm7, %xmm12
        por       %xmm9, %xmm14
        movdqa    %xmm8, %xmm9
        paddd     176(%rsp), %xmm12
        pslld     $11, %xmm9
        psrld     $21, %xmm8
        paddd     %xmm3, %xmm11
        por       %xmm8, %xmm9
        movdqa    %xmm12, %xmm8
        pslld     $11, %xmm8
        psrld     $21, %xmm12
        por       %xmm12, %xmm8
        movdqa    %xmm10, %xmm12
        pxor      %xmm5, %xmm12
        movdqa    %xmm4, %xmm7
        pxor      %xmm14, %xmm12
        pxor      %xmm2, %xmm7
        paddd     %xmm12, %xmm11
        paddd     %xmm3, %xmm0
        paddd     464(%rsp), %xmm11
        pxor      %xmm9, %xmm7
        movdqa    %xmm6, %xmm15
        paddd     %xmm7, %xmm0
        pxor      %xmm1, %xmm15
        movdqa    %xmm11, %xmm12
        paddd     480(%rsp), %xmm0
        paddd     %xmm3, %xmm13
        pxor      %xmm8, %xmm15
        pslld     $15, %xmm12
        psrld     $17, %xmm11
        paddd     %xmm15, %xmm13
        por       %xmm11, %xmm12
        movdqa    %xmm0, %xmm11
        paddd     400(%rsp), %xmm13
        pslld     $15, %xmm11
        psrld     $17, %xmm0
        movdqa    %xmm8, %xmm15
        por       %xmm0, %xmm11
        movdqa    %xmm13, %xmm0
        pslld     $15, %xmm0
        psrld     $17, %xmm13
        por       %xmm13, %xmm0
        movdqa    %xmm14, %xmm13
        pxor      %xmm5, %xmm13
        paddd     %xmm3, %xmm10
        pxor      %xmm12, %xmm13
        movdqa    %xmm9, %xmm7
        pxor      %xmm1, %xmm15
        paddd     %xmm13, %xmm10
        pxor      %xmm2, %xmm7
        paddd     %xmm3, %xmm6
        pxor      %xmm0, %xmm15
        paddd     %xmm3, %xmm4
        paddd     (%rsp), %xmm10
        pxor      %xmm11, %xmm7
        paddd     %xmm15, %xmm6
        paddd     %xmm7, %xmm4
        paddd     32(%rsp), %xmm6
        movdqa    %xmm10, %xmm13
        paddd     16(%rsp), %xmm4
        pslld     $3, %xmm13
        psrld     $29, %xmm10
        movdqa    %xmm6, %xmm7
        por       %xmm10, %xmm13
        movdqa    %xmm4, %xmm10
        pslld     $3, %xmm7
        psrld     $29, %xmm6
        pslld     $3, %xmm10
        psrld     $29, %xmm4
        por       %xmm6, %xmm7
        movdqa    %xmm12, %xmm6
        por       %xmm4, %xmm10
        pxor      %xmm14, %xmm6
        movdqa    %xmm11, %xmm4
        paddd     %xmm3, %xmm5
        pxor      %xmm13, %xmm6
        pxor      %xmm9, %xmm4
        paddd     %xmm6, %xmm5
        paddd     %xmm3, %xmm2
        pxor      %xmm10, %xmm4
        movdqa    %xmm0, %xmm6
        paddd     192(%rsp), %xmm5
        paddd     %xmm4, %xmm2
        pxor      %xmm8, %xmm6
        paddd     %xmm3, %xmm1
        paddd     256(%rsp), %xmm2
        pxor      %xmm7, %xmm6
        movdqa    %xmm5, %xmm4
        paddd     %xmm6, %xmm1
        pslld     $9, %xmm4
        psrld     $23, %xmm5
        movdqa    %xmm2, %xmm6
        por       %xmm5, %xmm4
        paddd     272(%rsp), %xmm1
        pslld     $9, %xmm6
        psrld     $23, %xmm2
        movdqa    %xmm10, %xmm5
        por       %xmm2, %xmm6
        movdqa    %xmm1, %xmm2
        pxor      %xmm11, %xmm5
        pslld     $9, %xmm2
        psrld     $23, %xmm1
        paddd     %xmm3, %xmm9
        pxor      %xmm6, %xmm5
        movdqa    %xmm7, %xmm15
        por       %xmm1, %xmm2
        movdqa    %xmm13, %xmm1
        paddd     %xmm5, %xmm9
        pxor      %xmm0, %xmm15
        paddd     80(%rsp), %xmm9
        pxor      %xmm12, %xmm1
        paddd     %xmm3, %xmm8
        pxor      %xmm2, %xmm15
        paddd     %xmm3, %xmm14
        pxor      %xmm4, %xmm1
        paddd     %xmm15, %xmm8
        movdqa    %xmm9, %xmm15
        paddd     64(%rsp), %xmm8
        paddd     %xmm1, %xmm14
        pslld     $11, %xmm15
        psrld     $21, %xmm9
        paddd     96(%rsp), %xmm14
        por       %xmm9, %xmm15
        movdqa    %xmm8, %xmm9
        movdqa    %xmm14, %xmm1
        pslld     $11, %xmm9
        psrld     $21, %xmm8
        pslld     $11, %xmm1
        psrld     $21, %xmm14
        por       %xmm8, %xmm9
        paddd     %xmm3, %xmm12
        movdqa    %xmm4, %xmm8
        paddd     %xmm3, %xmm11
        movdqa    %xmm6, %xmm5
        paddd     %xmm3, %xmm0
        movdqa    %xmm2, %xmm3
        por       %xmm14, %xmm1
        pxor      %xmm13, %xmm8
        pxor      %xmm10, %xmm5
        pxor      %xmm7, %xmm3
        pxor      %xmm1, %xmm8
        pxor      %xmm15, %xmm5
        pxor      %xmm9, %xmm3
        paddd     %xmm8, %xmm12
        paddd     %xmm5, %xmm11
        paddd     %xmm3, %xmm0
        movdqa    .L_2il0floatpacket.474(%rip), %xmm8
        movdqa    .L_2il0floatpacket.477(%rip), %xmm5
        paddd     %xmm8, %xmm10
        paddd     384(%rsp), %xmm12
        paddd     %xmm5, %xmm4
        paddd     688(%rsp), %xmm11
        movdqa    %xmm12, %xmm3
        paddd     704(%rsp), %xmm0
        pslld     $15, %xmm3
        movdqa    %xmm4, 48(%rsi)
        movdqa    %xmm11, %xmm4
        movdqa    %xmm10, 64(%rsi)
        movdqa    %xmm0, %xmm10
        psrld     $17, %xmm12
        pslld     $15, %xmm4
        psrld     $17, %xmm11
        pslld     $15, %xmm10
        psrld     $17, %xmm0
        por       %xmm12, %xmm3
        movdqa    .L_2il0floatpacket.475(%rip), %xmm12
        por       %xmm11, %xmm4
        movdqa    .L_2il0floatpacket.476(%rip), %xmm14
        por       %xmm0, %xmm10
        paddd     %xmm8, %xmm13
        paddd     %xmm12, %xmm3
        paddd     %xmm14, %xmm1
        paddd     %xmm12, %xmm4
        paddd     %xmm14, %xmm15
        paddd     %xmm5, %xmm6
        paddd     %xmm8, %xmm7
        paddd     %xmm12, %xmm10
        paddd     %xmm14, %xmm9
        paddd     %xmm5, %xmm2
        movdqa    %xmm13, (%rsi)
        movdqa    %xmm3, 16(%rsi)
        movdqa    %xmm1, 32(%rsi)
        movdqa    %xmm4, 80(%rsi)
        movdqa    %xmm15, 96(%rsi)
        movdqa    %xmm6, 112(%rsi)
        movdqa    %xmm7, 128(%rsi)
        movdqa    %xmm10, 144(%rsi)
        movdqa    %xmm9, 160(%rsi)
        movdqa    %xmm2, 176(%rsi)
        addq      $776, %rsp
..___tag_value_SSEmd4body.212:
        ret       
        .align    16,0x90
..___tag_value_SSEmd4body.213:
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
..___tag_value_SSESHA1body.214:
        xorl      %r8d, %r8d
        xorl      %eax, %eax
..B9.2:
        shlq      $4, %r8
        incl      %eax
        cmpl      $64, %eax
        movdqa    208(%rdi,%r8), %xmm0
        movdqa    1488(%rdi,%r8), %xmm2
        pxor      128(%rdi,%r8), %xmm0
        pxor      1408(%rdi,%r8), %xmm2
        pxor      32(%rdi,%r8), %xmm0
        pxor      1312(%rdi,%r8), %xmm2
        pxor      1280(%rdi,%r8), %xmm2
        pxor      (%rdi,%r8), %xmm0
        movdqa    %xmm2, %xmm3
        movdqa    %xmm0, %xmm1
        psrld     $31, %xmm0
        pslld     $1, %xmm1
        pslld     $1, %xmm3
        psrld     $31, %xmm2
        por       %xmm0, %xmm1
        por       %xmm2, %xmm3
        movdqa    %xmm1, 256(%rdi,%r8)
        movdqa    %xmm3, 1536(%rdi,%r8)
        movl      %eax, %r8d
        jb        ..B9.2
..B9.3:
        testq     %rdx, %rdx
        je        ..B9.12
..B9.4:
        movdqa    (%rdx), %xmm7
        movdqa    16(%rdx), %xmm1
        movdqa    32(%rdx), %xmm6
        movdqa    48(%rdx), %xmm2
        movdqa    64(%rdx), %xmm11
        movdqa    80(%rdx), %xmm10
        movdqa    96(%rdx), %xmm5
        movdqa    112(%rdx), %xmm9
        movdqa    128(%rdx), %xmm3
        movdqa    144(%rdx), %xmm0
..B9.5:
        movdqa    %xmm6, %xmm12
        movdqa    %xmm7, %xmm8
        pxor      %xmm2, %xmm12
        movdqa    %xmm7, %xmm14
        pand      %xmm1, %xmm12
        movdqa    %xmm9, %xmm13
        pxor      %xmm2, %xmm12
        pslld     $5, %xmm8
        psrld     $27, %xmm14
        pxor      %xmm3, %xmm13
        paddd     %xmm12, %xmm11
        por       %xmm14, %xmm8
        pand      %xmm5, %xmm13
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm12
        paddd     %xmm8, %xmm11
        movdqa    .L_2il0floatpacket.503(%rip), %xmm4
        pxor      %xmm3, %xmm13
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        paddd     %xmm4, %xmm11
        paddd     %xmm13, %xmm0
        por       %xmm12, %xmm14
        movdqa    %xmm1, %xmm8
        movdqa    %xmm5, %xmm13
        paddd     %xmm14, %xmm0
        paddd     (%rdi), %xmm11
        pslld     $30, %xmm8
        psrld     $2, %xmm1
        pslld     $30, %xmm13
        psrld     $2, %xmm5
        paddd     %xmm4, %xmm0
        por       %xmm1, %xmm8
        por       %xmm5, %xmm13
        movdqa    %xmm11, %xmm1
        movdqa    %xmm11, %xmm12
        movdqa    %xmm9, %xmm14
        pslld     $5, %xmm1
        paddd     1280(%rdi), %xmm0
        psrld     $27, %xmm12
        pxor      %xmm13, %xmm14
        por       %xmm12, %xmm1
        pand      %xmm10, %xmm14
        movdqa    %xmm0, %xmm12
        movdqa    %xmm0, %xmm15
        movdqa    %xmm6, %xmm5
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm12
        psrld     $27, %xmm15
        pxor      %xmm8, %xmm5
        paddd     %xmm14, %xmm3
        por       %xmm15, %xmm12
        movdqa    %xmm7, %xmm14
        movdqa    %xmm10, %xmm15
        pand      %xmm7, %xmm5
        pslld     $30, %xmm14
        psrld     $2, %xmm7
        pslld     $30, %xmm15
        psrld     $2, %xmm10
        pxor      %xmm6, %xmm5
        paddd     %xmm12, %xmm3
        por       %xmm7, %xmm14
        por       %xmm10, %xmm15
        paddd     %xmm5, %xmm2
        paddd     %xmm4, %xmm3
        movdqa    %xmm14, %xmm7
        movdqa    %xmm15, %xmm12
        paddd     %xmm1, %xmm2
        paddd     1296(%rdi), %xmm3
        pxor      %xmm8, %xmm7
        pxor      %xmm13, %xmm12
        paddd     %xmm4, %xmm2
        pand      %xmm11, %xmm7
        pand      %xmm0, %xmm12
        movdqa    %xmm3, %xmm1
        movdqa    %xmm3, %xmm5
        paddd     16(%rdi), %xmm2
        pxor      %xmm8, %xmm7
        pxor      %xmm13, %xmm12
        pslld     $5, %xmm1
        psrld     $27, %xmm5
        paddd     %xmm7, %xmm6
        movdqa    %xmm2, %xmm7
        movdqa    %xmm2, %xmm10
        paddd     %xmm12, %xmm9
        por       %xmm5, %xmm1
        pslld     $5, %xmm7
        psrld     $27, %xmm10
        paddd     %xmm1, %xmm9
        movdqa    %xmm11, %xmm1
        por       %xmm10, %xmm7
        pslld     $30, %xmm1
        psrld     $2, %xmm11
        movdqa    %xmm0, %xmm5
        paddd     %xmm7, %xmm6
        por       %xmm11, %xmm1
        pslld     $30, %xmm5
        psrld     $2, %xmm0
        paddd     %xmm4, %xmm6
        por       %xmm0, %xmm5
        movdqa    %xmm1, %xmm0
        movdqa    %xmm5, %xmm12
        paddd     32(%rdi), %xmm6
        pxor      %xmm14, %xmm0
        pand      %xmm2, %xmm0
        movdqa    %xmm6, %xmm7
        movdqa    %xmm6, %xmm11
        pxor      %xmm14, %xmm0
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        paddd     %xmm0, %xmm8
        por       %xmm11, %xmm7
        paddd     %xmm7, %xmm8
        movdqa    %xmm2, %xmm7
        pxor      %xmm15, %xmm12
        pslld     $30, %xmm7
        psrld     $2, %xmm2
        movdqa    %xmm3, %xmm11
        pand      %xmm3, %xmm12
        por       %xmm2, %xmm7
        pslld     $30, %xmm11
        psrld     $2, %xmm3
        paddd     %xmm4, %xmm8
        por       %xmm3, %xmm11
        movdqa    %xmm7, %xmm3
        pxor      %xmm15, %xmm12
        paddd     48(%rdi), %xmm8
        pxor      %xmm1, %xmm3
        paddd     %xmm4, %xmm9
        paddd     %xmm12, %xmm13
        pand      %xmm6, %xmm3
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, %xmm2
        pxor      %xmm1, %xmm3
        paddd     1312(%rdi), %xmm9
        pslld     $5, %xmm12
        psrld     $27, %xmm2
        movdqa    %xmm9, %xmm10
        movdqa    %xmm9, %xmm0
        paddd     %xmm3, %xmm14
        por       %xmm2, %xmm12
        pslld     $5, %xmm10
        psrld     $27, %xmm0
        paddd     %xmm12, %xmm14
        movdqa    %xmm11, %xmm3
        movdqa    %xmm6, %xmm12
        por       %xmm0, %xmm10
        pxor      %xmm5, %xmm3
        pslld     $30, %xmm12
        psrld     $2, %xmm6
        movdqa    %xmm9, %xmm2
        paddd     %xmm10, %xmm13
        pand      %xmm9, %xmm3
        por       %xmm6, %xmm12
        pslld     $30, %xmm2
        psrld     $2, %xmm9
        paddd     %xmm4, %xmm13
        paddd     %xmm4, %xmm14
        por       %xmm9, %xmm2
        movdqa    %xmm12, %xmm9
        paddd     1328(%rdi), %xmm13
        pxor      %xmm5, %xmm3
        paddd     64(%rdi), %xmm14
        pxor      %xmm7, %xmm9
        paddd     %xmm3, %xmm15
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm0
        pand      %xmm8, %xmm9
        movdqa    %xmm14, %xmm3
        movdqa    %xmm14, %xmm6
        pslld     $5, %xmm10
        psrld     $27, %xmm0
        pxor      %xmm7, %xmm9
        pslld     $5, %xmm3
        psrld     $27, %xmm6
        por       %xmm0, %xmm10
        paddd     %xmm9, %xmm1
        por       %xmm6, %xmm3
        paddd     %xmm10, %xmm15
        paddd     %xmm3, %xmm1
        movdqa    %xmm8, %xmm3
        paddd     %xmm4, %xmm15
        movdqa    %xmm2, %xmm9
        pslld     $30, %xmm3
        psrld     $2, %xmm8
        pxor      %xmm11, %xmm9
        paddd     1344(%rdi), %xmm15
        por       %xmm8, %xmm3
        paddd     %xmm4, %xmm1
        pand      %xmm13, %xmm9
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, %xmm0
        movdqa    %xmm13, %xmm6
        movdqa    %xmm3, %xmm8
        paddd     80(%rdi), %xmm1
        pxor      %xmm11, %xmm9
        pslld     $5, %xmm10
        psrld     $27, %xmm0
        pslld     $30, %xmm6
        psrld     $2, %xmm13
        pxor      %xmm12, %xmm8
        paddd     %xmm9, %xmm5
        por       %xmm0, %xmm10
        por       %xmm13, %xmm6
        pand      %xmm14, %xmm8
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm13
        paddd     %xmm10, %xmm5
        pxor      %xmm12, %xmm8
        pslld     $5, %xmm9
        psrld     $27, %xmm13
        paddd     %xmm4, %xmm5
        paddd     %xmm8, %xmm7
        por       %xmm13, %xmm9
        paddd     1360(%rdi), %xmm5
        paddd     %xmm9, %xmm7
        movdqa    %xmm14, %xmm9
        movdqa    %xmm6, %xmm0
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm10
        pslld     $30, %xmm9
        psrld     $2, %xmm14
        pxor      %xmm2, %xmm0
        pslld     $5, %xmm8
        psrld     $27, %xmm10
        por       %xmm14, %xmm9
        paddd     %xmm4, %xmm7
        pand      %xmm15, %xmm0
        por       %xmm10, %xmm8
        movdqa    %xmm15, %xmm10
        movdqa    %xmm9, %xmm14
        pxor      %xmm2, %xmm0
        paddd     96(%rdi), %xmm7
        pslld     $30, %xmm10
        psrld     $2, %xmm15
        pxor      %xmm3, %xmm14
        paddd     %xmm0, %xmm11
        por       %xmm15, %xmm10
        pand      %xmm1, %xmm14
        movdqa    %xmm7, %xmm0
        movdqa    %xmm7, %xmm15
        pxor      %xmm3, %xmm14
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        paddd     %xmm8, %xmm11
        paddd     %xmm14, %xmm12
        por       %xmm15, %xmm0
        paddd     %xmm4, %xmm11
        paddd     %xmm0, %xmm12
        movdqa    %xmm10, %xmm8
        movdqa    %xmm1, %xmm0
        pxor      %xmm6, %xmm8
        paddd     1376(%rdi), %xmm11
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        pand      %xmm5, %xmm8
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm13
        por       %xmm1, %xmm0
        movdqa    %xmm5, %xmm1
        pxor      %xmm6, %xmm8
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        pslld     $30, %xmm1
        psrld     $2, %xmm5
        paddd     %xmm8, %xmm2
        por       %xmm13, %xmm14
        por       %xmm5, %xmm1
        movdqa    %xmm0, %xmm5
        paddd     %xmm14, %xmm2
        pxor      %xmm9, %xmm5
        paddd     %xmm4, %xmm2
        pand      %xmm7, %xmm5
        movdqa    %xmm1, %xmm14
        paddd     1392(%rdi), %xmm2
        pxor      %xmm9, %xmm5
        pxor      %xmm10, %xmm14
        paddd     %xmm5, %xmm3
        pand      %xmm11, %xmm14
        movdqa    %xmm2, %xmm5
        movdqa    %xmm2, %xmm15
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm6
        por       %xmm15, %xmm5
        paddd     %xmm5, %xmm6
        movdqa    %xmm7, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm7
        por       %xmm7, %xmm5
        movdqa    %xmm11, %xmm7
        pslld     $30, %xmm7
        psrld     $2, %xmm11
        paddd     %xmm4, %xmm12
        por       %xmm11, %xmm7
        movdqa    %xmm5, %xmm11
        paddd     %xmm4, %xmm6
        paddd     112(%rdi), %xmm12
        pxor      %xmm0, %xmm11
        pand      %xmm12, %xmm11
        movdqa    %xmm7, %xmm14
        paddd     1408(%rdi), %xmm6
        pxor      %xmm0, %xmm11
        pxor      %xmm1, %xmm14
        paddd     %xmm11, %xmm9
        pand      %xmm2, %xmm14
        movdqa    %xmm6, %xmm11
        movdqa    %xmm6, %xmm15
        pxor      %xmm1, %xmm14
        pslld     $5, %xmm11
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm10
        por       %xmm15, %xmm11
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm8
        paddd     %xmm11, %xmm10
        movdqa    %xmm12, %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        pslld     $30, %xmm11
        psrld     $2, %xmm12
        por       %xmm8, %xmm13
        por       %xmm12, %xmm11
        movdqa    %xmm2, %xmm12
        paddd     %xmm13, %xmm3
        pslld     $30, %xmm12
        psrld     $2, %xmm2
        paddd     %xmm4, %xmm3
        por       %xmm2, %xmm12
        movdqa    %xmm11, %xmm2
        paddd     %xmm4, %xmm10
        paddd     128(%rdi), %xmm3
        pxor      %xmm5, %xmm2
        pand      %xmm3, %xmm2
        movdqa    %xmm12, %xmm14
        paddd     1424(%rdi), %xmm10
        pxor      %xmm5, %xmm2
        pxor      %xmm7, %xmm14
        paddd     %xmm2, %xmm0
        pand      %xmm6, %xmm14
        movdqa    %xmm10, %xmm2
        movdqa    %xmm10, %xmm15
        pxor      %xmm7, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm1
        por       %xmm15, %xmm2
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm8
        paddd     %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        por       %xmm8, %xmm13
        por       %xmm3, %xmm2
        movdqa    %xmm6, %xmm3
        paddd     %xmm13, %xmm9
        pslld     $30, %xmm3
        psrld     $2, %xmm6
        paddd     %xmm4, %xmm9
        por       %xmm6, %xmm3
        movdqa    %xmm2, %xmm6
        paddd     %xmm4, %xmm1
        paddd     144(%rdi), %xmm9
        pxor      %xmm11, %xmm6
        pand      %xmm9, %xmm6
        movdqa    %xmm3, %xmm14
        paddd     1440(%rdi), %xmm1
        pxor      %xmm11, %xmm6
        pxor      %xmm12, %xmm14
        paddd     %xmm6, %xmm5
        pand      %xmm10, %xmm14
        movdqa    %xmm1, %xmm6
        movdqa    %xmm1, %xmm15
        pxor      %xmm12, %xmm14
        pslld     $5, %xmm6
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm7
        por       %xmm15, %xmm6
        movdqa    %xmm9, %xmm13
        movdqa    %xmm9, %xmm8
        paddd     %xmm6, %xmm7
        movdqa    %xmm9, %xmm6
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        pslld     $30, %xmm6
        psrld     $2, %xmm9
        por       %xmm8, %xmm13
        por       %xmm9, %xmm6
        movdqa    %xmm10, %xmm9
        paddd     %xmm13, %xmm0
        pslld     $30, %xmm9
        psrld     $2, %xmm10
        paddd     %xmm4, %xmm0
        por       %xmm10, %xmm9
        movdqa    %xmm6, %xmm10
        paddd     %xmm4, %xmm7
        paddd     160(%rdi), %xmm0
        pxor      %xmm2, %xmm10
        pand      %xmm0, %xmm10
        movdqa    %xmm9, %xmm14
        paddd     1456(%rdi), %xmm7
        movdqa    %xmm0, %xmm13
        movdqa    %xmm0, %xmm8
        pxor      %xmm2, %xmm10
        pxor      %xmm3, %xmm14
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        paddd     %xmm10, %xmm11
        pand      %xmm1, %xmm14
        movdqa    %xmm7, %xmm10
        movdqa    %xmm7, %xmm15
        por       %xmm8, %xmm13
        pxor      %xmm3, %xmm14
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm5
        paddd     %xmm14, %xmm12
        por       %xmm15, %xmm10
        paddd     %xmm4, %xmm5
        paddd     %xmm10, %xmm12
        movdqa    %xmm0, %xmm10
        psrld     $2, %xmm0
        paddd     176(%rdi), %xmm5
        pslld     $30, %xmm10
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm8
        por       %xmm0, %xmm10
        movdqa    %xmm1, %xmm0
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        pslld     $30, %xmm0
        psrld     $2, %xmm1
        por       %xmm8, %xmm13
        por       %xmm1, %xmm0
        movdqa    %xmm10, %xmm1
        paddd     %xmm13, %xmm11
        pxor      %xmm6, %xmm1
        paddd     %xmm4, %xmm11
        paddd     %xmm4, %xmm12
        pand      %xmm5, %xmm1
        movdqa    %xmm0, %xmm14
        pxor      %xmm6, %xmm1
        paddd     192(%rdi), %xmm11
        pxor      %xmm9, %xmm14
        paddd     1472(%rdi), %xmm12
        paddd     %xmm1, %xmm2
        movdqa    %xmm11, %xmm13
        movdqa    %xmm11, %xmm8
        pand      %xmm7, %xmm14
        movdqa    %xmm12, %xmm1
        movdqa    %xmm12, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm8
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        por       %xmm8, %xmm13
        paddd     %xmm14, %xmm3
        por       %xmm15, %xmm1
        paddd     %xmm13, %xmm2
        paddd     %xmm1, %xmm3
        paddd     %xmm4, %xmm2
        paddd     %xmm4, %xmm3
        movdqa    %xmm5, %xmm1
        paddd     1488(%rdi), %xmm3
        pslld     $30, %xmm1
        paddd     208(%rdi), %xmm2
        psrld     $2, %xmm5
..B9.19:
        por       %xmm5, %xmm1
        movdqa    %xmm7, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm7
        movdqa    %xmm10, %xmm14
        por       %xmm7, %xmm5
        pxor      %xmm1, %xmm14
        movdqa    %xmm0, %xmm8
        pand      %xmm11, %xmm14
        pxor      %xmm5, %xmm8
        pxor      %xmm10, %xmm14
        pand      %xmm12, %xmm8
        paddd     %xmm14, %xmm6
        pxor      %xmm0, %xmm8
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm7
        paddd     %xmm8, %xmm9
        pslld     $5, %xmm14
        psrld     $27, %xmm7
        movdqa    %xmm11, %xmm8
        movdqa    %xmm2, %xmm13
        movdqa    %xmm2, %xmm15
        por       %xmm7, %xmm14
        pslld     $30, %xmm8
        psrld     $2, %xmm11
        movdqa    %xmm12, %xmm7
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        por       %xmm11, %xmm8
        pslld     $30, %xmm7
        psrld     $2, %xmm12
        por       %xmm15, %xmm13
        por       %xmm12, %xmm7
        movdqa    %xmm8, %xmm12
        paddd     %xmm13, %xmm6
        paddd     %xmm14, %xmm9
        pxor      %xmm1, %xmm12
        paddd     %xmm4, %xmm6
        paddd     %xmm4, %xmm9
        pand      %xmm2, %xmm12
        movdqa    %xmm7, %xmm14
        pxor      %xmm1, %xmm12
        paddd     224(%rdi), %xmm6
        pxor      %xmm5, %xmm14
        paddd     1504(%rdi), %xmm9
        paddd     %xmm12, %xmm10
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        pand      %xmm3, %xmm14
        movdqa    %xmm9, %xmm13
        movdqa    %xmm9, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        pxor      %xmm5, %xmm14
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        por       %xmm11, %xmm12
        paddd     %xmm14, %xmm0
        por       %xmm15, %xmm13
        movdqa    %xmm2, %xmm11
        paddd     %xmm13, %xmm0
        pslld     $30, %xmm11
        psrld     $2, %xmm2
        movdqa    %xmm3, %xmm13
        por       %xmm2, %xmm11
        pslld     $30, %xmm13
        psrld     $2, %xmm3
        paddd     %xmm4, %xmm0
        por       %xmm3, %xmm13
        movdqa    %xmm11, %xmm3
        pxor      %xmm8, %xmm3
        paddd     %xmm12, %xmm10
        paddd     1520(%rdi), %xmm0
        pand      %xmm6, %xmm3
        pxor      %xmm8, %xmm3
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm14
        paddd     %xmm4, %xmm10
        paddd     %xmm3, %xmm1
        movdqa    %xmm13, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        paddd     240(%rdi), %xmm10
        pxor      %xmm7, %xmm3
        por       %xmm14, %xmm15
        movdqa    %xmm6, %xmm14
        movdqa    %xmm10, %xmm12
        movdqa    %xmm10, %xmm2
        pand      %xmm9, %xmm3
        pslld     $30, %xmm14
        psrld     $2, %xmm6
        pslld     $5, %xmm12
        psrld     $27, %xmm2
        pxor      %xmm7, %xmm3
        por       %xmm6, %xmm14
        por       %xmm2, %xmm12
        paddd     %xmm3, %xmm5
        movdqa    %xmm14, %xmm6
        paddd     %xmm12, %xmm1
        paddd     %xmm15, %xmm5
        movdqa    %xmm9, %xmm15
        pxor      %xmm11, %xmm6
        paddd     %xmm4, %xmm1
        pslld     $30, %xmm15
        psrld     $2, %xmm9
        pand      %xmm10, %xmm6
        paddd     256(%rdi), %xmm1
        paddd     %xmm4, %xmm5
        por       %xmm9, %xmm15
        pxor      %xmm11, %xmm6
        paddd     1536(%rdi), %xmm5
        paddd     %xmm6, %xmm8
        movdqa    %xmm1, %xmm6
        movdqa    %xmm1, %xmm9
        movdqa    %xmm15, %xmm12
        pslld     $5, %xmm6
        psrld     $27, %xmm9
        pxor      %xmm13, %xmm12
        movdqa    %xmm5, %xmm2
        movdqa    %xmm5, %xmm3
        por       %xmm9, %xmm6
        pand      %xmm0, %xmm12
        pslld     $5, %xmm2
        psrld     $27, %xmm3
        paddd     %xmm6, %xmm8
        pxor      %xmm13, %xmm12
        por       %xmm3, %xmm2
        movdqa    %xmm0, %xmm3
        paddd     %xmm4, %xmm8
        paddd     %xmm12, %xmm7
        pslld     $30, %xmm3
        psrld     $2, %xmm0
        paddd     272(%rdi), %xmm8
        paddd     %xmm2, %xmm7
        por       %xmm0, %xmm3
        paddd     %xmm4, %xmm7
        movdqa    %xmm10, %xmm2
        movdqa    %xmm8, %xmm12
        movdqa    %xmm8, %xmm6
        movdqa    %xmm3, %xmm9
        paddd     1552(%rdi), %xmm7
        pslld     $30, %xmm2
        psrld     $2, %xmm10
        pslld     $5, %xmm12
        psrld     $27, %xmm6
        pxor      %xmm15, %xmm9
        por       %xmm10, %xmm2
        por       %xmm6, %xmm12
        pand      %xmm5, %xmm9
        movdqa    %xmm7, %xmm6
        movdqa    %xmm7, %xmm10
        pxor      %xmm15, %xmm9
        pslld     $5, %xmm6
        psrld     $27, %xmm10
        movdqa    %xmm2, %xmm0
        paddd     %xmm9, %xmm13
        por       %xmm10, %xmm6
        pxor      %xmm14, %xmm0
        paddd     %xmm6, %xmm13
        movdqa    %xmm1, %xmm6
        pand      %xmm1, %xmm0
        pslld     $30, %xmm6
        psrld     $2, %xmm1
        movdqa    %xmm5, %xmm9
        pxor      %xmm14, %xmm0
        por       %xmm1, %xmm6
        pslld     $30, %xmm9
        psrld     $2, %xmm5
        paddd     %xmm0, %xmm11
        por       %xmm5, %xmm9
        movdqa    %xmm6, %xmm5
        paddd     %xmm12, %xmm11
        pxor      %xmm2, %xmm5
        paddd     %xmm4, %xmm11
        paddd     %xmm4, %xmm13
        pand      %xmm8, %xmm5
        movdqa    %xmm9, %xmm12
        pxor      %xmm2, %xmm5
        paddd     1568(%rdi), %xmm13
        pxor      %xmm3, %xmm12
        paddd     288(%rdi), %xmm11
        paddd     %xmm5, %xmm14
        movdqa    %xmm11, %xmm0
        movdqa    %xmm11, %xmm1
        pand      %xmm7, %xmm12
        movdqa    %xmm13, %xmm10
        movdqa    %xmm13, %xmm5
        pslld     $5, %xmm0
        psrld     $27, %xmm1
        pxor      %xmm3, %xmm12
        pslld     $5, %xmm10
        psrld     $27, %xmm5
        por       %xmm1, %xmm0
        paddd     %xmm12, %xmm15
        por       %xmm5, %xmm10
        movdqa    %xmm8, %xmm12
        paddd     %xmm0, %xmm14
        paddd     %xmm10, %xmm15
        pslld     $30, %xmm12
        psrld     $2, %xmm8
        paddd     %xmm4, %xmm14
        paddd     %xmm4, %xmm15
        por       %xmm8, %xmm12
        movdqa    %xmm7, %xmm4
        paddd     304(%rdi), %xmm14
        pslld     $30, %xmm4
        psrld     $2, %xmm7
        movdqa    %xmm12, %xmm8
        por       %xmm7, %xmm4
        pxor      %xmm6, %xmm8
        movdqa    %xmm14, %xmm5
        movdqa    %xmm14, %xmm7
        pxor      %xmm11, %xmm8
        pslld     $5, %xmm5
        psrld     $27, %xmm7
        paddd     %xmm8, %xmm2
        por       %xmm7, %xmm5
        movdqa    %xmm4, %xmm8
        paddd     1584(%rdi), %xmm15
        paddd     %xmm5, %xmm2
        movdqa    %xmm11, %xmm5
        pxor      %xmm9, %xmm8
        movdqa    .L_2il0floatpacket.504(%rip), %xmm0
        movdqa    %xmm15, %xmm10
        movdqa    %xmm15, %xmm1
        pslld     $30, %xmm5
        psrld     $2, %xmm11
        paddd     %xmm0, %xmm2
        pxor      %xmm13, %xmm8
        pslld     $5, %xmm10
        psrld     $27, %xmm1
        por       %xmm11, %xmm5
        movdqa    %xmm13, %xmm7
        paddd     %xmm8, %xmm3
        paddd     320(%rdi), %xmm2
        por       %xmm1, %xmm10
        pslld     $30, %xmm7
        psrld     $2, %xmm13
        movdqa    %xmm5, %xmm11
        paddd     %xmm10, %xmm3
        por       %xmm13, %xmm7
        pxor      %xmm12, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm13
        paddd     %xmm0, %xmm3
        pxor      %xmm14, %xmm11
        pslld     $5, %xmm8
        psrld     $27, %xmm13
        paddd     1600(%rdi), %xmm3
        paddd     %xmm11, %xmm6
        por       %xmm13, %xmm8
        movdqa    %xmm3, %xmm11
        paddd     %xmm8, %xmm6
        movdqa    %xmm3, %xmm10
        movdqa    %xmm14, %xmm8
        movdqa    %xmm7, %xmm1
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pslld     $30, %xmm8
        psrld     $2, %xmm14
        paddd     %xmm0, %xmm6
        pxor      %xmm4, %xmm1
        por       %xmm10, %xmm11
        por       %xmm14, %xmm8
        movdqa    %xmm15, %xmm10
        pxor      %xmm15, %xmm1
        paddd     336(%rdi), %xmm6
        pslld     $30, %xmm10
        psrld     $2, %xmm15
        movdqa    %xmm8, %xmm14
        paddd     %xmm1, %xmm9
        por       %xmm15, %xmm10
        pxor      %xmm5, %xmm14
        movdqa    %xmm6, %xmm1
        movdqa    %xmm6, %xmm15
        paddd     %xmm11, %xmm9
        pxor      %xmm2, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm0, %xmm9
        paddd     %xmm14, %xmm12
        por       %xmm15, %xmm1
        paddd     1616(%rdi), %xmm9
        paddd     %xmm1, %xmm12
        movdqa    %xmm10, %xmm11
        movdqa    %xmm2, %xmm1
        pxor      %xmm7, %xmm11
        movdqa    %xmm9, %xmm14
        movdqa    %xmm9, %xmm13
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        pxor      %xmm3, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm13
        por       %xmm2, %xmm1
        movdqa    %xmm3, %xmm2
        paddd     %xmm11, %xmm4
        por       %xmm13, %xmm14
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        paddd     %xmm14, %xmm4
        por       %xmm3, %xmm2
        movdqa    %xmm1, %xmm3
        paddd     %xmm0, %xmm4
        pxor      %xmm8, %xmm3
        movdqa    %xmm2, %xmm14
        paddd     1632(%rdi), %xmm4
        pxor      %xmm6, %xmm3
        paddd     %xmm3, %xmm5
        pxor      %xmm10, %xmm14
        movdqa    %xmm4, %xmm3
        movdqa    %xmm4, %xmm15
        pxor      %xmm9, %xmm14
        pslld     $5, %xmm3
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm7
        por       %xmm15, %xmm3
        paddd     %xmm0, %xmm12
        paddd     %xmm3, %xmm7
        movdqa    %xmm6, %xmm3
        pslld     $30, %xmm3
        psrld     $2, %xmm6
        por       %xmm6, %xmm3
        movdqa    %xmm9, %xmm6
        pslld     $30, %xmm6
        psrld     $2, %xmm9
        por       %xmm9, %xmm6
        movdqa    %xmm3, %xmm9
        paddd     352(%rdi), %xmm12
        paddd     %xmm0, %xmm7
        pxor      %xmm1, %xmm9
        movdqa    %xmm6, %xmm14
        paddd     1648(%rdi), %xmm7
        pxor      %xmm12, %xmm9
        paddd     %xmm9, %xmm8
        pxor      %xmm2, %xmm14
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm15
        pxor      %xmm4, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm10
        por       %xmm15, %xmm9
        movdqa    %xmm12, %xmm13
        movdqa    %xmm12, %xmm11
        paddd     %xmm9, %xmm10
        movdqa    %xmm12, %xmm9
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        pslld     $30, %xmm9
        psrld     $2, %xmm12
        por       %xmm11, %xmm13
        por       %xmm12, %xmm9
        movdqa    %xmm4, %xmm12
        paddd     %xmm13, %xmm5
        pslld     $30, %xmm12
        psrld     $2, %xmm4
        paddd     %xmm0, %xmm5
        por       %xmm4, %xmm12
        movdqa    %xmm9, %xmm4
        paddd     368(%rdi), %xmm5
        paddd     %xmm0, %xmm10
        pxor      %xmm3, %xmm4
        movdqa    %xmm12, %xmm14
        paddd     1664(%rdi), %xmm10
        pxor      %xmm5, %xmm4
        paddd     %xmm4, %xmm1
        pxor      %xmm6, %xmm14
        movdqa    %xmm10, %xmm4
        movdqa    %xmm10, %xmm15
        pxor      %xmm7, %xmm14
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        paddd     %xmm14, %xmm2
        por       %xmm15, %xmm4
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm11
        paddd     %xmm4, %xmm2
        movdqa    %xmm5, %xmm4
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        pslld     $30, %xmm4
        psrld     $2, %xmm5
        por       %xmm11, %xmm13
        por       %xmm5, %xmm4
        movdqa    %xmm7, %xmm5
        paddd     %xmm13, %xmm8
        pslld     $30, %xmm5
        psrld     $2, %xmm7
        paddd     %xmm0, %xmm8
        por       %xmm7, %xmm5
        movdqa    %xmm4, %xmm7
        paddd     384(%rdi), %xmm8
        paddd     %xmm0, %xmm2
        pxor      %xmm9, %xmm7
        movdqa    %xmm5, %xmm14
        paddd     1680(%rdi), %xmm2
        pxor      %xmm8, %xmm7
        paddd     %xmm7, %xmm3
        pxor      %xmm12, %xmm14
        movdqa    %xmm2, %xmm7
        movdqa    %xmm2, %xmm15
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm11
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm7
        psrld     $27, %xmm15
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        paddd     %xmm14, %xmm6
        por       %xmm15, %xmm7
        por       %xmm11, %xmm13
        paddd     %xmm7, %xmm6
        movdqa    %xmm8, %xmm7
        paddd     %xmm13, %xmm1
        pslld     $30, %xmm7
        psrld     $2, %xmm8
        paddd     %xmm0, %xmm1
        por       %xmm8, %xmm7
        movdqa    %xmm10, %xmm8
        paddd     400(%rdi), %xmm1
        pslld     $30, %xmm8
        psrld     $2, %xmm10
        movdqa    %xmm1, %xmm13
        movdqa    %xmm1, %xmm11
        por       %xmm10, %xmm8
        movdqa    %xmm7, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        paddd     %xmm0, %xmm6
        pxor      %xmm4, %xmm10
        por       %xmm11, %xmm13
        paddd     1696(%rdi), %xmm6
        pxor      %xmm1, %xmm10
        movdqa    %xmm8, %xmm14
        paddd     %xmm13, %xmm3
        paddd     %xmm10, %xmm9
        pxor      %xmm5, %xmm14
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm15
        paddd     %xmm0, %xmm3
        pxor      %xmm2, %xmm14
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        paddd     416(%rdi), %xmm3
        paddd     %xmm14, %xmm12
        por       %xmm15, %xmm10
        movdqa    %xmm3, %xmm13
        movdqa    %xmm3, %xmm11
        paddd     %xmm10, %xmm12
        movdqa    %xmm1, %xmm10
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        pslld     $30, %xmm10
        psrld     $2, %xmm1
        por       %xmm11, %xmm13
        por       %xmm1, %xmm10
        movdqa    %xmm2, %xmm1
        paddd     %xmm13, %xmm9
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        paddd     %xmm0, %xmm9
        por       %xmm2, %xmm1
        movdqa    %xmm10, %xmm2
        paddd     432(%rdi), %xmm9
        paddd     %xmm0, %xmm12
        pxor      %xmm7, %xmm2
        movdqa    %xmm9, %xmm13
        paddd     1712(%rdi), %xmm12
        pxor      %xmm3, %xmm2
        movdqa    %xmm9, %xmm11
        movdqa    %xmm1, %xmm14
        paddd     %xmm2, %xmm4
        pslld     $5, %xmm13
        psrld     $27, %xmm11
        pxor      %xmm8, %xmm14
        movdqa    %xmm12, %xmm2
        movdqa    %xmm12, %xmm15
        por       %xmm11, %xmm13
        pxor      %xmm6, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm4
        paddd     %xmm14, %xmm5
        por       %xmm15, %xmm2
        paddd     %xmm0, %xmm4
        paddd     %xmm2, %xmm5
        movdqa    1728(%rdi), %xmm2
        paddd     %xmm0, %xmm5
        paddd     448(%rdi), %xmm4
..B9.18:
        paddd     %xmm2, %xmm5
        movdqa    %xmm3, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm3
        por       %xmm3, %xmm2
        movdqa    %xmm10, %xmm13
        pxor      %xmm2, %xmm13
        movdqa    %xmm6, %xmm11
        pxor      %xmm9, %xmm13
        pslld     $30, %xmm11
        psrld     $2, %xmm6
        paddd     %xmm13, %xmm7
        movdqa    %xmm4, %xmm13
        movdqa    %xmm4, %xmm14
        por       %xmm6, %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        movdqa    %xmm1, %xmm3
        por       %xmm14, %xmm13
        pxor      %xmm11, %xmm3
        movdqa    %xmm5, %xmm15
        movdqa    %xmm5, %xmm6
        paddd     %xmm13, %xmm7
        pxor      %xmm12, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm6
        paddd     %xmm0, %xmm7
        paddd     %xmm3, %xmm8
        por       %xmm6, %xmm15
        movdqa    %xmm9, %xmm3
        movdqa    %xmm12, %xmm6
        paddd     %xmm15, %xmm8
        paddd     464(%rdi), %xmm7
        pslld     $30, %xmm3
        psrld     $2, %xmm9
        pslld     $30, %xmm6
        psrld     $2, %xmm12
        paddd     %xmm0, %xmm8
        por       %xmm9, %xmm3
        por       %xmm12, %xmm6
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm13
        paddd     1744(%rdi), %xmm8
        pslld     $5, %xmm9
        psrld     $27, %xmm13
        movdqa    %xmm6, %xmm14
        por       %xmm13, %xmm9
        pxor      %xmm11, %xmm14
        movdqa    %xmm8, %xmm13
        movdqa    %xmm8, %xmm15
        movdqa    %xmm3, %xmm12
        pxor      %xmm5, %xmm14
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        pxor      %xmm2, %xmm12
        paddd     %xmm14, %xmm1
        por       %xmm15, %xmm13
        pxor      %xmm4, %xmm12
        paddd     %xmm13, %xmm1
        movdqa    %xmm4, %xmm13
        paddd     %xmm12, %xmm10
        pslld     $30, %xmm13
        psrld     $2, %xmm4
        movdqa    %xmm5, %xmm12
        por       %xmm4, %xmm13
        pslld     $30, %xmm12
        psrld     $2, %xmm5
        paddd     %xmm9, %xmm10
        paddd     %xmm0, %xmm1
        por       %xmm5, %xmm12
        movdqa    %xmm13, %xmm5
        paddd     %xmm0, %xmm10
        paddd     1760(%rdi), %xmm1
        pxor      %xmm3, %xmm5
        paddd     480(%rdi), %xmm10
        pxor      %xmm7, %xmm5
        movdqa    %xmm12, %xmm9
        movdqa    %xmm1, %xmm15
        movdqa    %xmm1, %xmm14
        paddd     %xmm5, %xmm2
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm4
        pxor      %xmm6, %xmm9
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm4
        pxor      %xmm8, %xmm9
        por       %xmm14, %xmm15
        movdqa    %xmm7, %xmm14
        por       %xmm4, %xmm5
        paddd     %xmm9, %xmm11
        pslld     $30, %xmm14
        psrld     $2, %xmm7
        paddd     %xmm5, %xmm2
        paddd     %xmm15, %xmm11
        por       %xmm7, %xmm14
        paddd     %xmm0, %xmm2
        paddd     %xmm0, %xmm11
        movdqa    %xmm8, %xmm15
        movdqa    %xmm14, %xmm7
        pslld     $30, %xmm15
        paddd     496(%rdi), %xmm2
        psrld     $2, %xmm8
        paddd     1776(%rdi), %xmm11
        pxor      %xmm13, %xmm7
        por       %xmm8, %xmm15
        pxor      %xmm10, %xmm7
        movdqa    %xmm2, %xmm5
        movdqa    %xmm2, %xmm8
        movdqa    %xmm11, %xmm4
        movdqa    %xmm11, %xmm9
        paddd     %xmm7, %xmm3
        pslld     $5, %xmm5
        psrld     $27, %xmm8
        movdqa    %xmm15, %xmm7
        pslld     $5, %xmm4
        psrld     $27, %xmm9
        por       %xmm8, %xmm5
        pxor      %xmm12, %xmm7
        por       %xmm9, %xmm4
        movdqa    %xmm10, %xmm9
        paddd     %xmm5, %xmm3
        pxor      %xmm1, %xmm7
        pslld     $30, %xmm9
        psrld     $2, %xmm10
        paddd     %xmm0, %xmm3
        paddd     %xmm7, %xmm6
        por       %xmm10, %xmm9
        movdqa    %xmm1, %xmm7
        paddd     512(%rdi), %xmm3
        pslld     $30, %xmm7
        psrld     $2, %xmm1
        movdqa    %xmm9, %xmm10
        por       %xmm1, %xmm7
        pxor      %xmm14, %xmm10
        movdqa    %xmm3, %xmm5
        movdqa    %xmm3, %xmm1
        paddd     %xmm4, %xmm6
        pxor      %xmm2, %xmm10
        pslld     $5, %xmm5
        psrld     $27, %xmm1
        paddd     %xmm0, %xmm6
        paddd     %xmm10, %xmm13
        por       %xmm1, %xmm5
        movdqa    %xmm7, %xmm10
        paddd     1792(%rdi), %xmm6
        paddd     %xmm5, %xmm13
        movdqa    %xmm2, %xmm5
        pxor      %xmm15, %xmm10
        movdqa    %xmm6, %xmm4
        movdqa    %xmm6, %xmm8
        pslld     $30, %xmm5
        psrld     $2, %xmm2
        pxor      %xmm11, %xmm10
        pslld     $5, %xmm4
        psrld     $27, %xmm8
        por       %xmm2, %xmm5
        movdqa    %xmm11, %xmm2
        paddd     %xmm0, %xmm13
        paddd     %xmm10, %xmm12
        por       %xmm8, %xmm4
        pslld     $30, %xmm2
        psrld     $2, %xmm11
        paddd     528(%rdi), %xmm13
        paddd     %xmm4, %xmm12
        por       %xmm11, %xmm2
        movdqa    %xmm5, %xmm11
        paddd     %xmm0, %xmm12
        pxor      %xmm9, %xmm11
        movdqa    %xmm13, %xmm1
        movdqa    %xmm13, %xmm10
        paddd     1808(%rdi), %xmm12
        pxor      %xmm3, %xmm11
        pslld     $5, %xmm1
        psrld     $27, %xmm10
        movdqa    %xmm2, %xmm8
        paddd     %xmm11, %xmm14
        por       %xmm10, %xmm1
        pxor      %xmm7, %xmm8
        movdqa    %xmm12, %xmm11
        movdqa    %xmm12, %xmm4
        movdqa    %xmm3, %xmm10
        pxor      %xmm6, %xmm8
        pslld     $5, %xmm11
        psrld     $27, %xmm4
        pslld     $30, %xmm10
        psrld     $2, %xmm3
        paddd     %xmm8, %xmm15
        por       %xmm4, %xmm11
        por       %xmm3, %xmm10
        paddd     %xmm1, %xmm14
        paddd     %xmm11, %xmm15
        movdqa    %xmm6, %xmm11
        movdqa    %xmm10, %xmm3
        paddd     %xmm0, %xmm14
        pslld     $30, %xmm11
        psrld     $2, %xmm6
        pxor      %xmm5, %xmm3
        paddd     %xmm0, %xmm15
        paddd     544(%rdi), %xmm14
        por       %xmm6, %xmm11
        pxor      %xmm13, %xmm3
        movdqa    %xmm14, %xmm6
        paddd     1824(%rdi), %xmm15
        paddd     %xmm3, %xmm9
        movdqa    %xmm14, %xmm3
        movdqa    %xmm11, %xmm1
        pslld     $5, %xmm3
        psrld     $27, %xmm6
        pxor      %xmm2, %xmm1
        movdqa    %xmm15, %xmm4
        movdqa    %xmm15, %xmm8
        por       %xmm6, %xmm3
        pxor      %xmm12, %xmm1
        pslld     $5, %xmm4
        psrld     $27, %xmm8
        paddd     %xmm3, %xmm9
        paddd     %xmm1, %xmm7
        por       %xmm8, %xmm4
        movdqa    %xmm12, %xmm3
        paddd     %xmm4, %xmm7
        pslld     $30, %xmm3
        psrld     $2, %xmm12
        paddd     %xmm0, %xmm7
        por       %xmm12, %xmm3
        paddd     1840(%rdi), %xmm7
        movdqa    %xmm13, %xmm1
        movdqa    %xmm3, %xmm6
        pslld     $30, %xmm1
        psrld     $2, %xmm13
        pxor      %xmm11, %xmm6
        movdqa    %xmm7, %xmm4
        movdqa    %xmm7, %xmm8
        por       %xmm13, %xmm1
        pxor      %xmm15, %xmm6
        pslld     $5, %xmm4
        psrld     $27, %xmm8
        movdqa    %xmm1, %xmm13
        paddd     %xmm6, %xmm2
        por       %xmm8, %xmm4
        pxor      %xmm10, %xmm13
        paddd     %xmm4, %xmm2
        movdqa    %xmm14, %xmm4
        pxor      %xmm14, %xmm13
        pslld     $30, %xmm4
        psrld     $2, %xmm14
        paddd     %xmm0, %xmm9
        por       %xmm14, %xmm4
        paddd     %xmm0, %xmm2
        movdqa    %xmm4, %xmm14
        movdqa    %xmm15, %xmm6
        paddd     560(%rdi), %xmm9
        pxor      %xmm1, %xmm14
        paddd     1856(%rdi), %xmm2
        pxor      %xmm9, %xmm14
        paddd     %xmm13, %xmm5
        movdqa    %xmm9, %xmm13
        movdqa    %xmm9, %xmm12
        pslld     $30, %xmm6
        psrld     $2, %xmm15
        paddd     %xmm14, %xmm10
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm8
        pslld     $5, %xmm13
        psrld     $27, %xmm12
        por       %xmm15, %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm8
        por       %xmm12, %xmm13
        movdqa    %xmm6, %xmm12
        por       %xmm8, %xmm14
        movdqa    %xmm9, %xmm8
        pxor      %xmm3, %xmm12
        pslld     $30, %xmm8
        psrld     $2, %xmm9
        paddd     %xmm13, %xmm5
        pxor      %xmm7, %xmm12
        por       %xmm9, %xmm8
        movdqa    %xmm7, %xmm9
        paddd     %xmm0, %xmm5
        paddd     %xmm12, %xmm11
        pslld     $30, %xmm9
        psrld     $2, %xmm7
        paddd     576(%rdi), %xmm5
        paddd     %xmm14, %xmm11
        por       %xmm7, %xmm9
        movdqa    %xmm8, %xmm7
        movdqa    %xmm5, %xmm13
        movdqa    %xmm5, %xmm15
        paddd     %xmm0, %xmm11
        pxor      %xmm4, %xmm7
        paddd     1872(%rdi), %xmm11
        pslld     $5, %xmm13
        psrld     $27, %xmm15
        pxor      %xmm5, %xmm7
        movdqa    %xmm9, %xmm14
        por       %xmm15, %xmm13
        paddd     %xmm7, %xmm1
        pxor      %xmm6, %xmm14
        movdqa    %xmm11, %xmm7
        movdqa    %xmm11, %xmm15
        paddd     %xmm13, %xmm10
        pxor      %xmm2, %xmm14
        pslld     $5, %xmm7
        psrld     $27, %xmm15
        paddd     %xmm0, %xmm10
        paddd     %xmm14, %xmm3
        por       %xmm15, %xmm7
        paddd     592(%rdi), %xmm10
        paddd     %xmm7, %xmm3
        movdqa    %xmm5, %xmm7
        movdqa    %xmm10, %xmm12
        movdqa    %xmm10, %xmm13
        pslld     $30, %xmm7
        psrld     $2, %xmm5
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        por       %xmm5, %xmm7
        movdqa    %xmm2, %xmm5
        por       %xmm13, %xmm12
        pslld     $30, %xmm5
        psrld     $2, %xmm2
        paddd     %xmm12, %xmm1
        por       %xmm2, %xmm5
        movdqa    %xmm7, %xmm2
        paddd     %xmm0, %xmm1
        paddd     %xmm0, %xmm3
        pxor      %xmm8, %xmm2
        paddd     608(%rdi), %xmm1
        pxor      %xmm10, %xmm2
        paddd     1888(%rdi), %xmm3
        movdqa    %xmm5, %xmm14
        paddd     %xmm2, %xmm4
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm13
        pxor      %xmm9, %xmm14
        movdqa    %xmm3, %xmm2
        movdqa    %xmm3, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm13
        pxor      %xmm11, %xmm14
        pslld     $5, %xmm2
        psrld     $27, %xmm15
        por       %xmm13, %xmm12
        paddd     %xmm14, %xmm6
        por       %xmm15, %xmm2
        paddd     %xmm12, %xmm4
        paddd     %xmm2, %xmm6
        paddd     %xmm0, %xmm4
        paddd     %xmm0, %xmm6
        movdqa    %xmm10, %xmm2
        movdqa    %xmm11, %xmm0
        pslld     $30, %xmm2
        psrld     $2, %xmm10
        pslld     $30, %xmm0
        psrld     $2, %xmm11
        por       %xmm10, %xmm2
        por       %xmm11, %xmm0
        movdqa    %xmm1, %xmm11
        movdqa    %xmm1, %xmm10
        por       %xmm2, %xmm11
        pand      %xmm2, %xmm10
        paddd     624(%rdi), %xmm4
        pand      %xmm7, %xmm11
        por       %xmm11, %xmm10
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm11
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        movdqa    %xmm3, %xmm14
        paddd     1904(%rdi), %xmm6
        paddd     %xmm10, %xmm8
        por       %xmm11, %xmm12
        movdqa    %xmm3, %xmm15
        por       %xmm0, %xmm14
        paddd     %xmm12, %xmm8
        pand      %xmm0, %xmm15
        pand      %xmm5, %xmm14
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm11
        por       %xmm14, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        paddd     %xmm15, %xmm9
        por       %xmm11, %xmm12
        movdqa    %xmm3, %xmm11
        paddd     %xmm12, %xmm9
        movdqa    %xmm1, %xmm12
        pslld     $30, %xmm12
        psrld     $2, %xmm1
        pslld     $30, %xmm11
        psrld     $2, %xmm3
        movdqa    .L_2il0floatpacket.505(%rip), %xmm13
        por       %xmm1, %xmm12
        por       %xmm3, %xmm11
        movdqa    %xmm4, %xmm3
        paddd     %xmm13, %xmm8
        movdqa    %xmm4, %xmm1
        por       %xmm12, %xmm3
        pand      %xmm12, %xmm1
        paddd     640(%rdi), %xmm8
        pand      %xmm2, %xmm3
        por       %xmm3, %xmm1
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm3
        paddd     %xmm13, %xmm9
        pslld     $5, %xmm10
        psrld     $27, %xmm3
        movdqa    %xmm6, %xmm14
        paddd     %xmm1, %xmm7
        paddd     1920(%rdi), %xmm9
        por       %xmm3, %xmm10
        movdqa    %xmm6, %xmm15
        por       %xmm11, %xmm14
        paddd     %xmm10, %xmm7
        pand      %xmm11, %xmm15
        pand      %xmm0, %xmm14
        movdqa    %xmm9, %xmm10
        movdqa    %xmm9, %xmm3
        por       %xmm14, %xmm15
        pslld     $5, %xmm10
        psrld     $27, %xmm3
        paddd     %xmm15, %xmm5
        por       %xmm3, %xmm10
        paddd     %xmm10, %xmm5
        movdqa    %xmm4, %xmm10
        movdqa    %xmm6, %xmm3
        pslld     $30, %xmm10
        psrld     $2, %xmm4
        pslld     $30, %xmm3
        psrld     $2, %xmm6
        por       %xmm4, %xmm10
        por       %xmm6, %xmm3
        movdqa    %xmm8, %xmm6
        paddd     %xmm13, %xmm7
        movdqa    %xmm8, %xmm4
        por       %xmm10, %xmm6
        pand      %xmm10, %xmm4
        paddd     656(%rdi), %xmm7
        pand      %xmm12, %xmm6
        por       %xmm6, %xmm4
        movdqa    %xmm7, %xmm6
        movdqa    %xmm7, %xmm1
        paddd     %xmm13, %xmm5
        pslld     $5, %xmm6
        psrld     $27, %xmm1
        movdqa    %xmm9, %xmm14
        paddd     %xmm4, %xmm2
        paddd     1936(%rdi), %xmm5
        por       %xmm1, %xmm6
        movdqa    %xmm9, %xmm15
        por       %xmm3, %xmm14
        paddd     %xmm6, %xmm2
        pand      %xmm3, %xmm15
        pand      %xmm11, %xmm14
        movdqa    %xmm5, %xmm6
        movdqa    %xmm5, %xmm1
        por       %xmm14, %xmm15
        pslld     $5, %xmm6
        psrld     $27, %xmm1
        paddd     %xmm15, %xmm0
        por       %xmm1, %xmm6
        paddd     %xmm6, %xmm0
        movdqa    %xmm8, %xmm1
        movdqa    %xmm9, %xmm6
        pslld     $30, %xmm1
        psrld     $2, %xmm8
        pslld     $30, %xmm6
        psrld     $2, %xmm9
        paddd     %xmm13, %xmm2
        por       %xmm8, %xmm1
        por       %xmm9, %xmm6
        movdqa    %xmm7, %xmm9
        movdqa    %xmm7, %xmm4
        paddd     672(%rdi), %xmm2
        por       %xmm1, %xmm9
        pand      %xmm1, %xmm4
        pand      %xmm10, %xmm9
        movdqa    %xmm2, %xmm14
        movdqa    %xmm2, %xmm8
        por       %xmm9, %xmm4
        pslld     $5, %xmm14
        psrld     $27, %xmm8
        paddd     %xmm4, %xmm12
        por       %xmm8, %xmm14
        movdqa    %xmm5, %xmm15
        paddd     %xmm14, %xmm12
        movdqa    %xmm5, %xmm4
        por       %xmm6, %xmm15
        paddd     %xmm13, %xmm0
        paddd     %xmm13, %xmm12
        pand      %xmm6, %xmm4
        pand      %xmm3, %xmm15
        paddd     688(%rdi), %xmm12
        por       %xmm15, %xmm4
        paddd     1952(%rdi), %xmm0
..B9.17:
        paddd     %xmm4, %xmm11
        movdqa    %xmm0, %xmm8
        movdqa    %xmm0, %xmm4
        pslld     $5, %xmm8
        psrld     $27, %xmm4
        movdqa    %xmm2, %xmm9
        por       %xmm4, %xmm8
        movdqa    %xmm7, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm7
        por       %xmm7, %xmm4
        movdqa    %xmm5, %xmm7
        pslld     $30, %xmm7
        psrld     $2, %xmm5
        movdqa    %xmm2, %xmm14
        por       %xmm4, %xmm9
        paddd     %xmm8, %xmm11
        por       %xmm5, %xmm7
        pand      %xmm4, %xmm14
        pand      %xmm1, %xmm9
        movdqa    %xmm12, %xmm5
        movdqa    %xmm12, %xmm8
        paddd     %xmm13, %xmm11
        por       %xmm9, %xmm14
        pslld     $5, %xmm5
        psrld     $27, %xmm8
        movdqa    %xmm0, %xmm15
        paddd     %xmm14, %xmm10
        paddd     1968(%rdi), %xmm11
        por       %xmm8, %xmm5
        movdqa    %xmm0, %xmm9
        por       %xmm7, %xmm15
        paddd     %xmm5, %xmm10
        pand      %xmm7, %xmm9
        pand      %xmm6, %xmm15
        movdqa    %xmm11, %xmm5
        movdqa    %xmm11, %xmm8
        por       %xmm15, %xmm9
        pslld     $5, %xmm5
        psrld     $27, %xmm8
        paddd     %xmm9, %xmm3
        por       %xmm8, %xmm5
        paddd     %xmm5, %xmm3
        movdqa    %xmm2, %xmm5
        pslld     $30, %xmm5
        psrld     $2, %xmm2
        por       %xmm2, %xmm5
        movdqa    %xmm0, %xmm2
        pslld     $30, %xmm2
        psrld     $2, %xmm0
        por       %xmm0, %xmm2
        movdqa    %xmm12, %xmm0
        movdqa    %xmm12, %xmm8
        por       %xmm5, %xmm0
        pand      %xmm5, %xmm8
        pand      %xmm4, %xmm0
        movdqa    %xmm11, %xmm14
        por       %xmm0, %xmm8
        movdqa    %xmm11, %xmm0
        por       %xmm2, %xmm14
        pand      %xmm2, %xmm0
        pand      %xmm7, %xmm14
        paddd     %xmm13, %xmm10
        por       %xmm14, %xmm0
        paddd     704(%rdi), %xmm10
        paddd     %xmm0, %xmm6
        movdqa    %xmm12, %xmm0
        paddd     %xmm13, %xmm3
        movdqa    %xmm10, %xmm9
        movdqa    %xmm10, %xmm15
        pslld     $30, %xmm0
        psrld     $2, %xmm12
        paddd     1984(%rdi), %xmm3
        pslld     $5, %xmm9
        psrld     $27, %xmm15
        por       %xmm12, %xmm0
        movdqa    %xmm11, %xmm12
        paddd     %xmm8, %xmm1
        por       %xmm15, %xmm9
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm8
        pslld     $30, %xmm12
        psrld     $2, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm8
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm11
        por       %xmm8, %xmm15
        movdqa    %xmm10, %xmm8
        por       %xmm0, %xmm11
        pand      %xmm0, %xmm8
        pand      %xmm5, %xmm11
        movdqa    %xmm3, %xmm14
        por       %xmm11, %xmm8
        movdqa    %xmm3, %xmm11
        por       %xmm12, %xmm14
        paddd     %xmm9, %xmm1
        pand      %xmm12, %xmm11
        pand      %xmm2, %xmm14
        paddd     %xmm13, %xmm1
        por       %xmm14, %xmm11
        paddd     %xmm15, %xmm6
        paddd     720(%rdi), %xmm1
        paddd     %xmm11, %xmm7
        movdqa    %xmm10, %xmm11
        paddd     %xmm13, %xmm6
        movdqa    %xmm1, %xmm9
        movdqa    %xmm1, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        paddd     2000(%rdi), %xmm6
        pslld     $5, %xmm9
        psrld     $27, %xmm15
        por       %xmm10, %xmm11
        movdqa    %xmm3, %xmm10
        paddd     %xmm8, %xmm4
        por       %xmm15, %xmm9
        movdqa    %xmm6, %xmm15
        movdqa    %xmm6, %xmm8
        pslld     $30, %xmm10
        psrld     $2, %xmm3
        pslld     $5, %xmm15
        psrld     $27, %xmm8
        por       %xmm3, %xmm10
        movdqa    %xmm1, %xmm3
        por       %xmm8, %xmm15
        movdqa    %xmm1, %xmm8
        por       %xmm11, %xmm3
        paddd     %xmm9, %xmm4
        pand      %xmm11, %xmm8
        pand      %xmm0, %xmm3
        movdqa    %xmm6, %xmm14
        paddd     %xmm13, %xmm4
        por       %xmm3, %xmm8
        movdqa    %xmm6, %xmm3
        por       %xmm10, %xmm14
        paddd     736(%rdi), %xmm4
        paddd     %xmm15, %xmm7
        pand      %xmm10, %xmm3
        pand      %xmm12, %xmm14
        paddd     %xmm13, %xmm7
        movdqa    %xmm4, %xmm9
        movdqa    %xmm4, %xmm15
        por       %xmm14, %xmm3
        paddd     2016(%rdi), %xmm7
        pslld     $5, %xmm9
        psrld     $27, %xmm15
        paddd     %xmm3, %xmm2
        movdqa    %xmm1, %xmm3
        paddd     %xmm8, %xmm5
        por       %xmm15, %xmm9
        movdqa    %xmm7, %xmm15
        movdqa    %xmm7, %xmm8
        pslld     $30, %xmm3
        psrld     $2, %xmm1
        movdqa    %xmm6, %xmm14
        paddd     %xmm9, %xmm5
        pslld     $5, %xmm15
        psrld     $27, %xmm8
        por       %xmm1, %xmm3
        pslld     $30, %xmm14
        psrld     $2, %xmm6
        movdqa    %xmm4, %xmm1
        paddd     %xmm13, %xmm5
        por       %xmm8, %xmm15
        por       %xmm6, %xmm14
        movdqa    %xmm4, %xmm6
        por       %xmm3, %xmm1
        paddd     752(%rdi), %xmm5
        paddd     %xmm15, %xmm2
        pand      %xmm3, %xmm6
        pand      %xmm11, %xmm1
        movdqa    %xmm7, %xmm15
        por       %xmm1, %xmm6
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm1
        movdqa    %xmm7, %xmm9
        por       %xmm14, %xmm15
        pslld     $5, %xmm8
        psrld     $27, %xmm1
        pand      %xmm14, %xmm9
        pand      %xmm10, %xmm15
        paddd     %xmm13, %xmm2
        paddd     %xmm6, %xmm0
        por       %xmm1, %xmm8
        por       %xmm15, %xmm9
        paddd     2032(%rdi), %xmm2
        paddd     %xmm8, %xmm0
        paddd     %xmm9, %xmm12
        movdqa    %xmm4, %xmm9
        movdqa    %xmm7, %xmm8
        movdqa    %xmm2, %xmm6
        movdqa    %xmm2, %xmm1
        pslld     $30, %xmm9
        psrld     $2, %xmm4
        pslld     $30, %xmm8
        psrld     $2, %xmm7
        pslld     $5, %xmm6
        psrld     $27, %xmm1
        por       %xmm4, %xmm9
        por       %xmm7, %xmm8
        movdqa    %xmm5, %xmm7
        por       %xmm1, %xmm6
        movdqa    %xmm5, %xmm1
        por       %xmm9, %xmm7
        paddd     %xmm13, %xmm0
        pand      %xmm9, %xmm1
        pand      %xmm3, %xmm7
        paddd     768(%rdi), %xmm0
        por       %xmm7, %xmm1
        movdqa    %xmm2, %xmm15
        paddd     %xmm6, %xmm12
        paddd     %xmm1, %xmm11
        movdqa    %xmm0, %xmm6
        movdqa    %xmm0, %xmm4
        movdqa    %xmm2, %xmm1
        por       %xmm8, %xmm15
        pslld     $5, %xmm6
        psrld     $27, %xmm4
        pand      %xmm8, %xmm1
        pand      %xmm14, %xmm15
        paddd     %xmm13, %xmm12
        por       %xmm4, %xmm6
        por       %xmm15, %xmm1
        paddd     2048(%rdi), %xmm12
        paddd     %xmm6, %xmm11
        paddd     %xmm1, %xmm10
        movdqa    %xmm5, %xmm1
        movdqa    %xmm2, %xmm6
        movdqa    %xmm12, %xmm7
        movdqa    %xmm12, %xmm4
        pslld     $30, %xmm1
        psrld     $2, %xmm5
        pslld     $30, %xmm6
        psrld     $2, %xmm2
        paddd     %xmm13, %xmm11
        pslld     $5, %xmm7
        psrld     $27, %xmm4
        por       %xmm5, %xmm1
        por       %xmm2, %xmm6
        movdqa    %xmm0, %xmm2
        por       %xmm4, %xmm7
        paddd     784(%rdi), %xmm11
        movdqa    %xmm0, %xmm4
        por       %xmm1, %xmm2
        paddd     %xmm7, %xmm10
        pand      %xmm1, %xmm4
        pand      %xmm9, %xmm2
        movdqa    %xmm11, %xmm5
        movdqa    %xmm11, %xmm7
        movdqa    %xmm12, %xmm15
        por       %xmm2, %xmm4
        pslld     $5, %xmm5
        psrld     $27, %xmm7
        movdqa    %xmm12, %xmm2
        por       %xmm6, %xmm15
        paddd     %xmm13, %xmm10
        paddd     %xmm4, %xmm3
        por       %xmm7, %xmm5
        pand      %xmm6, %xmm2
        pand      %xmm8, %xmm15
        paddd     %xmm5, %xmm3
        paddd     2064(%rdi), %xmm10
        por       %xmm15, %xmm2
        movdqa    %xmm0, %xmm5
        movdqa    %xmm12, %xmm15
        movdqa    %xmm10, %xmm7
        movdqa    %xmm10, %xmm4
        pslld     $30, %xmm5
        psrld     $2, %xmm0
        pslld     $30, %xmm15
        psrld     $2, %xmm12
        paddd     %xmm13, %xmm3
        pslld     $5, %xmm7
        psrld     $27, %xmm4
        por       %xmm0, %xmm5
        por       %xmm12, %xmm15
        movdqa    %xmm11, %xmm12
        paddd     800(%rdi), %xmm3
        paddd     %xmm2, %xmm14
        por       %xmm4, %xmm7
        movdqa    %xmm11, %xmm2
        por       %xmm5, %xmm12
        paddd     %xmm7, %xmm14
        pand      %xmm5, %xmm2
        pand      %xmm1, %xmm12
        movdqa    %xmm3, %xmm0
        movdqa    %xmm3, %xmm4
        paddd     %xmm13, %xmm14
        por       %xmm12, %xmm2
        pslld     $5, %xmm0
        psrld     $27, %xmm4
        movdqa    %xmm10, %xmm7
        paddd     %xmm2, %xmm9
        paddd     2080(%rdi), %xmm14
        por       %xmm4, %xmm0
        movdqa    %xmm10, %xmm2
        por       %xmm15, %xmm7
        paddd     %xmm0, %xmm9
        pand      %xmm15, %xmm2
        pand      %xmm6, %xmm7
        movdqa    %xmm14, %xmm0
        movdqa    %xmm14, %xmm4
        por       %xmm7, %xmm2
        pslld     $5, %xmm0
        psrld     $27, %xmm4
        paddd     %xmm2, %xmm8
        por       %xmm4, %xmm0
        movdqa    %xmm11, %xmm4
        movdqa    %xmm10, %xmm2
        pslld     $30, %xmm4
        psrld     $2, %xmm11
        pslld     $30, %xmm2
        psrld     $2, %xmm10
        por       %xmm11, %xmm4
        por       %xmm10, %xmm2
        movdqa    %xmm3, %xmm10
        paddd     %xmm13, %xmm9
        paddd     %xmm0, %xmm8
        movdqa    %xmm3, %xmm0
        por       %xmm4, %xmm10
        pand      %xmm4, %xmm0
        paddd     816(%rdi), %xmm9
        pand      %xmm5, %xmm10
        por       %xmm10, %xmm0
        movdqa    %xmm9, %xmm7
        movdqa    %xmm9, %xmm11
        movdqa    %xmm14, %xmm12
        paddd     %xmm13, %xmm8
        paddd     %xmm0, %xmm1
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        movdqa    %xmm14, %xmm0
        por       %xmm2, %xmm12
        paddd     2096(%rdi), %xmm8
        por       %xmm11, %xmm7
        pand      %xmm2, %xmm0
        pand      %xmm15, %xmm12
        paddd     %xmm7, %xmm1
        por       %xmm12, %xmm0
        movdqa    %xmm8, %xmm7
        movdqa    %xmm8, %xmm11
        paddd     %xmm0, %xmm6
        pslld     $5, %xmm7
        psrld     $27, %xmm11
        movdqa    %xmm3, %xmm0
        por       %xmm11, %xmm7
        pslld     $30, %xmm0
        psrld     $2, %xmm3
        movdqa    %xmm14, %xmm11
        paddd     %xmm13, %xmm1
        por       %xmm3, %xmm0
        pslld     $30, %xmm11
        psrld     $2, %xmm14
        movdqa    %xmm9, %xmm3
        por       %xmm14, %xmm11
        paddd     832(%rdi), %xmm1
        movdqa    %xmm9, %xmm14
        por       %xmm0, %xmm3
        paddd     %xmm7, %xmm6
        pand      %xmm0, %xmm14
        pand      %xmm4, %xmm3
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm7
        paddd     %xmm13, %xmm6
        por       %xmm3, %xmm14
        pslld     $5, %xmm10
        psrld     $27, %xmm7
        movdqa    %xmm8, %xmm3
        paddd     %xmm14, %xmm5
        paddd     2112(%rdi), %xmm6
        por       %xmm7, %xmm10
        movdqa    %xmm8, %xmm12
        por       %xmm11, %xmm3
        paddd     %xmm10, %xmm5
        pand      %xmm11, %xmm12
        pand      %xmm2, %xmm3
        movdqa    %xmm6, %xmm10
        movdqa    %xmm6, %xmm7
        por       %xmm3, %xmm12
        pslld     $5, %xmm10
        psrld     $27, %xmm7
        paddd     %xmm12, %xmm15
        por       %xmm7, %xmm10
        paddd     %xmm10, %xmm15
        movdqa    %xmm9, %xmm10
        movdqa    %xmm8, %xmm7
        pslld     $30, %xmm10
        psrld     $2, %xmm9
        pslld     $30, %xmm7
        psrld     $2, %xmm8
        por       %xmm9, %xmm10
        por       %xmm8, %xmm7
        movdqa    %xmm1, %xmm8
        paddd     %xmm13, %xmm5
        movdqa    %xmm1, %xmm9
        por       %xmm10, %xmm8
        pand      %xmm10, %xmm9
        paddd     848(%rdi), %xmm5
        pand      %xmm0, %xmm8
        por       %xmm8, %xmm9
        movdqa    %xmm5, %xmm8
        movdqa    %xmm5, %xmm3
        paddd     %xmm13, %xmm15
        pslld     $5, %xmm8
        psrld     $27, %xmm3
        paddd     2128(%rdi), %xmm15
        paddd     %xmm9, %xmm4
        por       %xmm3, %xmm8
        movdqa    %xmm15, %xmm3
        paddd     %xmm8, %xmm4
        movdqa    %xmm15, %xmm8
        pslld     $5, %xmm8
        psrld     $27, %xmm3
        movdqa    %xmm6, %xmm12
        por       %xmm3, %xmm8
        movdqa    %xmm1, %xmm3
        movdqa    %xmm6, %xmm14
        por       %xmm7, %xmm12
        pslld     $30, %xmm3
        psrld     $2, %xmm1
        pand      %xmm7, %xmm14
        pand      %xmm11, %xmm12
        por       %xmm1, %xmm3
        movdqa    %xmm6, %xmm1
        por       %xmm12, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm6
        paddd     %xmm13, %xmm4
        paddd     %xmm14, %xmm2
        por       %xmm6, %xmm1
        movdqa    %xmm5, %xmm6
        paddd     864(%rdi), %xmm4
        paddd     %xmm8, %xmm2
        movdqa    %xmm5, %xmm8
        por       %xmm3, %xmm6
        paddd     %xmm13, %xmm2
        pand      %xmm3, %xmm8
        pand      %xmm10, %xmm6
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm9
        por       %xmm6, %xmm8
        paddd     2144(%rdi), %xmm2
        pslld     $5, %xmm12
        psrld     $27, %xmm9
        movdqa    %xmm15, %xmm14
        paddd     %xmm8, %xmm0
        por       %xmm9, %xmm12
        movdqa    %xmm15, %xmm6
        por       %xmm1, %xmm14
        movdqa    %xmm2, %xmm9
        movdqa    %xmm2, %xmm8
        pand      %xmm1, %xmm6
        pand      %xmm7, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm8
        por       %xmm14, %xmm6
        por       %xmm8, %xmm9
        movdqa    %xmm5, %xmm8
        paddd     %xmm6, %xmm11
        pslld     $30, %xmm8
        psrld     $2, %xmm5
        movdqa    %xmm15, %xmm6
        paddd     %xmm12, %xmm0
        por       %xmm5, %xmm8
        pslld     $30, %xmm6
        psrld     $2, %xmm15
        movdqa    %xmm4, %xmm5
        paddd     %xmm13, %xmm0
        por       %xmm15, %xmm6
        movdqa    %xmm4, %xmm15
        por       %xmm8, %xmm5
        paddd     880(%rdi), %xmm0
        pand      %xmm8, %xmm15
        pand      %xmm3, %xmm5
        paddd     %xmm9, %xmm11
        por       %xmm5, %xmm15
        movdqa    %xmm0, %xmm9
        movdqa    %xmm0, %xmm5
        paddd     %xmm13, %xmm11
        pslld     $5, %xmm9
        psrld     $27, %xmm5
        movdqa    %xmm2, %xmm12
        paddd     %xmm15, %xmm10
        paddd     2160(%rdi), %xmm11
        por       %xmm5, %xmm9
        movdqa    %xmm2, %xmm14
        por       %xmm6, %xmm12
        paddd     %xmm9, %xmm10
        pand      %xmm6, %xmm14
        pand      %xmm1, %xmm12
        movdqa    %xmm11, %xmm9
        movdqa    %xmm11, %xmm5
        por       %xmm12, %xmm14
        pslld     $5, %xmm9
        psrld     $27, %xmm5
        paddd     %xmm14, %xmm7
        por       %xmm5, %xmm9
        paddd     %xmm9, %xmm7
        paddd     %xmm13, %xmm10
        paddd     %xmm13, %xmm7
        movdqa    %xmm4, %xmm5
        paddd     2176(%rdi), %xmm7
        pslld     $30, %xmm5
        paddd     896(%rdi), %xmm10
        psrld     $2, %xmm4
..B9.16:
        por       %xmm4, %xmm5
        movdqa    %xmm2, %xmm4
        pslld     $30, %xmm4
        psrld     $2, %xmm2
        movdqa    %xmm0, %xmm9
        por       %xmm2, %xmm4
        movdqa    %xmm0, %xmm2
        por       %xmm5, %xmm9
        pand      %xmm5, %xmm2
        pand      %xmm8, %xmm9
        movdqa    %xmm10, %xmm14
        movdqa    %xmm10, %xmm12
        por       %xmm9, %xmm2
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        paddd     %xmm2, %xmm3
        por       %xmm12, %xmm14
        movdqa    %xmm7, %xmm12
        movdqa    %xmm7, %xmm2
        movdqa    %xmm11, %xmm15
        pslld     $5, %xmm12
        psrld     $27, %xmm2
        movdqa    %xmm11, %xmm9
        por       %xmm4, %xmm15
        por       %xmm2, %xmm12
        movdqa    %xmm0, %xmm2
        pand      %xmm4, %xmm9
        pand      %xmm6, %xmm15
        pslld     $30, %xmm2
        psrld     $2, %xmm0
        paddd     %xmm14, %xmm3
        por       %xmm15, %xmm9
        por       %xmm0, %xmm2
        movdqa    %xmm11, %xmm0
        paddd     %xmm13, %xmm3
        paddd     %xmm9, %xmm1
        pslld     $30, %xmm0
        psrld     $2, %xmm11
        paddd     912(%rdi), %xmm3
        paddd     %xmm12, %xmm1
        por       %xmm11, %xmm0
        movdqa    %xmm10, %xmm11
        paddd     %xmm13, %xmm1
        movdqa    %xmm10, %xmm9
        por       %xmm2, %xmm11
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm12
        pand      %xmm2, %xmm9
        paddd     2192(%rdi), %xmm1
        pand      %xmm5, %xmm11
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        por       %xmm11, %xmm9
        por       %xmm12, %xmm14
        movdqa    %xmm1, %xmm12
        movdqa    %xmm1, %xmm11
        pslld     $5, %xmm12
        psrld     $27, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm11
        movdqa    %xmm7, %xmm15
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        paddd     %xmm9, %xmm8
        movdqa    %xmm7, %xmm9
        por       %xmm0, %xmm15
        por       %xmm10, %xmm11
        movdqa    %xmm7, %xmm10
        pand      %xmm0, %xmm9
        pand      %xmm4, %xmm15
        pslld     $30, %xmm10
        psrld     $2, %xmm7
        paddd     %xmm14, %xmm8
        por       %xmm15, %xmm9
        por       %xmm7, %xmm10
        movdqa    %xmm3, %xmm7
        paddd     %xmm13, %xmm8
        paddd     %xmm9, %xmm6
        movdqa    %xmm3, %xmm9
        por       %xmm11, %xmm7
        paddd     928(%rdi), %xmm8
        paddd     %xmm12, %xmm6
        pand      %xmm11, %xmm9
        pand      %xmm2, %xmm7
        paddd     %xmm13, %xmm6
        por       %xmm7, %xmm9
        movdqa    %xmm8, %xmm14
        movdqa    %xmm8, %xmm12
        movdqa    %xmm1, %xmm15
        paddd     %xmm9, %xmm5
        paddd     2208(%rdi), %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        movdqa    %xmm1, %xmm9
        por       %xmm10, %xmm15
        por       %xmm12, %xmm14
        pand      %xmm10, %xmm9
        pand      %xmm0, %xmm15
        movdqa    %xmm6, %xmm12
        movdqa    %xmm6, %xmm7
        por       %xmm15, %xmm9
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        paddd     %xmm9, %xmm4
        por       %xmm7, %xmm12
        paddd     %xmm14, %xmm5
        paddd     %xmm12, %xmm4
        paddd     %xmm13, %xmm5
        paddd     %xmm13, %xmm4
        movdqa    %xmm3, %xmm13
        pslld     $30, %xmm13
        psrld     $2, %xmm3
        por       %xmm3, %xmm13
        movdqa    %xmm1, %xmm3
        paddd     944(%rdi), %xmm5
        pslld     $30, %xmm3
        psrld     $2, %xmm1
        movdqa    %xmm5, %xmm12
        por       %xmm1, %xmm3
        movdqa    %xmm13, %xmm1
        movdqa    %xmm5, %xmm7
        pxor      %xmm11, %xmm1
        pslld     $5, %xmm12
        psrld     $27, %xmm7
        paddd     2224(%rdi), %xmm4
        pxor      %xmm8, %xmm1
        por       %xmm7, %xmm12
        movdqa    %xmm3, %xmm14
        movdqa    %xmm8, %xmm7
        paddd     %xmm1, %xmm2
        pxor      %xmm10, %xmm14
        movdqa    %xmm4, %xmm1
        movdqa    %xmm4, %xmm15
        pslld     $30, %xmm7
        psrld     $2, %xmm8
        pxor      %xmm6, %xmm14
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        por       %xmm8, %xmm7
        paddd     %xmm12, %xmm2
        movdqa    .L_2il0floatpacket.506(%rip), %xmm9
        paddd     %xmm14, %xmm0
        por       %xmm15, %xmm1
        movdqa    %xmm7, %xmm8
        paddd     %xmm9, %xmm2
        paddd     %xmm1, %xmm0
        movdqa    %xmm6, %xmm1
        pxor      %xmm13, %xmm8
        paddd     960(%rdi), %xmm2
        pslld     $30, %xmm1
        psrld     $2, %xmm6
        pxor      %xmm5, %xmm8
        por       %xmm6, %xmm1
        paddd     %xmm8, %xmm11
        movdqa    %xmm2, %xmm8
        movdqa    %xmm2, %xmm6
        pslld     $5, %xmm8
        psrld     $27, %xmm6
        por       %xmm6, %xmm8
        movdqa    %xmm1, %xmm12
        paddd     %xmm8, %xmm11
        movdqa    %xmm5, %xmm8
        paddd     %xmm9, %xmm0
        pxor      %xmm3, %xmm12
        pslld     $30, %xmm8
        psrld     $2, %xmm5
        movdqa    %xmm4, %xmm6
        pxor      %xmm4, %xmm12
        paddd     2240(%rdi), %xmm0
        por       %xmm5, %xmm8
        pslld     $30, %xmm6
        psrld     $2, %xmm4
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm14
        por       %xmm4, %xmm6
        movdqa    %xmm8, %xmm4
        paddd     %xmm9, %xmm11
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        pxor      %xmm7, %xmm4
        paddd     976(%rdi), %xmm11
        paddd     %xmm12, %xmm10
        por       %xmm14, %xmm15
        pxor      %xmm2, %xmm4
        paddd     %xmm15, %xmm10
        paddd     %xmm4, %xmm13
        movdqa    %xmm11, %xmm4
        movdqa    %xmm11, %xmm5
        paddd     %xmm9, %xmm10
        pslld     $5, %xmm4
        psrld     $27, %xmm5
        movdqa    %xmm6, %xmm12
        paddd     2256(%rdi), %xmm10
        por       %xmm5, %xmm4
        movdqa    %xmm2, %xmm5
        pxor      %xmm1, %xmm12
        movdqa    %xmm10, %xmm15
        movdqa    %xmm10, %xmm14
        pslld     $30, %xmm5
        psrld     $2, %xmm2
        paddd     %xmm4, %xmm13
        pxor      %xmm0, %xmm12
        pslld     $5, %xmm15
        psrld     $27, %xmm14
        por       %xmm2, %xmm5
        movdqa    %xmm0, %xmm2
        paddd     %xmm9, %xmm13
        paddd     %xmm12, %xmm3
        por       %xmm14, %xmm15
        pslld     $30, %xmm2
        psrld     $2, %xmm0
        paddd     %xmm15, %xmm3
        paddd     992(%rdi), %xmm13
        por       %xmm0, %xmm2
        movdqa    %xmm5, %xmm0
        paddd     %xmm9, %xmm3
        pxor      %xmm8, %xmm0
        movdqa    %xmm13, %xmm12
        movdqa    %xmm13, %xmm4
        pxor      %xmm11, %xmm0
        paddd     2272(%rdi), %xmm3
        pslld     $5, %xmm12
        psrld     $27, %xmm4
        movdqa    %xmm2, %xmm14
        paddd     %xmm0, %xmm7
        por       %xmm4, %xmm12
        pxor      %xmm6, %xmm14
        movdqa    %xmm3, %xmm4
        movdqa    %xmm3, %xmm15
        paddd     %xmm12, %xmm7
        pxor      %xmm10, %xmm14
        pslld     $5, %xmm4
        psrld     $27, %xmm15
        paddd     %xmm9, %xmm7
        paddd     %xmm14, %xmm1
        por       %xmm15, %xmm4
        movdqa    %xmm11, %xmm0
        paddd     %xmm4, %xmm1
        paddd     1008(%rdi), %xmm7
        pslld     $30, %xmm0
        psrld     $2, %xmm11
        movdqa    %xmm10, %xmm15
        paddd     %xmm9, %xmm1
        por       %xmm11, %xmm0
        pslld     $30, %xmm15
        psrld     $2, %xmm10
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm4
        paddd     2288(%rdi), %xmm1
        por       %xmm10, %xmm15
        pslld     $5, %xmm11
        psrld     $27, %xmm4
        por       %xmm4, %xmm11
        movdqa    %xmm15, %xmm12
        movdqa    %xmm1, %xmm4
        movdqa    %xmm1, %xmm14
        movdqa    %xmm0, %xmm10
        pxor      %xmm2, %xmm12
        pslld     $5, %xmm4
        psrld     $27, %xmm14
        pxor      %xmm5, %xmm10
        pxor      %xmm3, %xmm12
        por       %xmm14, %xmm4
        movdqa    %xmm13, %xmm14
        pxor      %xmm13, %xmm10
        paddd     %xmm12, %xmm6
        pslld     $30, %xmm14
        psrld     $2, %xmm13
        movdqa    %xmm3, %xmm12
        por       %xmm13, %xmm14
        pslld     $30, %xmm12
        psrld     $2, %xmm3
        paddd     %xmm10, %xmm8
        paddd     %xmm4, %xmm6
        por       %xmm3, %xmm12
        movdqa    %xmm14, %xmm3
        paddd     %xmm11, %xmm8
        paddd     %xmm9, %xmm6
        pxor      %xmm0, %xmm3
        paddd     %xmm9, %xmm8
        paddd     2304(%rdi), %xmm6
        pxor      %xmm7, %xmm3
        paddd     1024(%rdi), %xmm8
        paddd     %xmm3, %xmm5
        movdqa    %xmm6, %xmm3
        movdqa    %xmm6, %xmm13
        movdqa    %xmm8, %xmm10
        movdqa    %xmm8, %xmm4
        pslld     $5, %xmm3
        psrld     $27, %xmm13
        pslld     $5, %xmm10
        psrld     $27, %xmm4
        por       %xmm13, %xmm3
        movdqa    %xmm7, %xmm13
        por       %xmm4, %xmm10
        movdqa    %xmm12, %xmm11
        pslld     $30, %xmm13
        psrld     $2, %xmm7
        paddd     %xmm10, %xmm5
        pxor      %xmm15, %xmm11
        por       %xmm7, %xmm13
        movdqa    %xmm1, %xmm7
        paddd     %xmm9, %xmm5
        pxor      %xmm1, %xmm11
        pslld     $30, %xmm7
        psrld     $2, %xmm1
        paddd     1040(%rdi), %xmm5
        paddd     %xmm11, %xmm2
        por       %xmm1, %xmm7
        movdqa    %xmm13, %xmm1
        paddd     %xmm3, %xmm2
        pxor      %xmm14, %xmm1
        movdqa    %xmm5, %xmm4
        movdqa    %xmm5, %xmm3
        paddd     %xmm9, %xmm2
        pxor      %xmm8, %xmm1
        pslld     $5, %xmm4
        psrld     $27, %xmm3
        paddd     2320(%rdi), %xmm2
        paddd     %xmm1, %xmm0
        por       %xmm3, %xmm4
        movdqa    %xmm7, %xmm10
        paddd     %xmm4, %xmm0
        pxor      %xmm12, %xmm10
        movdqa    %xmm2, %xmm3
        movdqa    %xmm2, %xmm11
        movdqa    %xmm8, %xmm4
        pxor      %xmm6, %xmm10
        pslld     $5, %xmm3
        psrld     $27, %xmm11
        pslld     $30, %xmm4
        psrld     $2, %xmm8
        paddd     %xmm10, %xmm15
        por       %xmm11, %xmm3
        por       %xmm8, %xmm4
        paddd     %xmm3, %xmm15
        movdqa    %xmm6, %xmm3
        movdqa    %xmm4, %xmm8
        paddd     %xmm9, %xmm0
        pslld     $30, %xmm3
        psrld     $2, %xmm6
        pxor      %xmm13, %xmm8
        paddd     1056(%rdi), %xmm0
        por       %xmm6, %xmm3
        pxor      %xmm5, %xmm8
        movdqa    %xmm0, %xmm1
        paddd     %xmm8, %xmm14
        movdqa    %xmm0, %xmm6
        movdqa    %xmm3, %xmm8
        pslld     $5, %xmm1
        psrld     $27, %xmm6
        pxor      %xmm7, %xmm8
        por       %xmm6, %xmm1
        pxor      %xmm2, %xmm8
        paddd     %xmm1, %xmm14
        paddd     %xmm8, %xmm12
        movdqa    %xmm5, %xmm1
        movdqa    %xmm2, %xmm8
        paddd     %xmm9, %xmm15
        pslld     $30, %xmm1
        psrld     $2, %xmm5
        pslld     $30, %xmm8
        psrld     $2, %xmm2
        por       %xmm5, %xmm1
        paddd     2336(%rdi), %xmm15
        por       %xmm2, %xmm8
        movdqa    %xmm15, %xmm11
        movdqa    %xmm15, %xmm10
        movdqa    %xmm1, %xmm5
        movdqa    %xmm8, %xmm6
        paddd     %xmm9, %xmm14
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pxor      %xmm4, %xmm5
        pxor      %xmm3, %xmm6
        por       %xmm10, %xmm11
        paddd     1072(%rdi), %xmm14
        pxor      %xmm0, %xmm5
        pxor      %xmm15, %xmm6
        paddd     %xmm11, %xmm12
        paddd     %xmm5, %xmm13
        movdqa    %xmm14, %xmm5
        movdqa    %xmm14, %xmm2
        paddd     %xmm6, %xmm7
        movdqa    %xmm0, %xmm6
        paddd     %xmm9, %xmm12
        pslld     $5, %xmm5
        psrld     $27, %xmm2
        pslld     $30, %xmm6
        psrld     $2, %xmm0
        paddd     2352(%rdi), %xmm12
        por       %xmm2, %xmm5
        por       %xmm0, %xmm6
        paddd     %xmm5, %xmm13
        movdqa    %xmm12, %xmm11
        movdqa    %xmm12, %xmm10
        movdqa    %xmm15, %xmm5
        movdqa    %xmm6, %xmm0
        paddd     %xmm9, %xmm13
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pslld     $30, %xmm5
        psrld     $2, %xmm15
        pxor      %xmm1, %xmm0
        paddd     1088(%rdi), %xmm13
        por       %xmm10, %xmm11
        por       %xmm15, %xmm5
        pxor      %xmm14, %xmm0
        paddd     %xmm11, %xmm7
        paddd     %xmm0, %xmm4
        movdqa    %xmm13, %xmm0
        movdqa    %xmm13, %xmm15
        movdqa    %xmm5, %xmm2
        paddd     %xmm9, %xmm7
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        pxor      %xmm8, %xmm2
        por       %xmm15, %xmm0
        paddd     2368(%rdi), %xmm7
        pxor      %xmm12, %xmm2
        paddd     %xmm0, %xmm4
        paddd     %xmm2, %xmm3
        movdqa    %xmm7, %xmm11
        movdqa    %xmm7, %xmm10
        movdqa    %xmm14, %xmm2
        movdqa    %xmm12, %xmm0
        pslld     $5, %xmm11
        psrld     $27, %xmm10
        pslld     $30, %xmm2
        psrld     $2, %xmm14
        pslld     $30, %xmm0
        psrld     $2, %xmm12
        paddd     %xmm9, %xmm4
        por       %xmm10, %xmm11
        por       %xmm14, %xmm2
        por       %xmm12, %xmm0
        paddd     1104(%rdi), %xmm4
        paddd     %xmm11, %xmm3
        movdqa    %xmm2, %xmm12
        movdqa    %xmm0, %xmm11
        paddd     %xmm9, %xmm3
        pxor      %xmm6, %xmm12
        movdqa    %xmm4, %xmm10
        movdqa    %xmm4, %xmm14
        pxor      %xmm5, %xmm11
        pxor      %xmm13, %xmm12
        paddd     2384(%rdi), %xmm3
        pslld     $5, %xmm10
        psrld     $27, %xmm14
        pxor      %xmm7, %xmm11
        paddd     %xmm12, %xmm1
        por       %xmm14, %xmm10
        paddd     %xmm11, %xmm8
        movdqa    %xmm3, %xmm15
        movdqa    %xmm3, %xmm12
        movdqa    %xmm13, %xmm11
        paddd     %xmm10, %xmm1
        pslld     $5, %xmm15
        psrld     $27, %xmm12
        pslld     $30, %xmm11
        psrld     $2, %xmm13
        movdqa    %xmm7, %xmm10
        por       %xmm12, %xmm15
        por       %xmm13, %xmm11
        pslld     $30, %xmm10
        psrld     $2, %xmm7
        paddd     %xmm9, %xmm1
        paddd     %xmm15, %xmm8
        por       %xmm7, %xmm10
        movdqa    %xmm11, %xmm7
        paddd     1120(%rdi), %xmm1
        paddd     %xmm9, %xmm8
        pxor      %xmm2, %xmm7
        movdqa    %xmm1, %xmm13
        paddd     2400(%rdi), %xmm8
        pxor      %xmm4, %xmm7
        movdqa    %xmm1, %xmm12
        movdqa    %xmm10, %xmm14
        paddd     %xmm7, %xmm6
        pslld     $5, %xmm13
        psrld     $27, %xmm12
        pxor      %xmm0, %xmm14
        movdqa    %xmm8, %xmm7
        movdqa    %xmm8, %xmm15
        por       %xmm12, %xmm13
        pxor      %xmm3, %xmm14
        pslld     $5, %xmm7
        psrld     $27, %xmm15
        paddd     %xmm13, %xmm6
        paddd     %xmm14, %xmm5
        por       %xmm15, %xmm7
        paddd     %xmm9, %xmm6
        paddd     %xmm7, %xmm5
        movdqa    2416(%rdi), %xmm7
        paddd     %xmm9, %xmm5
        paddd     1136(%rdi), %xmm6
..B9.15:
        paddd     %xmm7, %xmm5
        movdqa    %xmm4, %xmm7
        pslld     $30, %xmm7
        psrld     $2, %xmm4
        por       %xmm4, %xmm7
        movdqa    %xmm11, %xmm12
        movdqa    %xmm3, %xmm4
        pxor      %xmm7, %xmm12
        movdqa    %xmm6, %xmm13
        movdqa    %xmm6, %xmm14
        pslld     $30, %xmm4
        psrld     $2, %xmm3
        pxor      %xmm1, %xmm12
        pslld     $5, %xmm13
        psrld     $27, %xmm14
        por       %xmm3, %xmm4
        paddd     %xmm12, %xmm2
        por       %xmm14, %xmm13
        movdqa    %xmm10, %xmm15
        movdqa    %xmm1, %xmm3
        paddd     %xmm13, %xmm2
        pxor      %xmm4, %xmm15
        movdqa    %xmm5, %xmm14
        movdqa    %xmm5, %xmm12
        pslld     $30, %xmm3
        psrld     $2, %xmm1
        paddd     %xmm9, %xmm2
        pxor      %xmm8, %xmm15
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        por       %xmm1, %xmm3
        movdqa    %xmm8, %xmm1
        paddd     1152(%rdi), %xmm2
        paddd     %xmm15, %xmm0
        por       %xmm12, %xmm14
        pslld     $30, %xmm1
        psrld     $2, %xmm8
        paddd     %xmm14, %xmm0
        por       %xmm8, %xmm1
        movdqa    %xmm3, %xmm13
        movdqa    %xmm2, %xmm12
        movdqa    %xmm2, %xmm8
        paddd     %xmm9, %xmm0
        pxor      %xmm7, %xmm13
        pslld     $5, %xmm12
        psrld     $27, %xmm8
        paddd     2432(%rdi), %xmm0
        pxor      %xmm6, %xmm13
        por       %xmm8, %xmm12
        movdqa    %xmm1, %xmm14
        movdqa    %xmm6, %xmm8
        paddd     %xmm13, %xmm11
        pxor      %xmm4, %xmm14
        movdqa    %xmm0, %xmm15
        movdqa    %xmm0, %xmm13
        pslld     $30, %xmm8
        psrld     $2, %xmm6
        pxor      %xmm5, %xmm14
        pslld     $5, %xmm15
        psrld     $27, %xmm13
        por       %xmm6, %xmm8
        movdqa    %xmm5, %xmm6
        paddd     %xmm14, %xmm10
        por       %xmm13, %xmm15
        pslld     $30, %xmm6
        psrld     $2, %xmm5
        paddd     %xmm15, %xmm10
        por       %xmm5, %xmm6
        movdqa    %xmm8, %xmm5
        paddd     %xmm12, %xmm11
        paddd     %xmm9, %xmm10
        pxor      %xmm3, %xmm5
        paddd     2448(%rdi), %xmm10
        paddd     %xmm9, %xmm11
        pxor      %xmm2, %xmm5
        movdqa    %xmm6, %xmm13
        paddd     1168(%rdi), %xmm11
        paddd     %xmm5, %xmm7
        pxor      %xmm1, %xmm13
        movdqa    %xmm10, %xmm5
        movdqa    %xmm10, %xmm15
        movdqa    %xmm11, %xmm14
        movdqa    %xmm11, %xmm12
        pxor      %xmm0, %xmm13
        pslld     $5, %xmm5
        psrld     $27, %xmm15
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        paddd     %xmm13, %xmm4
        por       %xmm15, %xmm5
        por       %xmm12, %xmm14
        paddd     %xmm5, %xmm4
        movdqa    %xmm2, %xmm5
        paddd     %xmm14, %xmm7
        pslld     $30, %xmm5
        psrld     $2, %xmm2
        paddd     %xmm9, %xmm7
        por       %xmm2, %xmm5
        movdqa    %xmm0, %xmm2
        psrld     $2, %xmm0
        paddd     1184(%rdi), %xmm7
        pslld     $30, %xmm2
        paddd     %xmm9, %xmm4
        por       %xmm0, %xmm2
        movdqa    %xmm7, %xmm14
        movdqa    %xmm7, %xmm12
        paddd     2464(%rdi), %xmm4
        pslld     $5, %xmm14
        psrld     $27, %xmm12
        movdqa    %xmm2, %xmm13
        por       %xmm12, %xmm14
        pxor      %xmm6, %xmm13
        movdqa    %xmm4, %xmm12
        movdqa    %xmm4, %xmm15
        pxor      %xmm10, %xmm13
        pslld     $5, %xmm12
        psrld     $27, %xmm15
        movdqa    %xmm5, %xmm0
        paddd     %xmm13, %xmm1
        por       %xmm15, %xmm12
        pxor      %xmm8, %xmm0
        paddd     %xmm12, %xmm1
        movdqa    %xmm11, %xmm12
        pxor      %xmm11, %xmm0
        pslld     $30, %xmm12
        psrld     $2, %xmm11
        por       %xmm11, %xmm12
        movdqa    %xmm10, %xmm11
        pslld     $30, %xmm11
        psrld     $2, %xmm10
        paddd     %xmm0, %xmm3
        por       %xmm10, %xmm11
        movdqa    %xmm12, %xmm10
        paddd     %xmm14, %xmm3
        paddd     %xmm9, %xmm1
        pxor      %xmm5, %xmm10
        paddd     2480(%rdi), %xmm1
        paddd     %xmm9, %xmm3
        pxor      %xmm7, %xmm10
        movdqa    %xmm11, %xmm13
        paddd     1200(%rdi), %xmm3
        paddd     %xmm10, %xmm8
        pxor      %xmm2, %xmm13
        movdqa    %xmm1, %xmm10
        movdqa    %xmm1, %xmm15
        movdqa    %xmm3, %xmm14
        movdqa    %xmm3, %xmm0
        pxor      %xmm4, %xmm13
        pslld     $5, %xmm10
        psrld     $27, %xmm15
        pslld     $5, %xmm14
        psrld     $27, %xmm0
        paddd     %xmm13, %xmm6
        por       %xmm15, %xmm10
        por       %xmm0, %xmm14
        paddd     %xmm10, %xmm6
        movdqa    %xmm7, %xmm10
        paddd     %xmm14, %xmm8
        pslld     $30, %xmm10
        psrld     $2, %xmm7
        paddd     %xmm9, %xmm8
        por       %xmm7, %xmm10
        movdqa    %xmm4, %xmm7
        psrld     $2, %xmm4
        paddd     1216(%rdi), %xmm8
        pslld     $30, %xmm7
        paddd     %xmm9, %xmm6
        por       %xmm4, %xmm7
        movdqa    %xmm8, %xmm14
        movdqa    %xmm8, %xmm0
        paddd     2496(%rdi), %xmm6
        pslld     $5, %xmm14
        psrld     $27, %xmm0
        movdqa    %xmm7, %xmm13
        movdqa    %xmm10, %xmm4
        por       %xmm0, %xmm14
        pxor      %xmm11, %xmm13
        movdqa    %xmm6, %xmm0
        movdqa    %xmm6, %xmm15
        pxor      %xmm12, %xmm4
        pxor      %xmm1, %xmm13
        pslld     $5, %xmm0
        psrld     $27, %xmm15
        pxor      %xmm3, %xmm4
        paddd     %xmm13, %xmm2
        por       %xmm15, %xmm0
        paddd     %xmm4, %xmm5
        paddd     %xmm0, %xmm2
        movdqa    %xmm3, %xmm0
        paddd     %xmm14, %xmm5
        pslld     $30, %xmm0
        psrld     $2, %xmm3
        movdqa    %xmm1, %xmm14
        paddd     %xmm9, %xmm5
        por       %xmm3, %xmm0
        pslld     $30, %xmm14
        psrld     $2, %xmm1
        paddd     %xmm9, %xmm2
        paddd     1232(%rdi), %xmm5
        por       %xmm1, %xmm14
        movdqa    %xmm0, %xmm1
        movdqa    %xmm5, %xmm4
        pxor      %xmm10, %xmm1
        movdqa    %xmm5, %xmm3
        paddd     2512(%rdi), %xmm2
        pxor      %xmm8, %xmm1
        pslld     $5, %xmm4
        psrld     $27, %xmm3
        movdqa    %xmm14, %xmm13
        paddd     %xmm1, %xmm12
        por       %xmm3, %xmm4
        pxor      %xmm7, %xmm13
        movdqa    %xmm2, %xmm15
        movdqa    %xmm2, %xmm1
        paddd     %xmm4, %xmm12
        pxor      %xmm6, %xmm13
        pslld     $5, %xmm15
        psrld     $27, %xmm1
        paddd     %xmm9, %xmm12
        paddd     %xmm13, %xmm11
        por       %xmm1, %xmm15
        movdqa    %xmm8, %xmm13
        movdqa    %xmm6, %xmm4
        paddd     %xmm15, %xmm11
        paddd     1248(%rdi), %xmm12
        pslld     $30, %xmm13
        psrld     $2, %xmm8
        pslld     $30, %xmm4
        psrld     $2, %xmm6
        paddd     %xmm9, %xmm11
        por       %xmm8, %xmm13
        por       %xmm6, %xmm4
        movdqa    %xmm12, %xmm3
        movdqa    %xmm12, %xmm1
        paddd     2528(%rdi), %xmm11
        movdqa    %xmm13, %xmm6
        pslld     $5, %xmm3
        psrld     $27, %xmm1
        movdqa    %xmm4, %xmm8
        pxor      %xmm0, %xmm6
        por       %xmm1, %xmm3
        pxor      %xmm14, %xmm8
        movdqa    %xmm11, %xmm1
        movdqa    %xmm11, %xmm15
        pxor      %xmm5, %xmm6
        pxor      %xmm2, %xmm8
        pslld     $5, %xmm1
        psrld     $27, %xmm15
        paddd     %xmm6, %xmm10
        paddd     %xmm8, %xmm7
        por       %xmm15, %xmm1
        paddd     %xmm3, %xmm10
        paddd     %xmm1, %xmm7
        movdqa    %xmm5, %xmm3
        movdqa    %xmm2, %xmm1
        paddd     %xmm9, %xmm10
        paddd     %xmm9, %xmm7
        pslld     $30, %xmm3
        psrld     $2, %xmm5
        pslld     $30, %xmm1
        psrld     $2, %xmm2
        por       %xmm5, %xmm3
        paddd     2544(%rdi), %xmm7
        por       %xmm2, %xmm1
        paddd     1264(%rdi), %xmm10
        je        ..B9.11
..B9.6:
        movdqa    (%rdx), %xmm2
        movdqa    16(%rdx), %xmm5
        paddd     %xmm2, %xmm10
        movdqa    32(%rdx), %xmm6
        paddd     %xmm5, %xmm12
        movdqa    48(%rdx), %xmm8
        paddd     %xmm6, %xmm3
        movdqa    64(%rdx), %xmm9
        paddd     %xmm8, %xmm13
        movdqa    80(%rdx), %xmm15
        paddd     %xmm9, %xmm0
        movdqa    96(%rdx), %xmm2
        paddd     %xmm15, %xmm7
        movdqa    112(%rdx), %xmm5
        paddd     %xmm2, %xmm11
        movdqa    128(%rdx), %xmm6
        paddd     %xmm5, %xmm1
        movdqa    144(%rdx), %xmm8
        paddd     %xmm6, %xmm4
        paddd     %xmm8, %xmm14
..B9.7:
        movdqa    %xmm10, (%rsi)
        testl     %ecx, %ecx
        movdqa    %xmm12, 16(%rsi)
        movdqa    %xmm3, 32(%rsi)
        movdqa    %xmm13, 48(%rsi)
        movdqa    %xmm0, 64(%rsi)
        je        ..B9.9
..B9.8:
        movdqa    %xmm7, 1280(%rsi)
        movdqa    %xmm11, 1296(%rsi)
        movdqa    %xmm1, 1312(%rsi)
        movdqa    %xmm4, 1328(%rsi)
        movdqa    %xmm14, 1344(%rsi)
        ret       
..B9.9:
        movdqa    %xmm7, 80(%rsi)
        movdqa    %xmm11, 96(%rsi)
        movdqa    %xmm1, 112(%rsi)
        movdqa    %xmm4, 128(%rsi)
        movdqa    %xmm14, 144(%rsi)
..B9.10:
        ret       
..B9.11:
        movdqa    .L_2il0floatpacket.498(%rip), %xmm2
        movdqa    .L_2il0floatpacket.499(%rip), %xmm5
        paddd     %xmm2, %xmm10
        movdqa    .L_2il0floatpacket.500(%rip), %xmm6
        paddd     %xmm5, %xmm12
        movdqa    .L_2il0floatpacket.501(%rip), %xmm8
        paddd     %xmm6, %xmm3
        movdqa    .L_2il0floatpacket.502(%rip), %xmm9
        paddd     %xmm8, %xmm13
        paddd     %xmm9, %xmm0
        paddd     %xmm2, %xmm7
        paddd     %xmm5, %xmm11
        paddd     %xmm6, %xmm1
        paddd     %xmm8, %xmm4
        paddd     %xmm9, %xmm14
        jmp       ..B9.7
..B9.12:
        movdqa    .L_2il0floatpacket.498(%rip), %xmm7
        movdqa    .L_2il0floatpacket.499(%rip), %xmm1
        movdqa    %xmm7, %xmm10
        movdqa    .L_2il0floatpacket.500(%rip), %xmm6
        movdqa    %xmm1, %xmm5
        movdqa    .L_2il0floatpacket.501(%rip), %xmm2
        movdqa    %xmm6, %xmm9
        movdqa    .L_2il0floatpacket.502(%rip), %xmm11
        movdqa    %xmm2, %xmm3
        movdqa    %xmm11, %xmm0
        jmp       ..B9.5
        .align    16,0x90
..___tag_value_SSESHA1body.216:
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
.L_2il0floatpacket.474:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.474,@object
	.size	.L_2il0floatpacket.474,16
	.align 16
.L_2il0floatpacket.475:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.475,@object
	.size	.L_2il0floatpacket.475,16
	.align 16
.L_2il0floatpacket.476:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.476,@object
	.size	.L_2il0floatpacket.476,16
	.align 16
.L_2il0floatpacket.477:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.477,@object
	.size	.L_2il0floatpacket.477,16
	.align 16
.L_2il0floatpacket.478:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.478,@object
	.size	.L_2il0floatpacket.478,16
	.align 16
.L_2il0floatpacket.479:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.479,@object
	.size	.L_2il0floatpacket.479,16
	.align 16
.L_2il0floatpacket.498:
	.long	0x67452301,0x67452301,0x67452301,0x67452301
	.type	.L_2il0floatpacket.498,@object
	.size	.L_2il0floatpacket.498,16
	.align 16
.L_2il0floatpacket.499:
	.long	0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89
	.type	.L_2il0floatpacket.499,@object
	.size	.L_2il0floatpacket.499,16
	.align 16
.L_2il0floatpacket.500:
	.long	0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe
	.type	.L_2il0floatpacket.500,@object
	.size	.L_2il0floatpacket.500,16
	.align 16
.L_2il0floatpacket.501:
	.long	0x10325476,0x10325476,0x10325476,0x10325476
	.type	.L_2il0floatpacket.501,@object
	.size	.L_2il0floatpacket.501,16
	.align 16
.L_2il0floatpacket.502:
	.long	0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0,0xc3d2e1f0
	.type	.L_2il0floatpacket.502,@object
	.size	.L_2il0floatpacket.502,16
	.align 16
.L_2il0floatpacket.503:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.type	.L_2il0floatpacket.503,@object
	.size	.L_2il0floatpacket.503,16
	.align 16
.L_2il0floatpacket.504:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.type	.L_2il0floatpacket.504,@object
	.size	.L_2il0floatpacket.504,16
	.align 16
.L_2il0floatpacket.505:
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.type	.L_2il0floatpacket.505,@object
	.size	.L_2il0floatpacket.505,16
	.align 16
.L_2il0floatpacket.506:
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	.type	.L_2il0floatpacket.506,@object
	.size	.L_2il0floatpacket.506,16
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
	.2byte 0x500e
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
	.4byte 0x00000024
	.4byte 0x00000204
	.8byte ..___tag_value_SSEmd5body.112
	.8byte ..___tag_value_SSEmd5body.116-..___tag_value_SSEmd5body.112
	.byte 0x04
	.4byte ..___tag_value_SSEmd5body.114-..___tag_value_SSEmd5body.112
	.4byte 0x0406900e
	.4byte ..___tag_value_SSEmd5body.115-..___tag_value_SSEmd5body.114
	.2byte 0x080e
	.byte 0x00
	.4byte 0x000000a4
	.4byte 0x0000022c
	.8byte ..___tag_value_md5cryptsse.117
	.8byte ..___tag_value_md5cryptsse.208-..___tag_value_md5cryptsse.117
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.119-..___tag_value_md5cryptsse.117
	.4byte 0x100e028c
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.121-..___tag_value_md5cryptsse.119
	.4byte 0x180e038d
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.123-..___tag_value_md5cryptsse.121
	.4byte 0x200e048e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.125-..___tag_value_md5cryptsse.123
	.4byte 0x280e058f
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.127-..___tag_value_md5cryptsse.125
	.4byte 0x300e0683
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.129-..___tag_value_md5cryptsse.127
	.4byte 0x380e0786
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.131-..___tag_value_md5cryptsse.129
	.4byte 0x0435d00e
	.4byte ..___tag_value_md5cryptsse.186-..___tag_value_md5cryptsse.131
	.4byte 0x04c6380e
	.4byte ..___tag_value_md5cryptsse.188-..___tag_value_md5cryptsse.186
	.4byte 0x04c3300e
	.4byte ..___tag_value_md5cryptsse.190-..___tag_value_md5cryptsse.188
	.4byte 0x04cf280e
	.4byte ..___tag_value_md5cryptsse.192-..___tag_value_md5cryptsse.190
	.4byte 0x04ce200e
	.4byte ..___tag_value_md5cryptsse.194-..___tag_value_md5cryptsse.192
	.4byte 0x04cd180e
	.4byte ..___tag_value_md5cryptsse.196-..___tag_value_md5cryptsse.194
	.4byte 0x04cc100e
	.4byte ..___tag_value_md5cryptsse.198-..___tag_value_md5cryptsse.196
	.2byte 0x080e
	.byte 0x04
	.4byte ..___tag_value_md5cryptsse.199-..___tag_value_md5cryptsse.198
	.8byte 0x8c0786068335d00e
	.8byte 0x00058f048e038d02
	.4byte 0x00000000
	.2byte 0x0000
	.4byte 0x00000024
	.4byte 0x000002d4
	.8byte ..___tag_value_SSEmd4body.209
	.8byte ..___tag_value_SSEmd4body.213-..___tag_value_SSEmd4body.209
	.byte 0x04
	.4byte ..___tag_value_SSEmd4body.211-..___tag_value_SSEmd4body.209
	.4byte 0x0406900e
	.4byte ..___tag_value_SSEmd4body.212-..___tag_value_SSEmd4body.211
	.2byte 0x080e
	.byte 0x00
	.4byte 0x00000014
	.4byte 0x000002fc
	.8byte ..___tag_value_SSESHA1body.214
	.8byte ..___tag_value_SSESHA1body.216-..___tag_value_SSESHA1body.214
# End
