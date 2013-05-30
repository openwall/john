;
; This file is part of John the Ripper password cracker,
; Copyright (c) 1996-98 by Solar Designer
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted.
;
; There's ABSOLUTELY NO WARRANTY, express or implied.
;

.model tiny
.code
.startup
.8086

	mov	sp,400h

	push	sp
	pop	ax
	cmp	ax,sp
	jne	No386

.186
	push	0F200h
	popf
	pushf
	pop	ax
	test	ax,0F000h
	jnz	Is386

No386:
	mov	dx,offset MsgNo386
ShowMsg:
	push	cs
	pop	ds
	mov	ah,9
	int	21h
	int	20h

Error:
	mov	dx,offset MsgError
	jmp	short ShowMsg

Is386:
.386
	mov	ah,4Ah
	mov	bx,es
	mov	bh,-43h
	neg	bx
	int	21h
	jc	Error

	mov	ah,48h
	mov	bx,112*1024/16
	int	21h
	jc	Error
	mov	es,ax
FillHoles:
	mov	ah,48h
	int	21h
	jnc	FillHoles
	shr	bx,1
	jnz	FillHoles
	mov	ah,49h
	int	21h
	jc	Error

	mov	es,word ptr ds:[2Ch]
	push	es
	pop	ds
	xor	di,di
	xor	ax,ax
	mov	cx,0FFFCh
Search1:
	repne	scasb
	cmp	word ptr [di],100h
	loopne	Search1
	jne	Error
	lea	dx,[di+3]
	mov	al,'.'
Search2:
	repne	scasb
	cmp	dword ptr [di],'MOC'
	loopne	Search2
	jne	Error
	mov	al,'\'
	lea	cx,[di+2]
	sub	cx,dx
	lea	bx,[di-2]
	std
	repne	scasb
	mov	cx,bx
	sub	cx,di
	cmp	cx,5
	jb	Error
	lea	bx,[di+2]
	push	cx
	push	cs
	pop	es
	mov	di,0FFh
	mov	si,di
	sub	si,cx
	add	cs:[80h],cl
	sub	cx,7Fh
	neg	cx
	segcs
	rep	movsb
	pop	cx
	mov	si,bx
	mov	di,81h
	cld
LinkName:
	lodsb
	or	al,20h
	stosb
	loop	LinkName
	mov	al,' '
	dec	di
	stosb
	mov	di,bx
	mov	dword ptr [di],'NHOJ'
	mov	dword ptr [di+4],'NIB.'
	mov	byte ptr [di+8],cl

	mov	ax,3D00h
	int	21h
	jc	Error2
	xchg	ax,bx

	xor	cx,cx
	mov	dx,14h
	mov	ax,4200h
	int	21h
	jc	Error2

	mov	cl,2
	mov	dx,EntryOfs
	push	cs
	pop	ds
	mov	ah,3Fh
	int	21h
	jc	Error2
	xor	cx,ax
	jnz	Error2

	mov	dx,200h
	mov	ax,4200h
	int	21h
	jc	Error2

	mov	ax,cs
	add	ax,50h
	mov	al,0F0h
	mov	es,ax
	mov	cl,80h
	xor	si,si
	xor	di,di
	segcs
	rep	movsw

	add	ax,10h
	mov	ds,ax
	xor	dx,dx
	mov	ch,8
	mov	ah,3Fh
	int	21h
	jc	Error2
	cmp	ax,cx
	jne	Error2

	mov	ah,3Eh
	int	21h
	jc	Error2

	xor	di,di
	mov	al,0EBh
	push	es
	push	ds
	pop	es
Search3:
	repne	scasb
	cmp	dword ptr [di],21CD4AB4h
	loopne	Search3
	pop	es
	jne	Error2

	mov	byte ptr ds:[di+2],0Ch
	push	ds
EntryOfs = offset $ + 1
	push	8000h
	retf

Error2:
	jmp	Error

MsgNo386:
	db	'At least a 386 CPU is required', 13, 10, '$'

MsgError:
	db	'Unable to load main program', 13, 10, '$'

	end
