#include "sslfunctions.h"

//ensures that the password is valid for use
int my_cb(char *buf, int size, int rwflag, void *password){

	if(size < strlen((char *)password)+1)
		return 0;

	strncpy(buf, (char *)password, size);
	buf[size-1] = '\0';
	return strlen(buf);
}



/* initialize_ctx found on the internet as a matter of standard practice 
   in developing the context for use in our SSL encryption */

SSL_CTX *initialize_ctx(char *keyfile, char *password){

	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_library_init();
	SSL_load_error_strings();
	
	
	method = SSLv23_method();
	ctx = SSL_CTX_new(method);
	
	//loads certificate into the context
	if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile))){
		printf("CANT READ CERTIFICATE");
		exit(0);
	}

	SSL_CTX_set_default_passwd_cb(ctx, my_cb);
	
	if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))){
		printf("CANT READ THE KEY FILE");
		exit(0);
	}
	
	if(!(SSL_CTX_load_verify_locations(ctx, "568ca.pem",0))){
		printf("CANT READ CA LIST");
		exit(0);		
	}
	
	
	#if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
		SSL_CTX_set_verify_depth(ctx,1);
	#endif
	
	return ctx;
}

