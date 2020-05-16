#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include "sslfunctions.h"

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


int main(int argc, char **argv)
{
	// declaration of tcp and ssl connection variables
	int len, sock, port=PORT;
	char *host=HOST;
	struct sockaddr_in addr;
	struct hostent *host_entry;
	char buf[256];
	char *secret = "What's the question?";

	/*Parse command line arguments*/

	switch(argc){
		case 1:
			break;
		case 3:
			host = argv[1];
			port=atoi(argv[2]);
			if (port<1||port>65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s server port\n", argv[0]);
			exit(0);
	}

	////////////////////////////////////////////////////////////////
	/*Beginning of tcp connection*/

	host_entry = gethostbyname(host);
	  

	/*get ip address of the host*/
	if (!host_entry){
		fprintf(stderr,"Couldn't resolve host");
		exit(0);
	}

	
	memset(&addr,0,sizeof(addr));
	addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);	
	  
	printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

	/*open socket*/

	if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		perror("Error couldn't create socket");
	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
		perror("Error couldn't connect to socket ");
	
	/*TCP connection either established or failed*/
	///////////////////////////////////////////////////////////////////
	/*Set up SSL stuff*/

	//SSL, context, and BIO(filestream thing) declaration		
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *sbio;
	
	//initialize context with client certicifate and password
	ctx = initialize_ctx("alice.pem", "password");

	//make sure client only supports SSLV3 and TLSV1 (exclude SSLV2)
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	//set cipher list to use SHA1
	SSL_CTX_set_cipher_list(ctx,"SHA1");

	//define SSL structure using the context, which has above settings
	ssl = SSL_new(ctx);
	//returns socket BIO method (setting up for error detection)
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	//connect the bio to the ssl structure
	SSL_set_bio(ssl,sbio,sbio);

	// initiate handshake with the server and check if it failed 
	if(SSL_connect(ssl) <= 0){
		printf(FMT_CONNECT_ERR);
		ERR_print_errors(sbio);
		goto DONE;
	}
	
	//////////////////////////////////////////////////////////////////
	/*Check to make sure certificates are okay before sending*/

	//Define certificate check variables
	X509 *check;
	char check_CN[256];
	char check_email[256];
	char check_cert_issuer[256];

	//get the server certificate information passed into the ssl structure during handshake
	check = SSL_get_peer_certificate(ssl);
	
	//ensure that we recieved an actual certificate and verifying it
	if(check == NULL){
		printf(FMT_NO_VERIFY);
		goto DONE;
	}
	
	if(SSL_get_verify_result(ssl)!=X509_V_OK){
		printf(FMT_NO_VERIFY);
		goto DONE;
	}
	
	//check if the certificate CN, Email, and the Issuer is valid
	X509_NAME_get_text_by_NID(X509_get_subject_name(check), NID_commonName, check_CN, 256);
	X509_NAME_get_text_by_NID(X509_get_subject_name(check), NID_pkcs9_emailAddress, check_email, 256);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(check), NID_commonName, check_cert_issuer, 256);
	
	//actual comparisons
	if(strcasecmp(check_CN,"Bob's Server")){
		printf(FMT_CN_MISMATCH);
		goto DONE;
	}
	
	if(strcasecmp(check_email,"ece568bob@ecf.utoronto.ca")){
		printf(FMT_EMAIL_MISMATCH);
		goto DONE;
	}
	
	//print server cert info
	printf(FMT_SERVER_INFO, check_CN, check_email, check_cert_issuer);

	////////////////////////////////////////////////////////////////////
	/*send and receive data*/
	
	//write data to server
	len = SSL_write(ssl,secret,strlen(secret));

	//checks if send was valid, if not cancel and shutdown
	switch(SSL_get_error(ssl,len)){
		
		case SSL_ERROR_SYSCALL: //fatal IO error occured so sytem has shutdown
			printf(FMT_INCORRECT_CLOSE);
			SSL_free(ssl);
			goto DONE;
		case SSL_ERROR_ZERO_RETURN: //the connection was closed but not fatally
			SSL_shutdown(ssl);
			SSL_free(ssl);
			goto DONE;
	}
	
	//loop until we recieve data from the server
	while(1){
		//read the data
		len =SSL_read(ssl,buf,256);
		
		//check if read returned any errors
		switch(SSL_get_error(ssl,len)){
		
			case SSL_ERROR_NONE: //found no error
				buf[len]='\0'; //null terminate
				printf(FMT_OUTPUT, secret, buf);
				SSL_shutdown(ssl);
				SSL_free(ssl);
				goto DONE;
			case SSL_ERROR_SYSCALL: //fatal IO error as above
				printf(FMT_INCORRECT_CLOSE);
				SSL_free(ssl);
				goto DONE;
			case SSL_ERROR_ZERO_RETURN:
				SSL_shutdown(ssl);
				SSL_free(ssl);
				goto DONE;
		}
	}

	DONE:	//used to exit while loop and free the context and close the socket
	SSL_CTX_free(ctx);
	close(sock);
	return 1;
}
