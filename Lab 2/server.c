#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sslfunctions.h"

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"



int main(int argc, char **argv)
{
	int s, sock, port=PORT;
	struct sockaddr_in sin;
	int val=1;
	pid_t pid;

	/*Parse command line arguments*/

	switch(argc){
		case 1:
			break;
		case 2:
			port=atoi(argv[1]);
			if (port<1||port>65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s port\n", argv[0]);
			exit(0);
	}


	///////////////////////////////////////////////////////////////////
	/*Set up SSL stuff*/

	//define SSL structure and context and BIO
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *sbio;
	
	//initialize context with sevrer certificate and password
	ctx = initialize_ctx("bob.pem", "password");

	//server can use SSLV2/3/TLSV1
	SSL_CTX_set_cipher_list(ctx,"SSLv2:SSLv3:TLSv1");

	//sets the server context to check the client certificate before connection, if verification fails it shuts down the handshake
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);

	///////////////////////////////////////////////////////////////////
	/*Set up TCP stuff*/

	if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("socket");
		close(sock);
		exit(0);
	}

	memset(&sin,0,sizeof(sin));
	sin.sin_addr.s_addr=INADDR_ANY;
	sin.sin_family=AF_INET;
	sin.sin_port=htons(port);

	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

	if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
		perror("bind");
		close(sock);
		exit (0);
	}

	if(listen(sock,5)<0){
		perror("listen");
		close(sock);
		exit (0);
	} 

	///////////////////////////////////////////////////////////////////
	/*Set up actual verification stuff*/


	while(1){

		if((s=accept(sock, NULL, 0))<0){
			perror("accept");
			close(sock);
			close(s);
			exit (0);
		}

		/*fork a child to handle the connection*/

		if((pid=fork())){
			close(s);
		}
		else {
			/*Child code*/
			int len;
			char buf[256];
			char *answer = "42";
			
			//creating new SSL with the context
			ssl = SSL_new(ctx);
			sbio = BIO_new_socket(s, BIO_NOCLOSE);
			SSL_set_bio(ssl,sbio,sbio);
			
			//open up and wait for client to initiate the handshake
			len = SSL_accept(ssl);
			
			if(len <=0){
				//printf("LINE 119 of server.c");
				printf(FMT_ACCEPT_ERR);
				ERR_print_errors(sbio);
				SSL_shutdown(ssl);
				goto DONE;
			}

			//////////////////////////////////////////////////////////////////////////
			/*Check to make sure certificates are okay before sending and recieving*/			
			
			X509 *check;
			char check_CN[256];
			char check_email[256];

			//get client cert
			check = SSL_get_peer_certificate(ssl);
	
			if(check == NULL){
				//printf("LINE 136 of server.c");
				printf(FMT_ACCEPT_ERR);
				ERR_print_errors(sbio);
				goto DONE;
			}
	
			if(SSL_get_verify_result(ssl)!=X509_V_OK){
				//printf("LINE 142 of server.c");
				printf(FMT_ACCEPT_ERR);
				ERR_print_errors(sbio);
				goto DONE;
			}
	
			//get client cert info for printing
			X509_NAME_get_text_by_NID(X509_get_subject_name(check), NID_commonName, check_CN, 256);
	
			X509_NAME_get_text_by_NID(X509_get_subject_name(check), NID_pkcs9_emailAddress, check_email, 256);
			
			printf(FMT_CLIENT_INFO, check_CN, check_email);

			////////////////////////////////////////////////////////////////////
			/*send and receive data*/

			//read the data into our buffer
			len = SSL_read(ssl, buf, 256);

			switch(SSL_get_error(ssl,len)){
		
				case SSL_ERROR_NONE: // no error found,continue
					break;	
				case SSL_ERROR_SYSCALL: // fatal IO error, shutdown
					printf(FMT_INCOMPLETE_CLOSE);
					SSL_free(ssl);
					goto DONE;
				case SSL_ERROR_ZERO_RETURN: // peer has closed connection
					SSL_shutdown(ssl);
					SSL_free(ssl);
					goto DONE;
			}

			buf[len]= '\0';
			printf(FMT_OUTPUT, buf, answer);

			//write data to the SSL connection
			len = SSL_write(ssl, answer, strlen(answer));

			switch(SSL_get_error(ssl,len)){
		
				case SSL_ERROR_NONE:
					break;	
				case SSL_ERROR_SYSCALL:
					printf(FMT_INCOMPLETE_CLOSE);
					SSL_free(ssl);
					goto DONE;
				case SSL_ERROR_ZERO_RETURN:
					SSL_shutdown(ssl);
					SSL_free(ssl);
					goto DONE;
			}
			//routine that closes the socket for the child
			DONE:
			close(sock);
			close(s);
			return 0;
		}
	}
	//free the context and return the parent
	SSL_CTX_free(ctx);
	close(sock);
	return 1;
}


















