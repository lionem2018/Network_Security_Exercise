#include "codec.h"
#include "packet.h"
#include "packet_controller.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int read_msg(SSL *ssl, unsigned char **msgBuf, PACKET_HEADER **header);
ssize_t readn(SSL *ssl, unsigned char *buf, size_t nbytes);
ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes);  // print error message and exit
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sock;                                                   // socket identifier ( return value of socket() function )
	struct sockaddr_in serv_adr;                                // create address structure for server
	int length, recv_len = 0;                                   // length: send data length, recv_len: receive data length
	unsigned char *message, *sendBuf = NULL;                    // message: receive message, sendBuf: send message to server
	char id[MAX_ID_LEN] = {0}, password[MAX_PWD_LEN] = {0};     // id, password: input id, password from user

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////
	SSL_CTX *ctx;       // framework for TLS/SSL connection
	SSL *ssl;
	X509 *server_cert;  // standard defining the format of the public key certificates
	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////

	PACKET_HEADER *header;   // header pointer for packet
	LOGIN_REQ *loginReq;     // login request packet

	if(argc!=3) {            // check argumets (IP, PORT)
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	sock=socket(PF_INET, SOCK_STREAM, 0);    // create socket (PF_INET: IPv4 Protocol(usually use for socket), SOCK_STREAM:use STREAM for TCP, 0: usually)
	if(sock==-1)                             // fail of creating socket
		error_handling("socket() error");

	memset(&serv_adr, 0, sizeof(serv_adr));        // initialize server address structure (all value is 0)
	serv_adr.sin_family=AF_INET;                   // set sin_family value (AF_INET: IPv4 Protocol(usually use for address))
	serv_adr.sin_addr.s_addr=inet_addr(argv[1]);   // set server IP address (inet_addr(char * <String IP address>): 'char *' type -> 'long' type )
	serv_adr.sin_port=htons(atoi(argv[2]));        // set server port ( htons(int <port number>): change byte order 0x123456 -> 0x563412 => for Little-Endian host)

	if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)  // try to connect (return value -1 is fail)
		error_handling("connect() error!");
	else
		puts("Connected..........."); 

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////   
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	ctx = SSL_CTX_new(TLSv1_2_client_method());   // create SSL_CTX(only use TLSv1.2)

	ssl = SSL_new(ctx);                           // create SSL(with setting ctx)

	SSL_set_fd(ssl, sock);                        // link SSL and socket
	if(SSL_connect(ssl) == -1){                   // try to connect SSL
		return -1;
	}

	server_cert = SSL_get_peer_certificate(ssl);  // get peer(server)'s x509 certificate for ssl

	printf("\nServer certificate:\n");
	printf("subject: %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0));
	printf("issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0));

	X509_free(server_cert);  //free x509 certificate
	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////

	while(1)
	{
		fputs("Input ID(Q to quit): ", stdout);
		fgets(id, MAX_ID_LEN, stdin);
		fflush(stdin);

		id[strlen(id)-1] = '\0';

		if(!strcmp(id,"q\n") || !strcmp(id,"Q\n"))
			exit(0);

		fputs("Input Password: ", stdout);
		fgets(password, MAX_PWD_LEN, stdin);
		fflush(stdin);

		password[strlen(password)-1] = '\0';

		break;
	}

	//Generating Login Request Message
	loginReq = (LOGIN_REQ *)calloc(1, sizeof(LOGIN_REQ));
	strncpy(loginReq->id, id, sizeof(id));
	strncpy(loginReq->passwd, password, sizeof(password));
	//Encoding Packet
	length = encode_packet(MT_LOGIN_REQ, (void *)loginReq, &sendBuf);

	//Sending Login Request Packet
	length = writen(ssl, sendBuf, length);
	printf("\nClient Sent %d bytes\n", length);
	free(sendBuf); sendBuf = NULL;

	//Receiving Login Ack packet
	recv_len = read_msg(ssl, &message, &header);
	if(recv_len > 0)
	{
		if(Packet_Handler(message, &sendBuf, header->msgType, &length) != -1)
		{
			if(sendBuf != NULL)
			{
				//Sending Image Send Packet
				writen(ssl, sendBuf, length);
				printf("\nClient Sent %d bytes\n", length);
				free(header), free(message); free(sendBuf);

				//Receiving Image Ack packet
				recv_len = read_msg(ssl, &message, &header);
				if(recv_len > 0)
					Packet_Handler(message, NULL, header->msgType, &length);
				else
					error_handling("Read Message error!");
			}
		}
	}
	else
		error_handling("Read Message error!");

	SSL_shutdown(ssl);

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	free(header);
	free(message);
	close(sock);
	return 0;
}

int read_msg(SSL *ssl, unsigned char **msgBuf, PACKET_HEADER **header)
{
	size_t msgLength = 0;

	int headerLength = sizeof(PACKET_HEADER);
	unsigned char *buf = (unsigned char *)calloc(1, headerLength);

	readn(ssl, buf, headerLength);

	decode_PacketHeader(buf, header);
	msgLength = (*header)->length;

	*msgBuf = (unsigned char *)calloc(1, msgLength);

	readn(ssl, *msgBuf, msgLength);

	free(buf);
	return msgLength;
}

ssize_t readn(SSL *ssl, unsigned char *buf, size_t nbytes)
{
	size_t nleft;
	ssize_t nread;
	unsigned char *ptr;

	ptr = buf;
	nleft = nbytes;

	while(nleft > 0){
		nread = SSL_read(ssl, ptr, nleft);
		if(nread == 0)
			break;
		ptr += nread;
		nleft -= nread;
	}
	return (nbytes - nleft);
}

ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes)
{
	size_t nleft;
	ssize_t nwritten;
	unsigned char *ptr;

	ptr = buf;
	nleft = nbytes;

	while(nleft > 0){
		nwritten = SSL_write(ssl, ptr, nleft);
		if(nwritten == 0)
			break;
		ptr += nwritten;
		nleft -= nwritten;
	}
	return (nbytes - nleft);
}


void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}


