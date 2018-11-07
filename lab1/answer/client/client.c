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
ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes);
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in serv_adr;
	int length, recv_len = 0;
	unsigned char *message, *sendBuf = NULL;
	char id[MAX_ID_LEN] = {0}, password[MAX_PWD_LEN] = {0};

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *server_cert;
	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////

	PACKET_HEADER *header;
	LOGIN_REQ *loginReq;

	if(argc!=3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	sock=socket(PF_INET, SOCK_STREAM, 0);
	if(sock==-1)
		error_handling("socket() error");

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
	serv_adr.sin_port=htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
		error_handling("connect() error!");
	else
		puts("Connected...........");

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////   
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	ctx = SSL_CTX_new(TLSv1_2_client_method());

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sock);
	if(SSL_connect(ssl) == -1){
		return -1;
	}

	server_cert = SSL_get_peer_certificate(ssl);

	printf("\nServer certificate:\n");
	printf("subject: %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0));
	printf("issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0));

	X509_free(server_cert);
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


