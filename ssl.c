#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "openive.h"

SSL *open_https(const char *hostname)
{
	int sock;
	struct hostent *server;
	struct sockaddr_in address;

	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	server = gethostbyname(hostname);
	address.sin_family = AF_INET;
	address.sin_port = htons(443);
	memcpy(&address.sin_addr, server->h_addr, server->h_length);
	memset(&address.sin_zero, 0, 8);
	connect(sock, (struct sockaddr *) &address, sizeof address);

	SSL_library_init();
	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	ssl = SSL_new(ctx);
	bio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, bio, bio);
	SSL_connect(ssl);

	return ssl;
}

int ive_printf(SSL *ssl, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 1024, fmt, args);
	va_end(args);

	printf("%s", buf);

	return SSL_write(ssl, buf, strlen(buf));
}

int ive_getheader(SSL *ssl, unsigned char *buf)
{
	int i = 0;

	while(SSL_read(ssl, buf + i, 1))
	{
		if(buf[i] == 0xFF && buf[i-1] == 0xFF && buf[i-2] == 0x00 && buf[i-3] == 0x00)
		{
			printf("fin paquete\n");
			return i++;
		}
		if(buf[i] == '\n' && buf[i-1] == '\r' && buf[i-2] == '\n' && buf[i-3] == '\r')
		{
			buf[i+1] = '\0';
			return i++;
		}

		i++;
	}
}
