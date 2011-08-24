#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "openive.h"

void openive_init_openssl()
{
	SSL_library_init();
	ERR_clear_error();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

int openive_open_https(openive_info *vpninfo)
{
	int sock;
	struct hostent *server;
	struct sockaddr_in address;

	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	server = gethostbyname(vpninfo->hvalue);
	address.sin_family = AF_INET;
	address.sin_port = htons(443);
	memcpy(&address.sin_addr, server->h_addr, server->h_length);
	memset(&address.sin_zero, 0, 8);
	connect(sock, (struct sockaddr *) &address, sizeof address);

	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	ssl = SSL_new(ctx);
	bio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, bio, bio);
	SSL_connect(ssl);
	vpninfo->https_ssl = ssl;

	return 0;
}

int openive_SSL_printf(SSL *ssl, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 1024, fmt, args);
	va_end(args);

	return SSL_write(ssl, buf, strlen(buf));
}

int openive_SSL_gets(SSL *ssl, char *buf)
{
        int i = 0;

        while(SSL_read(ssl, buf + i, 1))
        {
                if(buf[i] == 0xFF && buf[i-1] == 0xFF && buf[i-2] == 0x00 && buf[i-3] == 0x00)
                {
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
