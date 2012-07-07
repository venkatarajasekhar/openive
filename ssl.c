/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
	server = gethostbyname(vpninfo->host);
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

void openive_close_https(openive_info *vpninfo)
{
	SSL_shutdown(vpninfo->https_ssl);
	SSL_free(vpninfo->https_ssl);
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

int openive_SSL_gets(SSL *ssl, unsigned char *buf)
{
        int i = 0;

        while(SSL_read(ssl, buf + i, 1))
        {
                if(buf[i] == '\n' && buf[i-1] == '\r' && buf[i-2] == '\n' && buf[i-3] == '\r')
                {
                        buf[i+1] = '\0';
                        return i++;
                }

                i++;
        }
}

int openive_SSL_get_packet(SSL *ssl, unsigned char *buf)
{
        int i = 0;

        while(SSL_read(ssl, buf + i, 1))
        {
                if(buf[i] == 0xFF && buf[i-1] == 0xFF && buf[i-2] == 0x00 && buf[i-3] == 0x00)
                {
                        return ++i;
                }

                i++;
        }
}
