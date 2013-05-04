/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "openive.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

void openive_init_openssl()
{
	SSL_library_init();
}

int openive_open_https(openive_info * vpninfo)
{
	int sock;
	struct hostent *server;
	struct sockaddr_in address;

	server = gethostbyname(vpninfo->host);
	if (!server)
		return 1;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	address.sin_family = AF_INET;
	address.sin_port = htons(443);
	memcpy(&address.sin_addr, server->h_addr, server->h_length);
	memset(&address.sin_zero, 0, 8);
	connect(sock, (struct sockaddr *)&address, sizeof address);

	vpninfo->https_ctx = SSL_CTX_new(SSLv23_client_method());
	vpninfo->https_ssl = SSL_new(vpninfo->https_ctx);
	SSL_set_fd(vpninfo->https_ssl, sock);
	SSL_connect(vpninfo->https_ssl);

	return 0;
}

void openive_close_https(openive_info * vpninfo)
{
	//SSL_shutdown(vpninfo->https_ssl);
	SSL_free(vpninfo->https_ssl);
}

int openive_SSL_printf(SSL * ssl, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 1024, fmt, args);
	va_end(args);

	return SSL_write(ssl, buf, strlen(buf));
}

int openive_SSL_gets(SSL * ssl, unsigned char *buf)
{
	int i = 0;

	while (SSL_read(ssl, buf + i, 1)) {
		if (buf[i] == '\n' && buf[i - 1] == '\r' &&
		    buf[i - 2] == '\n' && buf[i - 3] == '\r') {
			buf[i + 1] = '\0';
			return i++;
		}

		i++;
	}
}

int openive_SSL_get_block(SSL * ssl, unsigned char *buf)
{
	int i = 0;

	while (SSL_read(ssl, buf + i, 1)) {
		if (buf[i] == 0xFF && buf[i - 1] == 0xFF &&
		    buf[i - 2] == 0x00 && buf[i - 3] == 0x00) {
			return ++i;
		}

		i++;
	}
}

int openive_SSL_write(openive_info * vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = SSL_write(vpninfo->https_ssl, buf, len);

		if (done > 0)
			len -= done;

		else {
			int err = SSL_get_error(vpninfo->https_ssl, done);
			fprintf(stderr, "Failed to write to SSL socket\n");
		}
	}

	return orig_len;
}

int openive_SSL_read(openive_info * vpninfo, char *buf, size_t len)
{
	int done;

	while ((done = SSL_read(vpninfo->https_ssl, buf, len)) < 0) {
		int err = SSL_get_error(vpninfo->https_ssl, done);
		fprintf(stderr, "Failed to read from SSL socket\n");
	}

	return done;
}
