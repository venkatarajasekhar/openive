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

#ifndef __OPENIVE_H__
#define __OPENIVE_H__

#include <zlib.h>
#include <openssl/ssl.h>

typedef struct {
	char *host;
	char *user;
	char *pass;
	char *realm;
	char *dsid;

	SSL *https_ssl;
	SSL_CTX *https_ctx;
	unsigned long s_addr;

	fd_set fds;
	int tun_fd;
	int left;

	int compression;
	z_stream inflate_strm;
	z_stream deflate_strm;
} openive_info;

/* auth.c */
int openive_obtain_cookie(openive_info * vpninfo);

/* ncp.c */
int make_ncp_connection(openive_info * vpninfo);

/* pac.c */
char *read_uint16(char *buf, unsigned short *value);
char *read_uint32(char *buf, unsigned *value);
void pac_parse(openive_info * vpninfo, char *buf);

/* ssl.c */
void openive_init_openssl();
int openive_open_https(openive_info * vpninfo);
int openive_SSL_printf(SSL * ssl, const char *fmt, ...);
int openive_SSL_gets(SSL * ssl, unsigned char *buf);
int openive_SSL_get_block(SSL * ssl, unsigned char *buf);

/* tun.c */
int setup_tun(openive_info * vpninfo);

#endif
