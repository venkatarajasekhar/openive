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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __OPENIVE_H__
#define __OPENIVE_H__

#include <openssl/ssl.h>
#include <zlib.h>

typedef struct {
	char *hvalue;
	char *uvalue;
	char *pvalue;
	char *rvalue;
	char *svalue;
	SSL *https_ssl;
	char *dsid;
	char *dsfa;
	z_stream inflate_strm;
	z_stream deflate_strm;
	unsigned long s_addr;
} openive_info;

/* auth.c */
int openive_obtain_cookie(openive_info *vpninfo);

/* ncp.c */
int make_ncp_connection(openive_info *vpninfo);

/* ssl.c */
void openive_init_openssl();
int openive_open_https(openive_info *vpninfo);
int openive_SSL_printf(SSL *ssl, const char *fmt, ...);
int openive_SSL_gets(SSL *ssl, unsigned char *buf);

/* tun.c */
int tun_alloc();
int setup_tun(openive_info *vpninfo);

#endif
