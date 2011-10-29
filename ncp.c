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

#include "openive.h"
#include <sys/ioctl.h>

int ncp_recv(openive_info *vpninfo, char *buf)
{
	unsigned short size;

	SSL_read(vpninfo->https_ssl, &size, 2);
	SSL_read(vpninfo->https_ssl, buf, size);

	return size;
}

void ncp_hello(openive_info *vpninfo)
{
	char hello[] = {0x13, 0x00, //length
			0x00,0x04,0x00,0x00,0x00,0x06,0x00,
			'd','e','b','i','a','n', //hostname
			0xbb,0x01,0x00,0x00, 0x00, 0x00};

	SSL_write(vpninfo->https_ssl, hello, 21);
}

static int openive_https_post_login(openive_info *vpninfo, char *response)
{
        char *request = "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Cookie: DSLastAccess=%s;DSID=%s\r\n"
                        "Connection: close\r\n"
                        "Content-Length: 256\r\n"
                        "NCP-Version: 2\r\n"
                        "Accept-encoding: gzip\r\n\r\n";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue, vpninfo->dsfa, vpninfo->dsid);

	openive_SSL_gets(vpninfo->https_ssl, response);

	return 0;
}

int make_ncp_connection(openive_info *vpninfo)
{
	char buf[1024];

	if(openive_https_post_login(vpninfo, buf))
	{
		fprintf(stderr, "failed to login\n");
		return 1;
	}

	printf("%s\n", buf);

	ncp_hello(vpninfo);

	int size = ncp_recv(vpninfo, buf);

	if(size == 1)
	{
		int bytestoread=0;
		int sock = SSL_get_fd(vpninfo->https_ssl);
		ioctl(SSL_get_fd(vpninfo->https_ssl), FIONREAD, &bytestoread);
		printf("%d\n", bytestoread);
		size = ncp_recv(vpninfo, buf);
	}

	FILE *f = fopen("debug", "w");
	fwrite(buf, size, 1, f);

	if(buf[7] == 0x01 && buf[8] == 0x2d && buf[9] == 0x01)
	{
		printf("parse pac\n");
		pac_parse(vpninfo, buf+17);
	}

	return 0;
}
