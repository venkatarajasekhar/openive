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
#include <byteswap.h>
#include <sys/ioctl.h>

int ncp_recv(openive_info *vpninfo, char *buf)
{
	unsigned short size;

	SSL_read(vpninfo->https_ssl, &size, 2);
	SSL_read(vpninfo->https_ssl, buf, size);

	return size;
}

int ncp_send(openive_info *vpninfo, char *buf, unsigned short len)
{
	unsigned size = len;
	char tmp[65536];
	len+=20;

	char header[] = {0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,0x2c,0x01,
			0x00,0x00,0x00,0x01,0x00,0x00,0x00};

	memcpy(tmp, &len, 2);
	memcpy(tmp+2, header, 16);
	size = bswap_32(size);
	memcpy(tmp+18, &size, 4);
	memcpy(tmp+22, buf, len);
	SSL_write(vpninfo->https_ssl, tmp, len+2);
}

void ncp_hello(openive_info *vpninfo)
{
	char hello[] = {0x13, 0x00, //length
			0x00,0x04,0x00,0x00,0x00,0x06,0x00,
			'd','e','b','i','a','n', //hostname
			0xbb,0x01,0x00,0x00, 0x00, 0x00};

	SSL_write(vpninfo->https_ssl, hello, 21);
}

void ncp_mtu(openive_info *vpninfo)
{
	char mtu[] = {	0x24, 0x00, //length
			0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,0x2f,0x01,
			0x00,0x00,0x00,0x01,0x00,0x00,0x00,
			0x00,0x00,0x00,0x10,
			0x00,0x06,
			0x00,0x00,0x00,0x0a,
			0x00,0x02,
			0x00,0x00,0x00,0x04,
			0x00,0x00,0x05,0x78}; //mtu

	SSL_write(vpninfo->https_ssl, mtu, 38);
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

	printf("-> openive_https_post_login\n");
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

	printf("ncp established\n");

	ncp_hello(vpninfo);

	int size = ncp_recv(vpninfo, buf);

	if(size == 1)
	{
		printf("size 0\n");
		size = ncp_recv(vpninfo, buf);
	}

	if(buf[7] == 0x01 && buf[8] == 0x2d && buf[9] == 0x01)
	{
		printf("parse pac\n");
		pac_parse(vpninfo, buf+17);
	}
	else if(buf[6] == 0x01 && buf[7] == 0x2d && buf[8] == 0x01)
	{
		printf("alt parse pac\n");
		pac_parse(vpninfo, buf+16);
	}
	else
	{
		printf("non pac\n");
		return 1;
	}

	ncp_mtu(vpninfo);
	FD_SET(SSL_get_fd(vpninfo->https_ssl), &vpninfo->fds);

	return 0;
}
