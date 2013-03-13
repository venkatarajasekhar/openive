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

	if(vpninfo->compression)
	{
		char tmp[65536];
		unsigned short compr_len, uncompr_len;
		compr_len = openive_SSL_get_packet(vpninfo->https_ssl, buf);
		vpninfo->inflate_strm.avail_in = compr_len;
		vpninfo->inflate_strm.next_in = buf;
		vpninfo->inflate_strm.avail_out = 65536;
		vpninfo->inflate_strm.next_out = tmp;
		inflate(&vpninfo->inflate_strm, Z_NO_FLUSH);
		uncompr_len = 65536 - vpninfo->inflate_strm.avail_out;
		memcpy(&size, tmp, 2);
		if(size == 1)
		{
			memcpy(&size, tmp+3, 2);
			memcpy(buf, tmp+3, size);
			printf("size 0\n");
			return uncompr_len-3;
		}
		memcpy(buf, tmp, uncompr_len);
		return uncompr_len;
	}

	SSL_read(vpninfo->https_ssl, &size, 2);
	SSL_read(vpninfo->https_ssl, buf+2, size);

	return size;
}

void ncp_loop(openive_info *vpninfo, char *buf, unsigned short len)
{
	char *vptr = buf;
	unsigned size;

	while(vptr - buf < len)
	{
		if(vptr[6] == 0x01 && vptr[7] == 0x2c && vptr[8] == 0x01)
		{
			vptr += 16;
			vptr = read_uint32(vptr, &size);

			int left = len+buf-vptr;
			if(size > left)
			{
				//printf("entre2\n");
				//FIXME: half packet
				vpninfo->left = size - left;
				break;
			}

			write(vpninfo->tun_fd, vptr, size);
			vptr += size;
		}
		else if(vpninfo->left)
		{
			//printf("entre3\n");
			vptr += vpninfo->left;
			vpninfo->left = 0;
		}
		else
		{
			int left = len+buf-vptr;
			if(left > 5)
				printf("unknown packet %d\n", left);
			break;
		}
	}
}

int tun_read(openive_info *vpninfo, char *buf)
{
	int size, len;

	char header[] = {0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,0x2c,0x01,
			0x00,0x00,0x00,0x01,0x00,0x00,0x00};

	len = read(vpninfo->tun_fd, buf+20, 2500);

	memcpy(buf, header, 16);
	size = bswap_32(len);
	memcpy(buf+16, &size, 4);

	return len+20;
}

int ncp_send(openive_info *vpninfo, char *buf, unsigned short len)
{
	char msj[65536];

	memcpy(msj, &len, 2);
	memcpy(msj+2, buf, len);

	if(vpninfo->compression)
	{
		char tmp[65536];
		vpninfo->deflate_strm.avail_in = len;
		vpninfo->deflate_strm.next_in = msj+2;
		vpninfo->deflate_strm.avail_out = 65534;
		vpninfo->deflate_strm.next_out = tmp+2;
		deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
		unsigned short compr_len = 65534 - vpninfo->deflate_strm.avail_out;
		memcpy(tmp, &compr_len, 2);
		return SSL_write(vpninfo->https_ssl, tmp, compr_len+2);
	}

	return SSL_write(vpninfo->https_ssl, msj, len+2);
}

int ncp_hello(openive_info *vpninfo)
{
	char hello[] = {0x13, 0x00, //length
			0x00,0x04,0x00,0x00,0x00,0x06,0x00,
			'd','e','b','i','a','n', //hostname
			0xbb,0x01,0x00,0x00,0x00,0x00};

	if(vpninfo->compression)
	{
		char tmp[512];
		vpninfo->deflate_strm.avail_in = 19;
		vpninfo->deflate_strm.next_in = hello+2;
		vpninfo->deflate_strm.avail_out = 510;
		vpninfo->deflate_strm.next_out = tmp+2;
		deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
		unsigned short len = 510 - vpninfo->deflate_strm.avail_out;
		memcpy(tmp, &len, 2);
		return SSL_write(vpninfo->https_ssl, tmp, len+2);
	}

	return SSL_write(vpninfo->https_ssl, hello, 21);
}

int ncp_mtu(openive_info *vpninfo)
{
	char mtu[] = {  0x24, 0x00, //length
			0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,0x2f,0x01,
			0x00,0x00,0x00,0x01,0x00,0x00,0x00,
			0x00,0x00,0x00,0x10,
			0x00,0x06,
			0x00,0x00,0x00,0x0a,
			0x00,0x02,
			0x00,0x00,0x00,0x04,
			0x00,0x00,0x05,0x78}; //mtu

	if(vpninfo->compression)
	{
		char tmp[512];
		vpninfo->deflate_strm.avail_in = 36;
		vpninfo->deflate_strm.next_in = mtu+2;
		vpninfo->deflate_strm.avail_out = 510;
		vpninfo->deflate_strm.next_out = tmp+2;
		deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
		unsigned short len = 510 - vpninfo->deflate_strm.avail_out;
		memcpy(tmp, &len, 2);
		return SSL_write(vpninfo->https_ssl, tmp, len+2);
	}

	return SSL_write(vpninfo->https_ssl, mtu, 38);
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
		printf("Failed to open HTTPS connection to %s\n", vpninfo->host);
		return 1;
	}

	printf("-> openive_https_post_login\n");
	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->host, vpninfo->dsfa, vpninfo->dsid);

	openive_SSL_gets(vpninfo->https_ssl, response);
	/*this one stays open*/

	return 0;
}

int make_ncp_connection(openive_info *vpninfo)
{
	char buf[1024];
	char *compression = NULL;

	if(openive_https_post_login(vpninfo, buf))
	{
		fprintf(stderr, "failed to login\n");
		return 1;
	}

	printf("ncp established\n");

	compression = strstr(buf, "gzip");

	if(compression)
	{
		vpninfo->compression = 1;
		inflateInit2(&vpninfo->inflate_strm, 16+MAX_WBITS);
		deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -10, 8, Z_DEFAULT_STRATEGY);
		printf("compression enabled\n");
	}

	ncp_hello(vpninfo);

	int size = ncp_recv(vpninfo, buf);

	if(size == 1)
	{
		printf("size 0\n");
		size = ncp_recv(vpninfo, buf);
	}

	if(buf[9] == 0x01 && buf[10] == 0x2d && buf[11] == 0x01)
	{
		printf("parse pac\n");
		pac_parse(vpninfo, buf+19);
	}
	else if(buf[8] == 0x01 && buf[9] == 0x2d && buf[10] == 0x01)
	{
		printf("alt parse pac\n");
		pac_parse(vpninfo, buf+18);
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
