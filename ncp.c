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

int make_ncp_connection(openive_info *vpninfo)
{
	char buf[1024];

	char *request = "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Cookie: DSLastAccess=%s;DSID=%s\r\n"
			"Connection: close\r\n"
			"Content-Length: 256\r\n"
			"NCP-Version: 1\r\n"
			"Accept-encoding: gzip\r\n\r\n";

	if(openive_open_https(vpninfo))
	{
		printf("Failed to open HTTPS connection to %s\n", vpninfo->hvalue);
		return 1;
	}

	inflateInit2(&vpninfo->inflate_strm, 16+MAX_WBITS);
	deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);

	openive_SSL_printf(vpninfo->https_ssl, request, vpninfo->hvalue, vpninfo->dsfa, vpninfo->dsid);

	openive_SSL_gets(vpninfo->https_ssl, buf);
	printf("%s\n", buf);
	
	send_hello(vpninfo);

	return 0;
}

void send_hello(openive_info *vpninfo)
{
	char buf[1024];

	char hello[] = {0x00,0x04,0x00,0x00,0x00,0x06,0x00,
			'r','r','_','i','v','e', //hostname
			0xbb,0x01,0x00,0x00, 0x00, 0x00};

	vpninfo->deflate_strm.avail_in = 19;
	vpninfo->deflate_strm.next_in = hello;
	vpninfo->deflate_strm.avail_out = 1024;
	vpninfo->deflate_strm.next_out = buf;

	deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);

	unsigned char have = 1024 - vpninfo->deflate_strm.avail_out;
	unsigned char zero = 0x00;
	SSL_write(vpninfo->https_ssl, &have, 1);
	SSL_write(vpninfo->https_ssl, &zero, 1);
	SSL_write(vpninfo->https_ssl, buf, have);

	parse_pac(vpninfo);
}

void parse_pac(openive_info *vpninfo)
{
	int count;
	char buf[1024];
	char pac[1024];

	count = openive_SSL_gets(vpninfo->https_ssl, buf);
	
	vpninfo->inflate_strm.avail_in = count;
	vpninfo->inflate_strm.next_in = buf;
	vpninfo->inflate_strm.avail_out = 1024;
	vpninfo->inflate_strm.next_out = pac;

	inflate(&vpninfo->inflate_strm, Z_NO_FLUSH);

	FILE *f = fopen("debug", "w");
	fwrite(pac, 1024-vpninfo->inflate_strm.avail_out, 1, f);
}
