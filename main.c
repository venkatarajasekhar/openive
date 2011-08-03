#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "openive.h"

int main(int argc, char **argv)
{
	int c;
	char *hvalue = NULL;
	char *uvalue = NULL;
	char *pvalue = NULL;
	char *rvalue = NULL;
	SSL *ssl = NULL;

	while ((c = getopt (argc, argv, "h:u:p:r:")) != -1)
	{
		switch (c)
		{
			case 'h':
				hvalue = optarg;
				break;
			case 'u':
				uvalue = optarg;
				break;
			case 'p':
				pvalue = optarg;
				break;
			case 'r':
				rvalue = optarg;
				break;
		}
	}
	/*
	ssl = ive_login(hvalue, uvalue, pvalue, rvalue);

	char test[] = {0x00,0x04,0x00,0x00,0x00,0x06,0x00,'r',
	               'r','_','i','v','e',0xbb,0x01,0x00,
	               0x00, 0x00, 0x00};

	z_stream strm = def_init();
	z_stream str2 = inf_init();


	char buf[1024];
	strm.avail_in = 19;
	strm.next_in = test;
	strm.avail_out = 1024;
	strm.next_out = buf;
	deflate(&strm, Z_SYNC_FLUSH);

	//printf("%d\n", 1024-strm.avail_out);
	unsigned char have = 1024-strm.avail_out;
	unsigned char zero = 0x00;
	SSL_write(ssl, &have, 1);
	SSL_write(ssl, &zero, 1);
	SSL_write(ssl, buf, have);

	char in[1024];
	int count = ive_getheader(ssl, in);
	char out[1024];

	str2.avail_in = count;
	str2.next_in = in;
	str2.avail_out = 1024;
	str2.next_out = out;

	inflate(&str2, Z_NO_FLUSH);
	FILE *f = fopen("debug", "w");
	fwrite(out, 1024-str2.avail_out, 1, f);
	*/

	char a_name = '\0';
	int tapfd = 0;
	tapfd = tun_alloc(&a_name);
	printf("%d\n", tapfd);
	while(1)
	{
	}
}
