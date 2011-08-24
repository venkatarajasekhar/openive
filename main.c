#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "openive.h"

void usage()
{
	printf("openive -h host -u user -p passwd -r realm\n");
}

int main(int argc, char **argv)
{
	openive_info *vpninfo;
	int opt;

	openive_init_openssl();

	vpninfo = malloc(sizeof(*vpninfo));
	memset(vpninfo, 0, sizeof(*vpninfo));

	while((opt = getopt(argc, argv, "h:u:p:r:")) != -1)
	{
		switch(opt)
		{
			case 'h':
				vpninfo->hvalue = optarg;
				break;
			case 'u':
				vpninfo->uvalue = optarg;
				break;
			case 'p':
				vpninfo->pvalue = optarg;
				break;
			case 'r':
				vpninfo->rvalue = optarg;
				break;
		}
	}

	if(!vpninfo->hvalue || !vpninfo->uvalue || !vpninfo->pvalue || !vpninfo->rvalue)
	{
		usage();
		exit(1);
	}

	if(openive_obtain_cookie(vpninfo))
	{
		fprintf(stderr, "Failed to obtain WebVPN cookie\n");
		exit(1);
	}

	if(make_ncp_connection(vpninfo))
	{
		fprintf(stderr, "Creating SSL connection failed\n");
		exit(1);
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
	/*
	int tapfd = 0;
	tapfd = tun_alloc('\0');
	printf("%d\n", tapfd);
	while(1)
	{
	}
	*/
}
