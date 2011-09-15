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

	while((opt = getopt(argc, argv, "h:u:p:r:s:")) != -1)
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
			case 's':
				vpninfo->svalue = optarg;
				break;
		}
	}

	if(!vpninfo->hvalue || !vpninfo->uvalue || !vpninfo->pvalue || !vpninfo->rvalue)
	{
		usage();
		exit(1);
	}
/*
	if(auth_url(vpninfo))
	{
		fprintf(stderr, "Failed to obtain Auth url\n");
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

	if(setup_tun(vpninfo))
	{
		fprintf(stderr, "Set up tun device failed\n");
		exit(1);
	}
*/
	tun_alloc();
	for(;;)
	{
	}
}
