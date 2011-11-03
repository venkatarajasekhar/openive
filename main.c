/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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

	if(openive_obtain_cookie(vpninfo))
	{
		printf("Failed to obtain WebVPN cookie\n");
		exit(1);
	}

	if(make_ncp_connection(vpninfo))
	{
		printf("Creating SSL connection failed\n");
		exit(1);
	}

	if(setup_tun(vpninfo))
	{
		printf("Set up tun device failed\n");
		exit(1);
	}

	for(;;)
	{
		fd_set fds;
		memcpy(&fds, &vpninfo->fds, sizeof(fds));

		char buf[1500];
		unsigned short len;

		select(vpninfo->tun_fd + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(SSL_get_fd(vpninfo->https_ssl), &fds))
		{
			printf("ssl\n");
			len = ncp_recv(vpninfo, buf);
			if(buf[6] == 0x01 && buf[7] == 0x2c && buf[8] == 0x01)
			{
				write(vpninfo->tun_fd, buf+20, len-20);
			}
		}

		if(FD_ISSET(vpninfo->tun_fd, &fds))
		{
			printf("tun\n");
			len = read(vpninfo->tun_fd, buf, sizeof(buf));
			ncp_send(vpninfo, buf, len);
		}
	}
}
