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
				printf("entre2\n");
				//FIXME: half packet
				vpninfo->left = size - left;
				break;
			}

			write(vpninfo->tun_fd, vptr, size);
			vptr += size;
		}
		else if(vpninfo->left)
		{
			printf("entre3\n");
			vptr += vpninfo->left;
			vpninfo->left = 0;
		}
		else
		{
			int left = len+buf-vptr;
			printf("unknown packet %d\n", left);
			break;
		}
	}
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
				vpninfo->host = optarg;
				break;
			case 'u':
				vpninfo->user = optarg;
				break;
			case 'p':
				vpninfo->pass = optarg;
				break;
			case 'r':
				vpninfo->realm = optarg;
				break;
		}
	}

	if(!vpninfo->host || !vpninfo->user || !vpninfo->pass || !vpninfo->realm)
	{
		printf("openive -h host -u user -p passwd -r realm\n");
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

		char buf[65536];
		unsigned short len;

		select(vpninfo->tun_fd + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(SSL_get_fd(vpninfo->https_ssl), &fds))
		{
			int count = 0;
			int size = ncp_recv(vpninfo, buf);

			if(vpninfo->compression)
			{
				while(count < size)
				{
					memcpy(&len, buf+count, 2);
					count += 2;
					int left = size - count;
					if(len > left)
					{
						printf("different %d\n", left);
						break;
					}
					ncp_loop(vpninfo, buf+count, len);
					count += len;
				}
			}
			else
				ncp_loop(vpninfo, buf, size);
		}

		if(FD_ISSET(vpninfo->tun_fd, &fds))
		{
			len = tun_read(vpninfo, buf);
			int mf = buf[26] & 0x20;
			if(mf)
			{
				printf("more fragments\n");
				len += tun_read(vpninfo, buf+len);
			}
			ncp_send(vpninfo, buf, len);
		}
	}
}
