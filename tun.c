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
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int setup_tun(openive_info *vpninfo)
{
	int tun_fd, tmp_fd;
	struct ifreq ifr;
	struct sockaddr_in addr;

	if((tun_fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 

	if(ioctl(tun_fd, TUNSETIFF, &ifr) < 0)
		return -1;

	tmp_fd = socket(PF_INET, SOCK_DGRAM, 0);

	/* set ip of this end point of tunnel */
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = vpninfo->s_addr;
	addr.sin_family = AF_INET;
	memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

	if(ioctl(tmp_fd, SIOCSIFADDR, &ifr) < 0)
		return -1;

	ifr.ifr_flags |= IFF_UP;

	if(ioctl(tmp_fd, SIOCSIFFLAGS, &ifr) < 0)
		return -1;

	ifr.ifr_mtu = 1400;

	if(ioctl(tmp_fd, SIOCSIFMTU, &ifr) < 0)
		return -1;

	close(tmp_fd);
	vpninfo->tun_fd = tun_fd;
	FD_SET(tun_fd, &vpninfo->fds);

	return 0;
}
