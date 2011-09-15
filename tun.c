#include "openive.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc()
{
	int fd, tmp_fd;
	struct ifreq ifr;
	struct sockaddr_in addr;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return fd;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 

	if(ioctl(fd, TUNSETIFF, &ifr) < 0)
		return -1;

	tmp_fd = socket(PF_INET, SOCK_DGRAM, 0);

	/* set ip of this end point of tunnel */
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = 0x10101010;
	addr.sin_family = AF_INET;
	memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

	if(ioctl(tmp_fd, SIOCSIFADDR, &ifr) < 0)
		return -1;

	ifr.ifr_flags |= IFF_UP;

	if(ioctl(tmp_fd, SIOCSIFFLAGS, &ifr) < 0)
		return -1;

	ifr.ifr_mtu = 1492;

	if(ioctl(tmp_fd, SIOCSIFMTU, &ifr) < 0)
		return -1;

	return fd;
}
