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

int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return fd;

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
	 *        IFF_TAP   - TAP device  
	 *
	 *        IFF_NO_PI - Do not provide packet information  
	 */ 
	ifr.ifr_flags = IFF_TUN; 
	if( *dev )
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}

int set_tun_addr(int fd, int tun_addr, char *tun_dev)
{
	struct sockaddr_in addr;
	struct ifreq ifr_tun;

	memset(&ifr_tun, 0, sizeof(ifr_tun));
	memset(&addr, 0, sizeof(addr));

	addr.sin_addr.s_addr = tun_addr;
	addr.sin_family = AF_INET;
	memcpy(&ifr_tun.ifr_addr, &addr, sizeof(struct sockaddr));

	strncpy(ifr_tun.ifr_name, tun_dev, IFNAMSIZ - 1);

	if(ioctl(fd, SIOCSIFADDR, &ifr_tun) < 0)
	{
		//debug_output( 0, "Error - can't set tun address (SIOCSIFADDR): %s\n", strerror(errno) );
		return -1;
	}

	return 1;
}

int setup_tun(openive_info *vpninfo)
{
	return 1;
}
