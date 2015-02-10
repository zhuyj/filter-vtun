#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int tun_alloc(char *dev, int addordel)
{
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/vtun", O_RDWR)) < 0 )
		return -1;

	memset(&ifr, 0, sizeof(ifr));

      /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
       *        IFF_TAP   - TAP device  
       *
       *        IFF_NO_PI - Do not provide packet information  
       */
	ifr.ifr_flags |= IFF_TUN; 
	if( *dev )
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if((err = ioctl(fd, TUNSETIFF, &ifr)) < 0){
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	if ((err = ioctl(fd, TUNSETPERSIST, addordel)) < 0){
		close(fd);
		return err;	
	}
	close(fd);
	return err;
}

int main(int argc, char *argv[])
{
	char ifname[32] = {0};
	
	if (argc < 2){
		printf("error!argc < 2");
		exit(0);
	}
	printf("%s\n", argv[1]);
	strcpy(ifname, "vtun0");
	if (strcmp(argv[1], "add") == 0){
		tun_alloc(ifname, 1);
	}
	if (strcmp(argv[1], "del") == 0){
		tun_alloc(ifname, 0);
	}
	return 0;
}       
