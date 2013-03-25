#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "interface.h"
#include "config.h"

static char* mac_to_str(unsigned char *ha)
{
    int i;  
    static char macstr_buf[18] = {'\0', };
    sprintf(macstr_buf, "%02X:%02X:%02X:%02X:%02X:%02X", ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
    return macstr_buf; 
}

void init_interfaces()
{
	struct if_nameindex *interfaces = if_nameindex(), *interface;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	for (interface = interfaces; interface && interface->if_index; interface++) {
		struct ifreq ifopt;
		char addr[6] = {0};
		int valid_addr = 0;
		
		memset(&ifopt, 0, sizeof(ifopt));
		strcpy(ifopt.ifr_name, interface->if_name);
		if (ioctl(fd, SIOCGIFHWADDR, &ifopt) == -1) {
			printf("Failed to get MAC address of %s\n", interface->if_name);
			valid_addr = 0;
		} else {
			memcpy(addr, ifopt.ifr_hwaddr.sa_data, 6);
			valid_addr = 1;
		}
		if (strcmp(network_interface_name, interface->if_name) == 0 && !network_interface) {
			network_interface = malloc(sizeof(struct interface));
			memset(network_interface, 0, sizeof(struct interface));
			strcpy(network_interface->name, interface->if_name);
			memcpy(network_interface->addr, addr, 6);
			printf("network-interface is %s, macaddr=%s\n", network_interface->name, mac_to_str(network_interface->addr));
		}
		if (strcmp(config_interface_name, interface->if_name) == 0 && !config_interface) {
			config_interface = malloc(sizeof(struct interface));
			memset(config_interface, 0, sizeof(struct interface));
			strcpy(config_interface->name, interface->if_name);
			memcpy(config_interface->addr, addr, 6);
			printf("config-interface is %s, macaddr=%s\n", config_interface->name, mac_to_str(config_interface->addr));
		}
	}
	if_freenameindex(interfaces);
	close(fd);  
}
