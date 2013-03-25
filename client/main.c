#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "dhcp.h"

MODE mode;

static void usage()
{
	printf("Usage : thudhclient [options] <config_interface>\n");
	printf("        options:\n");
	printf("            --network-interface <network_interface>         default the same as config_interface\n");
	printf("            --encap-mode <mode>                             valid modes: ipv4, ipv6, dhcpv6, default ipv4\n");
}

int main(int argc, char **argv)
{
	mode = IPv4;
	int i;
	for (i = 0; i < argc; ++i) {
		if (i + 1 < argc && strcmp(argv[i], "--network-interface") == 0) {
			++i;
			strcpy(network_interface_name, argv[i]);
		} else if (i + 1 < argc && strcmp(argv[i], "--encap-mode") == 0) {
			++i;
			if (strcmp(argv[i], "ipv4") == 0) {
				mode = IPv4;
			} else if (strcmp(argv[i], "ipv6") == 0) {
				mode = IPv6;
			} else if (strcmp(argv[i], "dhcpv6") == 0) {
				mode = DHCPv6;
			} else {
				usage();
				exit(0);
			}
		} else {//config-interface
			strcpy(config_interface_name, argv[i]);
		}
	}
	if (config_interface_name[0] == '\0') {
		usage();
		exit(0);
	}
	if (network_interface_name[0] == '\0')
		strcpy(network_interface_name, config_interface_name);
	
	init_interfaces();
	init_dhcp();
}
