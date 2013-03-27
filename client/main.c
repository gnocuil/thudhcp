#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h> 

#include "config.h"
#include "dhcp.h"

MODE mode;

static void usage()
{
	printf("Usage : thudhclient [options] <config_interface>\n");
	printf("        options:\n");
	printf("            --network-interface <network_interface>         default the same as config_interface\n");
	printf("            --encap-mode <mode>                             valid modes: ipv4, ipv6, dhcpv6, default ipv4\n");
	printf("            --server-addr <server_ipv6_addr>                IPv6 address of DHCPv4-over-IPv6 server");
}

int main(int argc, char **argv)
{
	mode = IPv4;
	int i;
	for (i = 1; i < argc; ++i) {
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
		} else if (i + 1 < argc && strcmp(argv[i], "--server-addr") == 0) {
			++i;
			strcpy(server_addr, argv[i]);
		} else {//config-interface
			strcpy(config_interface_name, argv[i]);
		}
	}
	
	if (mode == IPv6) {
		if (strlen(server_addr) == 0) {
			fprintf(stderr, "server-addr MUST be configured in DHCPv4-over-IPv6 mode!\n");
			exit(0);
		}
		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		dest.sin6_port = htons(67);
		if (inet_pton(AF_INET6, server_addr, &dest.sin6_addr) < 0) {
			fprintf(stderr, "Failed to resolve server_addr : %s\n", server_addr);
			exit(1);
		}
		printf("server-addr : %s\n", server_addr);
	}
	
	if (config_interface_name[0] == '\0') {
		usage();
		exit(0);
	}
	if (network_interface_name[0] == '\0')
		strcpy(network_interface_name, config_interface_name);
	
	init_interfaces();
	init_dhcp();
	while (1) {
		handle_dhcp();
	}
	return 0;
}
