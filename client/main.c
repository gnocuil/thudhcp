#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h> 

#include "config.h"
#include "dhcp.h"
#include "socket.h"

MODE mode;

static void usage()
{
	printf("Usage : thclient [options] <config_interface>\n");
	printf("        options:\n");
	printf("            -f                                       running in front mode (default in daemon mode)\n");
	printf("            -p                                       Use port set\n");
	printf("            --network-interface <network_interface>  default the same as config_interface\n");
	printf("            --encap-mode <mode>                      available modes: ipv4(default), ipv6, dhcpv6\n");
	printf("            --server-addr <server_ipv6_addr>         IPv6 address of DHCPv4-over-IPv6 server\n");
}

static void init_daemon()
{
	int pid, sid;
	if ((pid = fork()) > 0) {//father process
		exit(0);
	} else if (pid < 0) {//fork error
		fprintf(err, "Failed to fork...");
		exit(1);
	}
	sid = setsid();
	if (sid < 0) {
		fprintf(err, "Failed to setsid\n");
		exit(1);
	}
	if ((pid = fork()) > 0) {//father process
		exit(0);
	} else if (pid < 0) {//fork error
		exit(1);
	}
	close(0);
	close(1);
	close(2);
	chdir("/tmp");
	umask(0);
	
	err = fopen(DAEMON_LOG, "a");
	if (err <= 0) {
		exit(1);
	}
	fprintf(err, "logging!\n");
	
}

int main(int argc, char **argv)
{
	mode = IPv4;
	daemon = 1;
	err = stderr;
	portset = 0;
	int i;
	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-f") == 0) {
			daemon = 0;
		} else if (strcmp(argv[i], "-p") == 0) {
			portset = 1;
		} else if (i + 1 < argc && strcmp(argv[i], "--network-interface") == 0) {
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
			fprintf(err, "server-addr MUST be configured in DHCPv4-over-IPv6 mode!\n");
			exit(0);
		}
		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		//dest.sin6_port = htons(IPv6_SERVER_PORT);
		if (inet_pton(AF_INET6, server_addr, &dest.sin6_addr) < 0) {
			fprintf(err, "Failed to resolve server_addr : %s\n", server_addr);
			exit(1);
		}
		printf("server-addr : %s\n", server_addr);
	}

    //DHCPv6 support
    if (mode == DHCPv6) {
		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr) < 0) {
			fprintf(err, "Failed to resolve server_addr : %s\n", server_addr);
			exit(1);
		}
	}

	if (portset)
		printf("port set mode\n");
//	else
//		printf("No Port Set!\n");
	
	if (config_interface_name[0] == '\0') {
		usage();
		exit(0);
	}
	if (network_interface_name[0] == '\0')
		strcpy(network_interface_name, config_interface_name);
	
	init_interfaces();
	init_dhcp();
	if (daemon)
		init_daemon();
		
	while (1) {
		handle_dhcp();
	}
	return 0;
}
