#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <net/route.h>
//#include <net/if_arp.h>

#include "interface.h"
#include "config.h"
#include "lease.h"

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
	
	if (!network_interface) {
		fprintf(stderr, "network-interface not found ! name=%s\n", network_interface_name);
		exit(1);
	}
	if (!config_interface) {
		fprintf(stderr, "config-interface not found ! name=%s\n", config_interface_name);
		exit(1);
	}
}

static int set_ipaddr(char *interface_name, struct sockaddr_in addr)
{
    int s;

    if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Error up %s :%m\n",interface_name, errno);
        return -1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface_name);

    memcpy(&ifr.ifr_ifru.ifru_addr, &addr, sizeof(struct sockaddr_in));

    if(ioctl(s, SIOCSIFADDR, &ifr) < 0)
    {
        printf("Error set %s ip :%m\n",interface_name, errno);
        return -1;
    }

    return 0;
}

static int route_add(char * interface_name, struct lease *lease)
{
    int skfd;
    struct rtentry rt;

    struct sockaddr_in dst;
    struct sockaddr_in gateway;
    struct sockaddr_in genmask;

    bzero(&genmask,sizeof(struct sockaddr_in));
    genmask.sin_family = AF_INET;
    genmask.sin_addr.s_addr = inet_addr("0.0.0.0");

    bzero(&dst,sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("0.0.0.0");
    
    bzero(&gateway,sizeof(struct sockaddr_in));
    gateway.sin_family = AF_INET;
    gateway.sin_addr.s_addr = lease->router_ip;

    memset(&rt, 0, sizeof(rt));

    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;
    //rt.rt_gateway = *(struct sockaddr*) &gateway;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCDELRT, &rt) < 0) 
    {
        //printf("Error route del :%m\n", errno);
        //return -1;
    }

    memset(&rt, 0, sizeof(rt));

    rt.rt_metric = 0;
  
    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;
    rt.rt_gateway = *(struct sockaddr*) &gateway;

    rt.rt_dev = interface_name;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    //skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCADDRT, &rt) < 0) 
    {
        printf("Error route add :%m\n", errno);
        return -1;
    }
}

static int check_dns_name(struct lease* lease)
{
	if (strlen(lease->dns) == 0)
		return 0;
	if (strcmp(lease->dns, "lan") == 0)
		return 0;
	return 1;
}

static void config_dns(struct lease* lease)
{
	FILE *dns_file = fopen("/etc/resolv.conf", "w");
	if (!dns_file)
		return;
	if (check_dns_name(lease)) {
		fprintf(dns_file, "nameserver %s\n", lease->dns);
	}
	struct sockaddr_in dns;
	memset(&dns, 0, sizeof(dns));
	dns.sin_family = AF_INET;
	dns.sin_addr.s_addr = lease->dns_ip;
	fprintf(dns_file, "nameserver %s\n", (char*)inet_ntoa(dns.sin_addr));
	fclose(dns_file);
}

void configure_interface(struct lease* lease)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = lease->client_ip;
	struct sockaddr_in gateway;
	memset(&gateway, 0, sizeof(gateway));
	gateway.sin_family = AF_INET;
	gateway.sin_addr.s_addr = lease->router_ip;
	struct sockaddr_in dns;
	memset(&dns, 0, sizeof(dns));
	dns.sin_family = AF_INET;
	dns.sin_addr.s_addr = lease->dns_ip;

	
	printf("Configure interface %s:\n", config_interface->name);
	printf("    IP address : %s\n", (char*)inet_ntoa(addr.sin_addr));
	printf("    Gateway address : %s\n", (char*)inet_ntoa(gateway.sin_addr));
	if (check_dns_name(lease))
		printf("    DNS Server : %s\n", lease->dns);
	printf("    DNS Server : %s\n", (char*)inet_ntoa(dns.sin_addr));
	
	if (set_ipaddr(config_interface->name, addr) != 0) {
		//fprintf("Failed to config IP address!\n");
		return;
	}
	if (route_add(config_interface->name, lease) != 0) {
		return;
	}
	config_dns(lease);
}
