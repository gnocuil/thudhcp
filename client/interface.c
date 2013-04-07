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
			fprintf(err, "Failed to get MAC address of %s\n", interface->if_name);
			valid_addr = 0;
		} else {
			memcpy(addr, ifopt.ifr_hwaddr.sa_data, 6);
			valid_addr = 1;
		}
		if (!valid_addr || (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0)) {
            valid_addr = 0;
		    addr[0] = rand() % 0xFF;
		    addr[1] = rand() % 0xFF;
		    addr[2] = rand() % 0xFF;
		    addr[3] = rand() % 0xFF;
		    addr[4] = rand() % 0xFF;
		    addr[5] = rand() % 0xFF;
		}
		if (strcmp(network_interface_name, interface->if_name) == 0 && !network_interface) {
			network_interface = malloc(sizeof(struct interface));
			memset(network_interface, 0, sizeof(struct interface));
			strcpy(network_interface->name, interface->if_name);
			memcpy(network_interface->addr, addr, 6);
			fprintf(err, "network-interface is %s, macaddr=%s\n", network_interface->name, mac_to_str(network_interface->addr));
		}
		if (strcmp(config_interface_name, interface->if_name) == 0 && !config_interface) {
            if (!valid_addr)
                fprintf(err, "Interface %s does not have mac address, use random value instead\n", interface->if_name);
			config_interface = malloc(sizeof(struct interface));
			memset(config_interface, 0, sizeof(struct interface));
			strcpy(config_interface->name, interface->if_name);
			memcpy(config_interface->addr, addr, 6);
			fprintf(err, "config-interface is %s, macaddr=%s\n", config_interface->name, mac_to_str(config_interface->addr));
		}
	}
	if_freenameindex(interfaces);
	close(fd);  
	
	if (!network_interface) {
		fprintf(err, "network-interface not found ! name=%s\n", network_interface_name);
		exit(1);
	}
	if (!config_interface) {
		fprintf(err, "config-interface not found ! name=%s\n", config_interface_name);
		exit(1);
	}
}

static int set_ipaddr(char *interface_name, struct sockaddr_in addr)
{
	int s;
	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(err, "Error up %s :%m\n",interface_name, errno);
		return -1;
	}
	struct ifreq ifr;
	strcpy(ifr.ifr_name, interface_name);
	memcpy(&ifr.ifr_ifru.ifru_addr, &addr, sizeof(struct sockaddr_in));
	if(ioctl(s, SIOCSIFADDR, &ifr) < 0) {
		fprintf(err, "Error set %s ip :%m\n",interface_name, errno);
		return -1;
	}
	return 0;
}

static int set_submask(char *interface_name, struct sockaddr_in mask)
{
	int s;
	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(err, "Error up %s :%m\n",interface_name, errno);
		return -1;
	}
	struct ifreq ifr;
	strcpy(ifr.ifr_name, interface_name);
	memcpy(&ifr.ifr_ifru.ifru_addr, &mask, sizeof(struct sockaddr_in));
	if(ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
		fprintf(err, "Error set %s mask :%m\n",interface_name, errno);
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
	//if(ioctl(skfd, SIOCDELRT, &rt) < 0) 
	//{
		//fprintf(err, "Error route del :%m\n", errno);
		//return -1;
	//}

	memset(&rt, 0, sizeof(rt));

	rt.rt_metric = 2;
  
	rt.rt_dst = *(struct sockaddr*) &dst;
	rt.rt_genmask = *(struct sockaddr*) &genmask;
	rt.rt_gateway = *(struct sockaddr*) &gateway;

	rt.rt_dev = interface_name;
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	//skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(ioctl(skfd, SIOCADDRT, &rt) < 0) 
	{
		fprintf(err, "Error route add :%m\n", errno);
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

#define DEL 0
#define ADD 1

#define TCP 0
#define UDP 1
#define ICMP 2
static void iptables(char *ipmask, uint16_t port_start, uint16_t port_end, int protocol, int mode)
{
	char cmd[100] = {0};
	sprintf(cmd, "iptables -t nat -%c POSTROUTING -s %s -p %s -j MASQUERADE --to-ports %d-%d",
		(mode == DEL) ? 'D' : 'A',
		ipmask,
		(protocol == TCP) ? "TCP" : ((protocol == UDP) ? "UDP" : "ICMP"),
		port_start,
		port_end
	);
	system(cmd);
}

static void config_portset(struct lease* lease)
{
	int mask = lease->mask_ip;
	int mask_len = 0;
	while (mask) {
		if (mask & 1)
			++mask_len;
		mask >>= 1;
	}
	char ipmask[20] = {0};
	uint32_t network = lease->client_ip & lease->mask_ip;
	sprintf(ipmask, "%d.%d.%d.%d/%d",
		network & 0xFF,
		(network >> 8) & 0xFF,
		(network >> 16) & 0xFF,
		(network >> 24) & 0xFF,
		mask_len
	);
	puts(ipmask);
	uint16_t port_start = lease->portset_index & lease->portset_mask;
	uint16_t port_end = lease->portset_index | (~lease->portset_mask);
	int mode, protocol;
	for (mode = DEL; mode <= ADD; ++mode)
		for (protocol = TCP; protocol <= ICMP; ++protocol)
			iptables(ipmask, port_start, port_end, protocol, mode);
}

void configure_interface(struct lease* lease)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = lease->client_ip;
	struct sockaddr_in mask;
	memset(&mask, 0, sizeof(mask));
	mask.sin_family = AF_INET;
	mask.sin_addr.s_addr = lease->mask_ip;
	struct sockaddr_in gateway;
	memset(&gateway, 0, sizeof(gateway));
	gateway.sin_family = AF_INET;
	gateway.sin_addr.s_addr = lease->router_ip;
	struct sockaddr_in dns;
	memset(&dns, 0, sizeof(dns));
	dns.sin_family = AF_INET;
	dns.sin_addr.s_addr = lease->dns_ip;

	
	fprintf(err, "Configure interface %s:\n", config_interface->name);
	fprintf(err, "\tIP address : %s\n", (char*)inet_ntoa(addr.sin_addr));
	fprintf(err, "\tIP subnet mask : %s\n", (char*)inet_ntoa(mask.sin_addr));
	fprintf(err, "\tGateway address : %s\n", (char*)inet_ntoa(gateway.sin_addr));
	if (check_dns_name(lease))
		fprintf(err, "\tDNS Server : %s\n", lease->dns);
	fprintf(err, "\tDNS Server : %s\n", (char*)inet_ntoa(dns.sin_addr));
	fprintf(err, "\tLease time : %ds\n", lease->lease_time);
	fprintf(err, "\tRenew time : %ds\n", lease->renew_time);
	if (portset) {
		fprintf(err, "\tPort set mask  : 0x%04x\n", lease->portset_mask);
		fprintf(err, "\tPort set index : 0x%04x\n", lease->portset_index);
	}

	
	if (set_ipaddr(config_interface->name, addr) != 0) {
		//ffprintf(err, "Failed to config IP address!\n");
		return;
	}
	if (set_submask(config_interface->name, mask) != 0) {
		return;
	}
	if (route_add(config_interface->name, lease) != 0) {
		//return;
	}
	config_dns(lease);
	if (portset) {
		config_portset(lease);
	}
	
	save_lease(lease);
}

void save_lease(struct lease* lease)
{
	char path[500] = {0};
	strcpy(path, DEFAULT_LEASE_PATH);
	int len = strlen(path);
	if (path[len - 1] != '/')
		path[len++] = '/';
	char cmd[600] = {0};
	sprintf(cmd, "mkdir -p %s\n", path);
	system(cmd);
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "%s%s.lease", path, config_interface->name);
	fprintf(err, "Saving lease to %s\n", cmd);
	FILE *fout = fopen(cmd, "w");
	if (!fout)
		return;
	fwrite(lease, 1, sizeof(struct lease), fout);
	fwrite(config_interface, 1, sizeof(struct interface), fout);
	fclose(fout);
}

int load_lease(struct lease* lease)
{
	char path[500] = {0};
	strcpy(path, DEFAULT_LEASE_PATH);
	int len = strlen(path);
	if (path[len - 1] != '/')
		path[len++] = '/';
	char cmd[600] = {0};
	sprintf(cmd, "%s%s.lease", path, config_interface->name);
	fprintf(err, "Loading lease from %s\n", cmd);
	FILE *fin = fopen(cmd, "r");
	if (!fin)
		return 0;
	fread(lease, 1, sizeof(struct lease), fin);
	struct interface tmp_interface;
	fread(&(tmp_interface), 1, sizeof(struct interface), fin);
	fclose(fin);
	if (memcmp(&tmp_interface, config_interface, sizeof(struct interface)) != 0)
		return 0;/* lease does not match! */
	if (portset) {//port set mode
		if (lease->portset_index == 0 && lease->portset_mask == 0)
			return 0;/* invalid port set */
	} else {//no port set mode
		if (lease->portset_index != 0 || lease->portset_mask != 0)
			return 0;/* invalid port set */
	}
	return 1;
}


