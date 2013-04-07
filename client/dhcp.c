#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
      
#include "dhcp.h"
#include "interface.h"
#include "lease.h"
#include "socket.h"

STATE next_state;

uint32_t generate_xid()
{
	return xid = rand();
}

void init_dhcp()
{
	srand(time(NULL));
	timeout_count = TIMEOUT_RETRY_TIMES;
	
	if (load_lease(&offer_lease)) {
		renew = 1;
		generate_xid();
		next_state = REQUEST;
		dhcp_request();
	} else {
		next_state = DISCOVER;
		dhcp_discover();
	}
}

void handle_dhcp()
{
	printf("Sleep for %d seconds...\n", ack_lease.renew_time);
	sleep(ack_lease.renew_time);
	memcpy(&offer_lease, &ack_lease, sizeof(struct lease));
	renew = 1;
	generate_xid();
	next_state = REQUEST;
	dhcp_request();
}

int gen_options(struct dhcp_packet *packet)
{
	int pos = 0;
	packet->options[pos++] = 0x63;
	packet->options[pos++] = 0x82;
	packet->options[pos++] = 0x53;
	packet->options[pos++] = 0x63;
	pos = gen_option_message_type(packet->options, pos);
	pos = gen_option_host_name(packet->options, pos);
	pos = gen_option_parameter_request_list(packet->options, pos);
	if (next_state == REQUEST) {
		pos = gen_option_server_id(packet->options, pos);
		pos = gen_option_ip_address(packet->options, pos);
	}
	packet->options[pos++] = 0xff;
	int len = sizeof(struct dhcp_packet) - sizeof(packet->options) + pos;
	return len;
}

int gen_option_message_type(char *options, int pos)
{
	options[pos++] = OPTION_MESSAGETYPE;
	options[pos++] = 1;
	switch (next_state) {
	case DISCOVER:
		options[pos++] = 1;
		break;
	case REQUEST:
		options[pos++] = 3;
		break;
	default:
		printf("unknown next_state!\n");
		exit(0);
	}
	return pos;
}

int gen_option_host_name(char *options, int pos)
{
	gethostname(hostname, HOSTNAME_LEN);
	int len = strlen(hostname);
	hostname[len++] = '-';
	int len2 = strlen(config_interface->name);
	strcpy(hostname + len, config_interface->name);
	len += len2;
	options[pos++] = OPTION_HOSTNAME;
	options[pos++] = len;
	memcpy(options + pos, hostname, len);
	return pos + len;
}

int gen_option_parameter_request_list(char *options, int pos)
{
	options[pos++] = OPTION_PARAMETERREQUESTLIST;
	char *len = options + pos++;
	*len = 0;
	++*len; options[pos++] = OPTION_SUBNETMASK;
	++*len; options[pos++] = OPTION_BROADCAST;
	++*len; options[pos++] = OPTION_ROUTER;
	++*len; options[pos++] = OPTION_DOMAINNAME;
	++*len; options[pos++] = OPTION_DNSSERVER;
	++*len; options[pos++] = OPTION_SERVERID;
	return pos;
}

int gen_option_server_id(char *options, int pos)
{
	options[pos++] = OPTION_SERVERID;
	options[pos++] = 4;
	*(uint32_t*)(options + pos) = offer_lease.server_ip;
	return pos + 4;
}

int gen_option_ip_address(char *options, int pos)
{
	options[pos++] = OPTION_IPADDRESS;
	options[pos++] = 4;
	*(uint32_t*)(options + pos) = offer_lease.client_ip;
	return pos + 4;
}


static struct dhcp_packet* make_packet(int *len)
{
	struct dhcp_packet *packet = malloc(sizeof(struct dhcp_packet));
	memset(packet, 0, sizeof(struct dhcp_packet));
	packet->op = BOOT_REQUEST;
	packet->htype = 1;/* ETH */
	packet->hlen = 6;
	packet->hops = 0;
	packet->xid = xid;
	packet->secs = 0;
	packet->flags = 0;/* is this right? */
	packet->ciaddr = 0;
	packet->yiaddr = 0;
	packet->siaddr = 0;
	packet->giaddr = 0;
	memcpy(packet->chaddr, config_interface->addr, 6);
	*len = gen_options(packet);
	return packet;
}

void dhcp_discover()
{
	if (next_state != DISCOVER) {
		printf("State is not DISCOVER!\n");
		return;
	}
	printf("dhcp_discover()...\n");
	
	generate_xid();
	renew = 0;
	
	int len;
	struct dhcp_packet *packet = make_packet(&len);
	send_packet((char*)packet, len);
	free(packet);
	
	next_state = OFFER;
	dhcp_offer();
}

int check_packet(struct dhcp_packet *packet)
{
	if (packet->op != BOOT_REPLY) {
		//fprintf(stderr, "received packet is not BOOT_REPLY!\n");
		return 0;
	}
	if (packet->xid != xid) {
		//fprintf(stderr, "received packet transaction ID does not match!\n");
		return 0;
	}
	
	if (memcmp(packet->chaddr, config_interface->addr, 6) != 0) {
		//fprintf(stderr, "received packet mac address does not match!\n");
		return 0;
	}
	if (packet->options[0] != 0x63)
		return 0;
	if (packet->options[1] != 0x82)
		return 0;
	if (packet->options[2] != 0x53)
		return 0;
	if (packet->options[3] != 0x63)
		return 0;
	
	return 1;
/*	
	if (next_state == OFFER) {	
	} else if (next_state == ACK) {
	}
*/
}

void process_lease(struct lease* lease, struct dhcp_packet *packet)
{
	memset(lease, 0, sizeof(struct lease));
	lease->client_ip = packet->yiaddr;
	char *p = packet->options + 4;
	while ((*p & 0xff) != 0xff) {
		switch (*p) {
		case OPTION_DOMAINNAME:
			memcpy(lease->dns, p + 2, *(p + 1));
			break;
		case OPTION_DNSSERVER:
			lease->dns_ip = *(uint32_t*)(p + 2);
			break;
		case OPTION_LEASETIME:
			lease->lease_time = htonl(*(uint32_t*)(p + 2));
			break;
		case OPTION_RENEWALTIME:
			lease->renew_time = htonl(*(uint32_t*)(p + 2));
			break;
		case OPTION_ROUTER:
			lease->router_ip = *(uint32_t*)(p + 2);
			break;
		case OPTION_SERVERID:
			lease->server_ip = *(uint32_t*)(p + 2);
			break;
		case OPTION_SUBNETMASK:
			lease->mask_ip = *(uint32_t*)(p + 2);
			break;
		default:
			break;
		}
		p++;
		p += *p + 1;
	}
	if (lease->renew_time == 0)
		lease->renew_time = lease->lease_time / 2;
}

void dhcp_offer()
{
	if (next_state != OFFER) {
		printf("State is not OFFER!\n");
		return;
	}
	
	struct dhcp_packet *packet = malloc(sizeof(struct dhcp_packet));
	memset(packet, 0, sizeof(struct dhcp_packet));
	int valid = 0;
	while (!valid) {
		int len = recv_packet((char*)packet, sizeof(struct dhcp_packet));
		if (len < 0) {/* timeout */
			free_socket();
			if (timeout_count--) {
				next_state = DISCOVER;
				dhcp_discover();
				return;
			} else {
				fprintf(stderr, "give up...\n");
				exit(0);
			}
		}
		valid = check_packet(packet);
	}
	process_lease(&offer_lease, packet);
		
	free(packet);
	free_socket();
	
	timeout_count = TIMEOUT_RETRY_TIMES;
	next_state = REQUEST;
	dhcp_request();
}

void dhcp_request()
{
	if (next_state != REQUEST) {
		printf("State is not REQUEST!\n");
		return;
	}
	printf("dhcp_request()...\n");
	
	int len;
	struct dhcp_packet *packet = make_packet(&len);
	send_packet((char*)packet, len);
	free(packet);
	
	next_state = ACK;
	dhcp_ack();
}

void dhcp_ack()
{
	if (next_state != ACK) {
		printf("State is not ACK!\n");
		return;
	}
	
	struct dhcp_packet *packet = malloc(sizeof(struct dhcp_packet));
	memset(packet, 0, sizeof(struct dhcp_packet));
	int valid = 0;
	while (!valid) {
		int len = recv_packet((char*)packet, sizeof(struct dhcp_packet));
		if (len < 0) {/* timeout */
			free_socket();
			if (timeout_count--) {
				next_state = REQUEST;
				dhcp_request();
				return;
			} else {
				if (renew) {
					fprintf(stderr, "Failed to renew, try to re-allocate\n");
					timeout_count = TIMEOUT_RETRY_TIMES;
					next_state = DISCOVER;
					dhcp_discover();
					return;
				} else {
					fprintf(stderr, "give up...\n");
					exit(0);
				}
			}
		}
		valid = check_packet(packet);
	}
	process_lease(&ack_lease, packet);
		
	free(packet);
	free_socket();
	
	configure_interface(&ack_lease);
}

