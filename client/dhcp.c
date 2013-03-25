#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
      
#include "dhcp.h"
#include "interface.h"

STATE next_state;

uint32_t generate_xid()
{
	return xid = rand();
}

void init_dhcp()
{
	next_state = DISCOVER;
	srand(time(NULL));
	socket_init();
	dhcp_discover();
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
	return pos;
}

int gen_option_server_id(char *options, int pos)
{
	//TODO
	return pos;
}

int gen_option_ip_address(char *options, int pos)
{
	//TODO
	return pos;
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
	
	generate_xid();
	
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
		fprintf(stderr, "received packet is not BOOT_REPLY!\n");
		return 0;
	}
	if (packet->xid != xid) {
		fprintf(stderr, "received packet transaction ID does not match!\n");
		return 0;
	}
	
	if (memcmp(packet->chaddr, config_interface->addr, 6) != 0) {
		fprintf(stderr, "received packet mac address does not match!\n");
		return 0;
	}
	
	return 1;
/*	
	if (next_state == OFFER) {	
	} else if (next_state == ACK) {
	}
*/
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
		valid = check_packet(packet);
	}
	//process lease...
		
	free(packet);
	
	next_state = REQUEST;
	dhcp_request();
}

void dhcp_request()
{
	if (next_state != REQUEST) {
		printf("State is not REQUEST!\n");
		return;
	}
	
	int len;
	struct dhcp_packet *packet = make_packet(&len);
	send_packet((char*)packet, len);
	free(packet);
	
	next_state = ACK;
	dhcp_ack();
}

void dhcp_ack()
{
	printf("ACK!!!\n");
}

