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

void dhcp_discover()
{
	if (next_state != DISCOVER) {
		printf("State is not DISCOVER!\n");
		return;
	}
	
	generate_xid();
	
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
	int len = gen_options(packet);
	
	send_packet((char*)packet, len);
	
	free(packet);
}
