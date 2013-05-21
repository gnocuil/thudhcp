#ifndef __DHCP_H__
#define __DHCP_H__

#include <stdint.h>
#include "lease.h"

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint8_t options[1500];
};

#define PACKET_END(p) (((uint8_t*)(p)) + sizeof(struct dhcp_packet))
#define PACKET_INSIDE(i,p) (((uint8_t*)(i)) >= ((uint8_t*)(p)) && ((uint8_t*)(i)) <= PACKET_END(p))

void init_dhcp();
void handle_dhcp();
uint32_t generate_xid();
void dhcp_discover();
void dhcp_offer();
void dhcp_request();
void dhcp_ack();
void process_lease(struct lease* lease, struct dhcp_packet *packet);
int check_packet(struct dhcp_packet *packet);
int gen_options(struct dhcp_packet *packet);
int gen_option_message_type(uint8_t *options, int pos);
int gen_option_host_name(uint8_t *options, int pos);
int gen_option_parameter_request_list(uint8_t *options, int pos);
int gen_option_server_id(uint8_t *options, int pos);
int gen_option_ip_address(uint8_t *options, int pos);
int gen_option_portset(uint8_t *options, int pos);

#define HOSTNAME_LEN 80
char hostname[HOSTNAME_LEN];

uint32_t xid;/* transaction ID */

int renew;/* whether renewing */

int portset;

typedef enum {
	DISCOVER,
	OFFER,
	REQUEST,
	ACK
} STATE;

extern STATE next_state;

extern FILE *err;

#define DISCOVER 1
#define REQUEST 3

#define BOOT_REQUEST 1
#define BOOT_REPLY 2

#define BOOTREQUESTV6              245
#define BOOTREPLYV6                246

#define OPTION_PAD                   0
#define OPTION_SUBNETMASK            1
#define OPTION_ROUTER                3
#define OPTION_DNSSERVER             6
#define OPTION_HOSTNAME             12
#define OPTION_DOMAINNAME           15
#define OPTION_BROADCAST            28
#define OPTION_IPADDRESS            50
#define OPTION_LEASETIME            51
#define OPTION_MESSAGETYPE          53
#define OPTION_SERVERID             54
#define OPTION_PARAMETERREQUESTLIST 55
#define OPTION_RENEWALTIME          58
#define OPTION_PORTSET              224

#define OPTION_BOOTP_MSG            54321

#endif /* __DHCP_H__ */
