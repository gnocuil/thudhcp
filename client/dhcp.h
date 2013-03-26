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

void init_dhcp();
uint32_t generate_xid();
void dhcp_discover();
void dhcp_offer();
void dhcp_request();
void dhcp_ack();
void process_lease(struct lease* lease, struct dhcp_packet *packet);
int check_packet(struct dhcp_packet *packet);
int gen_options(struct dhcp_packet *packet);
int gen_option_message_type(char *options, int pos);
int gen_option_host_name(char *options, int pos);
int gen_option_parameter_request_list(char *options, int pos);
int gen_option_server_id(char *options, int pos);
int gen_option_ip_address(char *options, int pos);


#define HOSTNAME_LEN 80
char hostname[HOSTNAME_LEN];

uint32_t xid;/* transaction ID */

int renew;/* whether renewing */

typedef enum {
	DISCOVER,
	OFFER,
	REQUEST,
	ACK
} STATE;

extern STATE next_state;

#define BOOT_REQUEST 1
#define BOOT_REPLY 2


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

#endif /* __DHCP_H__ */
