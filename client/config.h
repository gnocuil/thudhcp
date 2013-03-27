#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "interface.h"

char config_interface_name[INTERFACE_NAME_LEN];
char network_interface_name[INTERFACE_NAME_LEN];

char server_addr[100];
struct sockaddr_in6 dest;/* server_addr */

typedef enum {
	IPv4,
	IPv6,
	DHCPv6
} MODE;

extern MODE mode;



#endif /* __CONFIG_H__ */
