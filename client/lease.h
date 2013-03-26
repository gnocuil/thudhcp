#ifndef __LEASE_H__
#define __LEASE_H__

#include <stdint.h>

#define DNS_NAME_LEN 100

struct lease {
	uint32_t server_ip;
	uint32_t client_ip;
	uint32_t mask_ip;
	uint32_t router_ip;
	uint32_t dns_ip;
	char dns[DNS_NAME_LEN];
	uint32_t lease_time;
	uint32_t renew_time;
};

struct lease offer_lease;
struct lease ack_lease;

void save_lease(struct lease* lease);
int load_lease(struct lease* lease);


#define DEFAULT_LEASE_PATH "/var/lib/thudhcp/"

#endif /* __LEASE_H__ */
