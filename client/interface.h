#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#define INTERFACE_NAME_LEN 100

struct interface {
	char name[INTERFACE_NAME_LEN];
	char addr[6];/* macaddr */
};

struct interface *config_interface;
struct interface *network_interface;

void init_interfaces();


#endif /* __INTERFACE_H__ */
