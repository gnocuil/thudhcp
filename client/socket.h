#ifndef __SOCKET_H__
#define __SOCKET_H__

void init_socket();
void free_socket();

void send_packet(char *packet, int len);
void send_packet_ipv4(char *packet, int len);
void send_packet_ipv6(char *packet, int len);

int recv_packet(char* packet, int max_len);
int recv_packet_ipv4(char* packet, int max_len);
int recv_packet_ipv6(char* packet, int max_len);

#define UDP 0x11

#define IPv4_SERVER_PORT 67
#define IPv4_CLIENT_PORT 68

#define RECV_TIMEOUT_SEC 3
#define TIMEOUT_RETRY_TIMES 4
int timeout_count;

#define BUF_LEN 2000
char buf[BUF_LEN];

int ipv4_fd;
int ipv6_fd;

int listen_raw_fd;

struct udp6_psedoheader {
    uint8_t srcaddr[16];
    uint8_t dstaddr[16];
    uint32_t length;
    uint16_t zero1;
    uint8_t zero2;
    uint8_t next_header;
};

struct udp4_psedoheader {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

#endif /* __SOCKET_H__ */
