#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "socket.h"
#include "config.h"
#include "interface.h"
#include "dhcp.h"

void init_socket()
{
	/* UDP socket */
	struct sockaddr_in servaddr;
	
	if (mode == IPv4) {
		if (next_state == DISCOVER || next_state == REQUEST) {
			listen_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			if (listen_raw_fd < 0) {
				printf("Failed to create listening raw socket.\n");
				exit(0);
			}
			struct timeval timeout;
			timeout.tv_sec = RECV_TIMEOUT_SEC;
			timeout.tv_usec = 0;
			setsockopt(listen_raw_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
			
			/* create a UDP socket to prevent ICMP port unreachable */
			ipv4_fd = socket(AF_INET, SOCK_DGRAM, 0);		
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
			servaddr.sin_port = htons(IPv4_CLIENT_PORT);
			if (bind(ipv4_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
				//fprintf(stderr, "socket_init(): bind error\n");
				//exit(1);
			}
		}
	}
}

void free_socket()
{
	if (mode == IPv4) {
		if (next_state == OFFER || next_state == ACK) {
			close(listen_raw_fd);
			if (ipv4_fd) {
				close(ipv4_fd);
				ipv4_fd = 0;
			}
		}
	}
}

static uint16_t udpchecksum(char *iphead, char *udphead, int udplen, int type)
{
    udphead[6] = udphead[7] = 0;
    uint32_t checksum = 0;
    //printf("udp checksum is 0x%02x%02x\n", (uint8_t)udphead[6], (uint8_t)udphead[7]);
    if (type == 6)
    {
        struct udp6_psedoheader header;
        memcpy(header.srcaddr, iphead + 24, 16);
        memcpy(header.dstaddr, iphead + 8, 16);
        header.length = ntohs(udplen);
        header.zero1 = header.zero2 = 0;
        header.next_header = 0x11;
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }
    else if (type == 4)
    {
        struct udp4_psedoheader header;
        memcpy((char*)&header.srcaddr, iphead + 12, 4);
        memcpy((char*)&header.dstaddr, iphead + 16, 4);
        header.zero = 0;
        header.protocol = 0x11;
        header.length = ntohs(udplen);
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }    
    uint16_t *uptr = (uint16_t*)udphead;
    while (udplen > 1) {    
        checksum += *(uptr++);
        udplen -= 2;
    }
    if (udplen) {
        checksum += (*((uint8_t*)uptr)) ;
    }
    do {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    } while (checksum != (checksum & 0xFFFF));
    uint16_t ans = checksum;
    return (ans == 0xFF)? 0xFF :ntohs(~ans);
}

static uint16_t checksum(uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= sizeof (uint16_t);
    }

    if (nleft == 1) {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void send_packet(char *packet, int len)
{
	init_socket();
	switch (mode) {
	case IPv4:
		send_packet_ipv4(packet, len);
		return;
	default:
		printf("send_packet : unknown mode!\n");
		exit(0);
	}
}

void send_packet_ipv4(char *packet, int len)
{
	memset(buf, 0, sizeof(buf));
	memcpy(buf + 14 + 20 + 8, packet, len);
	struct udphdr *udp = (struct udphdr*)(buf + 14 + 20);
	udp->source = htons(IPv4_CLIENT_PORT);
	udp->dest = htons(IPv4_SERVER_PORT);
	udp->len = htons(len + 8);
	udp->check = 0;
	
	struct iphdr* ip = (struct iphdr*)(buf + 14);
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0x10;
	ip->tot_len = htons(len + 20 + 8);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 128;
	ip->protocol = UDP;
	ip->check = 0;
	inet_aton("0.0.0.0", &(ip->saddr));
	inet_aton("255.255.255.255", &(ip->daddr));
	
	udp->check = htons(udpchecksum((char*)ip, (char*)udp, len + 8, 4));
	ip->check = checksum((uint16_t*)ip, 20);
	
	memset(buf, 0xff, 6);
	memcpy(buf + 6, network_interface->addr, 6);
	buf[12] = 0x08;
	buf[13] = 0x00;
	
	int total_len = len + 14 + 20 + 8;
	
	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		fprintf(stderr, "Failed to create send socket.\n");
		exit(1);
	}
	
	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex(network_interface->name)) == 0) {
		fprintf(stderr, "Failed to resolve the index of %s.\n", network_interface->name);
		exit(1);
	}
	
	if (sendto(fd, buf, total_len, 0, (struct sockaddr *)&device, sizeof(device)) < 0) {
		fprintf(stderr, "Failed to send ipv4 packet.\n");
		exit(1);
	}
	close(fd);
}

int recv_packet(char* packet, int max_len)
{
	switch (mode) {
	case IPv4:
		return recv_packet_ipv4(packet, max_len);
	default:
		printf("recv_packet : unknown mode!\n");
		exit(0);
	}
}

int recv_packet_ipv4(char* packet, int max_len)
{
/*  UDP socket
	int len;
	if ((len = recvfrom(ipv4_fd, packet, max_len, 0, NULL, NULL)) < 0) {
		perror("receive error!\n");
		exit(0);
	}
	printf("received %d bytes\n", len);
//	close(fd);
	return len;
*/
	
	int len = recv(listen_raw_fd, buf, max_len, 0);
	if (len < 0) {
		fprintf(stderr, "recv timeout!\n");
		return -1;
	}
	len -= 14 + 20 + 8;
	memcpy(packet, buf + 14 + 20 + 8, len);
	return len;
}



