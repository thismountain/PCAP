// libnet-headers.h
#ifndef __LIBNET_HEADERS_H__
#define __LIBNET_HEADERS_H__

#include <stdint.h>

/*
 * Ethernet addresses are 6 bytes
 */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct libnet_ethernet_hdr {
	uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
	uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
	uint16_t ether_type;                     /* protocol */
};

/* IP header */
struct libnet_ipv4_hdr {
	uint8_t  ip_hl:4,      /* header length */
	         ip_v:4;       /* version */
	uint8_t  ip_tos;       /* type of service */
	uint16_t ip_len;       /* total length */
	uint16_t ip_id;        /* identification */
	uint16_t ip_off;       /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* don't fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	uint8_t  ip_ttl;       /* time to live */
	uint8_t  ip_p;         /* protocol */
	uint16_t ip_sum;       /* checksum */
	struct   in_addr ip_src, ip_dst; /* source and dest address */
};

/* TCP header */
typedef uint32_t tcp_seq;

struct libnet_tcp_hdr {
	uint16_t th_sport;      /* source port */
	uint16_t th_dport;      /* destination port */
	tcp_seq th_seq;         /* sequence number */
	tcp_seq th_ack;         /* acknowledgement number */
	uint8_t  th_x2:4,       /* (unused) */
	         th_off:4;      /* data offset */
	uint8_t  th_flags;
	uint16_t th_win;        /* window */
	uint16_t th_sum;        /* checksum */
	uint16_t th_urp;        /* urgent pointer */
};

#endif /* __LIBNET_HEADERS_H__ */

