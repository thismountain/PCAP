#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>  
#include "header.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_payload(const u_char* payload, int len) {
	for (int i = 0; i < len && i < 20; i++) {
		printf("%02x ", payload[i]);
	}
	printf("\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;
	struct libnet_tcp_hdr *tcp_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;
	ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return;
	}

	tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));

	printf("Ethernet Header\n");
	printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
		eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
		eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

	printf("IP Header\n");
	printf("   Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("   Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

	printf("TCP Header\n");
	printf("   Src Port: %d\n", ntohs(tcp_hdr->th_sport));
	printf("   Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

	printf("Payload\n");
	print_payload(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4), header->caplen - (sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4)));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	if (pcap_loop(pcap, 0, packet_handler, NULL) < 0) {
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(pcap));
		return -1;
	}

	pcap_close(pcap);
}

