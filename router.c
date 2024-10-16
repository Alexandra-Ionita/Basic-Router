#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

/* Routing table */
struct route_table_entry *route_table;
int route_table_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

queue packets;

void send_arp_reply(int interface, struct ether_header *eth, struct arp_header *sender_arp) {
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "memory");
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, sender_arp->sha, 6);

	// arp header
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	DIE(arp_hdr == NULL, "memory");
	arp_hdr->op = htons(2);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->spa = sender_arp->tpa;
	arp_hdr->tpa = sender_arp->spa;
	memcpy(arp_hdr->tha, sender_arp->sha, 6);
	memcpy(arp_hdr->sha, eth->ether_dhost, 6);

	size_t packet_size = sizeof(struct ether_header) + sizeof(struct arp_header);
	char arp_packet[packet_size];
	memcpy(arp_packet, eth_hdr, sizeof(struct ether_header));
	memcpy(arp_packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	send_to_link(interface, arp_packet, packet_size);

	free(eth_hdr);
	free(arp_hdr);
}

void send_arp_request(struct route_table_entry *lpm) {
	// ether header
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "memory");
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(lpm->interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, BROADCAST_ADDR, 6);

	// arp header
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	DIE(arp_hdr == NULL, "memory");
	arp_hdr->op = htons(1);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->spa = inet_addr(get_interface_ip(lpm->interface));
	arp_hdr->tpa = lpm->next_hop;
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr->tha, eth_hdr->ether_dhost, 6);

	size_t packet_size = sizeof(struct ether_header) + sizeof(struct arp_header);
	char arp_packet[packet_size];
	memcpy(arp_packet, eth_hdr, sizeof(struct ether_header));
	memcpy(arp_packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	send_to_link(lpm->interface, arp_packet, packet_size);

	free(eth_hdr);
	free(arp_hdr);
}

void send_icmp_error(uint8_t type, uint8_t code, int interface, struct iphdr *ip_hdr, char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr) {
    struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	DIE(icmp_hdr == NULL, "memory");
	struct iphdr *new_ip_hdr = malloc(sizeof(struct iphdr));
	DIE(new_ip_hdr == NULL, "memory");
	struct ether_header *eth = malloc(sizeof(struct ether_header));
	DIE(eth == NULL, "memory");
	memcpy(new_ip_hdr, ip_hdr, sizeof(struct iphdr));

	new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	new_ip_hdr->check = 0;
	new_ip_hdr->ttl = 64;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));
	new_ip_hdr->protocol = 1;

	memcpy(eth->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth->ether_shost);
	eth->ether_type = eth_hdr->ether_type;

    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->checksum = 0;

    // Calculate the size of the ICMP packet
    size_t icmp_packet_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
    char icmp_packet[icmp_packet_size];

	// Copy eth
	memcpy(icmp_packet, eth, sizeof(struct ether_header));
    // Copy the new IP header
    memcpy(icmp_packet + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
    // Copy the ICMP header
    memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	// Copy the original ipv4
	memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));
    // Copy the first 8 bytes of the original packet's data
    memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr), buf + sizeof(struct iphdr) + sizeof(struct ether_header), 8);

	free(icmp_hdr);
	// Calculate the ICMP checksum
	icmp_hdr = (struct icmphdr*) (icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr) + 8));

    // Send the ICMP packet
    send_to_link(interface, icmp_packet, icmp_packet_size);

	free(new_ip_hdr);
	free(eth);
}

void send_echo_reply(int interface, struct iphdr *ip_hdr, char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, struct icmphdr *icmp_hdr) {
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));
    // Calculate the size of the ICMP packet
    size_t icmp_packet_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    char icmp_packet[icmp_packet_size];

	// Copy eth
	memcpy(icmp_packet, eth_hdr, sizeof(struct ether_header));
    // Copy the new IP header
    memcpy(icmp_packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
    // Copy the ICMP header
    memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));    

    // Send the ICMP packet
    send_to_link(interface, icmp_packet, icmp_packet_size);
}

int lpm_compare(const void *a, const void *b) {
	if (((struct route_table_entry *)a)->prefix == ((struct route_table_entry *)b)->prefix) {
		if (ntohl(((struct route_table_entry *)a)->mask) > ntohl(((struct route_table_entry *)b)->mask)) {
			return 1;
		} 

		if (ntohl(((struct route_table_entry *)a)->mask) < ntohl(((struct route_table_entry *)b)->mask)) {
			return -1;
		} 
	}

	if (ntohl(((struct route_table_entry *)a)->prefix) < ntohl(((struct route_table_entry *)b)->prefix)) {
		return -1;
	}

	if (ntohl(((struct route_table_entry *)a)->prefix) > ntohl(((struct route_table_entry *)b)->prefix)) {
		return 1;
	}

	return 0;
}

/* LPM algorithm that searches for the best route */
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int left = 0, right = route_table_len - 1;
	struct route_table_entry *bestr = NULL;

	while (left <= right) {
		int middle = left + (right - left) / 2;

		if (route_table[middle].prefix == (ip_dest & route_table[middle].mask)) {
			bestr = &route_table[middle];
		}

		if (ntohl(route_table[middle].prefix) > ntohl(ip_dest)) {
			right = middle - 1;
		} else {
			left = middle + 1;
		}
	}

	return bestr;

}

/* ARP entry to match the given ip */
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
} 

void get_arp_reply(struct ether_header *eth_hdr, struct arp_header *arp_hdr, int interface) {
    arp_table[arp_table_len].ip = arp_hdr->spa;
    memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
    arp_table_len++;

    struct queue *aux_packets = queue_create();

	while (!queue_empty(packets)) {
		char *q_packet = queue_deq(packets);
		
		struct ether_header *q_eth = malloc(sizeof(struct ether_header));
		DIE(q_eth == NULL, "memory");
		q_eth = (struct ether_header *)q_packet;

		struct iphdr *q_ip = malloc(sizeof(struct iphdr));
		DIE(q_ip == NULL, "memory");
		q_ip = (struct iphdr *)(q_packet + sizeof(struct ether_header));

		struct route_table_entry *r = malloc(sizeof(struct route_table_entry));
		DIE(r == NULL, "memory");
		r = get_best_route(q_ip->daddr);

        struct arp_table_entry *arp_entry = malloc(sizeof(struct arp_table_entry));
		DIE(arp_entry == NULL, "memory");
		arp_entry = get_arp_entry(r->next_hop);

		struct iphdr *ip_packet = malloc(sizeof(struct iphdr));
		DIE(ip_packet == NULL, "memory");
		ip_packet = (struct iphdr *)(q_packet + sizeof(struct ether_header));
		uint16_t len = ntohs(ip_packet->tot_len) + sizeof(struct ether_header);

		if (arp_entry == NULL) {
            queue_enq(aux_packets, q_packet);
            continue;
        }

        get_interface_mac(r->interface, q_eth->ether_shost);
        memcpy(q_eth->ether_dhost, arp_entry->mac, 6);
        q_eth->ether_type = htons(ETHERTYPE_IP);
        send_to_link(r->interface, q_packet, len);
    }

	packets = aux_packets;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(route_table == NULL, "memory");
	route_table_len = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), lpm_compare);


	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");

	packets = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		char *copy = malloc(len);
		DIE(copy == NULL, "memory");
        memcpy(copy, buf, len);

		/* ethernet header and ip header from payload */
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		/* Check IPv4 buf */
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Verify echo request
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				send_echo_reply(interface, ip_hdr, buf, eth_hdr, icmp_hdr);
				continue;
			}

			/* ip_hdr integrity check */
			uint16_t checksum_copy = 0;
			checksum_copy = ip_hdr->check;
			ip_hdr->check = 0;

			if (checksum_copy != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
				printf("Failed checksum\n");
				continue;
			}
			ip_hdr->check = checksum_copy;

			/* search for the most specific route */
			struct route_table_entry *lpm = get_best_route(ip_hdr->daddr);
			if (lpm == NULL) {
				send_icmp_error(3, 0, interface, ip_hdr, buf, eth_hdr);
				continue; 
			}

			/* TTL check */
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(11, 0, interface, ip_hdr, buf, eth_hdr);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


			/* Ethernet addresses update */
			struct arp_table_entry *arp_entry = get_arp_entry(lpm->next_hop);
			get_interface_mac(lpm->interface, eth_hdr->ether_shost);

			if (arp_entry == NULL) {
                // add packet to queue
                queue_enq(packets, copy);

                // arp request
				send_arp_request(lpm);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

			send_to_link(lpm->interface, buf, len);
			continue;
		} 
   
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (arp_hdr->op == htons(1)) {
				send_arp_reply(interface, eth_hdr, arp_hdr);
				continue;
			}

			if (arp_hdr->op == htons(2)) {
				get_arp_reply(eth_hdr, arp_hdr, interface);
				continue;
			}
		}

		free(copy);
	}

	free(route_table);
	free(arp_table);
}
