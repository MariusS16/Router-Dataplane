#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define BROADCAST_MAC 1
#define MY_MAC 2
#define OTHER 0

struct data {
	struct arp_table_entry *arp_entry;
	struct route_table_entry *rtable_entry;
	int len_rtable;
	int len_arp_table;
	int interface;
};

int get_type_mac(uint8_t *mac, int interface){
	int ok_br = 0;
	for(int i = 0; i < 6; i++){
		if(mac[i] != 0xff){
			ok_br = 1;
		}
	}

	if (ok_br == 0){
		return BROADCAST_MAC;
	}

	uint8_t my_mac[6];
	get_interface_mac(interface, my_mac);
	int ok_my_mac = 0;
	
	for(int i = 0; i < 6; i++){
		if(mac[i] != my_mac[i]){
			ok_my_mac = 1;
		}
	}

	if (ok_my_mac == 0){
		return MY_MAC;
	}

	return OTHER;
}

int check_sum(char *buf) {
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	uint16_t old = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	uint16_t new = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
	ip_hdr->check = old;
	if (old == new) {
		return 1;
	}
	return 0;
}

int check_ttl(char *buf) {
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	if (ip_hdr->ttl <= 1) {
		return 0;
	}
	return 1;
}

int lpm_binary(char *buf, struct route_table_entry *rtable, int len_rtable) {
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    uint32_t dest_ip = ip_hdr->daddr;
    int best_match_index = -1;
    int left = 0;
    int right = len_rtable - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        uint32_t masked_ip = dest_ip & rtable[mid].mask;

        if (masked_ip == rtable[mid].prefix) {
            best_match_index = mid;
            right = mid - 1;
        } else if (masked_ip > rtable[mid].prefix) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return best_match_index;
}

int check_arp_table(uint32_t ip, struct arp_table_entry *arp_table, int arp_table_len) {
	for (int i = 0; i < arp_table_len; i++) {
		if (ip == arp_table[i].ip) {
			return i;
		}
	}
	return -1;
}

void dec_ttl(char *buf) {
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	ip_hdr->ttl--;
}

void recalc_checksum(char *buf) {
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)));
}

void send_icmp_error(int interface, char *buf, size_t len, uint8_t type, uint8_t code) {
	char *icmp_packet = calloc(1, MAX_PACKET_LEN);

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *) (icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr)); 

	struct ether_header *icmp_eth_hdr = (struct ether_header *) icmp_packet;
	struct iphdr *icmp_ip_hdr = (struct iphdr *) (icmp_packet + sizeof(struct ether_header));

	icmp_eth_hdr->ether_type = htons(0x800);
	get_interface_mac(interface, icmp_eth_hdr->ether_shost);
	for (int i = 0; i < 6; i++) {
		icmp_eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	}
	
	icmp_ip_hdr->version = 4;
	icmp_ip_hdr->ihl = 5;
	icmp_ip_hdr->tos = 0;
	icmp_ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

	icmp_ip_hdr->id = htons(1);
	icmp_ip_hdr->frag_off = 0;
	icmp_ip_hdr->ttl = 64;
	icmp_ip_hdr->protocol = IPPROTO_ICMP;
	icmp_ip_hdr->daddr = ip_hdr->saddr;
	icmp_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	icmp_ip_hdr->check = 0;
	icmp_ip_hdr->check = htons(checksum((uint16_t*) icmp_ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;
	char *icmp_data = ((char *) icmp_hdr) + sizeof(struct icmphdr);
	memcpy(icmp_data, ip_hdr, sizeof(struct iphdr) + 8);
	icmp_hdr->checksum = htons(checksum((uint16_t*) icmp_hdr, ntohs(icmp_ip_hdr->tot_len) - sizeof(struct iphdr)));

	send_to_link(interface, icmp_packet, sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header) + 8 + sizeof(struct iphdr));
	free(icmp_packet);

}

int forward_packet(char *buf, size_t len, struct data *data){
	struct route_table_entry *rtable = data->rtable_entry;
	int len_rtable = data->len_rtable;
	struct arp_table_entry *arp_table = data->arp_entry;
	int arp_table_len = data->len_arp_table;

	if (check_sum(buf) == 0)
		return -1;
	
	if (check_ttl(buf) == 0) {
		send_icmp_error(data->interface, buf, len, 11, 0);
		return -1;
	} 

	int index = lpm_binary(buf, rtable, len_rtable);
	if (index == -1) {
		send_icmp_error(data->interface, buf, len, 3, 0);
		return -1;
	}
	struct route_table_entry *rtable_entry = rtable + index;

	struct ether_header *eth_hdr = (struct ether_header *) buf;

	int arp_index = check_arp_table(rtable_entry->next_hop, arp_table, arp_table_len);
	if (arp_index == -1) 
		return -1;


	uint8_t my_mac[6];
	get_interface_mac(rtable_entry->interface, my_mac);
	struct arp_table_entry *arp_entry = arp_table + arp_index;

	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_dhost[i] = arp_entry->mac[i];
		eth_hdr->ether_shost[i] = my_mac[i];
	}

	dec_ttl(buf);
	recalc_checksum(buf);

	send_to_link(rtable_entry->interface, buf, len);
	return 0;
}


int compare(const void * a, const void * b) {
    struct route_table_entry *r1 = (struct route_table_entry *) a;
    struct route_table_entry *r2 = (struct route_table_entry *) b;


    if (r1->prefix > r2->prefix) {
        return -1;
    }
    if (r1->prefix < r2->prefix) {
        return 1;
    }


    if (r1->mask > r2->mask) {
        return -1;
    }
    if (r1->mask < r2->mask) {
        return 1;
    }


    return 0;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	struct data data;

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int len_rtable = read_rtable(argv[1], rtable);

	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	int arp_table_len = parse_arp_table("./arp_table.txt", arp_table);

	qsort(rtable, len_rtable, sizeof(struct route_table_entry), compare);

	data.arp_entry = arp_table;
	data.rtable_entry = rtable;
	data.len_rtable = len_rtable;
	data.len_arp_table = arp_table_len;
	data.interface = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		data.interface = interface;

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		int mac_type = get_type_mac(eth_hdr->ether_dhost, interface);

		switch (mac_type) {
			case BROADCAST_MAC:
				if (ntohs(eth_hdr->ether_type) == 0x806) {
					printf("Broadcast ARP\n");
				}
				break;
			case MY_MAC:
				if (ntohs(eth_hdr->ether_type) == 0x800) {
					if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
						if (ip_hdr->protocol == IPPROTO_ICMP) 
							send_icmp_error(interface, buf, len, 0, 0);
					} else {
					forward_packet(buf, len, &data);
					}
				} else {
					printf("Other protocol\n");
				}
				break;
			default:
				break;
		}
		
	}
}

