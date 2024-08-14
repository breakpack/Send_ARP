#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETH_HDRLEN 14
#define ARP_HDRLEN 28
#define ETHER_TYPE_ARP 0x0806

#pragma pack(push, 1)
struct EthArpPacket final {
	ethhdr eth_;
	arphdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

unsigned char* get_mac_address(const char *interface) {
    int fd;
    struct ifreq ifr;
    static unsigned char mac[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Socket");
        return NULL;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return NULL;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(fd);
    return mac;
}

void send_arp_request(pcap_t *handle, const char *iface, const char *target_ip) {
    unsigned char buffer[ETH_HDRLEN + ARP_HDRLEN];
    struct ether_header *eth_hdr = (struct ether_header *) buffer;
    struct ether_arp *arp_hdr = (struct ether_arp *) (buffer + ETH_HDRLEN);

    unsigned char src_mac[6];
    get_mac_address(iface, src_mac);

    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Broadcast

    // 이더넷 헤더 구성
    memcpy(eth_hdr->ether_shost, src_mac, 6);
    memcpy(eth_hdr->ether_dhost, dest_mac, 6);
    eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

    // ARP 헤더 구성
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ea_hdr.ar_hln = 6;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARP_REQUEST);

    memcpy(arp_hdr->arp_sha, src_mac, 6);
    inet_pton(AF_INET, "0.0.0.0", arp_hdr->arp_spa);
    memcpy(arp_hdr->arp_tha, dest_mac, 6);
    inet_pton(AF_INET, target_ip, arp_hdr->arp_tpa);

    if (pcap_sendpacket(handle, buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
    }
}

void capture_arp_reply(pcap_t *handle) {
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue; // Timeout

        struct ether_header *eth_hdr = (struct ether_header *) packet;
        if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
            struct ether_arp *arp_hdr = (struct ether_arp *) (packet + ETH_HDRLEN);

            if (ntohs(arp_hdr->ea_hdr.ar_op) == ARP_REPLY) {
                printf("Sender's MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2],
                    arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);
                break;
            }
        }
    }
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	const char *interface = argv[1];
	const char *target_ip = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(interface, 0, 0, 0, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

	unsigned char *mac;

	mac = get_mac_address(interface);
	send_arp_request(handle, interface, target_ip);
    	capture_arp_reply(handle);

	//EthArpPacket packet;

	//int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	//if (res != 0) {
	//	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	//}

	pcap_close(handle);
}
