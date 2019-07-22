#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define MAC_LEN 6
#define IP_ADDR_LEN 4


/*이더넷 헤더 */
struct sniff_ethernet {
        u_char ether_dhost[MAC_LEN];
        u_char ether_shost[MAC_LEN];
        u_short ether_type;
};

/*IP 헤더*/
struct sniff_ip {
        u_char  ip_vhl;
        u_char  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;
        u_char  ip_p;
        u_short ip_sum;
        u_char ip_src[IP_ADDR_LEN];
        u_char ip_dst[IP_ADDR_LEN];
};

/*TCP 헤더*/

struct sniff_tcp {
        u_short sport;
        u_short dport;
        u_char seq;
        u_char ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
};

        void usage() {
        printf("syntax: pcap_test <interface>\n");
        printf("sample: pcap_test wlan0\n");
    }


void print_mac(const u_char* mac) {
            for(int i=0; i<MAC_LEN ; i++)
              {
                  printf("%02x", mac[i]);
                  if(i != MAC_LEN-1)
                      printf(":");
              }
            }

void print_ip(const u_char* ip) {
        for(int i=0; i<IP_ADDR_LEN;i++)
          {
              printf("%d", ip[i]);
              if(i!=IP_ADDR_LEN-1)
                  printf(".");

        }
}

int main(int argc, char* argv[]) {

    int size_ip;
    int size_tcp;

    if (argc != 2) {
            usage();
            return -1;
        }

        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
            return -1;
        }

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;

            const struct sniff_ethernet *ethernet;
            ethernet = (struct sniff_ethernet *)(packet);

            const struct sniff_ip *ip;
            ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

            u_char IP_HL = ip->ip_vhl & 0x0f;
            u_char IP_V = ip->ip_vhl >>4;

            size_ip = IP_HL*4;

            const struct sniff_tcp *tcp;
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

            size_tcp = TH_OFF(tcp)*4;

            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            char track[] = "컨설팅";
            char name[] = "조현수";
            printf("     [bob8][%s]pcap_test[%s]\n", track, name);



            if (packet[0] == 0x00 && packet[1] == 0x0c && packet[2] == 0x29 && packet[3] == 0x1a && packet[4] == 0xdf && packet[5] == 0xe3) {
                            printf("          RECEIVE");
                        }
                        else printf("          SEND");
            printf("          %u bytes captured\n", header->caplen);

            printf("--------------------------------------------------\n");
            printf("Destination MAC : ");
            print_mac(ethernet->ether_dhost);
            printf("\n");
            printf("Source MAC      : ");
            print_mac(ethernet->ether_shost);
            printf("\n");

            int a = ntohs(ethernet->ether_type);
            switch (a) {
            case 0x0800:
                printf("IPv4\n");
                break;
            case 0x0806:
                printf("ARP\n");
                break;
            case 0x86DD:
                printf("IPv6\n");
                break;
            }

            printf("--------------------------------------------------\n");
            printf("IP Version : %d", IP_V);
            printf("  : IP Header Length : %d \n", IP_HL);

            if ( ip->ip_p == 17) printf("UDP\n");
            else if (ip->ip_p == 6) printf("TCP\n");

            printf("Source IP       : ");
            print_ip(ip->ip_src);
            printf("\n");
            printf("Destination IP  : ");
            print_ip(ip->ip_dst);
            printf("\n");

            printf("--------------------------------------------------\n");
            printf("Source Port : ");
            printf("%d\n", ntohs(tcp->sport));
            printf("Destination port :");
            printf("%d\n", ntohs(tcp->dport));

            printf("--------------------------------------------------\n");

            for (int x = 0 ; x < 500 ; x++){
                printf("%c", packet[SIZE_ETHERNET+size_ip+size_tcp+x]);
                if (packet[SIZE_ETHERNET+size_ip+size_tcp+x]==0x0d && packet[SIZE_ETHERNET+size_ip+size_tcp+x+1]==0x0a && packet[SIZE_ETHERNET+size_ip+size_tcp+x+2]==0x0d && packet[SIZE_ETHERNET+size_ip+size_tcp+x+3]==0x0a)
                    break;
            }

            printf("\n\n\n");
        }

        pcap_close(handle);
        return 0;

}
