#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

struct ethernet_header {
    u_char ether_dhost[6]; /* Destination host address */
    u_char ether_shost[6]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct ipv4_header{
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short flags;
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    u_char source_ip[4];
    u_char destination_ip[4];
};

struct tcp_header{
    u_char source_port[2];
    u_char dest_port[2];
    u_char seq_num[4];
    u_char ack_num[4];
    u_short flag;
    u_char window_size[2];
    u_char check_sum[2];
    u_short urgent_pointer;
    u_char option[12];
};

void printMac(const u_char* data)
{
    printf("Mac Address : %02X:%02X:%02X:%02X:%02X:%02X\n",
           data[0],data[1],data[2],data[3],data[4],data[5]);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
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
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("^^^^^^^^^^^^^^^^^^^^^^\n");
    printf("%u bytes captured\n", header->caplen);

    const struct ethernet_header *ethernet;
    ethernet = (struct ethernet_header*)(packet);
    printf("Destination ");
    printMac(ethernet->ether_dhost);
    printf("Source ");
    printMac(ethernet->ether_shost);

    if(htons(ethernet->ether_type) == 0x86dd)
    {
        printf("IPv6\n");
    }

    if(htons(ethernet->ether_type) == 0x0800)
    {
        const struct ipv4_header *ip;
        ip = (struct ipv4_header*)(packet + sizeof(struct ethernet_header));
        printf("IPv4\n");
        printf("Source IP: %d.%d.%d.%d\n",ip->source_ip[0],ip->source_ip[1],ip->source_ip[2],ip->source_ip[3]);
        printf("Destination IP: %d.%d.%d.%d\n",ip->destination_ip[0],ip->destination_ip[1],ip->destination_ip[2],ip->destination_ip[3]);

        if(ip->ip_p==0x11)  // UDP
        {
            printf("UDP\n");
        }
        if(ip->ip_p==0x06)  // TCP
        {
            printf("TCP\n");
            const struct tcp_header *tcp;
            tcp = (struct tcp_header*)(packet + sizeof(struct ethernet_header) + sizeof(struct ipv4_header));

            printf("Source-Port : %d\n"
                   "Destination-Port : %d\n",
                   tcp->source_port[0]<<8|tcp->source_port[1],
                   tcp->dest_port[0]<<8|tcp->dest_port[1]);
            printf("Tcp_data : %d\n",int(header->caplen)-(sizeof(ethernet_header)+sizeof(ipv4_header))-sizeof(tcp_header));


            printf("Data: ");
            for(int i=0;i<10;i++)
            {
                printf(" %02X ", packet[i+sizeof(ethernet_header)+sizeof(ipv4_header)+sizeof(tcp_header)]);
            }
            printf("\n");

            printf("Packet_size: %d \n",int (header->caplen));
            printf("ethernet+ipv4_header_size: %d \n",sizeof(ethernet_header)+sizeof(ipv4_header));
            printf("tcp_header_size: %d \n",sizeof(tcp_header));


        }


    }


    /* source host add.
     *  print " IAM ip v4
     * if == 8bbb
     *  print " iam ip v6
     * print source ip
     * print des. ip
     * offset = start point
     * print TCP data size
     *
     */

    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
