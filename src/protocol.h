#define PCAP_HEADER_LEN 24
#define PACKET_HEADER_LEN 16

/* ============= Ethernet ============ */
#define ETHER_LEN 14
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2

#define ETHER_DEST_OFFSET (0 * ETHER_ADDR_LEN)
#define ETHER_SRC_OFFSET (1 * ETHER_ADDR_LEN)
#define ETHER_TYPE_OFFSET (2 * ETHER_ADDR_LEN)

typedef struct _ether_header {
    uint8_t host_dest[ETHER_ADDR_LEN];
    uint8_t host_src[ETHER_ADDR_LEN];
    uint16_t type;
    #define ETHER_TYPE_MIN 0x0600
    #define ETHER_TYPE_IP 0x0800
    #define ETHER_TYPE_ARP 0x0806
    #define ETHER_TYPE_8021Q 0x8100
    #define ETHER_TYPE_BRCM 0x886c
    #define ETHER_TYPE_802_1X 0x888e
    #define ETHER_TYPE_802_1X_PREAUTH 0x88c7
}ether_header;

/*============== IP ================*/
#define IP_LEN_MIN 20
#define IPTOSBUFFERS 12
/* IPv4 header */
typedef struct _ip_header {
    uint32_t ver;// Version
    uint32_t hl;// Internet header length
    uint8_t tos; // Type of service
    uint16_t tlen; // Total length
    uint16_t ident; // Identification
    uint16_t offset; // Fragment offset
    uint8_t ttl; // Time to live
    uint8_t proto; // Protocol
    #define IP_ICMP 1
    #define IP_IGMP 2
    #define IP_TCP 6
    #define IP_UDP 17
    #define IP_IGRP 88
    #define IP_OSPF 89
    uint16_t crc; // Header checksum
    uint32_t saddr; // Source address
    uint32_t daddr; // Destination address
}ip_header;

/*=============== TCP ================*/
#define TCP_LEN_MIN 20

typedef struct _tcp_header {
    uint16_t th_sport; // source port
    uint16_t th_dport; // destination port
    uint32_t th_seq; // sequence number field
    uint32_t th_ack; // acknowledgement number field
    uint8_t th_len:4; // header length
    uint8_t th_x2:4; // unused
    uint8_t th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
}tcp_header; 

/*================ UDP ==================*/
#define UDP_LEN 8

typedef struct _udp_header {
    uint16_t uh_sport; // Source port
    uint16_t uh_dport; // Destination port
    uint16_t uh_len; // Datagram length
    uint16_t uh_sum; // Checksum
}udp_header;