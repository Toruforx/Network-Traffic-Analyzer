#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "protocol.h"
#define HASH_TABLE_SIZE 0xffff

typedef struct _netset {
    u_int sip;
    u_int dip;
    u_short sport;
    u_short dport;
    u_char protocol;
}netset;

typedef struct _net_link_node {
    netset set;
    int up_size;
    int down_size;
    int up_num;
    int down_num;
    u_char state;
    #define CLOSED 0x00

    #define SYN_SENT 0x01
    #define SYN_RECV 0x02
    #define ESTAB 0x03

    #define FIN_SENTC 0x04
    #define FIN_RECVS 0x05
    #define ACK_RECV 0x06
    #define FIN_SENTS 0x07
    #define FIN_RECVC 0x08 
    #define UNDEFINED 0xff
    struct _net_link_node *next;
}net_link_node, *net_link_p;

typedef struct _net_link_header {
    int con;
    int up_size;
    int down_size;
    int up_num;
    int down_num;
    net_link_p link;
}net_link_header;

char *long_to_time(long time) {
    time_t t;
    struct tm *p;
    static char s[100];
    t = time;
    p = localtime(&t);
    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
    return s;
}

static char *iptos(bpf_u_int32 in) {
    static char output[IPTOSBUFFERS][16];
    static short loc;
    u_char *p;
    p = (u_char *)&in;
    if(loc + 1 == IPTOSBUFFERS) {
        loc = 0;
    }
    else {
        loc ++;
    }
    sprintf(output[loc], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[loc];
}

/*
 * 三个链表
 * 一个哈希链表，保存处于连接状态的数据包
 * 两个链表分别保存tcp和udp的流量
 */
net_link_header *flow_TCP, *flow_UDP;
net_link_p hash_table[HASH_TABLE_SIZE];

void init_flow_link(net_link_header *head) {
    head -> con = 0;
    head -> up_size = 0;
    head -> down_size = 0;
    head -> up_num = 0;
    head -> down_num = 0;
    head -> link = NULL;
}

void add_flow_link(net_link_header *head, const net_link_node *node) {
    net_link_node *nnode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(nnode, node, sizeof(net_link_node));
    head -> con ++;
    head -> up_size += nnode -> up_size;
    head -> down_size += nnode -> down_size;
    head -> up_num += nnode -> up_num;
    head -> down_num += nnode -> down_num;
    nnode -> next = head -> link;
    head -> link = nnode;
}

void clear_flow_link(net_link_header *head) {
    if(head -> con == 0 || head -> link == NULL) {
        return;
    }
    net_link_node *p1 = NULL, *p2 = NULL;
    p1 = head -> link;
    p2 = p1 -> next;
    while(p2 != NULL) {
        free(p1);
        p1 = p2;
        p2 = p2 -> next;
    }
    free(p1);
    init_flow_link(head);
}

void analyse_TCP(FILE *file_TCP) {
    fprintf(file_TCP, "TCP连接个数：\t%d\n", flow_TCP -> con);
    fprintf(file_TCP, "TCP数据包个数：\t%d\n", flow_TCP -> up_num + flow_TCP -> down_num);
    fprintf(file_TCP, "TCP数据总流量：\t%d bytes\n", flow_TCP -> up_size + flow_TCP -> down_size);
    fprintf(file_TCP, "TCP数据上传量：\t%d bytes\n", flow_TCP -> up_size);
    fprintf(file_TCP, "TCP数据下载量：\t%d bytes\n", flow_TCP -> down_size);
    fprintf(file_TCP, "--------------------------------------------------------\n");
    net_link_node *p = NULL;
    p = flow_TCP -> link;
    while(p != NULL) {
        fprintf(file_TCP, "%s : %u\t", iptos(p -> set.sip), p -> set.sport);
        fprintf(file_TCP, "==>\t%s : %u\t", iptos(p -> set.dip), p -> set.dport);
        fprintf(file_TCP, "上传包数量：%d\t", p -> up_num);
        fprintf(file_TCP, "下载包数量：%d\t", p -> down_num);
        fprintf(file_TCP, "上传量：%d bytes\t", p -> up_size);
        fprintf(file_TCP, "下载量：%d bytes\t", p -> down_size);
        fprintf(file_TCP, "\n");
        p = p -> next;
    }
    clear_flow_link(flow_TCP);
}

void analyse_UDP(FILE *file_UDP)
{
    fprintf(file_UDP, "UDP数据包个数：\t%d\n", flow_UDP -> up_num + flow_UDP -> down_num);
    fprintf(file_UDP, "UDP数据流量：\t%d bytes\n", flow_UDP -> up_size + flow_UDP -> down_size);
    clear_flow_link(flow_UDP);
}

u_short get_hash(const netset *set) {
    u_int sip = set -> sip;
    u_int dip = set -> dip;
    u_int sport = set -> sport;
    u_int dport = set -> dport;
    u_int res = (sip ^ dip) ^(u_int)(sport * dport);
    u_short hash = (u_short)((res & 0x00ff) ^ (res >> 16));
    return hash;
}

void add_hash_table(u_short hash, const net_link_node *node, u_char flags) {
    net_link_node *nnode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(nnode, node, sizeof(net_link_node));
    if(hash_table[hash] == NULL) {
        hash_table[hash] = nnode;
        return;
    }
    net_link_node *p = NULL, *pb = NULL;
    p = hash_table[hash];
    int flag_up = 0, flag_down = 0;
    while(p != NULL) {
        if(p -> set.sip == nnode -> set.sip && p -> set.dip == nnode -> set.dip && p -> set.sport == nnode -> set.sport && p -> set.dport == nnode -> set.dport) {
            flag_up = 1;
        }
        else {
            flag_up = 0;
        }
        if(p -> set.sip == nnode -> set.dip && p -> set.dip == nnode -> set.sip && p -> set.sport == nnode -> set.dport && p -> set.dport == nnode -> set.sport) {
            flag_down = 1;
        }
        else {
            flag_down = 0;
        }
        if(flag_up) {
            p -> up_size += nnode -> up_size;
            p -> up_num ++;
            if(p -> state == ESTAB && (flags & TH_FIN)) {
                p -> state = FIN_SENTC;
            }
            else if(p -> state == FIN_RECVC && (flags & TH_ACK)) {
                p -> state = CLOSED;
                if(pb == NULL) {
                    hash_table[hash] = NULL;
                }
                else {
                    pb -> next = p -> next;
                }
                add_flow_link(flow_TCP, p);
                free(p);
            }
            else if(p -> state == FIN_RECVS && (flags & TH_FIN)) {
                p -> state = FIN_SENTS;
            }
            free(nnode);
            break;
        }
        else if(flag_down) {
            p -> down_size += nnode -> up_size;
            p -> down_num ++;
            if(p -> state == ESTAB && (flags & TH_FIN)) {
                p -> state =FIN_RECVS;
            }
            else if(p -> state == FIN_SENTS && (flags & TH_ACK)) {
                p -> state = CLOSED;
                if(pb == NULL) {
                    hash_table[hash] = NULL;
                }
                else {
                    pb -> next = p -> next;
                }
                add_flow_link(flow_TCP, p);
                free(p);
            }
            else if(p -> state == FIN_SENTC && (flags & TH_ACK)) {
                p -> state = ACK_RECV;
            }
            else if(p -> state == ACK_RECV && (flags & TH_FIN)) {
                p -> state = FIN_RECVC;
            }
            free(nnode);
            break;
        }
        pb = p;
        p = p -> next;
    }
    if(p == NULL) {
        pb -> next = nnode;
    }
}

void clear_hash_table() {
    net_link_node *p1 = NULL, *p2 = NULL;
    for(int i = 0; i < HASH_TABLE_SIZE; i ++) {
        if(hash_table[i] == NULL) {
            continue;
        }
        p1 = hash_table[i];
        p2 = p1 -> next;
        while(p2 != NULL) {
            add_flow_link(flow_TCP, p1);
            free(p1);
            p1 = p2;
            p2 = p2 -> next;
        }
        add_flow_link(flow_TCP, p1);
        free(p1);
        hash_table[i] = NULL;
    }
}

void data_analysis(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int id = 1;
    ether_header *ehdr = (ether_header *)packet; // 得到以太网字头
    ip_header *iphdr = (ip_header *)(packet + sizeof(struct ether_header)); // 得到 IP 报头
    tcp_header *tcphdr = (tcp_header *)(packet + sizeof(struct ether_header) + sizeof(struct ip)); // 得到 TCP 包头
    udp_header *udphdr = (udp_header *)(packet + sizeof(struct ether_header) + sizeof(struct ip)); // 得到 UDP 包头
    netset *netst = (netset *)malloc(sizeof(netset));
    net_link_node *lnode = (net_link_node *)malloc(sizeof(net_link_node));

    int *cycle = (int *)userarg;
    static long work_start = 0;
    static long work_end = 0;
    static long work_now = 0;

    char *file_o = "result.data";
    FILE *file;
    file = fopen(file_o, "a+");

    u_short ip_len_real = 0;
    u_short ip_len_total = 0;
    u_short tcp_len_real = 0;
    u_short data_len = 0;

    
    if(id == 1) {
        work_start = pkthdr -> ts.tv_sec;
        work_end = work_start;
        file = fopen(file_o, "w");
        fclose(file);
        file = fopen(file_o, "a+");
        fprintf(file, "数据文件：%s\n", "traffic.data");
        fprintf(file, "分析周期：%d s\n", *cycle);
    }
    work_now = pkthdr -> ts.tv_sec;
    if(work_now - work_end >= *cycle) {
        fprintf(file, "\n>>>>> 时间段：%s", long_to_time(work_end));
        fprintf(file, " --> %s\n", long_to_time(work_end + *cycle));

        fprintf(file, "--------------------------------------------------------\n");
        clear_hash_table();
        analyse_UDP(file);
        init_flow_link(flow_UDP);

        fprintf(file, "--------------------------------------------------------\n");
        analyse_TCP(file);
        init_flow_link(flow_TCP);
        fprintf(file, "\n");
        work_end = work_now;
    }
    if(ntohs(ehdr -> type) == ETHERTYPE_IP) {
        ip_len_real = (iphdr -> ver_ihl & 0x0f) * 4;
        ip_len_total = ntohs(iphdr -> tlen);
        if(iphdr -> proto == IPPROTO_TCP || iphdr -> proto == IPPROTO_UDP) {
            netst -> sip = iphdr -> saddr;
            netst -> dip = iphdr -> daddr;
            netst -> protocol = iphdr -> proto;
            if(iphdr -> proto == IPPROTO_TCP) {
                tcp_len_real = (((tcphdr -> th_len)>>4) & 0x0f) * 4;
                data_len = ip_len_total - ip_len_real - tcp_len_real;
                netst -> sport = ntohs(tcphdr -> th_sport);
                netst -> dport = ntohs(tcphdr -> th_dport);
            }
            else if(iphdr -> proto == IPPROTO_UDP) {
                data_len = ntohs(udphdr -> uh_len) - UDP_LEN;
                netst -> sport = ntohs(udphdr -> uh_sport);
                netst -> dport = ntohs(udphdr -> uh_dport);
            }
            lnode -> set = *netst;
            lnode -> up_size = data_len;
            lnode -> down_size = 0;
            lnode -> up_num = 1;
            lnode -> down_num = 0;
            lnode -> state = ESTAB;
            lnode -> next = NULL;
            if(iphdr -> proto == IPPROTO_TCP) {
                add_hash_table(get_hash(netst), lnode, tcphdr -> th_flags);
            }
            else if(iphdr -> proto == IPPROTO_UDP) {
                add_flow_link(flow_UDP, lnode);
            }
        }
    }
    fprintf(file, "\n**************************开始**************************\n");
    fprintf(file, "ID：%d\n", id ++);
    fprintf(file, "数据包长度：%d\n", pkthdr -> len);
    fprintf(file, "实际捕获包长度：%d\n", pkthdr -> caplen);
    fprintf(file, "时间：%s", ctime((const time_t *)&pkthdr -> ts.tv_sec));

    fprintf(file, "-----------------数据链路层 解析以太网帧-----------------\n");
    u_char *ptr;
    ptr = ehdr -> host_src;
    fprintf(file, "源MAC地址：");
    fprintf(file, "%x", ptr[0]);
    for(int i = 1; i < ETHER_ADDR_LEN; i ++) {
        fprintf(file, ":%x", ptr[i]);
    }
    fprintf(file, "\n");

    ptr = ehdr -> host_dest;
    fprintf(file, "目的MAC地址：");
    fprintf(file, "%x", ptr[0]);
    for(int i = 1; i < ETHER_ADDR_LEN; i ++) {
        fprintf(file, ":%x", ptr[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "以太网帧类型：%x\n", ntohs(ehdr -> type));
    fprintf(file, "-----------------数据链路层 解析 IP 报头-----------------\n");
    fprintf(file, "版本号：%d\n", iphdr -> ver_ihl >> 4);
    fprintf(file, "首部长度：%d\n", iphdr -> ver_ihl & 0x0f);
    fprintf(file, "服务类型：%hhu\n", iphdr -> tos);
    fprintf(file, "报文总长度：%d\n", ntohs(iphdr -> tlen));
    fprintf(file, "标识：%d\n", ntohs(iphdr -> ident));
    fprintf(file, "片偏移：%d\n", ntohs(iphdr -> flags_off & 0x1fff));
    fprintf(file, "生存时间：%hhu\n", iphdr -> ttl);
    fprintf(file, "协议类型：%hhu\n", iphdr -> proto);
    fprintf(file, "首部校验和：%d\n", ntohs(iphdr -> crc));
    fprintf(file, "源地址：%s\n", iptos(iphdr -> saddr));
    fprintf(file, "目的地址：%s\n", iptos(iphdr -> daddr));

    if(iphdr -> proto == IPPROTO_TCP) {    
        fprintf(file, "-----------------数据链路层 解析 TCP 报头-----------------\n");
        fprintf(file, "目的端口：%d\n", ntohs(tcphdr -> th_dport));
        fprintf(file, "源端口：%d\n", ntohs(tcphdr -> th_sport));
        fprintf(file, "序列号：%u\n", tcphdr -> th_seq);
        fprintf(file, "确认号：%u\n", tcphdr -> th_ack);
        fprintf(file, "报头长度：%d\n", tcphdr -> th_len);
        fprintf(file, "保留：%d\n", tcphdr -> th_x2);
        fprintf(file, "标志：%hhu\n", tcphdr -> th_flags);
        fprintf(file, "窗口：%d\n", ntohs(tcphdr -> th_win));
        fprintf(file, "校验和：%d\n", ntohs(tcphdr -> th_sum));
        fprintf(file, "紧急：%d\n", ntohs(tcphdr -> th_urp));    
    }else if(iphdr -> proto == IPPROTO_UDP) {
        
        fprintf(file, "----------------数据链路层 解析 UDP 报头-----------------\n");
        fprintf(file, "源端口：%d\n", ntohs(udphdr -> uh_sport));
        fprintf(file, "目的端口：%d\n", ntohs(udphdr -> uh_dport));
        fprintf(file, "用户数据包长度：%d\n", ntohs(udphdr -> uh_len));
        fprintf(file, "校验和：%d\n", ntohs(udphdr -> uh_sum));
        
    }
    fprintf(file, "**************************结束**************************\n");
    free(netst);
    free(lnode);
    fclose(file);
}

int main(int argc, char **argv) {
    char *file_in = "traffic.data";
    FILE *file_i = fopen(file_in, "r");
    printf("载入文件...\n");
    int cycle;
    printf("输入分析周期(s)：");
    scanf("%d", &cycle);

    pcap_t *handle;
    char err_inf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(file_in, err_inf);
    printf("开始分析\n");

    flow_TCP = (net_link_header *)malloc(sizeof(net_link_header));
    flow_UDP = (net_link_header *)malloc(sizeof(net_link_header));
    init_flow_link(flow_TCP);
    init_flow_link(flow_UDP);
    
    pcap_loop(handle, -1, data_analysis, &cycle);
    printf("分析结束\n");
    free(flow_TCP);
    free(flow_UDP);

    return 0;
}