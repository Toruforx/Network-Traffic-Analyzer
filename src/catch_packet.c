#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void callback(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dump(dumpfile, pkthdr, packet);
    static int id = 0;
    ++ id;
    printf("The %d packet length: %d\n", id, pkthdr->len);
}

int main(int argc, char const *argv[]) {
    pcap_t *handle;
    char *device;
    bpf_u_int32 mask, net;
    char err_inf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_expsn[] = "ip";
    pcap_dumper_t *file;
    char file_name[] = "traffic.data";
    int flag, to_ms;

    device = pcap_lookupdev(err_inf);
    if(device == NULL) {
        printf("pcap_lookupdev: %s\n", err_inf);
        return 1;
    }
    printf("device: %s\n", device);

    flag = pcap_lookupnet(device, &net, &mask, err_inf);
    if(flag == -1) {
        printf("pcap_lookupnet: %s\n", err_inf);
        return 1;
    }
    
    printf("请输入抓取时长(s）：");
    scanf("%d", &to_ms);
    to_ms *= 1000; // 秒数转换为毫秒数
    
    handle = pcap_open_live(device, 65535, 1, to_ms, err_inf);
    if(handle == NULL) {
        printf("pcap_open_live: %s\n", err_inf);
        return 1;
    }

    flag = pcap_compile(handle, &filter, filter_expsn, 1, mask);
    if(flag == -1) {
        printf("pcap_compile: Error\n");
        return 1;
    }

    flag = pcap_setfilter(handle, &filter);
    if(flag == -1) {
        printf("pcap_setfilter: Error\n");
        return 1;
    }

    file = pcap_dump_open(handle, file_name);
    if(file == NULL) {
        printf("pcap_dump_open: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_dispatch(handle, 0, callback, (u_char*) file);
    printf("Crawl succeeded\n");
    pcap_dump_close(file);
    pcap_close(handle);
    return 0;
}
