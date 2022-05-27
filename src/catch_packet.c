#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int id = 0;
typedef struct _argument {
    pcap_t *handle;
    int time_len;
}argument;

void *thread_clock(void *argv) {
    pcap_t *handle = ((argument*)argv) -> handle;
    int time_len = ((argument*)argv) -> time_len;
    sleep(time_len);
    pcap_breakloop(handle);
}
void get_packet(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dump(dumpfile, pkthdr, packet);
    id ++;
}

int main() {
    pcap_t *handle;
    char *device;
    bpf_u_int32 mask, net;
    char err_inf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_expsn[] = "ip";
    pcap_dumper_t *file;
    char file_name[] = "traffic.data";
    int flag, cycle;

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
    
    handle = pcap_open_live(device, BUFSIZ, 1, 0, err_inf);
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

    pthread_t pt_clock;
    argument args;
    args.handle = handle;
    printf("请输入抓取时长(s）：");
    scanf("%d", &cycle);
    args.time_len = cycle;
    flag = pthread_create(&pt_clock, NULL, thread_clock, &args);
    if(flag != 0) {
        printf("pthread_create(): Error!\n");
        return 1;
    }

    pcap_loop(handle, -1, get_packet, (u_char*) file);
    
    printf("抓取结束\n");
    pcap_dump_close(file);
    pcap_close(handle);
    return 0;
}
