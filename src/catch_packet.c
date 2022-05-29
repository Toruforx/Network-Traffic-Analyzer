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
typedef struct _argument
{
    pcap_t *handle;
    int time_len;
} argument;

void *thread_clock(void *argv)
{
    pcap_t *handle = ((argument *)argv)->handle;
    int time_len = ((argument *)argv)->time_len;
    sleep(time_len);
    pcap_breakloop(handle);
}
void get_packet(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    pcap_dump(dumpfile, pkthdr, packet);
    id++;
}

void catch_pkt(char *file_out, char *filter_expsn, int cycle)
{
    pcap_t *handle;
    char *device;
    bpf_u_int32 mask, net;
    char err_inf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    pcap_dumper_t *file;
    int flag;

    device = pcap_lookupdev(err_inf);
    if (device == NULL)
    {
        printf("pcap_lookupdev: %s\n", err_inf);
        return;
    }
    printf("device: %s\n", device);

    flag = pcap_lookupnet(device, &net, &mask, err_inf);
    if (flag == -1)
    {
        printf("pcap_lookupnet: %s\n", err_inf);
        return;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 0, err_inf);
    if (handle == NULL)
    {
        printf("pcap_open_live: %s\n", err_inf);
        return;
    }

    flag = pcap_compile(handle, &filter, filter_expsn, 1, mask);
    if (flag == -1)
    {
        printf("pcap_compile: Error\n");
        return;
    }

    flag = pcap_setfilter(handle, &filter);
    if (flag == -1)
    {
        printf("pcap_setfilter: Error\n");
        return;
    }

    file = pcap_dump_open(handle, file_out);
    if (file == NULL)
    {
        printf("pcap_dump_open: %s\n", pcap_geterr(handle));
        return;
    }

    pthread_t pt_clock;
    argument args;
    args.handle = handle;
    args.time_len = cycle;
    flag = pthread_create(&pt_clock, NULL, thread_clock, &args);
    if (flag != 0)
    {
        printf("pthread_create(): Error!\n");
        return;
    }

    pcap_loop(handle, -1, get_packet, (u_char *)file);

    printf("Catch success\n");
    pcap_dump_close(file);
    pcap_close(handle);
    return;
}

#if 1
int main(int argc, void *argv[])
{
    char *option, *file_out, *filter;
    int time;

    if (argc != 5)
    {
        printf("Usage: catch <--catch> <file_out> <filter> <time>\n");
        return 0;
    }
    else
    {
        option = argv[1];
        file_out = argv[2];
        filter = argv[3];
        time = strtol(argv[4], NULL, 10);
        if (strcmp(option, "--catch") == 0)
        {
            catch_pkt(file_out, filter, time);
        }
        else
        {
            printf("Usage: catch <--catch> <file_out> <filter> <time>\n");
            return 0;
        }
    }

    return 0;
}
#endif
