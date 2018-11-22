#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "debug.h"
#include "lib.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <net/if_packet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <sys/signalfd.h>


int create_pid_file(struct nd_proxy_t* proxy, const char* app_name)
{
	FILE* fp = NULL;
    pid_t pid;

    snprintf(proxy->pid_file, sizeof(proxy->pid_file), "/var/run/%s.pid", app_name);
    if ( access(proxy->pid_file, R_OK)  < 0 ) {
        info("create pid file %s", app_name);
        fp = fopen(proxy->pid_file, "w");
    } else {
        info("found pid file");
        fp = fopen(proxy->pid_file, "rw");
        fscanf(fp, "%u", &pid);
        char process[32] = "";
        snprintf(process, sizeof(process), "/proc/%u/cmdline", (unsigned)pid);
        if ( access(process, R_OK) == 0 ) {
            error(0, EEXIST, "a %s process is running", app_name);
            return -EEXIST;
        } else {
            fclose(fp);
            fp = fopen(proxy->pid_file, "w");
            info("process logged in pid file is not exist: %s", process);
        }
    }
    if ( !fp ) {
        error(0, errno, "cant create pid file %s", proxy->pid_file);
        return -errno;
    }

    fprintf(fp, "%u", (unsigned)getpid());
    fclose(fp);

	return 0;
}

int parse_args(int argc, char **argv, struct proxy_args_t *args)
{
    memset(args, 0, sizeof(*args));

    int op;
    while( -1 != (op = getopt(argc, argv, "l:w:a:rdDt:f")) ) {
        switch (op) {
        case 'l':
            strcpy(args->lan_ifname,optarg);
            break;
        case 'f':
            args->foreground = true;
            break;
        case 'w':
            strcpy(args->wan_ifname,optarg);
            break;
        case 't':
            args->ra_interval = atoi(optarg);
            break;
        case 'a':
            args->aging_time = atoi(optarg);
            break;
        case 'r':
            args->ra_proxy = true;
            break;
        case 'd':
            args->dad_proxy = true;
            break;
        case 'D':
            args->debug = true;
            break;
        case '?':
            error(1, EINVAL, "%s is not a valid option", argv[optind]);
            return -1;
        default:
            break;
        }
    }

    return 0;
}

int create_timer(struct nd_proxy_t* proxy, unsigned interval)
{
    proxy->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK);
    if( proxy->timerfd < 0 ) {
        error(0, errno, "failed create timer");
        return -errno;
    }

    struct itimerspec its = {
        .it_interval.tv_sec = interval,
        .it_interval.tv_nsec = 0,
        .it_value.tv_sec = interval,
        .it_value.tv_nsec = 0,
    };

    if( 0 > timerfd_settime(proxy->timerfd, TFD_TIMER_ABSTIME, &its, NULL) ) {
        error(0, errno, "failed to set timer");
        return -errno;
    }

    return 0;
}

int create_raw_sock(struct port_t* port)
{
    /* bpf filter to capture all icmpv6 packets */
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 6, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 3, 0, 0x0000003a },
        { 0x15, 0, 3, 0x0000002c },
        { 0x30, 0, 0, 0x00000036 },
        { 0x15, 0, 1, 0x0000003a },
        { 0x6, 0, 0, 0x00000640 },
        { 0x6, 0, 0, 0x00000000 },
    };

    struct sock_fprog sprog = {
        .len    = sizeof(filter)/sizeof(struct sock_filter),
        .filter = filter,
    };

    port->rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if( port->rawsock < 0 ) {
        error(0, errno, "failed to create ICMPV6 socket");
        return -errno;
    }

    if( 0 > setsockopt(port->rawsock, SOL_SOCKET, SO_ATTACH_FILTER, &sprog, sizeof(sprog)) ) {
        error(0, errno, "failed to attach filter for icmpv6");
        return -1;
    }

//    if( 0 > setsockopt(port->rawsock, SOL_SOCKET, SO_BINDTODEVICE, port->ifname, sizeof(port->ifname)) ){
//        error(0, errno, "failed to bind socket to device %s", port->ifname);
//        return -errno;
//    }

    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof(ll));
    ll.sll_family   = PF_PACKET;
    ll.sll_ifindex  = port->ifindex;
    ll.sll_protocol = htons(ETH_P_IPV6);
    ll.sll_pkttype  = 0;

    if(0 > bind(port->rawsock, (struct sockaddr*)&ll, sizeof(ll))) {
        error(0, errno, "failed to bind socket to %s", port->ifname);
        return -1;
    }

    return 0;
}

int create_icmp6_sock(struct port_t* port)
{
    port->icmp6sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if( port->icmp6sock < 0 ) {
        error(0, errno, "failed to create icmp6 socket");
        return -errno;
    }

    if( 0 > setsockopt(port->icmp6sock, SOL_SOCKET, SO_BINDTODEVICE, port->ifname, strlen(port->ifname)) ) {
        error(0, errno, "failed to bind socket to device %s", port->ifname);
        return -errno;
    }

    int loop_on = 0;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_LOOP, &loop_on, sizeof(loop_on)) ) {
        error(0, errno, "failed to disbale multicast loop on %s", port->ifname);
        return -errno;
    }

    //join_multicast(port, "ff02::1");
    //join_multicast(port, "ff02::2");

//    int outgoing_if = port->ifindex;
//    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_IF, &outgoing_if, sizeof(outgoing_if))){
//        error(0, errno, "failed to bind outgoing multicast outgoing if");
//        return -errno;
//    }

    return 0;
}

int get_hw_addr(struct port_t* port)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, port->ifname, sizeof(port->ifname));

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if( fd < 0 ) {
        error(0, errno, "failed to get %s's hwaddr", port->ifname);
    } else if( ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ) {
        error(0, errno, "failed to get %s's hwaddr", port->ifname);
        close(fd);
        return -1;
    }
    close(fd);

    memcpy(&port->ethaddr, ifr.ifr_hwaddr.sa_data, sizeof(port->ethaddr));
    memcpy(&port->mc_ethaddr, ifr.ifr_hwaddr.sa_data, sizeof(port->mc_ethaddr));
    uint8_t* ptr = (uint8_t*)&port->mc_ethaddr;
    ptr[0] = ptr[1] = (uint8_t)0x33;

    return 0;
}

struct ether_header* eth_header(void* buffer, size_t* offset)
{
    *offset = 0;
    return (struct ether_header*)buffer;
}

struct ip6_hdr* ipv6_header(void* buffer, size_t* offset)
{
    *offset += sizeof(struct ether_header);
    return (struct ip6_hdr*)(buffer + sizeof(struct ether_header));
}

struct icmp6_hdr* icmp6_header(void* buffer, size_t* offset)
{
    *offset += sizeof(struct ip6_hdr);
    struct ip6_hdr* hdr = (struct ip6_hdr*)buffer;

    if( hdr->ip6_nxt == IPPROTO_ICMPV6 ) {
        return (struct icmp6_hdr*)(hdr + 1);
    }

    struct ip6_ext* ehdr = (struct ip6_ext*)(hdr + 1);
    *offset += (ehdr->ip6e_len + sizeof(struct ip6_ext));
    while( ehdr->ip6e_nxt != 58 ) {
        ehdr = (struct ip6_ext*)((void*)ehdr + ehdr->ip6e_len + sizeof(struct ip6_ext));
        *offset += (ehdr->ip6e_len + sizeof(struct ip6_ext));
    }

    return (struct icmp6_hdr*)((void*)ehdr + ehdr->ip6e_len + sizeof(struct ip6_ext));
}

ssize_t recv_raw_pkt(struct port_t* port, void* buf, size_t len)
{
    ssize_t ret;

    do {
        ret = recvfrom(port->rawsock, buf, len, 0, NULL, NULL);
    } while( ret < 0 && errno == EINTR);

    return ret;
}

ssize_t send_raw_pkt(struct port_t* port, size_t iovec_count, ...)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct sockaddr_ll sll;
    struct iovec iovec[iovec_count];
    va_list val;

    va_start(val, iovec_count);
    for( size_t i = 0 ; i < iovec_count ; i ++ ) {
        iovec[i].iov_base   = va_arg(val, void*);
        iovec[i].iov_len    = va_arg(val, size_t);
    }
    va_end(val);

    sll.sll_family  = PF_PACKET;
    sll.sll_ifindex = port->ifindex;

    memset(&cbuf, 0, sizeof(cbuf));
    msghdr.msg_iov          = iovec;
    msghdr.msg_iovlen       = iovec_count;
    msghdr.msg_control      = NULL;
    msghdr.msg_controllen   = 0;
    msghdr.msg_flags        = 0;
    msghdr.msg_name         = &sll;
    msghdr.msg_namelen      = sizeof(sll);

    do {
        ret = sendmsg(port->rawsock, &msghdr, 0);
    } while( ret < 0 && errno == EINTR);

    return ret;
}

ssize_t send_icmp6_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct sockaddr_in6 si6;
    struct iovec iovec[iovec_count];
    va_list val;

    va_start(val, iovec_count);
    for( size_t i = 0 ; i < iovec_count ; i ++ ) {
        iovec[i].iov_base   = va_arg(val, void*);
        iovec[i].iov_len    = va_arg(val, size_t);
    }
    va_end(val);

    memset(&si6, 0, sizeof(si6));
    si6.sin6_family = PF_INET6;
    memcpy(&si6.sin6_addr, to, sizeof(si6.sin6_addr));

    memset(&cbuf, 0, sizeof(cbuf));
    msghdr.msg_iov          = iovec;
    msghdr.msg_iovlen       = iovec_count;
    msghdr.msg_control      = NULL;
    msghdr.msg_controllen   = 0;
    msghdr.msg_flags        = 0;
    msghdr.msg_name         = &si6;
    msghdr.msg_namelen      = sizeof(si6);

    do {
        ret = sendmsg(port->icmp6sock, &msghdr, 0);
    } while( ret < 0 && errno == EINTR);

    return ret;
}


uint32_t checksum_partial(void* data, size_t len, uint32_t sum)
{
    const uint16_t* p16 = (uint16_t*)data;

    while(len >= sizeof(uint16_t)){
        sum += *p16 ++;
        len -= sizeof(uint16_t);
    }

    const uint8_t* p8 = (uint8_t*)p16;
    if( len > 0 ){
        sum += ((*p8) << 8) ;
    }

    return sum;
}

uint16_t checksum_fold(uint32_t sum)
{
    while(sum & 0xffff0000U){
        sum = (sum >> 16) + (sum&0xffffU);
    }

    return ~sum;
}

int create_signalfd(struct nd_proxy_t* proxy, unsigned sig_cnt, ...)
{
    sigset_t sigset;
    sigemptyset(&sigset);

    va_list val;
    va_start(val, sig_cnt);
    for( unsigned i = 0 ; i < sig_cnt ; i ++ ){
        sigaddset(&sigset, va_arg(val, int));
    }

    sigprocmask(SIG_BLOCK, &sigset, NULL);
    proxy->sigfd = signalfd(-1, &sigset, SFD_CLOEXEC);
    if( proxy->sigfd < 0 ){
        error(0, errno, "failed to create signalfd");
        return -errno;
    }

    return 0;
}

int send_signal(char* process_name, int sig, int val)
{
    char pid_file[FILENAME_MAX] = "";

    snprintf(pid_file, sizeof(pid_file), "/var/run/%s.pid", process_name);
    if( access(pid_file, R_OK) < 0 ){
        error(0, errno, "failed to find process %s's pidfile %s", process_name, pid_file);
        return -errno;
    }

    unsigned pid;
    FILE* fp = fopen(pid_file, "r");
    fscanf(fp, "%u", &pid);
    fclose(fp);


    union sigval sval;
    sval.sival_int = val;
    if( 0 > sigqueue(pid, sig, sval) ){
        error(0, errno, "failed to send signal %u with val %d to %s", sig, val, process_name);
        return -errno;
    }

    return 0;
}
