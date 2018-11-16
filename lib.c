#define _GNU_SOURCE

#include "lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <net/if_packet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>


int parse_args(int argc, char **argv, struct proxy_args_t *args)
{
    memset(args, 0, sizeof(*args));

    int op;
    while( -1 != (op = getopt(argc, argv, "l:w:rdDt:")) ){
        switch (op) {
        case 'l':
            strcpy(args->lan_ifname,optarg);
            break;
        case 'w':
            strcpy(args->wan_ifname,optarg);
            break;
        case 't':
            args->ra_interval = atoi(optarg);
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
}

int create_timer(struct port_t* port, unsigned interval)
{
    port->timerfd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC|TFD_NONBLOCK);
    if( port->timerfd < 0 ){
        error(0, errno, "failed create timer for %s", port->ifname);
        return -errno;
    }

    struct itimerspec its = {
        .it_interval.tv_sec = interval,
        .it_interval.tv_nsec = 0,
        .it_value.tv_sec = interval,
        .it_value.tv_nsec = 0,
    };

    if( 0 > timerfd_settime(port->timerfd, TFD_TIMER_ABSTIME, &its, NULL) ){
        close(port->timerfd);
        error(0, errno, "failed to set timer for %s", port->ifname);
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
    if( port->rawsock < 0 ){
        error(0, errno, "failed to create ICMPV6 socket");
        return -errno;
    }

    if( 0 > setsockopt(port->rawsock, SOL_SOCKET, SO_ATTACH_FILTER, &sprog, sizeof(sprog)) ){
        error(0, errno, "failed to attach filter for icmpv6");
        return -1;
    }

    if( 0 > setsockopt(port->rawsock, SOL_SOCKET, SO_BINDTODEVICE, port->ifname, sizeof(port->ifname)) ){
        error(0, errno, "failed to bind socket to device %s", port->ifname);
        close(port->rawsock);
        return -errno;
    }

    return 0;
}

int gethwaddr(struct port_t* port)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, port->ifname, sizeof(port->ifname));

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if( fd < 0 ){
        error(0, errno, "failed to get %s's hwaddr", port->ifname);
    }else if( ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ){
        error(0, errno, "failed to get %s's hwaddr", port->ifname);
        close(fd);
        return -1;
    }
    close(fd);

    memcpy(&port->mac, ifr.ifr_hwaddr.sa_data, sizeof(port->mac));

    return 0;
}

struct ip6_hdr* ipv6_header(void* buffer, size_t* offset)
{
    *offset += sizeof(struct ether_header);
    return (struct ip6_hdr*)(buffer + sizeof(struct ether_header));
}

struct icmp6_hdr* icmp6_header(void* buffer, size_t* offset)
{
    *offset = sizeof(struct ip6_hdr);
    struct ip6_hdr* hdr = (struct ip6_hdr*)buffer;

    if( hdr->ip6_nxt == IPPROTO_ICMPV6 ){
        return (struct hdr*)(hdr + 1);
    }

    struct ip6_ext* ehdr = (struct ip6_hdr*)(hdr + 1);
    *offset += (ehdr->ip6e_len + sizeof(struct ip6_ext));
    while( ehdr->ip6e_nxt != 58 ){
        ehdr = (struct ip6_ext*)((void*)ehdr + ehdr->ip6e_len + sizeof(struct ip6_ext));
        *offset += (ehdr->ip6e_len + sizeof(struct ip6_ext));
    }

    return (struct icmp6_hdr*)((void*)ehdr + ehdr->ip6e_len + sizeof(struct ip6_ext));
}

ssize_t recv_pkt(struct port_t* port, void* buf, size_t len)
{
    ssize_t ret;

    do{
        ret = recvfrom(port->rawsock, buf, len, 0, NULL, NULL);
    }while( ret < 0 && errno == EINTR);

    return ret;
}

ssize_t send_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct in6_pktinfo) + sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct sockaddr_in6 si6;
    struct iovec iovec[iovec_count];
    va_list val;

    va_start(val, iovec_count);
    for( size_t i = 0 ; i < iovec_count ; i ++ ){
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

    do{
        ret = sendmsg(port->rawsock, &msghdr, 0);
    }while( ret < 0 && errno == EINTR);

    return ret;
}

