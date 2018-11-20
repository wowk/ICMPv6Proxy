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
#include <ifaddrs.h>
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


int parse_args(int argc, char **argv, struct proxy_args_t *args)
{
    memset(args, 0, sizeof(*args));

    int op;
    while( -1 != (op = getopt(argc, argv, "l:w:rdDt:")) ) {
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

int create_timer(struct icmp6_proxy_t* proxy, unsigned interval)
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
    ll.sll_pkttype  = PACKET_HOST|PACKET_MULTICAST|PACKET_OTHERHOST|PACKET_MR_PROMISC;

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

    struct ipv6_mreq mreq;
    mreq.ipv6mr_interface = port->ifindex;
    inet_pton(PF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr);
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ) {
        error(0, errno, "failed to add multicast group ff02::1 on %s", port->ifname);
        return -errno;
    }

    mreq.ipv6mr_interface = port->ifindex;
    inet_pton(PF_INET6, "ff02::2", &mreq.ipv6mr_multiaddr);
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ) {
        error(0, errno, "failed to add multicast group ff02::2 on %s", port->ifname);
        return -errno;
    }

    int outgoing_if = port->ifindex;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_IF, &outgoing_if, sizeof(outgoing_if))){
        error(0, errno, "failed to bind outgoing multicast outgoing if");
        return -errno;
    }

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

    memcpy(&port->mac, ifr.ifr_hwaddr.sa_data, sizeof(port->mac));

    return 0;
}

int get_link_local_addr(struct port_t* port)
{
    bool found = false;
    struct ifaddrs* ifp = NULL;
    struct ifaddrs* ptr;
    struct sockaddr_in6* si6;

    if( 0 > getifaddrs(&ifp) ) {
        error(0, errno, "failed to get link local addresses");
        return -errno;
    }

    ptr = ifp;
    while( ptr ) {
        if( !ptr->ifa_name || strcmp(ptr->ifa_name, port->ifname) ) {
            ptr = ptr->ifa_next;
            continue;
        }
        if(!ptr->ifa_addr) {
            ptr = ptr->ifa_next;
            continue;
        }
        if(ptr->ifa_addr->sa_family != PF_INET6) {
            ptr = ptr->ifa_next;
            continue;
        }
        si6 = (struct sockaddr_in6*)ptr->ifa_addr;
        if(!IN6_IS_ADDR_LINKLOCAL(&si6->sin6_addr)) {
            ptr = ptr->ifa_next;
            continue;
        }
        found = true;
        break;
    }

    if(found) {
        memcpy(&port->addr, &si6->sin6_addr, sizeof(si6->sin6_addr));
        inet_pton(PF_INET6, "ff02::1:ff:00:00:00", &port->maddr);
        memcpy(port->maddr.s6_addr + 13, si6->sin6_addr.s6_addr + 13, 3);
    }

    freeifaddrs(ifp);

    char ip6addr[128] = "";
    char mip6addr[128] = "";
    inet_ntop(PF_INET6, &port->addr, ip6addr, sizeof(ip6addr));
    inet_ntop(PF_INET6, &port->maddr, mip6addr, sizeof(mip6addr));
    printf("%s's linklocal address = %s, link loca multicast address: %s\n", port->ifname, ip6addr, mip6addr);

    return found ? 0 : -1;
}

bool is_self_addr(struct in6_addr* addr)
{
    bool found = false;
    struct ifaddrs* ifp = NULL;
    struct ifaddrs* ptr;
    struct sockaddr_in6* si6;

    if( 0 > getifaddrs(&ifp) ) {
        error(0, errno, "failed to get link addresses");
        return false;
    }

    ptr = ifp;
    while( ptr ) {
        if(!ptr->ifa_addr) {
            ptr = ptr->ifa_next;
            continue;
        }
        if(ptr->ifa_addr->sa_family != PF_INET6) {
            ptr = ptr->ifa_next;
            continue;
        }
        si6 = (struct sockaddr_in6*)ptr->ifa_addr;
        if(!IN6_ARE_ADDR_EQUAL(addr, &si6->sin6_addr) ) {
            ptr = ptr->ifa_next;
            continue;
        }
        found = true;
        break;
    }

    freeifaddrs(ifp);
    if( found ){
        printf("from self, ignore it\n");
    }

    return found;
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

ssize_t send_raw_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct sockaddr_ll si6;
    struct iovec iovec[iovec_count];
    va_list val;

    va_start(val, iovec_count);
    for( size_t i = 0 ; i < iovec_count ; i ++ ) {
        iovec[i].iov_base   = va_arg(val, void*);
        iovec[i].iov_len    = va_arg(val, size_t);
    }
    va_end(val);

    si6.sll_family  = PF_PACKET;
    si6.sll_ifindex = port->ifindex;

    memset(&cbuf, 0, sizeof(cbuf));
    msghdr.msg_iov          = iovec;
    msghdr.msg_iovlen       = iovec_count;
    msghdr.msg_control      = NULL;
    msghdr.msg_controllen   = 0;
    msghdr.msg_flags        = 0;
    msghdr.msg_name         = &si6;
    msghdr.msg_namelen      = sizeof(si6);

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
