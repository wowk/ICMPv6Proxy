#define _GNU_SOURCE

#include "lib.h"
#include <a.out.h>
#include <stdint.h>
#include <stdbool.h>
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


int join_multicast(struct port_t* port, const char* mc_group)
{
    struct ipv6_mreq mreq;

    mreq.ipv6mr_interface   = port->ifindex;
    inet_pton(AF_INET6, mc_group, &mreq.ipv6mr_multiaddr);

    if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ){
        error(0, errno, "failed to join multicast group %s", mc_group);
        return -errno;
    }

    return 0;
}

int leave_multicast(struct port_t* port, const char* mc_group)
{
    struct ipv6_mreq mreq;

    mreq.ipv6mr_interface   = port->ifindex;
    inet_pton(AF_INET6, mc_group, &mreq.ipv6mr_multiaddr);

    if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) ){
        error(0, errno, "failed to leave multicast group %s", mc_group);
        return -errno;
    }

    return 0;
}

int create_icmpv6_sock(struct port_t* port)
{
    port->rawsock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if( port->rawsock < 0 ){
        error(0, errno, "failed to create ICMPV6 socket");
        return -errno;
    }

    if( 0 > setsockopt(port->rawsock, SOL_SOCKET, SO_BINDTODEVICE, port->ifname, sizeof(port->ifname)) ){
        error(0, errno, "failed to bind socket to device %s", port->ifname);
        close(port->rawsock);
        return -errno;
    }

    int pktinfo_on = 1;
    if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_RECVPKTINFO, &pktinfo_on, sizeof(pktinfo_on)) ){
        error(0, errno, "failed to set RECVPKTINFO flag");
        close(port->rawsock);
        return -errno;
    }

    if( !port->join_node_router_group && 0 == join_multicast(port, "ff01::2") ){
        port->join_node_router_group = true;
    }

    if( !port->join_link_router_group && 0 == join_multicast(port, "ff02::1") ){
        port->join_link_router_group = true;
    }

    if( !port->join_site_router_group && 0 == join_multicast(port, "ff02::1:ff00:0/104") ){
        port->join_site_router_group = true;
    }

    return 0;
}

ssize_t recv_icmpv6_pkt(
        struct port_t* port,
        void* buf, size_t len,
        struct in6_addr* from,
        struct in6_addr* to)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct in6_pktinfo) + sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct iovec iovec;
    struct sockaddr_in6 si6;

    memset(&cbuf, 0, sizeof(cbuf));
    iovec.iov_base          = buf;
    iovec.iov_len           = len;
    msghdr.msg_iovlen       = 1;
    msghdr.msg_iov          = &iovec;
    msghdr.msg_control      = cbuf;
    msghdr.msg_controllen   = sizeof(cbuf);
    msghdr.msg_flags        = 0;
    msghdr.msg_name         = &si6;
    msghdr.msg_namelen      = sizeof(si6);

    do{
        ret = recvmsg(port->rawsock, &msghdr, 0);
    }while( ret > 0 && errno == EINTR);

    if( ret > 0 ){
        struct in6_pktinfo* pktinfo = (struct in6_pktinfo*)CMSG_DATA((struct cmsghdr*)cbuf);
        memcpy(to, &pktinfo->ipi6_addr, sizeof(pktinfo->ipi6_addr));
        memcpy(from, &si6.sin6_addr, sizeof(si6.sin6_addr));
    }

    return ret;
}

ssize_t send_icmpv6_pkt(
        struct port_t* port,
        void* buf, size_t len,
        struct in6_addr* to)
{
    ssize_t ret;
    uint8_t cbuf[sizeof(struct in6_pktinfo) + sizeof(struct cmsghdr)];
    struct msghdr msghdr;
    struct iovec iovec;
    struct sockaddr_in6 si6;

    memset(&si6, 0, sizeof(si6));
    si6.sin6_family = PF_INET6;
    memcpy(&si6.sin6_addr, to, sizeof(si6.sin6_addr));

    memset(&cbuf, 0, sizeof(cbuf));
    iovec.iov_base          = buf;
    iovec.iov_len           = len;
    msghdr.msg_iovlen       = 1;
    msghdr.msg_iov          = &iovec;
    msghdr.msg_control      = NULL;
    msghdr.msg_controllen   = 0;
    msghdr.msg_flags        = 0;
    msghdr.msg_name         = &si6;
    msghdr.msg_namelen      = sizeof(si6);

    do{
        ret = sendmsg(port->rawsock, &msghdr, 0);
    }while( ret > 0 && errno == EINTR);

    return ret;
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
