#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

struct fdb_t {

};

struct port_t {
    int rawsock;
    uint8_t ifindex;
    uint8_t ifname[IF_NAMESIZE];
    struct sockaddr_in6 addr;
    bool join_node_router_group;
    bool join_link_router_group;
    bool join_site_router_group;
};

struct icmp6_proxy_t {
    struct port_t wan;
    struct port_t lan;
    struct fdb_t  fdb;
    uint32_t max_entrys;
    uint32_t aging_time;
    uint32_t timeout;
    volatile bool running;
};


static int create_icmpv6_sock(struct port_t* port){
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

    struct ipv6_mreq mreq;
    if( port->join_node_router_group ){
        mreq.ipv6mr_interface   = port->ifindex;
        inet_pton(AF_INET6, "ff01::2", &mreq.ipv6mr_multiaddr);
        if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ){
            error(0, errno, "failed to join multicast group ff01::2");
            close(port->rawsock);
            return -errno;
        }
        port->join_node_router_group = true;
    }


    if( port->join_link_router_group ){
        mreq.ipv6mr_interface   = port->ifindex;
        inet_pton(AF_INET6, "ff02::2", &mreq.ipv6mr_multiaddr);
        if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ){
            error(0, errno, "failed to join multicast group ff01::2");
            close(port->rawsock);
            return -errno;
        }
        port->join_link_router_group = true;
    }

    if( port->join_site_router_group ){
        mreq.ipv6mr_interface   = port->ifindex;
        inet_pton(AF_INET6, "ff05::2", &mreq.ipv6mr_multiaddr);
        if( 0 > setsockopt(port->rawsock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ){
            error(0, errno, "failed to join multicast group ff01::2");
            close(port->rawsock);
            return -errno;
        }
        port->join_site_router_group = true;
    }

    return 0;
}

static ssize_t recv_icmpv6_pkt(struct port_t* port, void* buf, size_t len,
                           struct in6_addr* from, struct in6_addr* to){
    int ret;
    uint8_t cbuf[sizeof(struct in6_pktinfo) + sizeof(struct cmsghdr)];
    struct cmsghdr* pcmsghdr;
    struct msghdr msghdr;
    struct iovec iovec;

    iovec.iov_base          = buf;
    iovec.iov_len           = len;
    msghdr.msg_control      = cbuf;
    msghdr.msg_controllen   = sizeof(cbuf);
    msghdr.msg_iov          = &iovec;
    msghdr.msg_iovlen       = 1;
    msghdr.msg_flags        = 0;

    do{
        ret = recvmsg(port->rawsock, &msghdr, 0);
    }while( ret > 0 && errno == EINTR);

    return ret;
}

static int cleanup_icmp6proxy(struct icmp6_proxy_t* proxy) {

}

int main(int argc, char** argv)
{
    struct icmp6_proxy_t* icmp6proxy;

    icmp6proxy = (struct icmp6_proxy_t*)calloc(1, sizeof(struct icmp6_proxy_t));
    if( !icmp6proxy ){
        error(1, errno, "failed to create icmp6proxy object");
    }

    if( create_icmpv6_sock(&icmp6proxy->lan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_icmpv6_sock(&icmp6proxy->wan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    int ret;
    int maxfd;
    fd_set rfdset;
    fd_set rfdset_save;
    struct in6_addr to;
    struct in6_addr from;
    uint8_t pktbuf[1520] = "";
    struct icmp6_hdr* icmp6pkt = (struct icmp6_hdr*)pktbuf;

    FD_ZERO(&rfdset_save);
    FD_SET(icmp6proxy->lan.rawsock, &rfdset_save);
    FD_SET(icmp6proxy->wan.rawsock, &rfdset_save);

    if( icmp6proxy->lan.rawsock > icmp6proxy->wan.rawsock ){
        maxfd = icmp6proxy->lan.rawsock;
    }else{
        maxfd = icmp6proxy->wan.rawsock;
    }

    icmp6proxy->running = true;
    while (icmp6proxy->running) {
        struct timeval tv = {
            .tv_sec     = icmp6proxy->timeout,
            .tv_usec    = 0
        };
        rfdset = rfdset_save;

        ret = select(maxfd + 1, &rfdset, NULL, NULL, &tv);
        if( ret == 0 ){
            continue;
        }else if( ret < 0 ){
            break;
        }

        if( FD_ISSET(icmp6proxy->lan.rawsock, &rfdset) ){
            if( 0 < recv_icmpv6_pkt(&icmp6proxy->lan, pktbuf, sizeof(pktbuf), &from, &to) ){
                //icmp6pkt->icmp6_type == ND_ROUTER_ADVERT
            }else{

            }
            //forward_pkt();
        }

        if( FD_ISSET(icmp6proxy->wan.rawsock, &rfdset) ){
            if( 0 < recv_icmpv6_pkt(&icmp6proxy->wan, pktbuf, sizeof(pktbuf), &from, &to) ){

            }else{

            }
            //forward_pkt();
        }
    }

    cleanup_icmp6proxy(icmp6proxy);

    return 0;
}
