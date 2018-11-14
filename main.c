#define _GNU_SOURCE

#include "proxy.h"
#include "lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/select.h>


static int forward_icmpv6_pkt(
        struct icmp6_proxy_t* proxy,
        struct port_t* port,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{
    char saddr[INET6_ADDRSTRLEN] = "";
    char daddr[INET6_ADDRSTRLEN] = "";

    inet_ntop(PF_INET6, from, saddr, sizeof(saddr));
    inet_ntop(PF_INET6, to, daddr, sizeof(daddr));

//    for( size_t i = 0 ; i < len ; i ++ ){
//        if( i && (i%16) == 0 ){
//            printf("\n");
//        }
//        printf("%.2x ", ((unsigned char*)hdr)[i]);
//    }
//    printf("\n");

    switch( hdr->icmp6_type ){
    case ND_ROUTER_ADVERT:
        printf("if: %s, from: %s, to: %s, type: RA\n", port->ifname, saddr, daddr);
        break;
    case ND_ROUTER_SOLICIT:
        printf("if: %s, from: %s, to: %s, type: RS\n", port->ifname, saddr, daddr);
        break;
    case ND_NEIGHBOR_ADVERT:
        printf("if: %s, from: %s, to: %s, type: NA\n", port->ifname, saddr, daddr);
        break;
    case ND_NEIGHBOR_SOLICIT:
        printf("if: %s, from: %s, to: %s, type: NS\n", port->ifname, saddr, daddr);
        break;
    default:
        printf("if: %s, from: %s, to: %s, type: Other(%u)\n", port->ifname, saddr, daddr, hdr->icmp6_type);
        break;
    }

    return 0;
}

static int forward_NS(
        struct icmp6_proxy_t* proxy,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{}

static int forward_NA(
        struct icmp6_proxy_t* proxy,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{}

static int handle_wan_side(
        struct icmp6_proxy_t* proxy,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{}

static int handle_lan_side(
        struct icmp6_proxy_t* proxy,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{}


static int forward_RA(
        struct icmp6_proxy_t* proxy,
        struct icmp6_hdr* hdr,
        size_t len, struct in6_addr* from,
        struct in6_addr* to)
{
    if( hdr->icmp6_type == ND_ROUTER_ADVERT ){
        struct nd_router_advert* ra = (struct nd_router_advert*)hdr;

        if( ra->nd_ra_curhoplimit - 1 == 0 ){
            error(0, 0, "hotlimit reached, drop it");
            return 0;
        }
        ra->nd_ra_curhoplimit --;

        /* find LinkSourceAddress option and replace the LinkAddress with EWMTA24's mac */
        size_t offset = sizeof(struct nd_router_advert);
        struct nd_opt_hdr* opt = (struct nd_opt_hdr*)(ra + 1);

        while( offset < len && opt->nd_opt_type != ND_OPT_SOURCE_LINKADDR ){
           offset += opt->nd_opt_len;
           opt = (struct nd_opt_hdr*)(offset + (void*)hdr);
        }

        /* found LinkSourceAddress header*/
        if( offset < len ){
            printf("get link target address option\n");
            void* dst = (void*)opt + sizeof(struct nd_opt_hdr);
            void* src = &proxy->lan.mac;
            memcpy(dst, src, sizeof(struct ether_addr));
        }

        if( 0 > send_icmpv6_pkt(&proxy->lan, ra, len, to) ){
            error(0, errno, "send icmp6 failed");
            return -errno;
        }

        return 0;
    }
}


static void clear_fdb(struct fdb_t* fdb)
{}

static void cleanup_icmp6proxy(struct icmp6_proxy_t* proxy) {
    if( proxy->wan.join_link_router_group ){
        leave_multicast(&proxy->wan, "ff02::2");
    }

    if( proxy->lan.join_link_router_group ){
        leave_multicast(&proxy->wan, "ff02::2");
    }

    close(proxy->wan.rawsock);
    close(proxy->lan.rawsock);

    clear_fdb(proxy->fdb);
}

int main(int argc, char** argv)
{
    struct icmp6_proxy_t* icmp6proxy;

    struct proxy_args_t {
        char wan_ifname[IF_NAMESIZE];
        char lan_ifname[IF_NAMESIZE];
    }args;
    memset(&args, 0, sizeof(args));

    int op;
    while( -1 != (op = getopt(argc, argv, "l:w:")) ){
        switch (op) {
        case 'l':
            strcpy(args.lan_ifname,optarg);
            break;
        case 'w':
            strcpy(args.wan_ifname,optarg);
            break;
        case '?':
            error(1, EINVAL, "%s is not a valid option", argv[optind]);
            break;
        default:
            break;
        }
    }

    icmp6proxy = (struct icmp6_proxy_t*)calloc(1, sizeof(struct icmp6_proxy_t));
    if( !icmp6proxy ){
        error(1, errno, "failed to create icmp6proxy object");
    }

    strcpy(icmp6proxy->lan.ifname, args.lan_ifname);
    icmp6proxy->lan.ifindex = if_nametoindex(args.lan_ifname);

    strcpy(icmp6proxy->wan.ifname, args.wan_ifname);
    icmp6proxy->wan.ifindex = if_nametoindex(args.wan_ifname);

    if( create_icmpv6_sock(&icmp6proxy->lan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( gethwaddr(&icmp6proxy->lan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( gethwaddr(&icmp6proxy->wan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_icmpv6_sock(&icmp6proxy->wan) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    int ret;
    int maxfd;
    ssize_t retlen;
    fd_set rfdset;
    fd_set rfdset_save;
    struct in6_addr to;
    struct in6_addr from;
    uint8_t pktbuf[1520] = "";

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
            retlen = recv_icmpv6_pkt(&icmp6proxy->lan, pktbuf, sizeof(pktbuf), &from, &to);
            if( 0 > retlen ){
                error(0, errno, "failed to read icmp6 packet from lan");
                break;
            }
            forward_icmpv6_pkt(icmp6proxy, &icmp6proxy->lan, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }

        if( FD_ISSET(icmp6proxy->wan.rawsock, &rfdset) ){
            retlen = recv_icmpv6_pkt(&icmp6proxy->wan, pktbuf, sizeof(pktbuf), &from, &to);
            if( 0 > retlen ){
                error(0, errno, "failed to read icmp6 packet from wan");
                break;
            }
            forward_icmpv6_pkt(icmp6proxy, &icmp6proxy->wan, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
            forward_RA(icmp6proxy, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }
    }

    cleanup_icmp6proxy(icmp6proxy);

    return 0;
}
