#define _GNU_SOURCE

#include "icmp6.h"
#include "proxy.h"
#include "lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/select.h>


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

    int ret, maxfd;
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
            handle_lan_side(icmp6proxy, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }

        if( FD_ISSET(icmp6proxy->wan.rawsock, &rfdset) ){
            retlen = recv_icmpv6_pkt(&icmp6proxy->wan, pktbuf, sizeof(pktbuf), &from, &to);
            if( 0 > retlen ){
                error(0, errno, "failed to read icmp6 packet from wan");
                break;
            }
            handle_wan_side(icmp6proxy, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }
    }

    cleanup_icmp6proxy(icmp6proxy);

    return 0;
}
