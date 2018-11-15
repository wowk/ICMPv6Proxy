#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#define max(a, b) ((a > b) ? a : b)

static void cleanup_icmp6proxy(struct icmp6_proxy_t* proxy);


int main(int argc, char** argv)
{
    struct icmp6_proxy_t* icmp6proxy;
    struct proxy_args_t args;

    parse_args(argc, argv, &args);

    icmp6proxy = (struct icmp6_proxy_t*)calloc(1, sizeof(struct icmp6_proxy_t));
    if( !icmp6proxy ){
        error(1, errno, "failed to create icmp6proxy object");
    }

    icmp6proxy->ra_proxy    = args.ra_proxy;
    icmp6proxy->dad_proxy   = args.dad_proxy;
    icmp6proxy->debug       = args.debug;
    icmp6proxy->lan.ifindex = if_nametoindex(args.lan_ifname);
    icmp6proxy->wan.ifindex = if_nametoindex(args.wan_ifname);
    strcpy(icmp6proxy->lan.ifname, args.lan_ifname);
    strcpy(icmp6proxy->wan.ifname, args.wan_ifname);

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

    if( create_timer(&icmp6proxy->wan, args.ra_interval) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_timer(&icmp6proxy->lan, args.ra_interval) < 0 ){
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    int ret;
    ssize_t retlen;
    fd_set rfdset;
    fd_set rfdset_save;
    struct in6_addr to;
    struct in6_addr from;
    uint8_t pktbuf[1520] = "";

    FD_ZERO(&rfdset_save);
    FD_SET(icmp6proxy->lan.rawsock, &rfdset_save);
    FD_SET(icmp6proxy->wan.rawsock, &rfdset_save);
    FD_SET(icmp6proxy->lan.timerfd, &rfdset_save);
    FD_SET(icmp6proxy->wan.timerfd, &rfdset_save);

    int max1 = max(icmp6proxy->lan.rawsock, icmp6proxy->wan.rawsock);
    int max2 = max(icmp6proxy->lan.timerfd, icmp6proxy->wan.timerfd);
    int maxfd = max(max1, max2);

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
            retlen = recv_pkt(&icmp6proxy->lan, pktbuf, sizeof(pktbuf), &from, &to);
            if( 0 > retlen ){
                error(0, errno, "failed to read icmp6 packet from lan");
                break;
            }
            handle_lan_side(icmp6proxy, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }

        if( FD_ISSET(icmp6proxy->wan.rawsock, &rfdset) ){
            retlen = recv_pkt(&icmp6proxy->wan, pktbuf, sizeof(pktbuf), &from, &to);
            if( 0 > retlen ){
                error(0, errno, "failed to read icmp6 packet from wan");
                break;
            }
            handle_wan_side(icmp6proxy, (struct icmp6_hdr*)pktbuf, retlen, &from, &to);
        }

        if( FD_ISSET(icmp6proxy->lan.timerfd, &rfdset) ){
            uint64_t expirations;
            struct in6_addr to;
            inet_pton(PF_INET6, "ff02::1", &to);
            read(icmp6proxy->lan.timerfd, &expirations, sizeof(expirations));
            if( !icmp6proxy->got_same_prefix_at_both_side ){
                struct prefix_info_t* pi;
                TAILQ_FOREACH(pi, &icmp6proxy->lan.prefix_list, entry){
                    if( 0 > send_ra(&icmp6proxy->lan, pi, &to) ){
                        error(0, errno, "failed to send RA packet to LAN side");
                    }
                }
            }
        }

        if( FD_ISSET(icmp6proxy->wan.timerfd, &rfdset) ){
            uint64_t expirations;
            read(icmp6proxy->wan.timerfd, &expirations, sizeof(expirations));
            printf("WAN timer triggerred\n");
        }
    }

    cleanup_icmp6proxy(icmp6proxy);

    return 0;
}

void cleanup_icmp6proxy(struct icmp6_proxy_t* proxy) {
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
