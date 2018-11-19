#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ndisc.h"
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
    if( !icmp6proxy ) {
        error(1, errno, "failed to create icmp6proxy object");
    }

    icmp6proxy->timeout     = 1;
    icmp6proxy->ra_proxy    = args.ra_proxy;
    icmp6proxy->dad_proxy   = args.dad_proxy;
    icmp6proxy->debug       = args.debug;
    icmp6proxy->lan.ifindex = if_nametoindex(args.lan_ifname);
    icmp6proxy->wan.ifindex = if_nametoindex(args.wan_ifname);
    strcpy(icmp6proxy->lan.ifname, args.lan_ifname);
    strcpy(icmp6proxy->wan.ifname, args.wan_ifname);
    LIST_INIT(&icmp6proxy->lan.nd_table);
    LIST_INIT(&icmp6proxy->wan.nd_table);


    if( create_raw_sock(&icmp6proxy->lan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_raw_sock(&icmp6proxy->wan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_icmp6_sock(&icmp6proxy->wan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_icmp6_sock(&icmp6proxy->lan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( get_hw_addr(&icmp6proxy->lan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( get_hw_addr(&icmp6proxy->wan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( get_link_local_addr(&icmp6proxy->lan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( get_link_local_addr(&icmp6proxy->wan) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    if( create_timer(icmp6proxy, args.ra_interval) < 0 ) {
        cleanup_icmp6proxy(icmp6proxy);
        return -errno;
    }

    int ret;
    ssize_t retlen;
    fd_set rfdset;
    fd_set rfdset_save;
    uint8_t pktbuf[1520] = "";

    FD_ZERO(&rfdset_save);
    FD_SET(icmp6proxy->lan.rawsock, &rfdset_save);
    FD_SET(icmp6proxy->wan.rawsock, &rfdset_save);
    FD_SET(icmp6proxy->timerfd, &rfdset_save);
    //FD_SET(icmp6proxy->lan.icmp6sock, &rfdset_save);
    //FD_SET(icmp6proxy->wan.icmp6sock, &rfdset_save);

    int max1 = max(icmp6proxy->lan.rawsock, icmp6proxy->wan.rawsock);
    //int max2 = max(icmp6proxy->lan.icmp6sock, icmp6proxy->wan.icmp6sock);
    //int max3 = max(max1, max2);
    int maxfd = max(max1, icmp6proxy->timerfd);

    icmp6proxy->running = true;
    while (icmp6proxy->running) {
        struct timeval tv = {
            .tv_sec     = icmp6proxy->timeout,
            .tv_usec    = 0
        };
        rfdset = rfdset_save;

        ret = select(maxfd + 1, &rfdset, NULL, NULL, &tv);
        if( ret == 0 ) {
            continue;
        } else if( ret < 0 ) {
            break;
        }

        if( FD_ISSET(icmp6proxy->lan.rawsock, &rfdset) ) {
            retlen = recv_pkt(&icmp6proxy->lan, pktbuf, sizeof(pktbuf));
            if( 0 > retlen ) {
                error(0, errno, "failed to read icmp6 packet from lan");
                break;
            }
            printf("recved\n");
            handle_lan_side(icmp6proxy, pktbuf, retlen);
        }

        if( FD_ISSET(icmp6proxy->wan.rawsock, &rfdset) ) {
            retlen = recv_pkt(&icmp6proxy->wan, pktbuf, sizeof(pktbuf));
            if( 0 > retlen ) {
                error(0, errno, "failed to read icmp6 packet from wan");
                break;
            }
            handle_wan_side(icmp6proxy, pktbuf, retlen);
        }

        if( FD_ISSET(icmp6proxy->timerfd, &rfdset) ) {
            uint64_t expirations;
            read(icmp6proxy->timerfd, &expirations, sizeof(expirations));
            if(!icmp6proxy->dad_proxy && !icmp6proxy->ra_proxy) {
                continue;
            }
            if(icmp6proxy->dad_proxy) {
                printf("update nd_table\n");
                update_nd_table(&icmp6proxy->lan.nd_table);
                update_nd_table(&icmp6proxy->wan.nd_table);
            }
            if(icmp6proxy->ra_proxy) {
                printf("handle ra proxy event\n");
            }

        }
    }

    cleanup_icmp6proxy(icmp6proxy);

    return 0;
}

void cleanup_icmp6proxy(struct icmp6_proxy_t* proxy)
{
    close(proxy->wan.rawsock);
    close(proxy->lan.rawsock);
}
