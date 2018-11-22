#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ndisc.h"
#include "rtnlmsg.h"
#include "proxy.h"
#include "debug.h"
#include "lib.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/select.h>
#include <sys/signalfd.h>


#define max(a, b) ((a > b) ? a : b)

static void cleanup_nd_proxy(struct nd_proxy_t* proxy);
static void handle_signal(struct nd_proxy_t* proxy, struct signalfd_siginfo* ssi);

int nd_proxy_ctl_main(int argc, char** argv)
{
    char help[] = "usage: ndproxyctl\n\t\t[disable|enable] [ra|dad]\n\t\t[ clear | dump ] [neigh|binding]\n";
    if( argc != 3 ){
        info(help);
        return 0;
    }

    if( !strcmp(argv[1], "enable")){
        if( !strcmp(argv[2], "ra")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_ENABLE_RA_PROXY);
        }else if( !strcmp(argv[2], "dad")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_ENABLE_DAD_PROXY);
        }else{
            info(help);
        }
    }else if( !strcmp(argv[1], "disable")){
        if( !strcmp(argv[2], "ra")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_DISABLE_RA_PROXY);
        }else if( !strcmp(argv[2], "dad")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_DISABLE_DAD_PROXY);
        }else{
            info(help);
        }
    }else if( !strcmp(argv[1], "clear")){
        if( !strcmp(argv[2], "neigh")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_CLEAR_NEIGHBOR_CACHE_TABLE);
        }else if( !strcmp(argv[2], "binding")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_CLEAR_BINDING_TABLE);
        }else{
            info(help);
        }
    }else if( !strcmp(argv[1], "dump")){
        if( !strcmp(argv[2], "neigh")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_DUMP_NEIGHBOR_CACHE_TABLE);
        }else if( !strcmp(argv[2], "binding")){
            send_signal("proxy", SIGUSR1, SIG_EVENT_DUMP_BINDING_TABLE);
        }else{
            info(help);
        }
    }else{
        info(help);
    }

    return 0;
}

int nd_proxy_main(int argc, char** argv)
{
    int ret;
    struct nd_proxy_t* ndproxy;
    struct proxy_args_t args;

    parse_args(argc, argv, &args);

    ndproxy = (struct nd_proxy_t*)calloc(1, sizeof(struct nd_proxy_t));
    if( !ndproxy ) {
        error(1, errno, "failed to create icmp6proxy object");
    }

    if( !args.foreground ){
        if( daemon(0, 0) < 0 ){
            error(0, errno, "cant put %s into background", argv[0]);
            return -errno;
        }
    }

    ndproxy->timerfd    = -1;
    ndproxy->sigfd      = -1;
    ndproxy->rtnlfd     = -1;
    ndproxy->lan.rawsock= -1;
    ndproxy->wan.rawsock= -1;
    ndproxy->lan.icmp6sock = -1;
    ndproxy->wan.icmp6sock = -1;

    ndproxy->timeout    = args.ra_interval ?: 1;
    ndproxy->aging_time = args.aging_time ?: 150;
    ndproxy->ra_proxy   = args.ra_proxy;
    ndproxy->dad_proxy  = args.dad_proxy;
    ndproxy->debug      = args.debug;
    ndproxy->lan.type   = LAN_PORT;
    ndproxy->wan.type   = WAN_PORT;
    ndproxy->lan.ifindex= if_nametoindex(args.lan_ifname);
    ndproxy->wan.ifindex= if_nametoindex(args.wan_ifname);
    strcpy(ndproxy->lan.ifname, args.lan_ifname);
    strcpy(ndproxy->wan.ifname, args.wan_ifname);
    LIST_INIT(&ndproxy->lan.nd_table);
    LIST_INIT(&ndproxy->wan.nd_table);

    if( create_pid_file(ndproxy, argv[0]) < 0 ){
        return 0;
    }

    if( create_raw_sock(&ndproxy->lan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_raw_sock(&ndproxy->wan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_icmp6_sock(&ndproxy->wan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_icmp6_sock(&ndproxy->lan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( get_hw_addr(&ndproxy->lan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( get_hw_addr(&ndproxy->wan) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_timer(ndproxy, args.ra_interval) < 0 ) {
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_signalfd(ndproxy, 5, SIGUSR1, SIGUSR2, SIGINT, SIGTERM, SIGQUIT) < 0 ){
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    if( create_rtnl_mc_socket(ndproxy, RTMGRP_IPV6_ROUTE) < 0){
        cleanup_nd_proxy(ndproxy);
        return -errno;
    }

    ssize_t retlen;
    fd_set rfdset;
    fd_set rfdset_save;
    uint8_t buffer[1520] = "";

    FD_ZERO(&rfdset_save);
    FD_SET(ndproxy->lan.rawsock, &rfdset_save);
    FD_SET(ndproxy->wan.rawsock, &rfdset_save);
    FD_SET(ndproxy->timerfd, &rfdset_save);
    FD_SET(ndproxy->sigfd, &rfdset_save);
    FD_SET(ndproxy->rtnlfd, &rfdset_save);

    int max1 = max(ndproxy->lan.rawsock, ndproxy->wan.rawsock);
    int max2 = max(ndproxy->sigfd, max1);
    int max3 = max(ndproxy->rtnlfd, max2);
    int maxfd = max(max3, ndproxy->timerfd);

    ndproxy->running = true;
    while (ndproxy->running) {
        struct timeval tv = {
            .tv_sec     = ndproxy->timeout,
            .tv_usec    = 0
        };
        rfdset = rfdset_save;

        ret = select(maxfd + 1, &rfdset, NULL, NULL, &tv);
        if( ret == 0 ) {
            continue;
        } else if( ret < 0 ) {
            break;
        }

        if( FD_ISSET(ndproxy->lan.rawsock, &rfdset) ) {
            retlen = recv_raw_pkt(&ndproxy->lan, buffer, sizeof(buffer));
            if( 0 > retlen ) {
                error(0, errno, "failed to read icmp6 packet from lan");
                break;
            }
            handle_lan_side(ndproxy, buffer, retlen);
        }

        if( FD_ISSET(ndproxy->wan.rawsock, &rfdset) ) {
            retlen = recv_raw_pkt(&ndproxy->wan, buffer, sizeof(buffer));
            if( 0 > retlen ) {
                error(0, errno, "failed to read icmp6 packet from wan");
                break;
            }
            handle_wan_side(ndproxy, buffer, retlen);
        }

        if( FD_ISSET(ndproxy->timerfd, &rfdset) ) {
            uint64_t expirations;
            read(ndproxy->timerfd, &expirations, sizeof(expirations));
            if(!ndproxy->dad_proxy && !ndproxy->ra_proxy) {
                continue;
            }
            if(ndproxy->dad_proxy) {
                update_nd_table(&ndproxy->lan, ndproxy->timeout);
                update_nd_table(&ndproxy->wan, ndproxy->timeout);
            }
            if(ndproxy->ra_proxy && ndproxy->got_same_prefix_at_both_side) {
                system("rc radvd stop");
            }
            if( !ndproxy->ra_proxy && !ndproxy->dad_proxy){
                /* enter IPv6 Path Through */
            }
        }

        if( FD_ISSET(ndproxy->sigfd, &rfdset) ){
            struct signalfd_siginfo ssi;
            read(ndproxy->sigfd, &ssi, sizeof(ssi));
            handle_signal(ndproxy, &ssi);
        }

        if( FD_ISSET(ndproxy->rtnlfd, &rfdset) ){
            error(0,0,"got route event");
            while( (0 > (retlen = read(ndproxy->rtnlfd, buffer, sizeof(buffer)))) && errno == EINTR);
            if( retlen > 0 ){
                handle_rtnl_mc_msg(ndproxy, buffer, retlen);
            }
        }
    }

    cleanup_nd_proxy(ndproxy);

    return 0;
}

int main(int argc, char** argv)
{
    const char* app_name = basename(argv[0]);
    return !strcmp(app_name, "ndproxyctl") ? nd_proxy_ctl_main(argc, argv) : nd_proxy_main(argc, argv);
}

void handle_signal(struct nd_proxy_t* proxy, struct signalfd_siginfo* ssi)
{
    switch (ssi->ssi_signo) {
    case SIGINT:
        info("Got SIGINT");
        cleanup_nd_proxy(proxy);
        break;
    case SIGQUIT:
        info("Got SIGQUIT");
        cleanup_nd_proxy(proxy);
        break;
    case SIGTERM:
        info("Got SIGTERM");
        cleanup_nd_proxy(proxy);
        exit(0);
        break;
    case SIGUSR1:
        if( ssi->ssi_int == SIG_EVENT_DISABLE_RA_PROXY){
            info("disable ra");
            proxy->ra_proxy = false;
        }else if( ssi->ssi_int == SIG_EVENT_ENABLE_RA_PROXY ){
            info("enable ra");
            proxy->ra_proxy = true;
        }else if( ssi->ssi_int == SIG_EVENT_DISABLE_DAD_PROXY){
            info("disable dad");
            proxy->dad_proxy = false;
        }else if( ssi->ssi_int == SIG_EVENT_ENABLE_DAD_PROXY){
            info("enable dad");
            proxy->dad_proxy = true;
        }else if( ssi->ssi_int == SIG_EVENT_DUMP_BINDING_TABLE){
            info("dump binding table");
            dump_nd_table(&proxy->lan);
        }else if( ssi->ssi_int == SIG_EVENT_DUMP_NEIGHBOR_CACHE_TABLE){
            info("dump neigh cache table");
            dump_nd_table(&proxy->wan);
        }else if( ssi->ssi_int == SIG_EVENT_CLEAR_BINDING_TABLE){
            info("clear binding table");
            clear_nd_table(&proxy->lan);
        }else if( ssi->ssi_int == SIG_EVENT_CLEAR_NEIGHBOR_CACHE_TABLE){
            info("clear neigh cache table");
            clear_nd_table(&proxy->wan);
        }
        break;
    default:
        break;
    }
}

void cleanup_nd_proxy(struct nd_proxy_t* proxy)
{
    remove(proxy->pid_file);

    clear_nd_table(&proxy->lan);
    clear_nd_table(&proxy->wan);

    if( proxy->timerfd >= 0 )
        close(proxy->timerfd);
    if( proxy->rtnlfd >= 0 )
        close(proxy->rtnlfd);
    if( proxy->sigfd >= 0 )
        close(proxy->sigfd);

    if( proxy->wan.rawsock >= 0 ){
        setsockopt(proxy->wan.rawsock, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        close(proxy->wan.rawsock);
    }
    if( proxy->lan.rawsock >= 0 ){
        setsockopt(proxy->lan.rawsock, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);
        close(proxy->lan.rawsock);
    }

    if( proxy->wan.icmp6sock >= 0 )
        close(proxy->wan.icmp6sock);
    if( proxy->lan.rawsock >= 0 )
        close(proxy->lan.icmp6sock);
}
