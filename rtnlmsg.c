#include "rtnlmsg.h"
#include "debug.h"
#include "table.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>


static int handle_del_route_event(struct nd_proxy_t* proxy, struct rtmsg* rtmsg, struct rtattrs_t* rta)
{
    if( !rta->tb[RTA_DST] ){
        return 0;
    }

    char ipaddr[INET6_ADDRSTRLEN] = "";
    struct in6_addr* addr = RTA_DATA((struct in6_addr*)rta->tb[RTA_DST]);
    struct nd_table_entry_t* pentry = NULL;
    LIST_FOREACH(pentry, &proxy->lan.nd_table, entry){
        if( !memcmp(&pentry->addr, addr, sizeof(pentry->addr)) ){
            break;
        }
    }

    if( pentry ){
        inet_ntop(PF_INET6, &pentry->addr, ipaddr, sizeof(ipaddr));
        error(0, 0, "static route rule for <%s> lost, re-inset it into routing table", ipaddr);
        add_host_route_rule(&proxy->lan, &pentry->addr);
    }else{
        error(0, 0, "not found entry in LAN side");
    }

    return 0;
}

static int parse_rtattr(struct rtattr* rtattr, short max, size_t payload_len, struct rtattrs_t* rtas)
{
    rtas->mask = 0;

    memset(rtas, 0, sizeof(struct rtattrs_t));

    while( payload_len && RTA_OK(rtattr, payload_len) ) {
        if( max >= rtattr->rta_type && !rtas->tb[rtattr->rta_type]) {
            rtas->tb[rtattr->rta_type] = rtattr;
        }
        rtattr = RTA_NEXT(rtattr, payload_len);
    }

    return 0;
}

int handle_rtnl_mc_msg(struct nd_proxy_t* proxy, void* msg, size_t msglen)
{
    int ret;
    struct rtattr* rtattr;
    struct rtattrs_t rtattrs;
    struct nlmsghdr *hdr = (struct nlmsghdr *)msg;

    while( msglen && NLMSG_OK(hdr, msglen) ) {
        if( hdr->nlmsg_type == RTM_DELROUTE ){
            struct rtmsg* rtmsg = (struct rtmsg*)NLMSG_DATA(hdr);
            rtattr = RTM_RTA(rtmsg);
            parse_rtattr(rtattr, RTM_MAX, RTM_PAYLOAD(hdr), &rtattrs);
            ret = handle_del_route_event(proxy, rtmsg, &rtattrs);
        }else if( hdr->nlmsg_type == NLMSG_DONE ) {
            break;
        }

        if( ret < 0 ) {
            return ret;
        }

        hdr = NLMSG_NEXT(hdr, msglen);
    }

    return 0;
}

int create_rtnl_mc_socket(struct nd_proxy_t* proxy, uint32_t nl_groups)
{
    proxy->rtnlfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (proxy->rtnlfd < 0) {
        error(0, errno, "failed to create evt socket");
        return -errno;
    }

    struct sockaddr_nl sn = {
        .nl_family = AF_NETLINK,
        .nl_groups = nl_groups,
        .nl_pid = 0,
        .nl_pad = 0,
    };

    if (bind(proxy->rtnlfd, (struct sockaddr *)&sn, sizeof(sn)) < 0) {
        error(0, errno, "failed to bind evt socket");
        return -errno;
    }

    return 0;
}
