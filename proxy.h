#ifndef ICMP6_PROXY_H__
#define ICMP6_PROXY_H__

#include "fdb.h"
#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/queue.h>
#include <netinet/icmp6.h>


struct proxy_args_t {
    char wan_ifname[IF_NAMESIZE];
    char lan_ifname[IF_NAMESIZE];
    bool debug;
    bool ra_proxy;
    bool dad_proxy;
    uint32_t ra_interval;
};

struct prefix_info_t {
    TAILQ_ENTRY(prefix_info_t) entry;
    struct nd_opt_prefix_info info;
    time_t expired_time;
};
TAILQ_HEAD(prefix_info_list_t, prefix_info_t);

struct port_t {
    int timerfd;
    int rawsock;
    uint8_t ifindex;
    char ifname[IF_NAMESIZE];
    struct ether_addr mac;
    struct sockaddr_in6 addr;
    struct prefix_info_list_t prefix_list;
    bool join_node_router_group;
    bool join_link_router_group;
    bool join_site_router_group;
};

struct icmp6_proxy_t {
    struct port_t wan;
    struct port_t lan;
    struct fdb_t*  fdb;
    uint32_t max_entrys;
    uint32_t aging_time;
    uint32_t timeout;
    bool ra_proxy;
    bool dad_proxy;
    bool debug;
    bool got_same_prefix_at_both_side;
    volatile bool running;
};

#endif
