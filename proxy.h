#ifndef ICMP6_PROXY_H__
#define ICMP6_PROXY_H__

#include "table.h"
#include "proxy.h"
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

struct port_t {
    int rawsock;
    int icmp6sock;
    uint8_t ifindex;
    char ifname[IF_NAMESIZE];
    struct ether_addr mac;
    struct in6_addr addr;
    struct nd_table_t  nd_table;
};

struct icmp6_proxy_t {
    int timerfd;
    struct port_t wan;
    struct port_t lan;
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
