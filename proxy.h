#ifndef ICMP6_PROXY_H__
#define ICMP6_PROXY_H__

#include "fdb.h"
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

struct ra_info_t {
    TAILQ_ENTRY(ra_info_t) entry;
    time_t expired_time;
    size_t pref_hdr_offset;
    struct icmp6 info[0];
};
TAILQ_HEAD(ra_info_list_t, ra_info_t);

struct port_t {
    int timerfd;
    int rawsock;
    uint8_t ifindex;
    char ifname[IF_NAMESIZE];
    struct ether_addr mac;
    struct sockaddr_in6 addr;
    struct ra_info_list_t ra_list;
};

struct icmp6_proxy_t {
    struct port_t wan;
    struct port_t lan;
    struct fdb_t  fdb;
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
