#ifndef ICMP6_PROXY_EVENT__
#define ICMP6_PROXY_EVENT__

#include "table.h"
#include "proxy.h"
#include <netinet/icmp6.h>

struct nd_opt_linkaddr{
    uint8_t  nd_opt_type;
    uint8_t  nd_opt_len;
    struct ether_addr addr;
} __attribute__((packed));

union icmp6_opt{
    struct nd_opt_hdr comm;
    struct nd_opt_prefix_info prefix;
    struct nd_opt_mtu mtu;
    struct nd_opt_linkaddr slinkaddr;   /* source link address */
    struct nd_opt_linkaddr tlinkaddr;   /* target link address */
};

struct icmp6 {
    union {
        struct nd_router_advert ra;
        struct nd_router_solicit rs;
        struct nd_neighbor_solicit ns;
        struct nd_neighbor_advert na;
        struct icmp6_hdr comm;
        uint8_t space[256];
    };
    size_t len;
    size_t opt_cnt;
    struct in6_addr from;
    struct in6_addr to;
    union icmp6_opt opt[0];
};

extern int handle_wan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len);
extern int handle_lan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len);

#endif
