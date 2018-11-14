#ifndef ICMP6_PROXY_H__
#define ICMP6_PROXY_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>


struct port_t;

struct fdb_entry_t {
    struct ether_addr mac;
    struct in6_addr addr;
    struct port_t* port;
};

struct fdb_t {};

struct port_t {
    int rawsock;
    uint8_t ifindex;
    char ifname[IF_NAMESIZE];
    struct ether_addr mac;
    struct sockaddr_in6 addr;
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
    bool got_same_prefix_at_both_side;
    volatile bool running;
};


#endif
