#ifndef ICMP6_PROXY_EVENT__
#define ICMP6_PROXY_EVENT__

#include "fdb.h"
#include "proxy.h"
#include <netinet/icmp6.h>

extern int send_ra(struct port_t* port, struct prefix_info_t* pi, struct in6_addr* to);
extern int handle_wan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr,
                           size_t len, struct in6_addr* from, struct in6_addr* to);
extern int handle_lan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr,
                           size_t len, struct in6_addr* from, struct in6_addr* to);

#endif
