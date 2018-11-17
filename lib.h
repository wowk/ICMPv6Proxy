#ifndef ICMP6_LIB_H__
#define ICMP6_LIB_H__

#include "proxy.h"

extern struct ether_header* eth_header(void* buffer, size_t* offset);
extern struct icmp6_hdr* icmp6_header(void* buffer, size_t* offset);
extern struct ip6_hdr* ipv6_header(void* buffer, size_t* offset);
extern int create_timer(struct icmp6_proxy_t* proxy, unsigned interval);
extern int parse_args(int argc, char** argv, struct proxy_args_t* args);
extern int join_multicast(struct port_t* port, const char* mc_group);
extern int leave_multicast(struct port_t* port, const char* mc_group);
extern int create_raw_sock(struct port_t* port);
extern int create_icmp6_sock(struct port_t* port);
extern ssize_t recv_pkt(struct port_t* port, void* buf, size_t len);
extern ssize_t send_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...);
extern int get_hw_addr(struct port_t* port);
extern int get_link_local_addr(struct port_t* port);

#endif
