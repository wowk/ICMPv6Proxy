#ifndef ICMP6_LIB_H__
#define ICMP6_LIB_H__

#include "proxy.h"

extern int create_timer(struct port_t* port, unsigned interval);
extern int parse_args(int argc, char** argv, struct proxy_args_t* args);
extern int join_multicast(struct port_t* port, const char* mc_group);
extern int leave_multicast(struct port_t* port, const char* mc_group);
extern int create_icmpv6_sock(struct port_t* port);
extern ssize_t recv_pkt(struct port_t* port, void* buf, size_t len, struct in6_addr* from, struct in6_addr* to);
extern ssize_t send_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...);
extern int gethwaddr(struct port_t* port);

#endif
