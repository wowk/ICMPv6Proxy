#ifndef ICMP6_LIB_H__
#define ICMP6_LIB_H__

#include "proxy.h"

extern int join_multicast(struct port_t* port, const char* mc_group);
extern int leave_multicast(struct port_t* port, const char* mc_group);
extern int create_icmpv6_sock(struct port_t* port);
extern ssize_t recv_icmpv6_pkt(struct port_t* port, void* buf, size_t len,
                                struct in6_addr* from, struct in6_addr* to);
extern ssize_t send_icmpv6_pkt(struct port_t* port, void* buf,
                               size_t len,struct in6_addr* to);
extern int gethwaddr(struct port_t* port);

#endif
