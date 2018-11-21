#ifndef ICMP6_LIB_H__
#define ICMP6_LIB_H__

#include "proxy.h"

extern int create_pid_file(const char* app_name);
extern int parse_args(int argc, char** argv, struct proxy_args_t* args);

extern int create_timer(struct icmp6_proxy_t* proxy, unsigned interval);

extern struct ether_header* eth_header(void* buffer, size_t* offset);
extern struct icmp6_hdr* icmp6_header(void* buffer, size_t* offset);
extern struct ip6_hdr* ipv6_header(void* buffer, size_t* offset);

extern int create_raw_sock(struct port_t* port);
extern int create_icmp6_sock(struct port_t* port);
extern ssize_t recv_raw_pkt(struct port_t* port, void* buf, size_t len);
extern ssize_t send_raw_pkt(struct port_t* port, size_t iovec_count, ...);
extern ssize_t send_icmp6_pkt(struct port_t* port, struct in6_addr* to, size_t iovec_count, ...);

extern int get_hw_addr(struct port_t* port);

extern uint32_t checksum_partial(void* data, size_t len, uint32_t sum);
extern uint16_t checksum_fold(uint32_t sum);

#endif
