#ifndef ICMP6_PROXY_TABLE_H__
#define ICMP6_PROXY_TABLE_H__


#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ether.h>
#include <sys/queue.h>


struct nd_table_entry_t {
    struct ether_addr mac;
    struct in6_addr addr;
    unsigned expired_time;
    LIST_ENTRY(nd_table_entry_t) entry;
};
LIST_HEAD(nd_table_t, nd_table_entry_t);

struct port_t;


extern int delete_host_route_rule(struct port_t* port, struct in6_addr* addr);
extern int add_host_route_rule(struct port_t* port, struct in6_addr* addr);
extern int add_nd_table_entry(struct port_t* nd_table, struct in6_addr* addr, struct ether_addr* mac, unsigned lifetime);
extern int find_nd_table_entry(struct port_t* nd_table, struct in6_addr* addr, struct nd_table_entry_t** entry);
extern void dump_nd_table(struct port_t* nd_table);
extern int update_nd_table(struct port_t* nd_table, unsigned passed_time);
extern void clear_nd_table(struct port_t* nd_table);

#endif
