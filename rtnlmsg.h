#ifndef ICMP6_RTNLMSG_H__
#define ICMP6_RTNLMSG_H__

#include "proxy.h"
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

struct rtattrs_t {
    struct rtattr* tb[128];
    uint64_t mask;
};

extern int create_rtnl_mc_socket(struct nd_proxy_t* proxy, uint32_t nl_groups);
extern int handle_rtnl_mc_msg(struct nd_proxy_t* proxy, void* msg, size_t len);

#endif
