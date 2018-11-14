#include "icmp6.h"
#include <stdio.h>
#include <error.h>
#include <errno.h>   
#include <netinet/in.h>
#include <arpa/inet.h>


static void dump_icmp_pkt(struct port_t* port, struct icmp6_hdr* hdr, struct in6_addr* from, struct in6_addr* to)
{
    char saddr[INET6_ADDRSTRLEN] = "";
    char daddr[INET6_ADDRSTRLEN] = "";

    if(  !inet_ntop(PF_INET6, from, saddr, sizeof(saddr)) )
        error(0, errno,"failed to parse src s6addr");

    if( !inet_ntop(PF_INET6, to, daddr, sizeof(daddr)) ){
        error(0, errno,"failed to parse dst s6addr");
    }

    char* type;
    switch( hdr->icmp6_type ){
    case ND_ROUTER_ADVERT:
        type = "RA";
        break;
    case ND_ROUTER_SOLICIT:
        type = "RS";
        break;
    case ND_NEIGHBOR_ADVERT:
        type = "NA";
        break;
    case ND_NEIGHBOR_SOLICIT:
        type = "NS";
        break;
    case ND_REDIRECT:
        type = "REDIRECT";
        break;
    default:
        type = "Other";
        break;
    }

    printf("if: %s, from: %s, to: %s, type: %s\n", port->ifname, saddr, daddr, type);
}

int handle_wan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->wan, hdr, from, to);
    return 0;
}

int handle_lan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->lan, hdr, from, to);
    return 0;
}
