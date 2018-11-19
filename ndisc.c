#include "ndisc.h"
#include "lib.h"
#include "table.h"
//#include "debug.h"
#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <sys/queue.h>
#include <sys/sysinfo.h>
#include <netinet/ip6.h>


static void dump_icmp_pkt(struct port_t* port, struct icmp6* icmp6)
{
    char saddr[INET6_ADDRSTRLEN] = "";
    char daddr[INET6_ADDRSTRLEN] = "";

    if(  !inet_ntop(PF_INET6, &icmp6->from, saddr, sizeof(saddr)) )
        error(0, errno,"failed to parse src s6addr");

    if( !inet_ntop(PF_INET6, &icmp6->to, daddr, sizeof(daddr)) ) {
        error(0, errno,"failed to parse dst s6addr");
    }

    const char* type;
    switch( icmp6->comm.icmp6_type ) {
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

    char linkaddr[INET6_ADDRSTRLEN] = "";
    inet_ntop(PF_INET6, &port->addr, linkaddr, sizeof(linkaddr));
    printf("if: %s, portaddr: %s, from: %s, to: %s, type: %s\n", port->ifname, linkaddr, saddr, daddr, type);
}

bool acceptable(struct icmp6_hdr* icmp6)
{
    switch (icmp6->icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
        break;
    default:
        return false;
    }

    return true;
}

bool need_forward(struct port_t* port, struct icmp6* icmp6)
{
    struct in6_addr allnotes;
    struct in6_addr solicitednodes;

    inet_pton(PF_INET6, "ff02::1", &allnotes);
    inet_pton(PF_INET6, "ff02::2", &solicitednodes);

    if(!memcmp(&icmp6->to, &solicitednodes, sizeof(solicitednodes))) {
        return true;
    } else if(!memcmp(&icmp6->to, &allnotes, sizeof(allnotes))) {
        return true;
    } else if(!memcmp(&icmp6->to, &port->addr, sizeof(port->addr))) {
        return true;
    } else if(IN6_IS_ADDR_UNSPECIFIED(&icmp6->from) && IN6_IS_ADDR_MC_LINKLOCAL(&icmp6->to)) {
        return true;
    }
}

struct icmp6* parse_icmp6(void* pkt, size_t len)
{
    size_t tmp;
    size_t hdrlen;
    size_t offset;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(ethdr, &offset);
    struct icmp6_hdr* icmp6hdr = icmp6_header(ip6hdr, &offset);

    if( icmp6hdr->icmp6_type == ND_ROUTER_ADVERT ) {
        hdrlen = sizeof(struct nd_router_advert);
    } else if( icmp6hdr->icmp6_type == ND_ROUTER_SOLICIT) {
        hdrlen = sizeof(struct nd_router_solicit);
    } else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_ADVERT) {
        hdrlen = sizeof(struct nd_neighbor_advert);
    } else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_SOLICIT) {
        hdrlen = sizeof(struct nd_neighbor_solicit);
    } else {
        return NULL;
    }

    offset += hdrlen;
    tmp = offset;
    union icmp6_opt* opt = (union icmp6_opt*)(pkt + offset);
    size_t count = 0;
    while (offset < len && opt->comm.nd_opt_type) {
        count += 1;
        opt = (union icmp6_opt*)((void*)opt + opt->comm.nd_opt_len * 8);
        offset += opt->comm.nd_opt_len * 8;
    }

    size_t size = sizeof(struct icmp6) + sizeof(union icmp6_opt) * count;
    struct icmp6* icmp6 = (struct icmp6*)malloc(size);
    icmp6->opt_cnt = count;
    if( !icmp6 ) {
        error(0, errno, "cant create icmp6 object\n");
        return NULL;
    }

    offset = tmp;
    memcpy(&icmp6->comm, icmp6hdr, hdrlen);
    for( size_t i = 0 ; i < count ; i ++ ) {
        opt = (union icmp6_opt*)(pkt + offset);
        memcpy(&icmp6->opt[i], opt, opt->comm.nd_opt_len * 8);
        offset += opt->comm.nd_opt_len * 8;
    }

    memcpy(&icmp6->from, &ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src));
    memcpy(&icmp6->to, &ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst));

    return icmp6;
}

int disable_ra_if_got_same_prefix(struct icmp6* icmp6)
{}

int replace_src_linkaddr(struct icmp6* icmp6, struct ether_addr* mac)
{
    union icmp6_opt* opt = NULL;

    for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++) {
        if(icmp6->opt[i].comm.nd_opt_type != ND_OPT_SOURCE_LINKADDR) {
            continue;
        }
        opt = &icmp6->opt[i];
        break;
    }

    if( opt ) {
        memcpy(&opt->slinkaddr.addr, mac, sizeof(*mac));
    }

    return 0;
}

int send_ra(struct port_t* port, struct icmp6* icmp6)
{
    disable_ra_if_got_same_prefix(icmp6);
    replace_src_linkaddr(icmp6, &port->mac);

    struct iovec iovec[icmp6->opt_cnt + 1];

    iovec[0].iov_base   = &icmp6->ra;
    iovec[0].iov_len    = sizeof(icmp6->ra);

    for( size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
        iovec[i+1].iov_base = &icmp6->opt[i];
        iovec[i+1].iov_len  = icmp6->opt[i].comm.nd_opt_len * 8;
    }

    struct sockaddr_in6 si6;
    memset(&si6, 0, sizeof(si6));
    si6.sin6_family     = PF_INET6;
    //memcpy(&si6.sin6_addr, &icmp6->to, sizeof(icmp6->to));
    inet_pton(PF_INET6, "ff02::1", &si6.sin6_addr);

    struct msghdr msghdr;
    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name     = &si6;
    msghdr.msg_namelen  = sizeof(si6);
    msghdr.msg_iov      = iovec;
    msghdr.msg_iovlen   = sizeof(iovec)/sizeof(iovec[0]);

    /* must set to 255, or the LAN host will not accept this RA packet */
    unsigned hops = 255;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) ) {
        error(0, errno, "failed to set multicast hops");
        return -errno;
    }

    ssize_t retlen;
    while( 0 > (retlen = sendmsg(port->icmp6sock, &msghdr, 0)) && errno == EINTR);
    if( retlen < 0 ) {
        error(0, errno, "failed to forward ICMPv6 packet\n");
    }

    return retlen;
}

int send_na(struct port_t* port, struct icmp6* icmp6, struct in6_addr* target, struct ether_addr* linkaddr)
{
    struct nd_neighbor_advert na;
    struct nd_opt_linkaddr opt_linkaddr;

    na.nd_na_type   = ND_NEIGHBOR_ADVERT;
    na.nd_na_code   = 0;
    na.nd_na_cksum  = 0;
    na.nd_na_flags_reserved = ND_NA_FLAG_ROUTER;
    if( IN6_IS_ADDR_MULTICAST(target) ){
        na.nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
    }
    memcpy(&na.nd_na_target, target, sizeof(*target));

    opt_linkaddr.nd_opt_type    = ND_OPT_SOURCE_LINKADDR;
    memcpy(&opt_linkaddr.addr, linkaddr, sizeof(*linkaddr));

    /* must set to 255, or the LAN host will not accept this RA packet */
    unsigned hops = 255;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) ) {
        error(0, errno, "failed to set multicast hops");
        return -errno;
    }

    return send_pkt(port, &icmp6->from, 1, &na, sizeof(na));//, &opt_linkaddr, sizeof(opt_linkaddr));
}

int send_ns(struct port_t* port, struct icmp6* icmp, struct in6_addr* target)
{
    struct nd_neighbor_solicit ns;
    struct nd_opt_linkaddr opt_linkaddr;

    ns.nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns.nd_ns_code   = 0;
    ns.nd_ns_cksum  = 0;
    ns.nd_ns_reserved   = 0;
    memcpy(&ns.nd_ns_target, target, sizeof(*target));
    opt_linkaddr.nd_opt_type    = ND_OPT_SOURCE_LINKADDR;
    opt_linkaddr.nd_opt_len     = sizeof(opt_linkaddr) >> 3;
    memcpy(&opt_linkaddr.addr, &port->mac, sizeof(port->mac));

    struct in6_addr dstaddr;
    inet_pton(PF_INET6, "ff02::01:ff:00:00:00", &dstaddr);
    memcpy(dstaddr.s6_addr + 13, target->s6_addr + 13, 3);

    /* must set to 255, or the LAN/WAN host will not accept this RA packet */
    unsigned hops = 255;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) ) {
        error(0, errno, "failed to set multicast hops");
        return -errno;
    }

    return send_pkt(port, target /*&dstaddr*/, 2, &ns, sizeof(ns), &opt_linkaddr, sizeof(opt_linkaddr));
}

int handle_wan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len)
{
    size_t offset = 0;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(pkt, &offset);
    struct icmp6_hdr* icmp6hdr = icmp6_header(ip6hdr, &offset);

    if(!acceptable(icmp6hdr)) {
        return 0;
    } else if(is_self_addr(&ip6hdr->ip6_src)) {
        return 0;
    }

    struct icmp6* icmp6 = parse_icmp6(pkt, len);
    if( !icmp6 ) {
        return 0;
    }

    int ret = 0;

    if( icmp6->comm.icmp6_type == ND_ROUTER_ADVERT ) {
        if(proxy->ra_proxy && need_forward(&proxy->wan, icmp6)) {
            dump_icmp_pkt(&proxy->wan, icmp6);
            printf("\tforward RA\n");
            ret = send_ra(&proxy->lan, icmp6);
        }
    } else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        dump_icmp_pkt(&proxy->wan, icmp6);

        /* icmp6->ns.nd_ns_target is at wan side, we dont care */
        struct nd_table_entry_t* entry;
        dump_nd_table(&proxy->wan.nd_table);
        ret = find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
        if( entry ) {
            printf("\tentry found at wan side, ignore this NS packet\n");
            goto RETURN;
        }

        if(IN6_IS_ADDR_UNSPECIFIED(&icmp6->from) && IN6_IS_ADDR_MULTICAST(&icmp6->to)) {
            /* this is a DAD packet */
            printf("\tThis is a DAD packet\n");
            ret = find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ) {
                printf("\t\tfound entry at LAN side, duplicated, send NA to WAN side\n");
                /* send NA paccket with EWMTA2.4's mac to the host at wan side */
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &proxy->wan.mac);
            } else {
                printf("\t\tno entry at LAN side, add entry to WAN side\n");
                add_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, (struct ether_addr*)ethdr->ether_shost);
            }
        } else {
            /* normal NS packet */
            printf("\tThis is a Normal NS packet\n");
            ret = find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ) {
                printf("\t\tfound entry at LAN side, send NA to WAN side\n");
                /* send NA packet to WAN */
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &proxy->wan.mac);
            } else {
                /* send NS packet to LAN */
                printf("\t\tno entry at LAN side, try to find it by sending NS to LAN side\n");
                if( 0 > send_ns(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target) ) {
                    error(0, errno, "failed to send NS");
                }
            }
        }
    } else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT ) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }
        if( !IN6_ARE_ADDR_EQUAL(&icmp6->to, &proxy->wan.addr) ) {
            goto RETURN;
        }

        dump_icmp_pkt(&proxy->wan, icmp6);
        union icmp6_opt* opt = NULL;
        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR ) {
                continue;
            }
            opt = &icmp6->opt[i];
            break;
        }
        if( opt ) {
            printf("\tadd entry to WAN side with target option value\n");
            add_nd_table_entry(&proxy->wan.nd_table, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr);
        } else {
            printf("\tadd entry to WAN side with source mac address\n");
            add_nd_table_entry(&proxy->wan.nd_table, &icmp6->na.nd_na_target, (struct ether_addr*)&ethdr->ether_shost);
        }
    } else {
        /* dont care about RS packet */
    }

RETURN:
    printf("\n\n");
    free(icmp6);
    return ret;
}

int handle_lan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len)
{
    size_t offset = 0;
    union icmp6_opt* opt = NULL;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(pkt, &offset);
    struct icmp6_hdr* icmp6hdr = icmp6_header(ip6hdr, &offset);

    if(!acceptable(icmp6hdr)) {
        return 0;
    } else if(is_self_addr(&ip6hdr->ip6_src)) {
        return 0;
    }

    struct icmp6* icmp6 = parse_icmp6(pkt, len);
    if( !icmp6 ) {
        return 0;
    }

    dump_icmp_pkt(&proxy->lan, icmp6);
    if(icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT ) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        struct nd_table_entry_t* entry = NULL;
        /* if NS packet from LAN side */
        dump_nd_table(&proxy->wan.nd_table);
        find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
        if( entry ) {
            printf("\tentry found at LAN side, ignore this NS packet\n");
            goto RETURN;
        }

        if( IN6_IS_ADDR_UNSPECIFIED(&ip6hdr->ip6_src) && IN6_IS_ADDR_MC_LINKLOCAL(&ip6hdr->ip6_dst)) {
            /* this is a DAD packet */
            find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ) {
                /* send NA paccket with EWMTA2.4's mac to the host at lan side */
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &proxy->lan.mac);
            } else {
                add_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, (struct ether_addr*)ethdr->ether_shost);
            }
        } else {
            /* normal NS packet */
            printf("\tThis is a Normal NS packet\n");
            find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry) {
                /* send NA to LAN side */
                printf("\t\tfound entry at LAN side, send NA to LAN side\n");
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &proxy->lan.mac);
            } else {
                /* send NS to WAN side */
                printf("\t\tno entry at WAN side, try to find it by sending NS to WAN side\n");
                if( 0 > send_ns(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target) ) {
                    error(0, errno, "failed to send NS to WAN side");
                }
            }
        }
    } else if(icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        if( !IN6_ARE_ADDR_EQUAL(&icmp6->to, &proxy->lan.addr) ) {
            goto RETURN;
        }

        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR )
                continue;
            opt = &icmp6->opt[i];
            break;
        }
        if( opt ) {
            add_nd_table_entry(&proxy->lan.nd_table, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr);
        } else {
            add_nd_table_entry(&proxy->lan.nd_table, &icmp6->na.nd_na_target, (struct ether_addr*)&ethdr->ether_shost);
        }
    } else if(icmp6->comm.icmp6_type == ND_ROUTER_ADVERT || icmp6->comm.icmp6_type == ND_ROUTER_SOLICIT) {
        /* dont care, RADVD will deal with it */
    }

RETURN:
    printf("\n\n");
    free(icmp6);
    return 0;
}
