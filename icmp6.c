#include "icmp6.h"
#include "lib.h"
#include "fdb.h"
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


static struct ra_info_t* find_ra_info_by_prefix(struct port_t* port, struct icmp6_opt* info)
{
    struct ra_info_t* ri;
    struct icmp6_opt* opt;

    TAILQ_FOREACH(ri, &port->ra_list, entry){
        opt = (struct icmp6_opt*)((void*)ri + ri->pref_hdr_offset);
        if( opt->prefix.nd_opt_pi_prefix_len != info->prefix.nd_opt_pi_prefix_len ){
            continue;
        }else if( !IN6_ARE_ADDR_EQUAL(&opt->prefix.nd_opt_pi_prefix, &info->prefix.nd_opt_pi_prefix) ){
            continue;
        }
        break;
    }

    return ri;
}

static struct ra_info_t* add_ra_info(struct port_t* port, struct icmp6* icmp6)
{
    struct ra_info_t* ri;
    struct icmp6_opt* opt;

    opt = find_nd_option(icmp6, len, ND_OPT_PREFIX_INFORMATION);
    if( !opt ){
        return NULL;
    }

    /* find|create new RA node */
    ri = find_ra_info_by_prefix(port, opt);
    if( !ri ){
        ri = (struct ra_info_t*)malloc(sizeof(struct ra_info_t) + icmp6->len);
        if( !ri ){
            error(0, errno, "failed to create new RA info node");
            return NULL;
        }
    }
    TAILQ_INSERT_HEAD(&port->ra_list, ri, entry);

    /* update info */
    struct sysinfo si;
    sysinfo(&si);
    ri->expired_time = si.uptime + opt->prefix.nd_opt_pi_valid_time;
    ri->pref_hdr_offset = (size_t)pi - (size_t)ra;
    if( icmp6->len > ri->info->len ){
        ri = (struct icmp6*)realloc(ri, icmp6->len);
        memcpy(ri->info, icmp6, icmp6->len);
    }

    return ri;
}

static void delete_ra_info(struct port_t* port, struct ra_info_t* info)
{
    TAILQ_REMOVE(&port->ra_list, info, entry);
    free(info);
}

static void update_ra_info(struct port_t* port)
{
    struct sysinfo si;
    struct ra_info_t* ri;
    struct ra_info_t* deleted;

    sysinfo(&si);
    deleted = NULL;

    TAILQ_FOREACH(ri, &port->ra_list, entry){
        if( deleted ){
            delete_ra_info(port, deleted);
            deleted = NULL;
        }
        if( si.uptime > ri->expired_time){
            deleted = ri;
        }
    }
    if( deleted ){
        delete_ra_info(port, deleted);
    }
}

static void clear_ra_info(struct port_t* port)
{
    struct ra_info_t* pi;
    struct ra_info_t* deleted;

    deleted = NULL;
    TAILQ_FOREACH(pi, &port->ra_list, entry){
        if( deleted ){
            delete_ra_info(port, deleted);
            deleted = NULL;
        }
        pi = deleted;
    }
}

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

struct icmp6* find_icmp6(void* buffer, size_t len)
{
    size_t offset = 0;
    struct ip6_hdr* ipv6hdr = ipv6_header(buffer, &offset);
    struct icmp6* icmp6hdr = icmp6_header(ipv6hdr, &offset);
    icmp6
    return icmp6hdr;
}

struct nd_opt_hdr* find_nd_option(struct icmp6_hdr* hdr, size_t len, uint32_t option)
{
    size_t offset;

    switch(hdr->icmp6_type){
    case ND_ROUTER_ADVERT:
        offset = sizeof(struct nd_router_advert);
        break;
    case ND_ROUTER_SOLICIT:
        offset = sizeof(struct nd_router_solicit);
        break;
    case ND_NEIGHBOR_ADVERT:
        offset = sizeof(struct nd_neighbor_advert);
        break;
    case ND_NEIGHBOR_SOLICIT:
        offset = sizeof(struct nd_neighbor_solicit);
        break;
    default:
        printf("do not care\n");
        return NULL;
    }

    struct nd_opt_hdr* opthdr = (struct nd_opt_hdr*)((void*)hdr + offset);
    while( offset < len && opthdr->nd_opt_type != option ){
        offset += opthdr->nd_opt_len;
        opthdr = (struct nd_opt_hdr*)((void*)hdr + offset);
    }

    if( offset >= len ){
        return NULL;
    }

    return opthdr;
}

int send_ra(struct port_t* port, struct ra_info_t* pi, struct in6_addr* addr)
{
    int ret;
    struct nd_router_advert hdr;

    hdr.nd_ra_type  = ND_ROUTER_ADVERT;
    hdr.nd_ra_code  = 0;
    hdr.nd_ra_cksum = 0;
    hdr.nd_ra_curhoplimit = 64;
    hdr.nd_ra_flags_reserved = ND_RA_FLAG_MANAGED;
    hdr.nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
    hdr.nd_ra_router_lifetime = 1800;
    hdr.nd_ra_reachable = 0;
    hdr.nd_ra_retransmit = 0;

    struct nd_opt_mtu mtu;
    mtu.nd_opt_mtu_mtu = 1500;
    mtu.nd_opt_mtu_type = ND_OPT_MTU;
    mtu.nd_opt_mtu_len = sizeof(mtu);
    mtu.nd_opt_mtu_reserved = 0;

    struct nd_opt_source_link_addr {
        uint8_t type;
        uint8_t len;
        struct ether_addr mac;
    } __attribute__((packed)) opt_linkaddr;

    opt_linkaddr.type = ND_OPT_SOURCE_LINKADDR;
    opt_linkaddr.len  = sizeof(struct nd_opt_source_link_addr);
    memcpy(&opt_linkaddr.mac, &port->mac, sizeof(port->mac));

    ret = send_pkt(port, addr, 4, &hdr, sizeof(hdr), &mtu, sizeof(mtu),
                    &opt_linkaddr, sizeof(opt_linkaddr), &pi->info, sizeof(pi->info));

    return ret;
}



int handle_wan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->wan, hdr, from, to);

    /* proxy RA packet from wan side */
    if( hdr->icmp6_type == ND_ROUTER_ADVERT ){
        if( !proxy->ra_proxy ){
            return 0;
        }

        struct nd_opt_hdr* opthdr;
        struct nd_opt_prefix_info* pref;

        /* add new incoming prefix*/
        add_ra_info(&proxy->wan, hdr, len);

        /* forward it to LAN side */
        opthdr = find_nd_option(hdr, len, ND_OPT_SOURCE_LINKADDR);
        if( !opthdr ){
            return 0;
        }

        void* linkaddr_pos = (void*)(opthdr) + opthdr->nd_opt_len;
        memcpy(linkaddr_pos, &proxy->lan.mac, sizeof(proxy->lan.mac));

        send_pkt(&proxy->lan, to, 1, hdr, len);

        return 0;
    }

    if( hdr->icmp6_type == ND_NEIGHBOR_SOLICIT ){

    }

    return 0;
}

int handle_lan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->lan, hdr, from, to);

    if( hdr->icmp6_type == ND_ROUTER_ADVERT ){
        /* if ra_proxy is disabled or has gotten same prefix, ignore this pkt */
        if( !proxy->ra_proxy || proxy->got_same_prefix_at_both_side){
            return 0;
        }

        struct nd_opt_hdr* opthdr;
        struct nd_opt_prefix_info* pref;

        opthdr = find_nd_option(hdr, len, ND_OPT_PREFIX_INFORMATION);
        /* dont interset in RA packet without prefix option */
        if( !opthdr ){
            return 0;
        }
        pref = (struct nd_opt_prefix_info*)opthdr;

        /* remove timeout prefix item */
        update_ra_info(&proxy->lan);
        update_ra_info(&proxy->wan);

        /* add new incoming prefix*/
        add_ra_info(&proxy->lan, pref);

        if( find_prefix_info(&proxy->wan, pref) ){
            proxy->got_same_prefix_at_both_side = true;
            return 0;
        }

        return 0;
    }

    if( hdr->icmp6_type == ND_ROUTER_SOLICIT ){
        if( !proxy->ra_proxy || proxy->got_same_prefix_at_both_side ){
            return 0;
        }

        struct ra_info_t* pi;
        TAILQ_FOREACH(pi, &proxy->wan.ra_list, entry){
            send_ra(&proxy->wan, pi, from);
        }

        return 0;
    }

    if( hdr->icmp6_type == ND_NEIGHBOR_SOLICIT ){
        struct nd_neighbor_solicit* ns = (struct nd_neighbor_solicit*)hdr;
        struct in6_addr* target_v6addr = (struct in6_addr*)(ns + 1);

        struct nd_opt_hdr* opthdr = find_nd_option(hdr, len, ND_OPT_SOURCE_LINKADDR);
        if( !opthdr ){
            return 0;
        }
        struct ether_addr* linkaddr = (struct ether_addr*)(opthdr + 1);
        if( IN6_IS_ADDR_UNSPECIFIED(from) && IN6_IS_ADDR_MULTICAST(to) ){
            add_fdb_entry(&proxy->fdb, &proxy->lan, target_v6addr, linkaddr);
        }


        return 0;
    }

    return 0;
}
