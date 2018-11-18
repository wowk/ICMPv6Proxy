#include "ndisc.h"
#include "lib.h"
#include "table.h"
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

    if( !inet_ntop(PF_INET6, &icmp6->to, daddr, sizeof(daddr)) ){
        error(0, errno,"failed to parse dst s6addr");
    }

    const char* type;
    switch( icmp6->comm.icmp6_type ){
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
    printf("if: %s, linkaddr: %s, from: %s, to: %s, type: %s, ", port->ifname, linkaddr, saddr, daddr, type);
}

bool acceptable(struct port_t* port, struct icmp6* icmp6)
{
    switch (icmp6->comm.icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
        break;
    default:
        return false;
    }

    struct in6_addr allnotes;
    struct in6_addr solicitednodes;

    inet_pton(PF_INET6, "ff02::1", &allnotes);
    inet_pton(PF_INET6, "ff02::2", &solicitednodes);

    if(!memcmp(&icmp6->to, &solicitednodes, sizeof(solicitednodes))){
        return true;
    }else if(!memcmp(&icmp6->to, &allnotes, sizeof(allnotes))){
        return true;
    }else if(!memcmp(&icmp6->to, &port->addr, sizeof(port->addr))){
        return true;
    }else if(IN6_IS_ADDR_UNSPECIFIED(&icmp6->from) && IN6_IS_ADDR_MC_LINKLOCAL(&icmp6->to)){
        return true;
    }

    return false;
}

struct icmp6* parse_icmp6(void* pkt, size_t len)
{
    size_t tmp;
    size_t hdrlen;
    size_t offset;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(ethdr, &offset);
    struct icmp6_hdr* icmp6hdr = icmp6_header(ip6hdr, &offset);
 
    if( icmp6hdr->icmp6_type == ND_ROUTER_ADVERT ){
        hdrlen = sizeof(struct nd_router_advert);
    }else if( icmp6hdr->icmp6_type == ND_ROUTER_SOLICIT){
        hdrlen = sizeof(struct nd_router_solicit);
    }else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_ADVERT){
        hdrlen = sizeof(struct nd_neighbor_advert);
    }else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_SOLICIT){
        hdrlen = sizeof(struct nd_neighbor_solicit);
    }else{
        return NULL;
    }

    offset += hdrlen;
    tmp = offset;
    union icmp6_opt* opt = (union icmp6_opt*)(pkt + offset);
    size_t count = 0;
    while (offset < len) {
        count += 1;
        opt = (union icmp6_opt*)((void*)opt + opt->comm.nd_opt_len + sizeof(struct nd_opt_hdr));
        offset += (opt->comm.nd_opt_len + sizeof(struct nd_opt_hdr));
    }

    size_t size = sizeof(struct icmp6) + sizeof(union icmp6_opt) * count;
    struct icmp6* icmp6 = (struct icmp6*)malloc(size);
    icmp6->opt_cnt = count;
    if( !icmp6 ){
        error(0, errno, "cant create icmp6 object\n");
        return NULL;
    }

    offset = tmp;
    memcpy(icmp6, icmp6hdr, hdrlen);
    for( size_t i = 0 ; i < count ; i ++ ){
        opt = (union icmp6_opt*)(pkt + offset);
        memcpy(&icmp6->opt[i], opt, opt->comm.nd_opt_len + sizeof(struct nd_opt_hdr));
        offset += (opt->comm.nd_opt_len + sizeof(struct nd_opt_hdr));
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

    for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++){
        if(icmp6->opt[i].comm.nd_opt_type != ND_OPT_SOURCE_LINKADDR){
            continue;
        }
        opt = &icmp6->opt[i];
        break;
    }

    if( opt ){
        memcpy(&opt->slinkaddr.addr, mac, sizeof(*mac));
    }

    return 0;
}

int send_ra(struct icmp6_proxy_t* proxy, struct icmp6* icmp6)
{
    disable_ra_if_got_same_prefix(icmp6);
    replace_src_linkaddr(icmp6, &proxy->lan.mac);

    struct iovec iovec[icmp6->opt_cnt + 1];

    iovec[0].iov_base   = &icmp6->ra;
    iovec[0].iov_len    = sizeof(icmp6->ra);

    for( size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ){
        iovec[i+1].iov_base = &icmp6->opt[i];
        iovec[i+1].iov_len  = icmp6->opt[i].comm.nd_opt_len + sizeof(struct nd_opt_hdr);
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

    ssize_t retlen;
    while( 0 > (retlen = sendmsg(proxy->lan.icmp6sock, &msghdr, 0)) && errno == EINTR);
    if( retlen < 0 ){
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
    na.nd_na_flags_reserved = ND_NA_FLAG_ROUTER|ND_NA_FLAG_SOLICITED;
    memcpy(&na.nd_na_target, target, sizeof(*target));

    opt_linkaddr.nd_opt_type    = ND_OPT_TARGET_LINKADDR;
    opt_linkaddr.nd_opt_len     = sizeof(*linkaddr);
    memcpy(&opt_linkaddr.addr, linkaddr, sizeof(*linkaddr));
    return send_pkt(port, &icmp6->from, 2, &na, sizeof(na), &opt_linkaddr, sizeof(opt_linkaddr));
}

int send_ns(struct port_t* port, struct icmp6* icmp, struct in6_addr* target)
{
    return 0;
}

int handle_wan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len)
{
    size_t offset = 0;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(pkt, &offset);
    struct icmp6* icmp6 = parse_icmp6(pkt, len);

    if(!icmp6){
        return 0;
    }else if(!acceptable(&proxy->wan, icmp6)){
        printf("denied\n");
        goto RETURN;
    }

    int ret = 0;

    dump_icmp_pkt(&proxy->wan, icmp6);
    if( icmp6->comm.icmp6_type == ND_ROUTER_ADVERT && proxy->ra_proxy ){
        printf("forward RA\n");
        ret = send_ra(proxy, icmp6);
    }else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT && proxy->dad_proxy ){
        /* icmp6->ns.nd_ns_target is at wan side, we dont care */
        struct nd_table_entry_t* entry;
        ret = find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
        if( entry ){
            goto RETURN;
        }

        if(IN6_IS_ADDR_UNSPECIFIED(&icmp6->from) && IN6_IS_ADDR_MULTICAST(&icmp6->to)){
            /* this is a DAD packet */
            ret = find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ){
                /* send NA paccket with EWMTA2.4's mac to the host at wan side */
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &entry->mac);
            }else{
                add_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, (struct ether_addr*)ethdr->ether_shost);
            }
        }else{
            /* normal NS packet */
            ret = find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ){
                /* send NA packet to WAN */
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &entry->mac);
            }else{
                /* send NS packet to LAN */
                send_ns(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target);
            }
        }
    }else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT && proxy->dad_proxy ){
        union icmp6_opt* opt = NULL;
        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ){
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR ){
                continue;
            }
            opt = &icmp6->opt[i];
            add_nd_table_entry(&proxy->wan.nd_table, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr);
            break;
        }
    }else{
       /* dont care about RS packet */
    }

RETURN:
    free(icmp6);
    return ret;
}

int handle_lan_side(struct icmp6_proxy_t* proxy, void* pkt, size_t len)
{
    size_t offset = 0;
    union icmp6_opt* opt = NULL;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(pkt, &offset);
    struct icmp6* icmp6 = parse_icmp6(pkt, len);

    if(!icmp6){
        return 0;
    }else if(!acceptable(&proxy->lan, icmp6)){
        goto RETURN;
    }

    dump_icmp_pkt(&proxy->lan, icmp6);
    if(icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT && proxy->dad_proxy){
        struct nd_table_entry_t* entry = NULL;
        /* if NS packet from LAN side */
        find_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, &entry);
        if( entry ){
            goto RETURN;
        }

        if( IN6_IS_ADDR_UNSPECIFIED(&ip6hdr->ip6_src) && IN6_IS_ADDR_MC_LINKLOCAL(&ip6hdr->ip6_dst)){
            /* this is a DAD packet */
            find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry ){
                /* send NA paccket with EWMTA2.4's mac to the host at lan side */
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &entry->mac);
            }else{
                add_nd_table_entry(&proxy->lan.nd_table, &icmp6->ns.nd_ns_target, (struct ether_addr*)ethdr->ether_shost);
            }
        }else{
            /* normal NS packet */
            find_nd_table_entry(&proxy->wan.nd_table, &icmp6->ns.nd_ns_target, &entry);
            if( entry){
                /* send NA to LAN side */
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &entry->mac);
            }else{
                /* send NS to WAN side */
                send_ns(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target);
            }
        }
    }else if(icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT && proxy->dad_proxy){
        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ){
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR )
                continue;
            opt = &icmp6->opt[i];
            break;
        }
        if( opt ){
            add_nd_table_entry(&proxy->lan.nd_table, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr);
        }
    }else if(icmp6->comm.icmp6_type == ND_ROUTER_ADVERT || icmp6->comm.icmp6_type == ND_ROUTER_SOLICIT){
        /* dont care, RADVD will deal with it */
    }

RETURN:
    free(icmp6);
    return 0;
}
