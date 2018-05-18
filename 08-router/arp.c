#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "log.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void arp_send_request(iface_info_t *iface, u32 dst_ip) {

    void *packet = malloc(ETHER_HDR_SIZE + ETHER_ARP_SIZE);
    struct ether_header *eth = (struct ether_header *) packet;
    memset(eth->ether_dhost, 0xFF, ETH_ALEN);
    memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);
    struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    arp->arp_hrd = htons(0x1);
    arp->arp_pro = htons(0x0800);
    arp->arp_hln = 0x6;
    arp->arp_pln = 0x4;
    arp->arp_op = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
    arp->arp_spa = htonl(iface->ip);
    memset(arp->arp_tha, 0, ETH_ALEN);
    arp->arp_tpa = htonl(dst_ip);
    
    iface_send_packet(iface, packet, ETHER_HDR_SIZE + ETHER_ARP_SIZE);
}

void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr) {

    void *packet = malloc(ETHER_HDR_SIZE + ETHER_ARP_SIZE);
    struct ether_header *eth = (struct ether_header *) packet;
    memcpy(eth->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
    memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    arp->arp_hrd = htons(0x1);
    arp->arp_pro = htons(0x0800);
    arp->arp_hln = 0x6;
    arp->arp_pln = 0x4;
    arp->arp_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
    arp->arp_spa = htonl(iface->ip);
    memcpy(arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
    arp->arp_tpa = htonl(req_hdr->arp_spa);

    iface_send_packet(iface, packet, ETHER_HDR_SIZE + ETHER_ARP_SIZE);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len) {
    struct ether_arp *req_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    if (ntohs(req_hdr->arp_op) == ARPOP_REQUEST){
        if (ntohl(req_hdr->arp_tpa) == iface->ip)
            arp_send_reply(iface, req_hdr);
    } else {
        arpcache_insert(ntohl(req_hdr->arp_spa), req_hdr->arp_sha);
    }
    return;
}

// send (IP) packet through arpcache lookup
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len) {
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);

    u8 dst_mac[ETH_ALEN];
    int found = arpcache_lookup(dst_ip, dst_mac);
    if (found) {
        log(DEBUG, "lookup "IP_FMT" success, pend this packet", HOST_IP_FMT_STR(dst_ip));
        memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
        iface_send_packet(iface, packet, len);
    } else {
        log(DEBUG, "lookup "IP_FMT" failed, pend this packet", HOST_IP_FMT_STR(dst_ip));
        arpcache_append_packet(iface, dst_ip, packet, len);
    }
}
