#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

//create a new mapping entry
struct nat_mapping *init_new_mapping(u32 saddr, u16 sport, u16 new_port){
    struct nat_mapping *new = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
    new->internal_ip = saddr;
    new->internal_port = sport;
    new->external_ip = (nat.external_iface)->ip;
    new->external_port = new_port;
    new->update_time = time(NULL);
    bzero(&(new->conn), sizeof(struct nat_connection));   
    return new;
}

//random choose an unused port id
u16 assign_external_port(){
    u16 random = 0;
    int bound = NAT_PORT_MAX - NAT_PORT_MIN;
    while(1){
        random = NAT_PORT_MIN + rand() % bound; // NAT_PORT_MIN ~ NAT_PORT_MAX
        if(nat.assigned_ports[random] == 0)
            break;
    }
    nat.assigned_ports[random] = 1;
    return random;
}

//NAT change ip and tcp header
void update_ip_and_tcp_header(char *packet, u32 addr, u16 port, int dir){
    struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
    struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);
    if(dir == DIR_IN){
        ip_hdr->daddr  = htonl(addr);
        tcp_hdr->dport = htons(port);
    } 
    else{
        ip_hdr->saddr  = htonl(addr);
        tcp_hdr->sport = htons(port);
    }
    tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
    ip_hdr->checksum  = ip_checksum(ip_hdr);
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
    u32 saddr = ntohl(ip->saddr);
    u32 daddr = ntohl(ip->daddr);

    if((longest_prefix_match((saddr))->iface->ip == nat.internal_iface->ip) && 
    	(longest_prefix_match((daddr))->iface->ip == nat.external_iface->ip))
        return DIR_OUT;
    else if((daddr == nat.external_iface->ip) && 
    	(longest_prefix_match((saddr))->iface->ip == nat.external_iface->ip))
        return DIR_IN;
    else
        return DIR_INVALID;
}

// for caculate ip+port hash
u8 caculate_hash8(u16 serv_port, u32 serv_ip){
    char buf[6];    
    memcpy(buf, &serv_ip, 4);
    memcpy(buf+4, &serv_port, 2);
    return hash8(buf, 6);
}

void recover_unused_conn(struct nat_mapping *pos, struct tcphdr *tcp){
    if(tcp->flags == TCP_FIN + TCP_ACK)
        (pos->conn).external_fin = 1;

    if(tcp->flags == TCP_RST){
        if((pos->conn).internal_fin + (pos->conn).external_fin == 2){
            nat.assigned_ports[pos->external_port] = 0;
            list_delete_entry(&(pos->list));
        }
    }
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	fprintf(stdout, "TODO: do translation for this packet.\n");
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
    struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);
    u16 sport = ntohs(tcp_hdr->sport);
    u32 saddr = ntohl(ip_hdr->saddr);
    u16 dport = ntohs(tcp_hdr->dport);
    u32 daddr = ntohl(ip_hdr->daddr);
    u32 serv_ip = (dir == DIR_IN) ? saddr : daddr;
    u16 serv_port = (dir == DIR_IN) ? sport : dport;
    u8  hash_value = caculate_hash8(serv_port, serv_ip);
    struct list_head * mapping_entry = &(nat.nat_mapping_list[hash_value]);
    pthread_mutex_lock(&nat.lock);
    struct nat_mapping * pos = NULL, *q = NULL;
    if(!list_empty(mapping_entry)){
        list_for_each_entry_safe(pos, q, mapping_entry, list){
            if(dir == DIR_OUT && NAT_MAPPING_MATCH_IN(pos,saddr,sport)){
                update_ip_and_tcp_header(packet, nat.external_iface->ip, pos->external_port, DIR_OUT);
                pos->update_time = time(NULL);
                ip_send_packet(packet, len);
                recover_unused_conn(pos, tcp_hdr);
                pthread_mutex_unlock(&nat.lock);
                return ;
            }
            else if(dir == DIR_IN && NAT_MAPPING_MATCH_EX(pos,daddr,dport)){
                update_ip_and_tcp_header(packet, pos->internal_ip, pos->internal_port, DIR_IN);
                pos->update_time = time(NULL);
                ip_send_packet(packet, len);
                recover_unused_conn(pos, tcp_hdr);
                pthread_mutex_unlock(&nat.lock);
                return ;
            }
        }       
    }
    // nat mapping does not find (OUT)

    u16 new_port = assign_external_port();
    struct nat_mapping *new_mapping = init_new_mapping(saddr,sport,new_port);
    list_add_tail(&(new_mapping->list), mapping_entry);

    update_ip_and_tcp_header(packet, (nat.external_iface)->ip, new_port, DIR_OUT);
    pthread_mutex_unlock(&nat.lock);
    ip_send_packet(packet, len);    
    return ;
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
    struct nat_mapping *pos = NULL, *q = NULL;
    struct list_head *mapping_entry = NULL;
    time_t now = 0;
    while (1) {
        pthread_mutex_lock(&nat.lock);
        now = time(NULL);
        for(int i = 0; i < HASH_8BITS; i++){
            mapping_entry = &(nat.nat_mapping_list[i]);
            list_for_each_entry_safe(pos, q, mapping_entry, list){
                if((now - pos->update_time) > TCP_ESTABLISHED_TIMEOUT){
                    nat.assigned_ports[pos->external_port] = 0;
                    list_delete_entry(&(pos->list));
                }
            }
        }
        pthread_mutex_unlock(&nat.lock);
        sleep(1);
    }

    return NULL;
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *mapping_entry, *q;
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			list_delete_entry(&mapping_entry->list);
			free(mapping_entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
