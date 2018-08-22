#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "packet.h"
#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *dump_database(void *param);



void *dump_database(void *param) {
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    while (1) {
        printf("\n================= Dumping Database - Start =========================\n");
        if (!list_empty(&mospf_db)) {
            list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
                printf("rid  = "IP_FMT"\n", HOST_IP_FMT_STR(db_entry->rid));
                printf("Neighbors\nSUBNET    MASK           RID\n");
                for (int i = 0; i < db_entry->nadv; i++) {
                    printf(IP_FMT"  "IP_FMT"  "IP_FMT"\n",
                           HOST_IP_FMT_STR(db_entry->array[i].subnet),
                           HOST_IP_FMT_STR(db_entry->array[i].mask),
                           HOST_IP_FMT_STR(db_entry->array[i].rid));
                }
                printf("\n");
            }
        } else
            printf("Database is now empty.\n");
        printf("================= Dumping Database - End  =========================\n\n");
        sleep(2);
    }
    return NULL;
}




void mospf_run()
{
	pthread_t hello, lsu, nbr,dump;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&dump, NULL,dump_database,NULL);
}

void send_mospf_lsu() {
    // pre-declarations of variables
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_lsu    * lsu   = NULL;
    struct mospf_lsa    * lsa   = NULL;
    char * packet = NULL, * lsa_packets = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    // count the number of neighbours
    int nbr_num = 0;
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            nbr_num += iface->num_nbr;
    }
    // get informations of all neighbours into lsa
    lsa_packets = (char *)malloc(nbr_num * MOSPF_LSA_SIZE);
    if (!list_empty(&(instance->iface_list))) {
        struct mospf_lsa * lsa_idx = (struct mospf_lsa *)lsa_packets;
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    lsa_idx->subnet = htonl(nbr_entry->nbr_ip & nbr_entry->nbr_mask);
                    lsa_idx->mask   = htonl(nbr_entry->nbr_mask);
                    lsa_idx->rid    = htonl(nbr_entry->nbr_id);
                    lsa_idx++;
                }
            }
        }
    }

    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    // update seq_num
                    instance->sequence_num++;
                    // set up new lsu packet
                    packet = (char *)malloc(LSU_PACKET_LEN(nbr_num));
                    // init ip header
                    ip = packet_to_ip_hdr(packet);
                    ip_init_hdr(ip, iface->ip, nbr_entry->nbr_ip, LSU_PACKET_LEN(nbr_num) - ETHER_HDR_SIZE, IPPROTO_MOSPF);                           
                    // init mospf header
                    mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
                    int mospf_len = LSU_PACKET_LEN(nbr_num) - ETHER_HDR_SIZE - IP_HDR_SIZE(ip);
                    mospf_init_hdr(mospf, MOSPF_TYPE_LSU, mospf_len, instance->router_id, 0);                   
                    // init mospf lsu part
                    lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
                    mospf_init_lsu(lsu, nbr_num);  // lsu, lsu->nadv
                    // set mospf lsa part
                    lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
                    memcpy(lsa, lsa_packets, nbr_num * MOSPF_LSA_SIZE);
                    // update checksum of ip and mospf
                    mospf->checksum = mospf_checksum(mospf);
                    ip->checksum = ip_checksum(ip);
                    // send packet
                    ip_send_packet(packet, LSU_PACKET_LEN(nbr_num));
                }
            }
        }
    }
    free(lsa_packets);
}



void *sending_mospf_hello_thread(void *param)
{
	//fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	int len = MOSPF_HDR_SIZE+MOSPF_HELLO_SIZE+IP_BASE_HDR_SIZE+ETHER_HDR_SIZE;
	iface_info_t *iface;
	struct ether_header *ether_hdr;
	struct iphdr *ip_header;
	struct mospf_hdr *mospf_header;
	struct mospf_hello *hello;
	char *hello_pac;
	while(1){
		list_for_each_entry(iface,&(instance->iface_list),list){
			hello_pac = (char *)malloc(len);
			//set ether header
			u8 mac_temp[ETH_ALEN] = {0x01,0x0,0x5e,0x0,0x0,0x5};
			ether_hdr = (struct ether_header *)hello_pac;
			memcpy(ether_hdr->ether_shost, iface->mac, ETH_ALEN);
	        memcpy(ether_hdr->ether_dhost, mac_temp, ETH_ALEN);
	        ether_hdr->ether_type = ntohs(ETH_P_IP);
			//set ip header
			ip_header = packet_to_ip_hdr(hello_pac);
			ip_init_hdr(ip_header,iface->ip,MOSPF_ALLSPFRouters,len-ETHER_HDR_SIZE,IPPROTO_MOSPF);
			//set mospf header
			mospf_header = packet_to_mospf_hdr(hello_pac);
			mospf_init_hdr(mospf_header,MOSPF_TYPE_HELLO,MOSPF_HDR_SIZE+MOSPF_HELLO_SIZE,instance->router_id,0);
			//set mospf_hello
			hello = (struct mospf_hello *)(((char*)mospf_header) + MOSPF_HDR_SIZE);
			mospf_init_hello(hello,iface->mask);
			//set check sum
			mospf_header->checksum = mospf_checksum(mospf_header);
			ip_header->checksum = ip_checksum(ip_header);
			iface_send_packet(iface,hello_pac,len);
		}
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	//fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	iface_info_t *iface;
	mospf_nbr_t *nbr,*temp;
	while(1){
		pthread_mutex_lock(&mospf_lock);
		list_for_each_entry(iface,&(instance->iface_list),list){
			if(!list_empty(&(iface->nbr_list))){
				list_for_each_entry_safe(nbr,temp,&(iface->nbr_list),list){
					nbr->alive++; // this process scan all nbr once per second
					if(nbr->alive >= MOSPF_NEIGHBOR_TIMEOUT){
						list_delete_entry(&(nbr->list));
						iface->num_nbr--;
						send_mospf_lsu();
					}
				}
			}
		}
		pthread_mutex_unlock(&mospf_lock);
		sleep(1);
	}
	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	//fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	struct iphdr *ip_header = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf_header = packet_to_mospf_hdr(packet);
	struct mospf_hello *hello = (struct mospf_hello *)((char*)mospf_header + MOSPF_HDR_SIZE);
	mospf_nbr_t *nbr;
	bool find = false;
	pthread_mutex_lock(&mospf_lock);
	if(!list_empty(&(iface->nbr_list))){
		list_for_each_entry(nbr,&(iface->nbr_list),list){
			if(nbr->nbr_id == ntohl(mospf_header->rid)){
				nbr->alive = 0; // reset alive count
				find = true;
				break;
			} 
		}
	}

	if(!find){
		(iface->num_nbr)++;
		mospf_nbr_t *new = (mospf_nbr_t *)malloc(MOSPF_NBR_SIZE);
		new->nbr_id = ntohl(mospf_header->rid);
		new->nbr_ip = ntohl(ip_header->saddr);
		new->nbr_mask = ntohl(hello->mask);
		new->alive = 0;
		list_add_tail(&(new->list),&(iface->nbr_list));
		send_mospf_lsu();
	}
	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	//fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	while(1){
        send_mospf_lsu();
        sleep(instance->lsuint);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	/* deal with the lsu  */
 	struct iphdr * ip_header = packet_to_ip_hdr(packet);
    struct mospf_hdr * mospf_header = packet_to_mospf_hdr(packet);
    struct mospf_lsu * lsu   = (struct mospf_lsu *)((char *)mospf_header + MOSPF_HDR_SIZE);
    struct mospf_lsa * lsa   = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
    bool find = false;
    mospf_db_entry_t *db_entry;
    pthread_mutex_lock(&mospf_lock);
    if(!list_empty(&(mospf_db))){
    	list_for_each_entry(db_entry,&mospf_db,list){
    		if(db_entry->rid == ntohl(mospf_header->rid)){
    			find = true;
    			//if the lsu is newer
    			if(db_entry->seq < ntohs(lsu->seq)){
    				db_entry->rid = ntohl(mospf_header->rid);
    				db_entry->seq = ntohs(lsu->seq);
    				db_entry->nadv = ntohl(lsu->nadv);
    				for(int i=0;i<db_entry->nadv;i++,lsa++){
    					db_entry->array[i].subnet = ntohl(lsa->subnet);
    					db_entry->array[i].mask = ntohl(lsa->mask);
    					db_entry->array[i].rid = ntohl(lsa->rid);
    				}
    			}
    			break; // find 
    		}
    	}
    }

	if(!find){   // create a new db_entry
        mospf_db_entry_t *new = (mospf_db_entry_t *)malloc(MOSPF_DB_ENTRY_SIZE);
        new->rid   = ntohl(mospf_header->rid);
        new->seq   = ntohs(lsu->seq);
        new->nadv  = ntohl(lsu->nadv);
        new->array = (struct mospf_lsa *)malloc((new->nadv) * MOSPF_LSA_SIZE);
        for (int i = 0; i < new->nadv; i++, lsa++) {
            new->array[i].subnet = ntohl(lsa->subnet);
            new->array[i].mask   = ntohl(lsa->mask);
            new->array[i].rid    = ntohl(lsa->rid);
        }
        list_add_tail(&(new->list), &mospf_db);
	}
	pthread_mutex_unlock(&mospf_lock);

	/*  forward the lsu  */
	if ((lsu->ttl--) > 0) { // ttl-1
        char * out_packet = NULL;
        struct iphdr        * out_ip    = NULL;
        struct mospf_hdr    * out_mospf = NULL;
        iface_info_t * iface = NULL, * iface_q = NULL;
        mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
        // for each iface and its nbr forward the packet
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if (nbr_entry->nbr_ip != ntohl(ip_header->saddr) && nbr_entry->nbr_id != ntohl(mospf_header->rid)) { // avoid sending packet back to source
                        out_packet = (char *)malloc(len);
                        memcpy(out_packet, packet, len);
                        out_ip = packet_to_ip_hdr(out_packet);
                        out_ip->saddr = htonl(iface->ip);
                        out_ip->daddr = htonl(nbr_entry->nbr_ip);
                        out_mospf =  packet_to_mospf_hdr(out_packet);
                        //update checksum
                        out_mospf->checksum = mospf_checksum(out_mospf);
                        out_ip->checksum = ip_checksum(out_ip);
                        ip_send_packet(out_packet, len);
                    }
                }
            }
        }
    }
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
