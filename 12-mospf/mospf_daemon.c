#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "packet.h"
#include "rtable.h"

#include "list.h"
#include "log.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

int  dist[MAX_NODE_NUM]    = {0};
int  prev[MAX_NODE_NUM]    = {0};
u32  num2id[MAX_NODE_NUM]  = {0};
bool visited[MAX_NODE_NUM] = {0};
int  graph[MAX_NODE_NUM][MAX_NODE_NUM] = {0};

void mospf_init() {
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
        iface->num_nbr = 0;
    }
    init_mospf_db();
    init_graph();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *dumping_database(void *param);
void *generating_mospf_rtable(void *param);
void *checking_database_thread(void *param);

void send_mospf_lsu();
void shortest_path_to_rtable();
void caculate_shortest_path();

void mospf_run() {
    pthread_t hello, lsu, nbr, db, check_db, rtable;
    pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
    pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
    pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
    pthread_create(&check_db, NULL, checking_database_thread, NULL);
    pthread_create(&rtable, NULL, generating_mospf_rtable, NULL);
}

void *checking_database_thread(void * param) {
    time_t now = 0;
    rt_entry_t * rt_entry = NULL, * rt_entry_q = NULL;
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    while (1) {
        if (!list_empty(&mospf_db)) {
            pthread_mutex_lock(&mospf_lock);
            now = time(NULL);
            list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
                if((now-db_entry->alive) >= 20){
                    list_for_each_entry_safe(rt_entry, rt_entry_q, &rtable, list) {
                        if(rt_entry->gw != 0)
                            remove_rt_entry(rt_entry);
                    }    
                    free(db_entry->array);
                    list_delete_entry(&(db_entry->list));
                }
            }
            pthread_mutex_unlock(&mospf_lock);
        } else
            printf("Database is now empty.\n");
        sleep(1);
    }
    return NULL;
}

void *generating_mospf_rtable(void *param){
    while(1){
        sleep(5);
        printf("\n================= database2rtable - Start =========================\n");
        database2rtable();
        printf("================ Print Rtable =================\n");
        print_rtable();
        printf("\n================= database2rtable - End   =========================\n");
    }
    return NULL;
}

void *dumping_database(void *param) {
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    while (1) {
        printf("\n================= Dumping Database - Start =========================\n");
        if (!list_empty(&mospf_db)) {
            list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
                printf("RID       SUBNET    MASK           NBR_RID\n");
                for (int i = 0; i < db_entry->nadv; i++) {
                    printf(IP_FMT"  "IP_FMT"  "IP_FMT"  "IP_FMT"\n",
                           HOST_IP_FMT_STR(db_entry->rid),
                           HOST_IP_FMT_STR(db_entry->array[i].subnet),
                           HOST_IP_FMT_STR(db_entry->array[i].mask),
                           HOST_IP_FMT_STR(db_entry->array[i].rid));
                }
                printf("\n");
            }
        } else
            printf("Database is now empty.\n");
        printf("================= Dumping Database -  End =========================\n\n");
        sleep(5);
    }
    return NULL;
}

void *sending_mospf_hello_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
    char * packet = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    struct ether_header * eth   = NULL;
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_hello  * hello = NULL;
    static u8 MOSPF_ALLSPFMac[ETH_ALEN] = {0x1, 0x0, 0x5e, 0x0, 0x0, 0x5};
    while (1) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            packet = (char *)malloc(HELLO_PACKET_LEN);
            // init ether header
            eth = (struct ether_header *)packet;
            memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
            memcpy(eth->ether_dhost, MOSPF_ALLSPFMac, ETH_ALEN);
            eth->ether_type = ntohs(ETH_P_IP);
            // init ip header
            ip = packet_to_ip_hdr(packet);
            ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, HELLO_PACKET_LEN - ETHER_HDR_SIZE, IPPROTO_MOSPF); 
            // init mospf header
            mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
            mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, 0);  
            // init mospf hello
            hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
            mospf_init_hello(hello, iface->mask);
            // update checksum of ip header and mospf header
            mospf->checksum = mospf_checksum(mospf);
            ip->checksum = ip_checksum(ip);
            // send packet
            iface_send_packet(iface, packet, HELLO_PACKET_LEN);
        }
        sleep(MOSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}

void *checking_nbr_thread(void *param) {
    // fprintf(stdout, "TODO: neighbor list timeout operation.\n");
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    while (1) {
        pthread_mutex_lock(&mospf_lock);
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if ((nbr_entry->alive++) > MOSPF_NEIGHBOR_TIMEOUT) {
                        list_delete_entry(&(nbr_entry->list));
                        iface->num_nbr--;
                        printf("DEBUG: Delete timeout neighbor.\n");
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

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr   * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_hello * hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
    mospf_nbr_t * nbr = NULL, * nbr_q = NULL;
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(iface->nbr_list))) {
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list) {
            if (nbr->nbr_id == ntohl(mospf->rid)) {
                nbr->alive = 0;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        (iface->num_nbr)++;
        mospf_nbr_t * new_nbr = (mospf_nbr_t *)malloc(MOSPF_NBR_SIZE);
        new_nbr->nbr_id   = ntohl(mospf->rid);
        new_nbr->nbr_ip   = ntohl(ip->saddr);
        new_nbr->nbr_mask = ntohl(hello->mask);
        new_nbr->alive    = 0;
        list_add_tail(&(new_nbr->list), &(iface->nbr_list));
        send_mospf_lsu();
    }
    pthread_mutex_unlock(&mospf_lock);
}

void send_mospf_lsu() {
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
            nbr_num += (iface->num_nbr == 0) ? 1 : iface->num_nbr;
    }
    // get informations of all neighbours into lsa
    lsa_packets = (char *)malloc(nbr_num * MOSPF_LSA_SIZE);
    if (!lsa_packets) {printf("lsa_packets malloc error.\n"); exit(-1);}
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
            } else {
                lsa_idx->subnet = htonl(iface->ip & iface->mask);
                lsa_idx->mask   = htonl(iface->mask);
                lsa_idx->rid    = htonl(0);
                lsa_idx++;
            }
        }
    }
    // generate LSU packet and send it through ip_send_packet();
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    // update seq_num
                    instance->sequence_num++;
                    // set up new lsu packet
                    packet = (char *)malloc(LSU_PACKET_LEN(nbr_num));
                    if (!packet) {printf("send_mospf_lsu: packet malloc error.\n"); exit(-1);}
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
                    // reset instance->lsuint
                    instance->lsuint = MOSPF_DEFAULT_LSUINT;
                    // send packet
                    ip_send_packet(packet, LSU_PACKET_LEN(nbr_num));
                }
            }
        }
    }
    free(lsa_packets);
}

void *sending_mospf_lsu_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
    while (1) {
        pthread_mutex_lock(&mospf_lock);
        instance->lsuint--;
        pthread_mutex_unlock(&mospf_lock);
        if(instance->lsuint <= 0)
            send_mospf_lsu();
        sleep(1);
    }
    return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_lsu * lsu   = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
    struct mospf_lsa * lsa   = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);

    // search db, then update db if necessary
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(mospf_db))) {
        mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
            if (db_entry->rid == ntohl(mospf->rid)) {
                found = 1;
                if (db_entry->seq < ntohs(lsu->seq)) { // packet seq is bigger, update lsa
                    db_entry->alive = time(NULL);
                    db_entry->rid   = ntohl(mospf->rid);
                    db_entry->seq   = ntohs(lsu->seq);
                    db_entry->nadv  = ntohl(lsu->nadv);
                    for (int i = 0; i < db_entry->nadv; i++, lsa++) {
                        db_entry->array[i].subnet = ntohl(lsa->subnet);
                        db_entry->array[i].mask   = ntohl(lsa->mask);
                        db_entry->array[i].rid    = ntohl(lsa->rid);
                    }
                }
                break;
            }
        }
    }
    // db entry not found or db entry does not exist
    // create a new db entry
    if (!found) {
        mospf_db_entry_t * new_db_entry = (mospf_db_entry_t *)malloc(MOSPF_DB_ENTRY_SIZE);
        new_db_entry->alive = time(NULL);
        new_db_entry->rid   = ntohl(mospf->rid);
        new_db_entry->seq   = ntohs(lsu->seq);
        new_db_entry->nadv  = ntohl(lsu->nadv);
        new_db_entry->array = (struct mospf_lsa *)malloc((new_db_entry->nadv) * MOSPF_LSA_SIZE);
        for (int i = 0; i < new_db_entry->nadv; i++, lsa++) {
            new_db_entry->array[i].subnet = ntohl(lsa->subnet);
            new_db_entry->array[i].mask   = ntohl(lsa->mask);
            new_db_entry->array[i].rid    = ntohl(lsa->rid);
        }
        list_add_tail(&(new_db_entry->list), &mospf_db);
    }
    pthread_mutex_unlock(&mospf_lock);
    // if ttl > 0, forward this packet
    if ((lsu->ttl--) > 0) {
        char * out_packet = NULL;
        struct iphdr        * out_ip    = NULL;
        struct mospf_hdr    * out_mospf = NULL;
        iface_info_t * iface = NULL, * iface_q = NULL;
        mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
        // for each iface and its nbr forward the packet
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list)
                    if (nbr_entry->nbr_ip != ntohl(ip->saddr) && nbr_entry->nbr_id != ntohl(mospf->rid)) { 
                        // avoid sending packet back to source
                        out_packet = (char *)malloc(len);
                        memcpy(out_packet, packet, len);
                        // change ip header
                        out_ip = packet_to_ip_hdr(out_packet);
                        out_ip->saddr = htonl(iface->ip);
                        out_ip->daddr = htonl(nbr_entry->nbr_ip);
                        // update checksum of ip and mospf header
                        out_mospf = (struct mospf_hdr *)((char *)out_ip + IP_HDR_SIZE(out_ip));
                        out_mospf->checksum = mospf_checksum(out_mospf);
                        out_ip->checksum = ip_checksum(out_ip);
                        // send packet
                        ip_send_packet(out_packet, len);
                    }
            }
    }
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len) {
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

int database2graph() {
    int num = 0, x = -1, y = -1;
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    init_graph();
    num2id[num++] = instance->router_id;
    if (!list_empty(&mospf_db)) {
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list)
            num2id[num++] = db_entry->rid;
    } else
        printf("Database is empty.\n");
    if (!list_empty(&mospf_db)) {
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
            for (int i = 0; i < db_entry->nadv; i++) {
                x = id2num(db_entry->array[i].rid, num);
                y = id2num(db_entry->rid, num);
                graph[x][y] = 1;
                graph[y][x] = 1;
            }
        }
    }

    return num;
}

int min_dist(int num) {
    int node_rank = -1,
        min = INT_MAX;
    for (int i = 0; i < num; i++)
        if (visited[i] == false && dist[i] < min) {
            min = dist[i];
            node_rank = i;
        }
    return node_rank;
}

void caculate_shortest_path(int num) {
    for (int i = 0; i < num; i++) {
        visited[i] = false;
        dist[i] = graph[0][i];
        if (dist[i] == INT_MAX || dist[i] == 0)
            prev[i] = -1;
        else
            prev[i] = 0;
    }

    dist[0] = 0;
    visited[0] = true;

    int u = 0;
    for (int i = 0; i < num - 1; i++) {
        u = min_dist(num);
        visited[u] = true;
        for (int v = 0; v < num; v++) {
            if (NEED_UPDATE_PATH(visited, graph, dist, u, v)) {
                dist[v] = dist[u] + graph[u][v];
                prev[v] = u;
            }
        }
    }
}

void swap(int *a, int *b){
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void path2rtable(int num) {
    int hop = -1, s = 0;
    // sort dist as up order
    int sorted[num], bak[num];
    for(int i = 0; i < num; i++) sorted[i] = i;
    memcpy(bak, dist, num * sizeof(int));
    for (int i = 0; i < num - 1; i++)
        for (int j = 0; j < num - 1 - i; j++)
            if (bak[j] > bak[j+1]) {
                swap(&(sorted[j]), &(sorted[j+1]));
                swap(&(bak[j]), &(bak[j+1]));
            }


    iface_info_t *iface = NULL;
    rt_entry_t * new_entry = NULL;
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    u32 gw = 0, dest = 0;
    for (int i = 0; i < num; i++) {
        if (prev[sorted[i]] != -1) {
            if (!list_empty(&mospf_db))
                list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list){
                    for (int j = 0; j < db_entry->nadv; j++)
                        if (!is_in_rtable(db_entry->array[j].subnet)) {
                            dest = db_entry->array[j].subnet;
                            hop = id2num(db_entry->rid, num);
                            while(prev[hop] != s)
                                hop = prev[hop];
                            iface = get_iface_and_gw(num2id[hop], &gw);
                            new_entry = new_rt_entry(dest, iface->mask, gw, iface);
                            add_rt_entry(new_entry);
                        }
                }
        }
    }
}

void database2rtable(){
    int num = database2graph();
    caculate_shortest_path(num);
    path2rtable(num);
}

// codes 
void init_graph() {
    for (int i = 0; i < MAX_NODE_NUM; i++)
        for (int j = 0; j < MAX_NODE_NUM; j++) {
            if(i != j)
                graph[i][j] = INT_MAX;
            else
                graph[i][j] = 0;
        }
}

int id2num(int rid, int num) {
    int rank = -1;
    for (int i = 0; i < num; i++) {
        if (rid == num2id[i]) {
            rank = i;
            break;
        }
    }
    return rank;
}

int is_in_rtable(u32 subnet) {
    int is_in = 0;
    rt_entry_t * rt_entry = NULL, * rt_entry_q = NULL;
    list_for_each_entry_safe(rt_entry, rt_entry_q, &rtable, list) 
        if ((rt_entry->dest & rt_entry->mask) == subnet) {
            is_in = 1;
            break;
        }
    return is_in;
}

iface_info_t *get_iface_and_gw(u32 rid, u32 *gw) {// get forward iface
    int is_connected = 0;
    iface_info_t *iface = NULL;
    mospf_nbr_t *nbr = NULL, *nbr_q = NULL;
    list_for_each_entry(iface, & (instance->iface_list), list) {
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list) {
            if (nbr->nbr_id == rid) {
                is_connected = 1;
                *gw = nbr->nbr_ip;
                break;
            }
        }
        if(is_connected) break;
    }
    return iface;
}