#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	pthread_mutex_lock(&mac_port_map.lock);
	
	u8 hash;
	hash = hash8(mac,ETH_ALEN);
	mac_port_entry_t *temp;
	bool find = false;
	for(temp = mac_port_map.hash_table[hash];temp != NULL;temp = temp->next){
		find = false;
		for(int i=0;i<ETH_ALEN;i++){
			if(mac[i] == temp->mac[i])
				find = true;
			else {
				find = false; 
				break;
			}
		}
		if (find)
			break;
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	if(find){
		return temp->iface;
	}
	return NULL;
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	pthread_mutex_lock(&mac_port_map.lock);
	u8 hash;
	hash = hash8(mac,ETH_ALEN);
	mac_port_entry_t **temp;

	mac_port_entry_t * new = malloc(sizeof(mac_port_entry_t));
	memcpy(new->mac,mac,sizeof(u8)*ETH_ALEN);
	new->iface = iface;
	new->visited = time(NULL);
	new->next = NULL;

	if(mac_port_map.hash_table[hash] == NULL){
		mac_port_map.hash_table[hash] = new;
	}
	else{
	for(temp = &(mac_port_map.hash_table[hash]);(*temp)->next!=NULL;temp = &((*temp)->next));
	(*temp)->next = new;
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), 
					entry->iface->name, (int)(now - entry->visited));

			entry = entry->next;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	pthread_mutex_lock(&mac_port_map.lock);
	int count = 0;
	mac_port_entry_t *temp1;
	mac_port_entry_t *temp2;
	for(int i=0;i<HASH_8BITS;i++){
		for(temp1 = mac_port_map.hash_table[i],temp2=NULL; temp1!=NULL; temp2 = temp1,temp1 = temp1->next){
			if(time(NULL) - temp1->visited >= MAC_PORT_TIMEOUT){
			
				if(temp2 == NULL)
					mac_port_map.hash_table[i] = temp1->next;
				else
					temp2->next = temp1->next;
				count++;
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	
	return 0;
}

void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
	}

	return NULL;
}
