#ifndef __BASE_H__
#define __BASE_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "types.h"
#define  IP_FORMAT(ip,scan_ip) \
	for(int i=0; i<4; i++) \
		((u8 *)&ip)[i] = scan_ip[i] 
#define  N_BIT_2(ip,n)    (((ip)>>(32-(n+1))) & 3)
#define  N_BIT_1(ip,n)    (((ip)>>(32-(n))) & 1)
#define  MASK(pre_len)  (u32) (~(~0 << (pre_len)) << (32 - (pre_len)))
#define  IP_FMT_STR(ip)  ((u8 *)&(ip))[3], \
					    ((u8 *)&(ip))[2], \
 					    ((u8 *)&(ip))[1], \
					    ((u8 *)&(ip))[0]
#define IP_FMT	"%hhu.%hhu.%hhu.%hhu"
typedef struct trie_node{
	u32    ip;
	u8     prefix;
	u16    port;
	bool   valid;
	struct trie_node *child[4];
}trie_node_t;

typedef trie_node_t *Trie_tree;

Trie_tree MBIT_Trie_Init();
int MBIT_Trie_Insert(Trie_tree tree, trie_node_t *node);
Trie_tree MBIT_Create_Node(u32 ip, u8 prefix, u16 port,bool valid);
Trie_tree MBIT_Trie_Search(Trie_tree tree, u32 ip);
int MBIT_Trie_Destroy(Trie_tree tree);
void MBIT_Print_Tree(Trie_tree tree);
void Leaf_Push(Trie_tree *tree,trie_node_t *node);

#endif