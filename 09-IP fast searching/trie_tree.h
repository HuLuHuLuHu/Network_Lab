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
#define  N_BIT(ip,n)    (((ip)>>(32-(n))) & 1) 
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
	struct trie_node *lchild,*rchild;
}trie_node_t;

typedef trie_node_t *Trie_tree;

Trie_tree Trie_Tree_Init();
int Trie_Tree_Insert(Trie_tree tree, trie_node_t *node);
Trie_tree Create_Node(u32 ip, u8 prefix, u16 port,bool valid);
Trie_tree Trie_Tree_Search(Trie_tree tree, u32 ip);
int Trie_Tree_Destroy(Trie_tree tree);
void Print_Tree(Trie_tree tree);
void Leaf_Push(Trie_tree *tree,trie_node_t *node);
#endif