#include "mbit_trie_tree.h"

Trie_tree MBIT_Trie_Init(){
	Trie_tree tree = (Trie_tree)malloc(sizeof(trie_node_t));
	tree->ip = 0;
	tree->prefix = 0;
	tree->port = -1;
	for(int i=0;i<4;i++)
		tree->child[i] = NULL;
	return tree;
}

int MBIT_Trie_Insert(Trie_tree tree,trie_node_t *node){
	u8 prefix = node->prefix;
	Trie_tree temp = tree;
	u32 ip = node->ip;
	int which = 0;
	for(u8 i=0;i<prefix;i = i+2){
		if(i == prefix-1){
			which = N_BIT_1(ip,i+1);
			if(which < 2){
				if(!temp->child[0] || (temp->child[0]->prefix < node->prefix))
				temp->child[0] = node;
				if(!temp->child[1] || (temp->child[1]->prefix < node->prefix))
				temp->child[1] = node;
			}
			else{
				if(!temp->child[2] || (temp->child[2]->prefix < node->prefix))
				temp->child[2] = node;
				if(!temp->child[3] || (temp->child[3]->prefix < node->prefix))
				temp->child[3] = node;
			}
		}
		else if(i == prefix-2){
			which = N_BIT_2(ip,i+1);
			if(!temp->child[which] || (temp->child[which]->prefix < node->prefix))
			temp->child[which] = node;
		}
		else{
			which = N_BIT_2(ip,i+1);
			if(!temp->child[which])
				temp->child[which] = MBIT_Create_Node(ip & MASK(i+2),i+2,-1,false);
			temp = temp->child[which];
		}
	}
	return 1;
}

void MBIT_Print_Tree(Trie_tree tree){
	for(int i=0;i<4;i++)
	if(tree->child[i]){
		MBIT_Print_Tree(tree->child[i]);
	}
	printf("%x\n",tree->ip);
}

Trie_tree MBIT_Create_Node(u32 ip, u8 prefix, u16 port,bool valid){
	trie_node_t *new = (trie_node_t *)malloc(sizeof(trie_node_t));
	new->ip = ip;
	new->prefix = prefix;
	new->port = port;
	new->valid = valid;
	for(int i=0;i<4;i++)
	new->child[i] = NULL;
	return new;
}

Trie_tree MBIT_Trie_Search(Trie_tree tree, u32 ip){
	trie_node_t *temp = tree;
	trie_node_t *result = NULL;
	int which = 0;
	for(int i=0; i<32 && temp; i=i+2){
		which = N_BIT_2(ip,i+1);
		temp = temp->child[which];
		if(temp)
			if(((temp->ip & (MASK(temp->prefix))) == (ip & (MASK(temp->prefix)))) && temp->valid == true)
				if(!result || result->prefix < temp->prefix)
					result = temp;
	}
	return result;
}

void Leaf_Push(Trie_tree *tree,trie_node_t *node){
	if(!((*tree)->child[0])&& !((*tree)->child[1]) && !((*tree)->child[2]) && !((*tree)->child[3]))
		return;
	trie_node_t *push_node = NULL;
	trie_node_t *new_node = NULL;
	push_node = ((*tree)->valid)? *tree : node;
	for(int i=0;i<4;i++){
		if(!((*tree)->child[i]))
			(*tree)->child[i] = push_node;
		else{
			if(((*tree)->child[i])->valid)
				Leaf_Push(&((*tree)->child[i]),NULL);
			else
				Leaf_Push(&((*tree)->child[i]),push_node);
		}
	}
	if((*tree)->valid){
		new_node = MBIT_Create_Node(0,0,0,false);
		for(int i=0;i<4;i++){
			new_node->child[i] = (*tree)->child[i];
			(*tree)->child[i] = NULL;
		}
		*tree = new_node; 
	}
}

int MBIT_Trie_Destroy(Trie_tree tree){
	for(int i=0;i<4;i++)
	if(tree->child[i])
	MBIT_Trie_Destroy(tree->child[i]);
	free(tree);
	return 1;
}


int main(int *argc,char *argv[]){
	FILE *fp = fopen("forwarding-table.txt","r");
	//assert(fp != NULL);
	u8 ip[4]  = {0};
	u16 port  = -1;
	u8 prefix = 0;
	u32 format_ip = 0;
	trie_node_t *node;
	int count =0;
	Trie_tree tree = MBIT_Trie_Init();

	while(fscanf(fp,"%hhu.%hhu.%hhu.%hhu %hhu %hu",&ip[3],&ip[2],&ip[1],&ip[0],&prefix,&port) == 6){
		IP_FORMAT(format_ip,ip);
		//	printf("%d\n",count++);
		node = MBIT_Create_Node(format_ip,prefix,port,true);
		//	printf("%d\n",count++);
		MBIT_Trie_Insert(tree,node);

	}
	fclose(fp);
	Leaf_Push(&tree,NULL);
	//MBIT_Print_Tree(tree);
	printf("input ip you want to search,eg: 192.168.1.1\n");
	while(1){
		printf(">>> ");
		scanf("%hhu.%hhu.%hhu.%hhu",&ip[3],&ip[2],&ip[1],&ip[0]);
		IP_FORMAT(format_ip,ip);
		//scanf("%u",&format_ip);
		node = MBIT_Trie_Search(tree,format_ip);
		if(node) 
			printf(IP_FMT"  prefix: %hhu,port: %hhu\n", IP_FMT_STR(node->ip),node->prefix,node->port);
		else
			printf("not found!\n");
	}
}