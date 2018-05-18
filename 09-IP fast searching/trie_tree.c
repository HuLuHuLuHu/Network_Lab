#include "trie_tree.h"

Trie_tree Trie_Tree_Init(){
	Trie_tree tree = (Trie_tree)malloc(sizeof(trie_node_t));
	tree->ip = 0;
	tree->prefix = 0;
	tree->port = -1;
	tree->valid = false;
	tree->lchild = NULL;
	tree->rchild = NULL;
	return tree;
}

int count = 0;
int Trie_Tree_Insert(Trie_tree tree,trie_node_t *node){
	u8 prefix = node->prefix;
	Trie_tree temp = tree;
	Trie_tree *child = NULL;
	for(u8 i=0;i<prefix;i++){
		if((N_BIT(node->ip,i+1)) == 0)
			child = &(temp->lchild);
		else
			child = &(temp->rchild);
		if(i == prefix -  1)
			*child = node;
		if(!(*child)){
				*child = Create_Node((node->ip & MASK(i+1)),i+1,-1,false);
		}
			temp = *child;
	}
	return 1;
}

void Print_Tree(Trie_tree tree){
	if(tree->lchild){
		Print_Tree(tree->lchild);
	}
	if(tree->rchild){
		Print_Tree(tree->rchild);
	}
	printf("%x\n",tree->ip);
}

void Leaf_Push(Trie_tree *tree,trie_node_t *node){
	if(!((*tree)->lchild)&& !((*tree)->rchild))
		return;
	trie_node_t *push_node = NULL;
	trie_node_t *new_node = NULL;
	push_node = ((*tree)->valid)? *tree : node;
	if(!((*tree)->lchild))
		(*tree)->lchild = push_node;
	else{
		if((*tree)->lchild->valid)
			Leaf_Push(&((*tree)->lchild),NULL);
		else
			Leaf_Push(&((*tree)->lchild),push_node);
	}
	if(!((*tree)->rchild))
		(*tree)->rchild = push_node;
	else{
		if((*tree)->rchild->valid)
			Leaf_Push(&((*tree)->rchild),NULL);
		else
			Leaf_Push(&((*tree)->rchild),push_node);
	}
	if((*tree)->valid){
		new_node = Create_Node(0,0,0,false);
		new_node->lchild = (*tree)->lchild;
		new_node->rchild = (*tree)->rchild;
		(*tree)->lchild = NULL;
		(*tree)->rchild = NULL;
		*tree = new_node; 
	}
}

Trie_tree Create_Node(u32 ip, u8 prefix, u16 port,bool valid){
	trie_node_t *new = (trie_node_t *)malloc(sizeof(trie_node_t));
	new->ip = ip;
	new->prefix = prefix;
	new->port = port;
	new->valid = valid;
	new->lchild = NULL;
	new->rchild = NULL;
	return new;
}

Trie_tree Trie_Tree_Search(Trie_tree tree, u32 ip){
	trie_node_t *temp = tree;
	trie_node_t *result = NULL;
	for(int i=0; i<32 && temp; i++){
		if((N_BIT(ip,i+1)) == 0)
			temp = temp->lchild;
		else
			temp = temp->rchild;
		if(temp)
			if(((temp->ip & (MASK(temp->prefix))) == (ip & (MASK(temp->prefix)))) && temp->valid == true)
				if(!result || (result->prefix < temp->prefix))
					result = temp;
	}
	return result;
}

int Trie_Tree_Destroy(Trie_tree tree){
	if(tree->lchild)
	Trie_Tree_Destroy(tree->lchild);
	if(tree->rchild)
	Trie_Tree_Destroy(tree->rchild);
	free(tree);
	return 1;
}


int main(int *argc,char *argv[]){
	FILE *fp = fopen("forwarding-table.txt","r");
	u8 ip[4]  = {0};
	u16 port  = -1;
	u8 prefix = 0;
	u32 format_ip = 0;
	trie_node_t *node;
	Trie_tree tree = Trie_Tree_Init();
	while(fscanf(fp,"%hhu.%hhu.%hhu.%hhu %hhu %hu",&ip[3],&ip[2],&ip[1],&ip[0],&prefix,&port) == 6){
		IP_FORMAT(format_ip,ip);
		node = Create_Node(format_ip,prefix,port,true);
		Trie_Tree_Insert(tree,node);
	}
	fclose(fp);
	//Print_Tree(tree);
	Leaf_Push(&tree,NULL);
	printf("input ip you want to search,eg: 192.168.1.1\n");
	while(1){
		printf(">>> ");
		scanf("%hhu.%hhu.%hhu.%hhu",&ip[3],&ip[2],&ip[1],&ip[0]);
		IP_FORMAT(format_ip,ip);
		//scanf("%u",&format_ip);
		node = Trie_Tree_Search(tree,format_ip);
		if(node) 
			printf(IP_FMT"  prefix: %hhu,port: %hhu\n", IP_FMT_STR(node->ip),node->prefix,node->port);
		else
			printf("not found!\n");
	}
}