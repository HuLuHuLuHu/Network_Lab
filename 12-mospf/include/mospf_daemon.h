#ifndef __MOSPF_DAEMON_H__
#define __MOSPF_DAEMON_H__

#include "base.h"
#include "types.h"
#include "list.h"
#include "mospf_database.h"
#include "mospf_proto.h"
#include "rtable.h"
#include <stdbool.h>

#define MAX_NODE_NUM 10
#define INT_MAX 255

#define NEED_UPDATE_PATH(visited,graph,dist,u,v) \
((visited[v] == false) && \
 (graph[u][v] > 0)     && \
 (dist[u] != INT_MAX)  && \
 (dist[u] + graph[u][v] < dist[v]))

extern u32  num2id[MAX_NODE_NUM];
extern int  dist[MAX_NODE_NUM];
extern int  prev[MAX_NODE_NUM];
extern int  graph[MAX_NODE_NUM][MAX_NODE_NUM];
extern bool visited[MAX_NODE_NUM];
extern ustack_t *instance;

void mospf_init();
void mospf_run();
void handle_mospf_packet(iface_info_t *iface, char *packet, int len);

// graph
void init_graph();
void path2rtable(int num);
void database2rtable();
iface_info_t *get_iface_and_gw(u32 rid, u32 *gw);// get forward iface

int database2graph();
int id2num(int rid, int num);
int is_connected(u32 rid1, u32 rid2);
int is_in_rtable(u32 subnet);