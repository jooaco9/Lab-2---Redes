#ifndef DIJKSTRA_H
#define DIJKSTRA_H

#include <stdlib.h>

#include "sr_if.h"
#include "sr_router.h"

#include "sr_protocol.h"

struct dijkstra_item
{
    struct pwospf_topology_entry* topology_entry;
    uint8_t cost;
    struct dijkstra_item* parent;
    struct dijkstra_item* next;
} __attribute__ ((packed)) ;

struct dijkstra_param
{
    struct sr_instance* sr;
    struct pwospf_topology_entry* topology;
    struct in_addr rid;
    pthread_mutex_t mutex;
}__attribute__ ((packed));
typedef struct dijkstra_param dijkstra_param_t;

void* run_dijkstra(void*);
void dijkstra_stack_push(struct dijkstra_item*, struct dijkstra_item*);
void dijkstra_stack_reorder(struct dijkstra_item*);
struct dijkstra_item* dijkstra_stack_pop(struct dijkstra_item*);
struct dijkstra_item* create_dikjstra_item(struct pwospf_topology_entry*, uint8_t);
#endif	/*DIJKSTRA_H*/
