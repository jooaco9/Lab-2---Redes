#ifndef PWOSPF_TOPOLOGY
#define PWOSPF_TOPOLOGY

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>
#include <stdlib.h>

#include "sr_router.h"


/* ----------------------------------------------------------------------------
 * struct pwospf_topology_entry
 *
 *
 * -------------------------------------------------------------------------- */

struct pwospf_topology_entry
{
    struct in_addr router_id;     /* -- id del router -- */
    struct in_addr net_num;       /* -- prefijo -- */
    struct in_addr net_mask;      /* -- máscara -- */
    struct in_addr neighbor_id;   /* -- id del vecino -- */
    struct in_addr next_hop;      /* -- próximo salto -- */
    uint16_t sequence_num;        /* -- número de secuencia del último LSU -- */
    int age;                      /* -- edad de la entrada -- */
    struct pwospf_topology_entry* next;
}__attribute__ ((packed));


void add_topology_entry(struct pwospf_topology_entry*, struct pwospf_topology_entry*);
void delete_topology_entry(struct pwospf_topology_entry*);
uint8_t check_topology_age(struct pwospf_topology_entry*);
void refresh_topology_entry(struct pwospf_topology_entry*, struct in_addr, struct in_addr, struct in_addr, struct in_addr, struct in_addr, uint16_t);
struct pwospf_topology_entry* create_ospfv2_topology_entry(struct in_addr, struct in_addr, struct in_addr, struct in_addr, struct in_addr, uint16_t);
struct pwospf_topology_entry* clone_ospfv2_topology_entry(struct pwospf_topology_entry*);
void print_topolgy_table(struct pwospf_topology_entry*);
uint8_t search_topolgy_table(struct pwospf_topology_entry*, uint32_t);
uint8_t check_sequence_number(struct pwospf_topology_entry* first_entry, struct in_addr router_id, uint16_t sequence_num);


#endif  /* --  PWOSPF_TOPOLOGY -- */
