#include <stdio.h>
#include <time.h>

#include "dijkstra.h"
#include "pwospf_topology.h"
#include "sr_rt.h"

/*---------------------------------------------------------------------
 * Method: run_dijkstra
 *
 * Run Dijkstra algorithm
 *
 *---------------------------------------------------------------------*/

void* run_dijkstra(void* arg)
{
    dijkstra_param_t* dij_param = ((dijkstra_param_t*)(arg));

    pthread_mutex_t mutex = dij_param->mutex;
    struct pwospf_topology_entry* topology = dij_param->topology;
    struct in_addr router_id = dij_param->rid;

    pthread_mutex_lock(&mutex);

    struct in_addr zero;
    zero.s_addr = 0;
    struct dijkstra_item* dijkstra_stack = create_dikjstra_item(create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0), 0);
   struct dijkstra_item*  dijkstra_heap = create_dikjstra_item(create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0), 0);

    /* Limpio la tabla*/
    clear_routes(dij_param->sr);

    /* ejecuto Dijkstra*/
    struct pwospf_topology_entry* topo_entry = topology->next;
    while(topo_entry != NULL)
    {
        if (check_route(dij_param->sr, topo_entry->net_num) == 0)
        {
            struct sr_if* temp_int = dij_param->sr->if_list;
            while (temp_int != NULL)
            {
                if (search_topolgy_table(topology, (temp_int->ip & temp_int->mask)) == 0)
                {
                    temp_int = temp_int->next;
                    continue;
                }

                if (temp_int->neighbor_id != 0)
                {
                    struct in_addr mask;	    mask.s_addr = temp_int->mask;
                    struct in_addr subnet;	    subnet.s_addr = temp_int->ip & mask.s_addr;
                    struct in_addr neighbor_id;	    neighbor_id.s_addr = temp_int->neighbor_id;
                    struct in_addr next_hop;	    next_hop.s_addr = temp_int->neighbor_ip;

                    dijkstra_stack_push(dijkstra_heap, create_dikjstra_item(create_ospfv2_topology_entry(router_id, subnet, mask, neighbor_id,
                        next_hop, 0), 1));
                }
                temp_int = temp_int->next;
            }

            struct dijkstra_item* dijkstra_popped_item;
            uint8_t stop = 0;
            while(1)
            {
                while(1)
                {
                    /* Pop from the heap */
                    dijkstra_popped_item = dijkstra_stack_pop(dijkstra_heap);
                    if (dijkstra_popped_item == NULL)
                    {
                        stop = 1;
                        break;
                    }
                    if (dijkstra_popped_item->topology_entry->net_num.s_addr == topo_entry->net_num.s_addr)
                    {
                        stop = 1;
                        break;
                    }
                    if (dijkstra_popped_item->topology_entry->neighbor_id.s_addr != 0)
                    {
                        break;
                    }
                }

                /* Push popped item in stack */
                if (dijkstra_popped_item != NULL)
                {
                    dijkstra_stack_push(dijkstra_stack, dijkstra_popped_item);
                }
                if (stop == 1)
                {
                    break;
                }
                struct pwospf_topology_entry* ptr = topology->next;
                while(ptr != NULL)
                {
                    if ((ptr->router_id.s_addr == dijkstra_popped_item->topology_entry->neighbor_id.s_addr) &&
                        (ptr->net_num.s_addr != dijkstra_popped_item->topology_entry->net_num.s_addr) &&
                        (ptr->neighbor_id.s_addr != dijkstra_popped_item->topology_entry->neighbor_id.s_addr))
                    {
                        struct pwospf_topology_entry* clone = clone_ospfv2_topology_entry(ptr);

                        struct dijkstra_item* to_be_pushed = create_dikjstra_item(clone, dijkstra_popped_item->cost + 1);
                        to_be_pushed->parent = dijkstra_popped_item;
                        dijkstra_stack_push(dijkstra_heap, to_be_pushed);
                        dijkstra_stack_reorder(dijkstra_heap);
                    }

                    ptr = ptr->next;
                }
            }
            struct dijkstra_item* final_item = dijkstra_stack_pop(dijkstra_stack);

            if (final_item != NULL)
            {
                while (final_item->parent != NULL)
                {
                    final_item = final_item->parent; /*dijkstra_stack_pop(dijkstra_stack);*/

                }
                struct sr_if* next_hop_int = dij_param->sr->if_list;
                while (next_hop_int != NULL)
                {
                    if ((next_hop_int->ip & next_hop_int->mask) == (final_item->topology_entry->next_hop.s_addr & final_item->topology_entry->net_mask.s_addr))
                    {
                        break;
                    }
                    next_hop_int = next_hop_int->next;
                }

                sr_add_rt_entry(dij_param->sr, topo_entry->net_num, final_item->topology_entry->next_hop, topo_entry->net_mask, next_hop_int->name, 110);
            }
        }
        topo_entry = topo_entry->next;
    }
    Debug("\n-> PWOSPF: Dijkstra algorithm completed\n\n");
    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(dij_param->sr);

    pthread_mutex_unlock(&mutex);

    return NULL;
} /* -- run_dijkstra -- */

void dijkstra_stack_push(struct dijkstra_item* dijkstra_first_item, struct dijkstra_item* dijkstra_new_item)
{
    if (dijkstra_first_item->next != NULL)
    {
        dijkstra_new_item->next = dijkstra_first_item->next;
        dijkstra_first_item->next = dijkstra_new_item;
    }

    dijkstra_first_item->next = dijkstra_new_item;
}

void dijkstra_stack_reorder(struct dijkstra_item* dijkstra_first_item)
{
    struct dijkstra_item* ptr = dijkstra_first_item;
    while (ptr->next != NULL)
    {
        if (ptr->next->next == NULL)
        {
            break;
        }

        if (ptr->next->cost > ptr->next->next->cost)
        {
            struct dijkstra_item* temp_1 = ptr->next->next->next;
            struct dijkstra_item* temp_2 = ptr->next->next;
            ptr->next->next->next = ptr->next;
            ptr->next->next = temp_1;
            ptr->next = temp_2;
        }

        ptr = ptr->next;
    }
}

struct dijkstra_item* dijkstra_stack_pop(struct dijkstra_item* dijkstra_first_item)
{
    if (dijkstra_first_item->next == NULL)
    {
        return NULL;
    }
    else
    {
        struct dijkstra_item* pResult = dijkstra_first_item->next;

        dijkstra_first_item->next = dijkstra_first_item->next->next;

        return pResult;
    }
}

struct dijkstra_item* create_dikjstra_item(struct pwospf_topology_entry* new_topology_entry, uint8_t cost)
{
    struct dijkstra_item* dijkstra_new_item = ((struct dijkstra_item*)(malloc(sizeof(struct dijkstra_item))));
    dijkstra_new_item->topology_entry = new_topology_entry;
    dijkstra_new_item->cost = cost;
    dijkstra_new_item->parent = NULL;
    dijkstra_new_item->next = NULL;
    return dijkstra_new_item;
}
