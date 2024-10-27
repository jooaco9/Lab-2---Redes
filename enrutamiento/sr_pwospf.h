/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * 
 * Descripción:
 * 
 * Este archivo contiene las definiciones de las funciones y estructuras
 * utilizadas en el subsistema de enrutamiento OSPF.
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include "sr_protocol.h"


/* forward declare */
struct sr_instance;

struct pwospf_subsys
{   /* -- hilo y lock del pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

struct powspf_hello_lsu_param
{
    struct sr_instance* sr;
    struct sr_if* interface;
}__attribute__ ((packed));
typedef struct powspf_hello_lsu_param powspf_hello_lsu_param_t;

struct powspf_rx_lsu_param
{
    struct sr_instance* sr;
    uint8_t packet[1500];
    unsigned int length;
    struct sr_if* rx_if;
}__attribute__ ((packed));
typedef struct powspf_rx_lsu_param powspf_rx_lsu_param_t;

int pwospf_init(struct sr_instance* sr);

void* check_neighbors_life(void*);
void* check_topology_entries_age(void*);
void* send_hellos(void*);
void* send_hello_packet(void*);
void* send_all_lsu(void*);
void* send_lsu(void*);
void sr_handle_pwospf_hello_packet(struct sr_instance*, uint8_t*, unsigned int, struct sr_if*);
void* sr_handle_pwospf_lsu_packet(void*);
void sr_handle_pwospf_packet(struct sr_instance*, uint8_t*, unsigned int, struct sr_if*);


#endif /* SR_PWOSPF_H */
