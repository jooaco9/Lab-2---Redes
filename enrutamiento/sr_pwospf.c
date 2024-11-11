/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 *
 * Descripción:
 * Este archivo contiene las funciones necesarias para el manejo de los paquetes
 * OSPF.
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "sr_utils.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_rt.h"
#include "pwospf_neighbors.h"
#include "pwospf_topology.h"
#include "dijkstra.h"

/*pthread_t hello_thread;*/
pthread_t g_hello_packet_thread;
pthread_t g_all_lsu_thread;
pthread_t g_lsu_thread;
pthread_t g_neighbors_thread;
pthread_t g_topology_entries_thread;
pthread_t g_rx_lsu_thread;
pthread_t g_dijkstra_thread;

struct in_addr g_router_id;
uint8_t g_ospf_multicast_mac[ETHER_ADDR_LEN];
struct ospfv2_neighbor* g_neighbors;
struct pwospf_topology_entry* g_topology;
uint16_t g_sequence_num;

/* -- Declaración de hilo principal de la función del subsistema pwospf --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Configura las estructuras de datos internas para el subsistema pwospf
 * y crea un nuevo hilo para el subsistema pwospf.
 *
 * Se puede asumir que las interfaces han sido creadas e inicializadas
 * en este punto.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    g_router_id.s_addr = 0;

    /* Defino la MAC de multicast a usar para los paquetes HELLO */
    g_ospf_multicast_mac[0] = 0x01;
    g_ospf_multicast_mac[1] = 0x00;
    g_ospf_multicast_mac[2] = 0x5e;
    g_ospf_multicast_mac[3] = 0x00;
    g_ospf_multicast_mac[4] = 0x00;
    g_ospf_multicast_mac[5] = 0x05;

    g_neighbors = NULL;

    g_sequence_num = 0;

    perror("pthread_create");
    struct in_addr zero;
    zero.s_addr = 0;
    g_neighbors = create_ospfv2_neighbor(zero);
    g_topology = create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
}

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} 

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Hilo principal del subsistema pwospf.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    sleep(5);

    struct sr_instance* sr = (struct sr_instance*)arg;

    /* Set the ID of the router */
    while(g_router_id.s_addr == 0)
    {
        struct sr_if* int_temp = sr->if_list;
        while(int_temp != NULL)
        {
            if (int_temp->ip > g_router_id.s_addr)
            {
                g_router_id.s_addr = int_temp->ip;
            }

            int_temp = int_temp->next;
        }
    }
    Debug("\n\nPWOSPF: Selecting the highest IP address on a router as the router ID\n");
    Debug("-> PWOSPF: The router ID is [%s]\n", inet_ntoa(g_router_id));


    Debug("\nPWOSPF: Detecting the router interfaces and adding their networks to the routing table\n");
    struct sr_if* int_temp = sr->if_list;
    while(int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr =  int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;

        if (check_route(sr, network) == 0)
        {
            Debug("-> PWOSPF: Adding the directly connected network [%s, ", inet_ntoa(network));
            Debug("%s] to the routing table\n", inet_ntoa(mask));
            sr_add_rt_entry(sr, network, gw, mask, int_temp->name, 1);
        }
        int_temp = int_temp->next;
    }
    
    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(sr);


    pthread_create(&g_hello_packet_thread, NULL, send_hellos, sr);
    pthread_create(&g_all_lsu_thread, NULL, send_all_lsu, sr);
    pthread_create(&g_neighbors_thread, NULL, check_neighbors_life, NULL);
    pthread_create(&g_topology_entries_thread, NULL, check_topology_entries_age, sr);

    return NULL;
} /* -- run_ospf_thread -- */

/***********************************************************************************
 * Métodos para el manejo de los paquetes HELLO y LSU
 * SU CÓDIGO DEBERÍA IR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void* check_neighbors_life(void* arg) {
  
  while(1) {
    usleep(1000000);
    check_neighbors_alive(g_neighbors);
    /* Cada 1 segundo, chequea la lista de vecinos. */
  }
} /* -- check_neighbors_life -- */


/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive 
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void* check_topology_entries_age(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    while(1){
      /*
      Cada 1 segundo, chequea el tiempo de vida de cada entrada
      de la topologia.

      Si hay un cambio en la topología, se llama a la función de Dijkstra
      en un nuevo hilo.
      Se sugiere también imprimir la topología resultado del chequeo.
      */
        usleep(1000000);
        if(check_topology_age(g_topology) == 1){
            Debug("\n\n CAMBIO DE TOPOLOGIA////////////////////////////////////////////////////////// \n");
            dijkstra_param_t* dij_param = (dijkstra_param_t*)malloc(sizeof(dijkstra_param_t));

            dij_param->topology = g_topology;
            dij_param->rid = g_router_id;
            dij_param->sr = sr;
            pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, dij_param);
            /*pthread_join(g_dijkstra_thread, NULL);*/
            Debug("\n\n TOPOLOGIA ACTUAL: \n");
            print_topolgy_table(g_topology);
            /*free(dij_param);*/
        }
    }

    return NULL;
} /* -- check_topology_entries_age -- */


/*---------------------------------------------------------------------
 * Method: send_hellos
 *
 * Para cada interfaz y cada helloint segundos, construye mensaje 
 * HELLO y crea un hilo con la función para enviar el mensaje.
 *
 *---------------------------------------------------------------------*/

void* send_hellos(void* arg) {
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* While true */
    while(1)
    {
        /* Se ejecuta cada 1 segundo */
        usleep(1000000);
        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        struct sr_if* if_list = sr->if_list;

        /* Chequeo todas las interfaces para enviar el paquete HELLO */
        /* Cada interfaz matiene un contador en segundos para los HELLO*/
        /* Crear un hilo para enviar el paquete HELLO */
        /* Reiniciar el contador de segundos para HELLO */
        int cont = 0;
        while(if_list){
            cont++;
            if(if_list->helloint <= 0){
                Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s Y estamos en la interfaz %d: \n", if_list->name,cont);
                powspf_hello_lsu_param_t* hello_param = (powspf_hello_lsu_param_t*)malloc(sizeof(powspf_hello_lsu_param_t));
                hello_param->sr = sr;
                hello_param->interface = if_list;
                pthread_create(&g_hello_packet_thread, NULL, send_hello_packet, hello_param);
                if_list->helloint = OSPF_DEFAULT_HELLOINT;
            } else {
                if_list->helloint--;
            }    
            if_list = if_list->next;
        };
        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    }
  return NULL;
 /* -- send_hellos -- */
}

/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/


void* send_hello_packet(void* arg)
{
    powspf_hello_lsu_param_t* hello_param = ((powspf_hello_lsu_param_t*)(arg));
    struct sr_instance* sr = hello_param->sr;
    struct sr_if* interface = hello_param->interface;
    /*Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", interface->name);*/

    /* Creo el paquete a transmitir */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t);
    uint8_t * helloPkt = (uint8_t *)malloc(len);
    memset(helloPkt, 0, len);
    sr_ethernet_hdr_t* ether_hdr_ipPacket = (sr_ethernet_hdr_t*)helloPkt;
    
    /* Seteo la dirección MAC de multicast para la trama a enviar */
    memcpy(ether_hdr_ipPacket->ether_dhost, g_ospf_multicast_mac, ETHER_ADDR_LEN);
    /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    memcpy(ether_hdr_ipPacket->ether_shost, interface->addr, ETHER_ADDR_LEN);
    /* Seteo el ether_type en el cabezal Ethernet */
    ether_hdr_ipPacket->ether_type = htons(ethertype_ip) ;

    /* Inicializo cabezal IP */
    sr_ip_hdr_t* header_ipPacket = (sr_ip_hdr_t*)(helloPkt + sizeof(sr_ethernet_hdr_t));
    /* Seteo el protocolo en el cabezal IP para ser el de OSPF (89) */
    header_ipPacket->ip_p = ip_protocol_ospfv2; 
    /* Seteo IP origen con la IP de mi interfaz de salida */
    header_ipPacket->ip_src = interface->ip;
    /* Seteo IP destino con la IP de Multicast dada: OSPF_AllSPFRouters  */
    header_ipPacket->ip_dst = OSPF_AllSPFRouters;
    header_ipPacket->ip_ttl = 1;
    header_ipPacket->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));

    /* Calculo y seteo el chechsum IP*/
    header_ipPacket->ip_sum = 0;
    header_ipPacket->ip_sum = ip_cksum(header_ipPacket, sizeof(sr_ip_hdr_t));

    /* Inicializo cabezal de PWOSPF con version 2 y tipo HELLO */
    ospfv2_hdr_t* header_ospfPacket = (ospfv2_hdr_t*)(helloPkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    header_ospfPacket->type = OSPF_TYPE_HELLO;

    header_ospfPacket->version = OSPF_V2;

    /* Seteo el Router ID con mi ID*/
    header_ospfPacket->rid = htonl(g_router_id.s_addr); 
    /*Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));*/
    /* Seteo el Area ID en 0 */
    header_ospfPacket->aid = 0; 

    header_ospfPacket->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));
    /* Seteo el Authentication Type y Authentication Data en 0*/
    header_ospfPacket->autype = 0;
    header_ospfPacket->audata = 0;
    ospfv2_hello_hdr_t* header_helloPacket = (ospfv2_hello_hdr_t*)(helloPkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t));

    /* Seteo máscara con la máscara de mi interfaz de salida */
    header_helloPacket->nmask = interface->mask;
    /* Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    header_helloPacket->helloint = OSPF_DEFAULT_HELLOINT;
    /* Seteo Padding en 0*/
    header_helloPacket->padding = 0;
    /* Calculo y actualizo el checksum del cabezal OSPF */
    header_ospfPacket->csum = 0;
    header_ospfPacket->csum = ospfv2_cksum(header_ospfPacket, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));

    /* Envío el paquete HELLO */
    /* Imprimo información del paquete HELLO enviado */
    
    /*struct in_addr interface_id, interface_mask;
    interface_id.s_addr = interface->ip;
    interface_mask.s_addr = interface->mask;
    Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", len, hello_param->interface->name);
    print_hdrs(helloPkt, len);
    Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
    Debug("      [Router IP = %s]\n", inet_ntoa(interface_id));
    Debug("      [Network Mask = %s]\n", inet_ntoa(interface_mask));*/
    sr_send_packet(sr,helloPkt,len,interface->name);
    free(hello_param);
    free(helloPkt);
    return NULL;
} /* -- send_hello_packet -- */

/*---------------------------------------------------------------------
 * Method: send_all_lsu
 *
 * Construye y envía LSUs cada 30 segundos
 *
 *---------------------------------------------------------------------*/

void* send_all_lsu(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* while true*/
    while(1)
    {
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        usleep(OSPF_DEFAULT_LSUINT * 1000000 );

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);
        
        /* Recorro todas las interfaces para enviar el paquete LSU */
        /* Si la interfaz tiene un vecino, envío un LSU */
        struct sr_if* if_list = sr->if_list;
        int cont = 0;
        while(if_list){
            cont++;
            if(if_list->neighbor_id != 0){
                Debug("\n\nMANDA UN LSU POR LA NUMERO %d\n", cont);
                powspf_hello_lsu_param_t* lsu_param = (powspf_hello_lsu_param_t*)malloc(sizeof(powspf_hello_lsu_param_t));
                lsu_param->sr = sr;
                lsu_param->interface = if_list;
                pthread_create(&g_lsu_thread, NULL, send_lsu, lsu_param);
            }
            else{
                Debug("\n\nNO MANDA UN LSU , NO TIENE VECINO POR LA NUMERO %d\n", cont);
            }
            if_list = if_list->next;
        };        

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    return NULL;
} /* -- send_all_lsu -- */

/*---------------------------------------------------------------------
 * Method: send_lsu
 *
 * Construye y envía paquetes LSU a través de una interfaz específica
 *
 *---------------------------------------------------------------------*/

void* send_lsu(void* arg)
{
    powspf_hello_lsu_param_t* lsu_param = ((powspf_hello_lsu_param_t*)(arg));
    struct sr_instance* sr = lsu_param->sr;
    struct sr_if* interface = lsu_param->interface;
    
    /* Solo envío LSUs si del otro lado hay un router*/
    if(interface->neighbor_ip != 0){ 
        /* Construyo el LSU */
        Debug("\n\nPWOSPF: Constructing LSU packet\n");
         /* Creo el paquete a transmitir */
        int cantLsa = count_routes(sr);
        unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + cantLsa * sizeof(ospfv2_lsa_t);
        uint8_t * lsuPkt = (uint8_t *)malloc(len);
        memset(lsuPkt, 0, len);
    
        /* Inicializo cabezal Ethernet */
        sr_ethernet_hdr_t* header_etherPacket = (sr_ethernet_hdr_t*)lsuPkt;
         /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
        memcpy(header_etherPacket->ether_shost, interface->addr, ETHER_ADDR_LEN);
        /* Seteo el ether_type en el cabezal Ethernet */
        header_etherPacket->ether_type = htons(ethertype_ip);
        
        /* Inicializo cabezal IP*/
        sr_ip_hdr_t* header_ipPacket = (sr_ip_hdr_t*)(lsuPkt + sizeof(sr_ethernet_hdr_t));
        /* La IP destino es la del vecino conectado a mi interfaz*/
        header_ipPacket->ip_dst = interface->neighbor_ip;
        header_ipPacket->ip_p = ip_protocol_ospfv2; 
        /* Seteo IP origen con la IP de mi interfaz de salida */
        header_ipPacket->ip_src = interface->ip;
        header_ipPacket->ip_ttl = 64;
        header_ipPacket->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + cantLsa * sizeof(ospfv2_lsa_t));
        /* Calculo y seteo el chechsum IP*/
        header_ipPacket->ip_sum = 0;
        header_ipPacket->ip_sum = ip_cksum(header_ipPacket, sizeof(sr_ip_hdr_t));

        /* Inicializo cabezal de OSPF*/
        ospfv2_hdr_t* header_ospfPacket = (ospfv2_hdr_t*)(lsuPkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        header_ospfPacket->type = OSPF_TYPE_LSU;
        header_ospfPacket->version = OSPF_V2;
        header_ospfPacket->len =  htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + cantLsa * sizeof(ospfv2_lsa_t));
        header_ospfPacket->rid = g_router_id.s_addr; 
        header_ospfPacket->aid = 0;
        header_ospfPacket->autype = 0;
        header_ospfPacket->audata = 0;
        /* Inicializo cabezal de LSU*/
        ospfv2_lsu_hdr_t * header_lsuPacket = (ospfv2_lsu_hdr_t*)(lsuPkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)); 
        /* Seteo el número de secuencia y avanzo*/
        header_lsuPacket->seq = g_sequence_num;
        g_sequence_num = g_sequence_num + 1;

        /* Seteo el TTL en 64 y el resto de los campos del cabezal de LSU */
        
        header_lsuPacket->ttl = 64;
        header_lsuPacket->unused = 0;
        /* Seteo el número de anuncios con la cantidad de rutas a enviar. Uso función count_routes */
        header_lsuPacket->num_adv = cantLsa;
        int cont = 0;
        struct sr_rt * ruta = sr->routing_table;
        /* Creo cada LSA iterando en las entradas de la tabla */
            /* Solo envío entradas directamente conectadas y agreagadas a mano*/
            /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/
        
        while(ruta != NULL){
            if(ruta->admin_dst <= 1){
                ospfv2_lsa_t * header_lsaPacket = (ospfv2_lsa_t*)(lsuPkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + cont * sizeof(ospfv2_lsa_t)); 
                cont++;
                struct sr_if* interface2 = sr->if_list;
                while(interface2 != NULL){
                    if(interface2->ip == ruta->dest.s_addr){
                        break;
                    }
                    interface2 = interface2->next;
                }
                header_lsaPacket->subnet = ruta->dest.s_addr & ruta->mask.s_addr;
                header_lsaPacket->mask = ruta->mask.s_addr;
                header_lsaPacket->rid = interface2->ip;
            }
            ruta = ruta->next;    
        }   
        if(cont != cantLsa){
            Debug("Error en la cantidad de rutas\n");
        }
        /* Calculo el checksum del paquete LSU */
        header_ospfPacket->csum = 0;
        header_ospfPacket->csum = ospfv2_cksum(header_ospfPacket, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + cantLsa * sizeof(ospfv2_lsa_t));


        /* Dirección MAC destino la dejo para el final ya que hay que hacer ARP */
        /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
        /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
        struct sr_arpentry *entry = sr_arpcache_lookup(&(lsu_param->sr->cache), interface->neighbor_ip);
        Debug("Ether_type: %d\n", ntohs(header_etherPacket->ether_type));
        if (entry) {
            fprintf(stderr,"Se encontro la direcion MAC en el cache\n");
            /* Se usa la direccion MAC para enviar el paquete*/
            memcpy(header_etherPacket->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            /* Liberar la entrada ARP*/
            /* Enviar el paquete*/
            sr_send_packet(sr, lsuPkt, len, interface->name);
            free(entry);
        } else {
            fprintf(stderr,"No se encontro la direcion MAC en el cache\n");
            /* Poner en cola la solicitud ARP*/
            struct sr_arpreq* arpRequest = sr_arpcache_queuereq(&(sr->cache), interface->neighbor_ip, lsuPkt, len, interface->name);
            handle_arpreq(sr, arpRequest); 
        }
        /* Libero memoria */
        free(lsu_param);
        free(lsuPkt);
    }
    return NULL;
} /* -- send_lsu -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_hello_packet
 *
 * Gestiona los paquetes HELLO recibidos
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_hello_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    
    /* Obtengo información del paquete recibido */
    sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    ospfv2_hdr_t * ospfHeader = (ospfv2_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    ospfv2_hello_hdr_t * helloHeader = (ospfv2_hello_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t));

    struct in_addr neighbor_id, neighbor_ip, net_mask;

    neighbor_id.s_addr = htonl(ospfHeader->rid); 
    neighbor_ip.s_addr = ipHeader->ip_src; 
    net_mask.s_addr = helloHeader->nmask;
        
   /* Imprimo info del paquete recibido*/
    
   /* Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    Debug("      [Neighbor IP = %s]\n", inet_ntoa(neighbor_ip));
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));
    */

    /* Chequeo checksum */
    if (ospfHeader->csum != ospfv2_cksum(ospfHeader, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }
    /* Chequeo de la máscara de red */
    if (net_mask.s_addr != rx_if->mask) {
      Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
      return;
    }
    /* Chequeo del intervalo de HELLO */
    if (helloHeader->helloint != OSPF_DEFAULT_HELLOINT) {
      Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
      return;
    }
    
    /* Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */
    Debug("-> MI INTERFAZ TIENE COMO VECINO A : %s\n",inet_ntoa(neighbor_id));
    rx_if->neighbor_id = neighbor_id.s_addr;
    rx_if->neighbor_ip = neighbor_ip.s_addr;
    rx_if->helloint = OSPF_DEFAULT_HELLOINT;
    rx_if->mask = net_mask.s_addr;
    struct ospfv2_neighbor* ptr = g_neighbors;
    while(ptr != NULL) {
      if (ptr->neighbor_id.s_addr == neighbor_id.s_addr){break;}
      ptr = ptr->next;
    }
    refresh_neighbors_alive(g_neighbors, neighbor_id);
    /* Si es un nuevo vecino, debo enviar un LSU*/
      /* Creo el hilo para enviar el LSU */

    if(ptr == NULL){
        Debug("VECINO NUEVO\n");
        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);
        
        /* Recorro todas las interfaces para enviar el paquete LSU */
        /* Si la interfaz tiene un vecino, envío un LSU */
        struct sr_if* if_list = sr->if_list;
        int cont = 0;
        while(if_list){
            cont++;
            if(if_list->neighbor_id != 0){
                Debug("\n\nMANDA UN LSU POR LA NUMERO %d\n", cont);
                powspf_hello_lsu_param_t* lsu_param = (powspf_hello_lsu_param_t*)malloc(sizeof(powspf_hello_lsu_param_t));
                lsu_param->sr = sr;
                lsu_param->interface = if_list;
                pthread_create(&g_lsu_thread, NULL, send_lsu, lsu_param);
            }
            else{
                Debug("\n\nNO MANDA UN LSU , NO TIENE VECINO POR LA NUMERO %d\n", cont);
            }
            if_list = if_list->next;
        };        
        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    }
} /* -- sr_handle_pwospf_hello_packet -- */


/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_lsu_packet
 *
 * Gestiona los paquetes LSU recibidos y actualiza la tabla de topología
 * y ejecuta el algoritmo de Dijkstra
 *
 *---------------------------------------------------------------------*/

void* sr_handle_pwospf_lsu_packet(void* arg)
{
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(arg));
    struct sr_instance* sr = rx_lsu_param->sr;
    uint8_t* packet = rx_lsu_param->packet;
    unsigned int length = rx_lsu_param->length;
    struct sr_if* rx_if = rx_lsu_param->rx_if;
    /* Obtengo el vecino que me envió el LSU*/

    /* Imprimo info del paquete recibido*/
    /* Obtengo información del paquete recibido */
    sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    ospfv2_hdr_t * ospfHeader = (ospfv2_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    ospfv2_lsu_hdr_t * lsuHeader = (ospfv2_lsu_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t));
    uint32_t neighbor_id = ospfHeader->rid;
    uint32_t neighbor_ip = ipHeader->ip_src;
    struct in_addr neighbor_id_addr,neighbor_ip_addr;
    neighbor_id_addr.s_addr = (neighbor_id);
    neighbor_ip_addr.s_addr = (neighbor_ip);
    Debug("-> PWOSPF: Detecting LSU Packet from [Neighbor ID = %s, IP = %s]\n", inet_ntoa(neighbor_id_addr), inet_ntoa(neighbor_ip_addr));
    
    /* Chequeo checksum */
    if (ospfHeader->csum != ospfv2_cksum(ospfHeader, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) {
      Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");
      return NULL;
    }

    /* Obtengo el Router ID del router originario del LSU y chequeo si no es mío */
    if (neighbor_id == g_router_id.s_addr) {
      Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");
      return NULL;
    }

    /* Obtengo el número de secuencia y uso check_sequence_number para ver si ya lo recibí desde ese vecino */
    if (!check_sequence_number(g_topology,neighbor_id_addr, lsuHeader->seq)) {
      Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");
      return NULL;
    }

    int num_adv = lsuHeader->num_adv;
    
    /* Itero en los LSA que forman parte del LSU. Para cada uno, actualizo la topología.*/
        /* Obtengo subnet */
        /* Obtengo vecino */
        /* Imprimo info de la entrada de la topología */
    Debug("-> PWOSPF: Processing LSAs and updating topology table\n"); 
    ospfv2_lsa_t * lsa; 
    struct in_addr mask, dest, gw;
    int i;
    for (i = 0; i < num_adv; i++) {
  
      lsa = (ospfv2_lsa_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + i * sizeof(ospfv2_lsa_t)); 
      mask.s_addr = lsa->mask;
      dest.s_addr = lsa->subnet;
      gw.s_addr = lsa->rid;
      /* LLamo a refresh_topology_entry*/
      refresh_topology_entry(g_topology, g_router_id, dest, mask,
                              neighbor_id_addr, gw, lsuHeader->seq);
     /* Debug("      [Subnet = %s]", inet_ntoa(dest));
      Debug("      [Mask = %s]", inet_ntoa(mask));
      Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id_addr));
      Debug("      [GW = %s]\n", inet_ntoa(gw));*/

    }
    /* Imprimo la topología */
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);

    /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/
    dijkstra_param_t* dij_param = (dijkstra_param_t*)malloc(sizeof(dijkstra_param_t));
    dij_param->topology = g_topology;
    dij_param->rid = g_router_id;
    dij_param->sr = sr;
    pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, dij_param);
    /* Flooding del LSU por todas las interfaces menos por donde me llegó */
            /* Seteo MAC de origen */
            /* Ajusto paquete IP, origen y checksum*/
            /* Ajusto cabezal OSPF: checksum y TTL*/
            /* Envío el paquete*/
    struct sr_if* if_list = sr->if_list;
    while(if_list && lsuHeader->ttl > 1 && ipHeader->ip_ttl > 1){
        if(if_list->neighbor_id != 0){
                uint8_t *newPacket = malloc(length);
                memcpy(newPacket, packet,length);
                /* Ajusto cabezal Ethernet */
                sr_ethernet_hdr_t* header_etherNewPacket = (sr_ethernet_hdr_t*)newPacket;
                /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
                memcpy(header_etherNewPacket->ether_shost, rx_if->addr, ETHER_ADDR_LEN);
                /* Seteo cabezal IP*/
                sr_ip_hdr_t* header_ipPacket = (sr_ip_hdr_t*)(newPacket + sizeof(sr_ethernet_hdr_t));
                /* La IP destino es la del vecino conectado a mi interfaz*/
                header_ipPacket->ip_dst = neighbor_ip;
                header_ipPacket->ip_ttl--;
                /* Seteo IP origen con la IP de mi interfaz de salida */
                header_ipPacket->ip_src = rx_if->ip;
                header_ipPacket->ip_sum = 0;
                header_ipPacket->ip_sum = ip_cksum(header_ipPacket, sizeof(sr_ip_hdr_t));
                /* Ajusto cabezal OSPF: checksum y TTL*/
                ospfv2_hdr_t * header_ospfHeader = (ospfv2_hdr_t *) (newPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                ospfv2_lsu_hdr_t * header_lsuHeader = (ospfv2_lsu_hdr_t *) (newPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t));
                header_lsuHeader->ttl--;
                header_ospfHeader->csum = 0;
                header_ospfHeader->csum = ospfv2_cksum(header_ospfHeader, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + num_adv * sizeof(ospfv2_lsa_t));
                /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
                /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
                struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), neighbor_ip);
                if (entry) {
                    fprintf(stderr,"Se encontro la direcion MAC en el cache\n");
                    /* Se usa la direccion MAC para enviar el paquete*/
                    memcpy(header_etherNewPacket->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                    /* Enviar el paquete*/
                    sr_send_packet(sr, newPacket, length, rx_if->name);
                    /* Liberar la entrada ARP*/
                    free(entry);
                } else {
                    fprintf(stderr,"No se encontro la direcion MAC en el cache\n");
                    /* Poner en cola la solicitud ARP*/
                    struct sr_arpreq* arpRequest = sr_arpcache_queuereq(&(sr->cache), neighbor_ip, newPacket, length, rx_if->name);
                    handle_arpreq(sr, arpRequest); 
                }

                free(newPacket);
        }
        if_list = if_list->next;
    };        

    
            
    return NULL;
} /* -- sr_handle_pwospf_lsu_packet -- */

/**********************************************************************************
 * SU CÓDIGO DEBERÍA TERMINAR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_packet
 *
 * Gestiona los paquetes PWOSPF
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    ospfv2_hdr_t* rx_ospfv2_hdr = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(malloc(sizeof(powspf_rx_lsu_param_t))));

    Debug("-> PWOSPF: Detecting PWOSPF Packet\n");
    Debug("      [Type = %d]\n", rx_ospfv2_hdr->type);

    switch(rx_ospfv2_hdr->type)
    {
        case OSPF_TYPE_HELLO:
            sr_handle_pwospf_hello_packet(sr, packet, length, rx_if);
            break;
        case OSPF_TYPE_LSU:
            rx_lsu_param->sr = sr;
            unsigned int i;
            for (i = 0; i < length; i++)
            {
                rx_lsu_param->packet[i] = packet[i];
            }
            rx_lsu_param->length = length;
            rx_lsu_param->rx_if = rx_if;
            pthread_create(&g_rx_lsu_thread, NULL, sr_handle_pwospf_lsu_packet, rx_lsu_param);
            break;
    }
} /* -- sr_handle_pwospf_packet -- */
