/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
  int ip_hdr_len = sizeof(sr_ip_hdr_t);

  /* Asignar memoria para el nuevo paquete */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *new_packet = (uint8_t *)malloc(len);
  if (!new_packet) {
    fprintf(stderr, "Error: No se pudo asignar memoria para el nuevo paquete\n");
    return;
  }

  /* Copiar la cabecera Ethernet e IP del paquete original */
  memcpy(new_packet, ipPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Modificar la cabecera IP */
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_dst = ip_hdr->ip_src;

  /* Encontrar la mejor coincidencia de prefijo en la tabla de enrutamiento */
  struct sr_rt *lpm_entry = LPM(sr, ipDst);
  if (!lpm_entry) {
    fprintf(stderr, "Error: No se encontró una coincidencia en la tabla de enrutamiento\n");
    free(new_packet);
    return;
  }

  /* Obtener la interfaz de salida */
  struct sr_if *iface = sr_get_interface(sr, lpm_entry->interface);
  new_ip_hdr->ip_src = iface->ip;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = ip_cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /* Crear la cabecera ICMP */
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;

  /* Copiar la cabecera IP original y los primeros 8 bytes del paquete original */
  memcpy(icmp_hdr->data, ip_hdr, ip_hdr_len + 8);

  /* Calcular el checksum del paquete ICMP */
  icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* Enviar el paquete ICMP */
  sr_send_packet(sr, new_packet, len, iface->name);

  /* Liberar memoria */
  free(new_packet);

} /* -- sr_send_icmp_error_packet -- */

void sr_send_icmp_echo_reply(struct sr_instance *sr,
                             uint8_t *packet,
                             unsigned int len,
                             char *interface)
{
  /* COLOQUE AQUÍ SU CÓDIGO*/

} /* -- sr_send_icmp_echo_reply -- */

struct sr_rt* LPM(struct sr_instance *sr, uint32_t destAddr) {
	struct sr_rt* routing_table = sr->routing_table;
	struct sr_rt* best_match = NULL;
	uint32_t longest_mask = 0;
	
	while(routing_table) {
		uint32_t mask = routing_table->mask.s_addr;
    uint32_t masked_dest = destAddr & mask;
    uint32_t masked_entry = routing_table->dest.s_addr & mask;
    
    if (masked_dest == masked_entry) {
      if(longest_mask <= mask){
      	longest_mask = mask;
        best_match = routing_table;
      }
		}
    
    routing_table = routing_table->next;
  } 

  return best_match;
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr){
  /*
    Poner en el informe que no verificamos el checksum porque 
    la funcion que llama a esta lo valida con is_valid_packet, 
    el cual verifica en cada cabezal que el checksum esta bien
  */ 
  print_hdrs (packet, (uint32_t) len);
  sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if * miInterfaz = sr_get_interface_given_ip(sr, ipHeader->ip_dst);
  /*Si miInterfaz es igual 0 significa que entonces el paquete no es para mi router*/
  if(miInterfaz == 0){
    fprintf(stderr,"MiInterfaz == 0, OSEA EL PAQUETE NO ES PARA MI\n");
    print_addr_ip_int (ipHeader->ip_dst);
		struct sr_rt * match = LPM(sr, ipHeader->ip_dst);
    if(match){
      fprintf(stderr,"SE ENCONTRO EN LA TABLA DE ENRUTAMIENTO\n");
			if(ipHeader->ip_ttl <= 1){
        fprintf(stderr,"el TTL es menor o igual a 1 \n");
        /* TTL es 1 o menor, enviar ICMP Time Exceeded*/
        sr_send_icmp_error_packet(11, 0, sr, ipHeader->ip_dst, packet);
      } else {

        fprintf(stderr,"el ttl es mayor a 1 \n");
        /* Copia del paquete */
        uint8_t *newPacket = malloc(len);
        memcpy(newPacket, packet, len);

        /* Modificacion del TTL y calculo de checksum*/
        sr_ip_hdr_t *newIpHeader = (sr_ip_hdr_t *) (newPacket + sizeof(sr_ethernet_hdr_t));
        newIpHeader->ip_ttl--;
        newIpHeader->ip_sum = 0;
        newIpHeader->ip_sum = ip_cksum(newIpHeader, sizeof(sr_ip_hdr_t));
        print_addr_ip_int (match->gw.s_addr);
        struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), match->gw.s_addr);
        if (entry) {
          
          fprintf(stderr,"Se encontro la direcion MAC en el cache\n");
          /* Usar la direccion MAC para enviar el paquete*/
          sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t *) newPacket;
          print_addr_ip_int (sr_get_interface(sr, match->interface)->ip);
          memcpy(ethHdr->ether_shost, sr_get_interface(sr, match->interface)->addr, ETHER_ADDR_LEN);
          memcpy(ethHdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

          /* Enviar el paquete*/
          sr_send_packet(sr, newPacket, len, match->interface);

          /* Liberar la entrada ARP*/
          free(entry);
        } else {
          fprintf(stderr,"No se encontro la direcion MAC en el cache\n");
          /* Poner en cola la solicitud ARP*/
          struct sr_arpreq* arpRequest = sr_arpcache_queuereq(&(sr->cache), match->gw.s_addr, newPacket, len, match->interface);
          handle_arpreq(sr, arpRequest); 
          /*
            Todo esto esta bien
          */
        }
				
      }
    } else {
      /*No hay coincidencia en mi tabla por lo que tengo que enviar un ICMP net unreacheable*/
        fprintf(stderr,"No se encontro en la tabla de enrutamiento\n");
        print_addr_ip_int (ipHeader->ip_src);
        sr_send_icmp_error_packet(3, 0, sr, ipHeader->ip_src, packet);
    }
  } else {
    fprintf(stderr,"MiInterfaz != 0\n");
    /* Verificar si es un paquete ICMP echo request y responder con echo reply*/
    if(ipHeader->ip_p == ip_protocol_icmp){
      fprintf(stderr,"el protocolo de la ip es icmp\n");
      sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
      if (icmpHeader->icmp_type == 8 && icmpHeader->icmp_code == 0) {  /* Echo request*/
        fprintf(stderr,"ES UN ECHO REQUEST\n");
        sr_send_icmp_echo_reply(sr, packet, len, interface);
      } 
    }
  }
  /* 
  * COLOQUE ASÍ SU CÓDIGO
  * SUGERENCIAS: 
  * - Obtener el cabezal IP y direcciones 
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento 
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

}

/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
    ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
    memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

    copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
    memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

    print_hdrs(copyPacket, currPacket->len);
    sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
    currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo el cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request) {  /* Si es un request ARP */
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0) {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
      printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");
      sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP;
      arpHdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, myInterface->name);
    }

    printf("******* -> ARP request processing complete.\n");

  } else if (op == arp_op_reply) {  /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    
    if (arpReq != NULL) { /* Si hay paquetes pendientes */

    	printf("****** -> Send outstanding packets.\n");
    	sr_arp_reply_send_pending_packets(sr, arpReq, (uint8_t *) myInterface->addr, (uint8_t *) senderHardAddr, myInterface);
    	sr_arpreq_destroy(&(sr->cache), arpReq);

    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);
  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */