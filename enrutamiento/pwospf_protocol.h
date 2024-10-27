/*-----------------------------------------------------------------------------
 * file:  pwospf_protocol.h
 * date:  Thu Mar 18 15:14:06 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 * Protocol headers for the PWOSPF protocol
 *
 *---------------------------------------------------------------------------*/

#ifndef PWOSPF_PROTOCOL_H
#define PWOSPF_PROTOCOL_H

#define OSPF_V2        2

#define OSPF_AllSPFRouters 0xe0000005 /*"224.0.0.5"*/

#define OSPF_TYPE_HELLO 1
#define OSPF_TYPE_LSU   4
#define OSPF_TYPE_LSUPDATE 4
#define OSPF_NET_BROADCAST 1
#define OSPF_DEFAULT_HELLOINT   5 /* seconds */
#define OSPF_DEFAULT_LSUINT    30 /* seconds */
#define OSPF_NEIGHBOR_TIMEOUT  20 /* seconds */ 

#define OSPF_TOPO_ENTRY_TIMEOUT 35 /* seconds */ 

#define OSPF_DEFAULT_AUTHKEY   0 /* ignored */

#define OSPF_MAX_HELLO_SIZE  1024 /* bytes */
#define OSPF_MAX_LSU_SIZE    1024 /* bytes */
#define  OSPF_MAX_LSU_TTL     255  


struct ospfv2_hdr
{
    uint8_t version; /* ospf version number */
    uint8_t type;    /* type of ospf packet */
    uint16_t len;    /* length of packet in bytes including header */
    uint32_t rid;    /* router ID of packet source */
    uint32_t aid;    /* area packet belongs to */
    uint16_t csum;   /* checksum */ 
    uint16_t autype; /* authentication type */
    uint64_t audata; /* used by authentication scheme */
}__attribute__ ((packed));
typedef struct ospfv2_hdr ospfv2_hdr_t;

struct ospfv2_hello_hdr
{
    uint32_t nmask;    /* netmask of source interface */
    uint16_t helloint; /* interval time for hello broadcasts */
    uint16_t padding;
}__attribute__ ((packed));
typedef struct ospfv2_hello_hdr ospfv2_hello_hdr_t;

struct ospfv2_lsu_hdr
{
    uint16_t seq;
    uint8_t  unused;
    uint8_t  ttl;
    uint32_t num_adv;  /* number of advertisements */
}__attribute__ ((packed));
typedef struct ospfv2_lsu_hdr ospfv2_lsu_hdr_t;

struct ospfv2_lsa
{
    uint32_t subnet; /* -- link subnet -- */
    uint32_t mask;   /* -- link subnet mask -- */
    uint32_t rid;    /* -- attached router id (if any) -- */
}__attribute__ ((packed));
typedef struct ospfv2_lsa ospfv2_lsa_t;


#endif  /* PWOSPF_PROTOCOL_H */
