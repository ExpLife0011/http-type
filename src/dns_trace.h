#ifndef _DNS_TRACE_HH_
#define _DNS_TRACE_HH_

/* MACROS AND INCLUDE FILES */
#include <stdint.h>
#include "headers.h"
#define DNS_SUCCESS 0x8180
#define TYPE_A		0x1
#define TYPE_CNAME	0x5
#define CLASS_IN	0x1

/* GLB TYPE AND VARS DEFINITION */

/**
 * Struct for DNS header
 */
struct DNS_header_t
{
	uint16_t ID;			//id field
	uint16_t tag;			//0x0000 in request
							//0x8000 in standard reply
							//0x8003 in ERR_NOTFOUND...
	uint16_t QDcount;		//request number
	uint16_t ANcount;		//answer number
	uint16_t NScount;		//set to 0
	uint16_t ARcount;		//set to 0
};


/**
 * Struct for DNS request
 */
struct DNS_request_t
{
	uint16_t qtype;			//set to 1
	uint16_t qclass;		//set to 1
};


/**
 * Struct for DNS respond
 */
struct DNS_respond_t
{
	uint16_t rtype;			//set to 1
	uint16_t rclass;		//set to 1
	uint32_t ttl;			//set to 0
	uint16_t rd_length;		//the length of RDATA
} __attribute__((packed));

#ifdef __cplusplus
#include <map>
#include <string>
extern std::map<uint32_t, std::string> dnsData;
extern int notInDnsData;
#endif

/* FUNCTION DEFINITIONS */
#ifdef __cplusplus
extern "C" {
#endif

void dns_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt);


#ifdef __cplusplus
}
std::string findAddr(int ip);
#endif
#endif
