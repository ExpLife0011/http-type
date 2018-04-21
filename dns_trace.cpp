#include "dns_trace.h"
#include "roll.h"
#include <iostream>
#include <assert.h>

using namespace std;
/*=====================*/
/* GLB VARS DEFINITION */
/*=====================*/

static int total = 0;
static int LOG_TIMES = 1000000;
/**
 * data map for dns answers.
 * map ipaddr (HOST ENDIAN) to url
 */
std::map<uint32_t, std::string> dnsData;

/*=============================*/
/* HELPER FUNCTION DEFINITIONS */
/*=============================*/

void parse_dns(const char *dnspkt);
int get_dns_reponse(const char * dns_content, const char * start);
int get_dns_request(const char * dns_content, const char * start);
int get_dns_string(const char * string_start, const char * dns_start,
						std::string & target);

/*=================*/
/* IMPLEMENTATIONS */
/*=================*/

int get_dns_string(const char * ss, const char * ds, 
							std::string &target)
{
	char buf[64];
	bzero(buf,sizeof(buf));
	char c = *ss;
	
	if(c == 0)
	{
		target.pop_back();
		return 1;
	}
	else if ((c & 0xc0) == 0xc0)
	{
		/* DEAL WITH POINTER */
		uint16_t cf = ntohs(*(const uint16_t*)ss);
		uint16_t offset = (uint16_t)(cf & 0x3fff);	//GET OFFSET
		int ret = get_dns_string(ds+offset, ds, target);	
		return 2;
	}
	else if ((c & 0xc0) == 0)
	{
		/* DEAL WITH SUBSTRING */
		int offset = (int)c;
		strncpy(buf,ss+1,offset);
		target += std::string(buf);
		target += '.';
		int ret = get_dns_string(ss+offset+1, ds, target);
		return ret+offset+1;
	}
	else return 0;

}

int get_dns_request(const char * dns_content, const char * start)
{
	int curr = 0;
	/*struct DNS_request_t * rheader
		= (DNS_request_t *) dns_content;
	curr += sizeof(DNS_request_t);*/
	std::string qname;
	curr = get_dns_string(dns_content, start, qname);
	std::cout << qname << endl;
	curr += sizeof(DNS_request_t);	
	return curr;
}
int get_dns_reponse(const char * dns_content, const char * start)
{
	//TODO:
	int curr = 0;
	std::string qname;
	curr += get_dns_string(dns_content, start, qname);

	// std::cerr<<"get dns_string : "<<qname << endl;

	DNS_respond_t * rheader =
		(DNS_respond_t *)(dns_content + curr);
	curr += sizeof(DNS_respond_t);

	uint16_t len = ntohs(rheader->rd_length);
	uint16_t rclass = ntohs(rheader->rclass),
			 rtype = ntohs(rheader->rtype);

	if(rclass == CLASS_IN)
	{
		if(rtype == TYPE_A)
		{
			uint32_t nip = *(uint32_t*)(dns_content + curr);
			struct in_addr in;in.s_addr = nip;
			uint32_t ip = ntohl(nip);
			dnsData[ip] = qname;
//			std::cerr<<" got ip : "<<inet_ntoa(in);
		}
		else if (rtype == TYPE_CNAME)
		{
			std::string cname;
			int ret = get_dns_string(dns_content + curr,
									start, cname);
//			std::cerr<<" got cname : "<<cname;
		}
	}
//	std::cerr<<std::endl;
	curr += len;
	return curr;
}

void parse_dns(const char *dnspkt)
{
	const char * curr = dnspkt;
	const struct DNS_header_t * header = 
		(const struct DNS_header_t*)dnspkt;
	uint16_t tag = ntohs(header->tag);
	if(tag != DNS_SUCCESS)
	{
		return;
	}
	uint16_t ancount = ntohs(header->ANcount),
			 qdcount = ntohs(header->QDcount);
	curr += sizeof(struct DNS_header_t);
	for(int i=0;i<qdcount;i++)
	{
		int len = get_dns_request(curr, dnspkt);
		curr+=len;
	}
	for(int i=0;i<ancount;i++)
	{
		int len = get_dns_reponse(curr, dnspkt);
		curr+=len;
	}
}

void dns_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt)
{
	total++; 
	if(total % LOG_TIMES == 0) std::cerr<<total<<" packets done"<<std::endl; 
	const struct Ethernet *link = (struct Ethernet *)pkt;
//	printf("eth type is: %x\n",link->type);
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	const struct Udp_t *trans = (struct Udp_t *)((u_char *)net + 4 * net->ihl);
	const char *app = (char *)((u_char *)trans + sizeof(struct Udp_t));

	uint16_t srcport = ntohs(trans->srcport);

	if(srcport == 53 && net->protocol == 0x11)
	{
		parse_dns(app);
		//TODO deal with DNS packet
	}
	return ;
}

std::string findAddr(int ip)
{
	if(dnsData.size() == 0)
	{
		fprintf(stderr,"No dns data found! call dns_roller() first!\n");
		exit(-1);
	}
	if(dnsData.count(ip))
		return dnsData[ip];
	else return ADDR_NOT_FOUND;
}
