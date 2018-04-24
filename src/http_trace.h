#ifndef _HTTP_TRACE_HH_
#define _HTTP_TRACE_HH_

#include "headers.h"
#include "utils.h"
// #include "flow.h"
#include "dns_trace.h"
/*
 * STRUCT HttpPacket
 * store (src,dst) tuple, seq number, length, and some tags
 */
#include <cstdint>

struct Channel
{
	uint32_t srcip,dstip;
	//Constructor
	Channel(uint32_t src=0,uint32_t dst=0):srcip(src),dstip(dst){}
};
//typedef SocketStat Channel;
inline bool operator==(const Channel & l, const Channel & r)
{
	return (l.srcip==r.srcip && l.dstip==r.dstip)
		//&& (l.srcport==r.srcport && l.dstport==r.dstport)
		;
}
inline bool operator<(const Channel & l, const Channel & r)
{
	if(l.srcip == r.srcip)
	{
		/*if(l.dstip == r.dstip)
		{
			if(l.srcport == r.srcport)
			{
				return l.dstport<r.dstport;
			}
			return l.srcport<r.srcport;
		}*/
		return l.dstip<r.dstip;
	}
	return l.srcip<r.srcip;
}

struct HttpPacket
{
	Channel ch;
	uint32_t seq;
	uint16_t tot_len;		//HTTP payload len
	bool taged=false;		//if true, then should be removed...
	struct timeval timestp;

	//Constructors
	HttpPacket():ch(),seq(0),tot_len(0),taged(false)
	{
	}
	HttpPacket(const Channel & c, uint32_t s, uint32_t tl)
	{
		this->ch.srcip = c.srcip;
		this->ch.dstip = c.dstip;
		this->taged=false;
		this->seq=s;
		this->tot_len=tl;
	}
	void setTime(const struct timeval & t)
	{
		timestp = t;
	}
	struct timeval getStartTime() const
	{
		return timestp;
	}
};

/*
 * STRUCT TargetShooter
 * store the seq number gap of a http session
 * also the content type
 */
#include <string>
struct TargetShooter
{
	Channel ch;
	uint32_t start,end;		//seq start and seq end
	std::string type;
	enum Dir_t {UPLINK,DOWNLINK} direction;

	//Constructors
	TargetShooter():ch(),type(),direction()
	{
		start=end=0;
	}
	TargetShooter(const Channel & c,uint32_t s,uint32_t e,std::string ty,Dir_t dir)
	{
		this->ch.srcip = c.srcip;
		this->ch.dstip = c.dstip;
		start=s;end=e;
		type=ty;
		direction=dir;
	}
	TargetShooter & operator=(const TargetShooter & t) 
	{
		this->ch=t.ch;
		this->start=t.start;this->end=t.end;
		this->type=t.type;
		this->direction=t.direction;
		return *this;
	}
	TargetShooter operator=(const TargetShooter & t) const
	{
		TargetShooter ret(t.ch,t.start,t.end,t.type,t.direction);
		return ret;
	}
};

inline bool operator<(const TargetShooter & l, const TargetShooter & r)
{
	if(l.ch==r.ch)
	{
		return (std::make_pair(l.start,l.end)<std::make_pair(r.start,r.end));
	}
	return l.ch<r.ch;
}
//inline bool operator==(const TargetShooter & l,


struct TargetShooterS
{
private:
	struct timeval st_time;
	bool t_valid;
public:
	const Channel ch;
	std::string type;
	size_t size;
	
	TargetShooterS(const Channel & l,int size = 0,
			std::string tt = ""):ch(l),type(tt)
	{

		this->size = size;
		t_valid = false;
	}

	void updateTime(const struct timeval & t)
	{
		if(t_valid == false)
			st_time = t;
		else if(t < st_time)
			st_time = t;
		t_valid = true;
	}
	struct timeval getStartTime()
	{
		if(!t_valid)
		{
			fprintf(stderr,"warning : getting uninitialized time info!\n");
		}
		return st_time;
	}

	const std::string & getType() const
	{
		return type;
	}

};

class Http_content {
public:
	uint32_t ip;
	std::string type;
	std::string len;

	Http_content(uint32_t _ip, std::string _type, std::string _len) {
		ip = _ip;
		type = _type;
		len = _len;
	}
	// Http_content() {}
};

#include <vector>
extern std::vector<Http_content> httpData;
extern std::map<uint32_t, std::map<std::string, int> > httpDataSum;  // ip, type, total len
extern std::map<std::string, std::map<std::string, int> > httpDataSumDns;  // DNS, type, total len
/*
 * FUNCTION -- PCAP_HANDLER
 *		pcap_handler http_roller;
 *
 * roll the pcap file and get http content characteristics
 */
void http_roller(u_char * user, const struct pcap_pkthdr * h, const u_char * pkt);
#endif
