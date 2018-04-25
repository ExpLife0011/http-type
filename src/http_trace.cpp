#include "http_trace.h"
#include <assert.h>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <algorithm>

#define MAXTIME 50000
#define ISUSR(ip) (((ip) & 0xffff0000) == 0xc0a80000)
#define ISHTTP(port) ((port) == 80)

using namespace std;


// class HttpData {
// public:
// 	string 
// }

vector<Http_content> httpData;
map<uint32_t, map<string, int> > httpDataSum;  // ip, type, total len
map<string, map<string, int> > httpDataSumDns;  // domainName, type, total len
map<string, map<string, int> > httpDataCntDns;  // domainName, type, total cnt

map<string, int>::iterator p;

extern map<uint32_t, string> dnsData;
extern int notInDnsData;

set<int> notInDnsDataSet;

/*
 * FUNCTION void dealDownlink(const char *, HttpPacket &)
 *
 * get a downlink http packet and deal with it
 *
 * @param
 *		app : content in the packet
 *		pack : basic infomation of the packet
 */
inline void dealDownlink(const char * app, HttpPacket & pack)
{
	// buffer.push_back(pack);
	char type[100],len[100];
	int r,_len;
	//We want to have type for content shooter packet;
	if((r = getField(type, app, "Content-Type: ")) < 0)
	   	return;
	else
	{				//contains Content-Type field
		std::string type_s(type);
		std::transform(type_s.begin(),type_s.end(),
					type_s.begin(),::tolower);

		if((r = getField(len, app, "Content-Length: ")) < 0) 
		{
			//if we don't get content length, we will assume it has only 1 packet for it's type
			// contentSize[type_s]+=pack.tot_len;
			// if(pack.tot_len != 0)
			// {
			// 	flowPerContent[type_s].push_back(pack.tot_len);
			// 	int st = pack.seq, en = pack.seq + _len; 
			// 	TargetShooter temp(
			// 			Channel(pack.ch),st,en,
			// 			std::string(type_s),TargetShooter::DOWNLINK);
			// 	TargetShooterS tempS(pack.ch,pack.tot_len,
			// 						std::string(type_s));
			// 	tempS.updateTime(pack.timestp);
			// 	tgtArrayS.push_back(tempS);
			// 	addTypeSize(temp,pack.tot_len);
			// }
			strcpy(len, "0");
		}
		// else
		// {
		// 	//we got expected length of the object, Expected Seq gap can be calculated...
		// 	_len = atoi(len);
		// 	using namespace std;
		// 	int st = pack.seq, en = pack.seq + _len; 
		// 	targetSet.insert(TargetShooter(
		// 			Channel(pack.ch),st,en,
		// 			std::string(type_s),TargetShooter::DOWNLINK)
		// 		);
		// //flush();
		// }
		uint32_t srcip = pack.ch.srcip;
		if (!dnsData.count(srcip)) {
//			cout << "not in dnsData : " << srcip << endl;
            notInDnsDataSet.insert(srcip);
			notInDnsData++;
			return;
		}
		string domainName = dnsData[srcip];

		// data1
		httpData.push_back(Http_content(srcip, type, len));
		
		// data2
		if (!httpDataSum.count(srcip)) httpDataSum[srcip] = map<string, int>();
		httpDataSum.find(srcip)->second[type] += atoi(len);

		// data3
		if (!httpDataSumDns.count(domainName)) httpDataSumDns[domainName] = map<string, int>();
        httpDataSumDns.find(domainName)->second[type] += atoi(len);

        if (!httpDataCntDns.count(domainName)) httpDataCntDns[domainName] = map<string, int>();
        httpDataCntDns.find(domainName)->second[type] += 1;
	}
	return;
}

void http_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
	// Only consider a protocol stack of Ethernet, IPv4 and TCP
	const struct Ethernet *link = (struct Ethernet *)pkt;
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	if(net->version != 0x4) return;
	if(net->protocol != 0x6) return;
	const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
	const char *app = (char *)((u_char *)trans + 4 * trans->doff);

	// IP:port in integer
	const int srcip = ntohl(net->srcip);
	const int dstip = ntohl(net->dstip);
	const int srcport = ntohs(trans->srcport);
	const int dstport = ntohs(trans->dstport);

	uint32_t seq = ntohl(trans->seq), tot_len = ntohs(net->tot_len);
	
	//Use the length of http payload
	tot_len = tot_len - net->ihl*4 - trans->doff*4;	

	//not http? return
	// if(!ISHTTP(srcport) && !ISHTTP(dstport))
	// 	return;
	
	// Only consider server-client flow
	if(!ISUSR(srcip) && ISUSR(dstip)) 
	{
		HttpPacket pack(Channel(srcip,dstip),seq,tot_len);
		pack.setTime(h->ts);
		dealDownlink(app,pack);
		
		// httpData.push_back(HttpData(ip, type, len));
	}
	// else return;


}
