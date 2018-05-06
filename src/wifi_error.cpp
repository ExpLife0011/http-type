#include "headers.h"
#include <assert.h>
#include <map>
#include <set>
#include <iostream>
#include <algorithm>

#define LOG_TIMES 1000000
#define ISUSR(ip) (((ip) & 0xffff0000) == 0xc0a80000)

using namespace std;

class Flow {
public:
	uint32_t usrip;
	uint32_t servip;
	uint16_t usrport;
	uint16_t servport;
	mutable int tp;

	Flow(uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2) {
		usrip = ip1;
		usrport = port1;
		servip = ip2;
		servport = port2;
		tp = 0;
	}
	Flow() {}

	friend bool operator< (const Flow &f1, const Flow &f2) {
		if(f1.usrip != f2.usrip) return f1.usrip < f2.usrip;
		else if(f1.servip != f2.servip) return f1.servip < f2.servip;
		else if(f1.usrport != f2.usrport) return f1.usrport < f2.usrport;
		else return f1.servport < f2.servport;
	}
};

static size_t total;

FILE *infp, *outfp;
Flow fl;

map<Flow, set<int> > serverAck;
uint32_t userRequestCnt = 0;
uint32_t lossCnt = 0;

void wifi_error(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
	if (total % LOG_TIMES == 0) 
        cerr<<total<<"packets done"<<endl; 
    total++;

	// Only consider a protocol stack of Ethernet, IPv4 and TCP
	const struct Ethernet *link = (struct Ethernet *)pkt;
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	if(net->version != 0x4) return;
	if(net->protocol != 0x6) return;
	const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
	// IP:port in integer
	const int srcip = ntohl(net->srcip);
	const int dstip = ntohl(net->dstip);
	const int srcport = ntohs(trans->srcport);
	const int dstport = ntohs(trans->dstport);

	const bool syn = trans->syn;	
	const bool ack = trans->ack;
	const bool fin = trans->fin;
	const uint32_t seq = ntohl(trans->seq);
	const uint32_t ackseq = ntohl(trans->ackseq);
	const uint32_t tcpLen = ntohs(net->tot_len) - net->ihl*4 - trans->doff*4;;

	// cerr << "len : " << tcpLen << endl;

	// Only consider server-client flow
	if(ISUSR(srcip) && !ISUSR(dstip)) {
		// client -> server
		fl = Flow(srcip, srcport, dstip, dstport);

		userRequestCnt++;

		if (serverAck.count(fl)) {
			// this is a handshake
			// if (syn && serverAck[fl].count(seq + 1)) lossCnt++;
			// this is a farewell
			// else if (fin && serverAck[fl].count(seq + 1)) lossCnt++;
			// this is a simple request(like http request)
			// else if (!syn && !fin && serverAck[fl].count(seq + tcpLen)) lossCnt++;
			if ((syn || tcpLen != 0) 
				&& serverAck[fl].count(seq + tcpLen)) {
				lossCnt++;
				cerr << total << endl;
			}
		}
	}
	else if(!ISUSR(srcip) && ISUSR(dstip)) {
		// server -> client
		fl = Flow(dstip, dstport, srcip, srcport);

		if (!serverAck.count(fl)) serverAck[fl] = set<int>();

		if (syn || fin) serverAck[fl].insert(ackseq - 1);
		else serverAck[fl].insert(ackseq);
	}

	// cout << total << " " << userRequestCnt << " " << lossCnt << endl;
}

int main(int argc, char *argv[]) {
	u_char err[100];
	int i, j;

	if(argc != 3) {
		printf("usage: WifiError <infile> <outfile>\n");
		exit(0);
	}

	infp = fopen(argv[1], "r");
	outfp = fopen(argv[2], "w+");
	assert(infp && outfp);

	pcap_t *pcap = pcap_fopen_offline(infp, NULL);
	pcap_loop(pcap, 0, wifi_error, err);

	cout << "loss : " << lossCnt << endl;
	cout << "total : " << userRequestCnt << endl;
	return 0;
}