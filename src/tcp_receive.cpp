//
// Created by cz on 29/04/2018.
//

#include "tcp_receive.h"
#include <assert.h>
#include <iostream>

#define ISUSR(ip) (((ip) & 0xffff0000) == 0xc0a80000)
#define ISHTTP(port) ((port) == 80)

using namespace std;

map<TcpFlow, HttpReceive> flowReceive;

vector<HttpReceive> receiveRatio;

int totalHttpPackage = 0;
int noHttpLengthPackage = 0;

typedef map<TcpFlow, HttpReceive>::iterator mapIt;
map<TcpFlow, HttpReceive>::iterator p;
HttpReceive httpReceive;

const char* findHttpBody(const char *app) {
    const char *start = strstr(app, "\r\n\r\n");
    return start + 4;
}

// delete one http flow
mapIt& clearHttp(mapIt &curHttp) {
    receiveRatio.push_back(curHttp->second);
    // curHttp = flowReceive.erase(curHttp);
    return curHttp;
}

// check if one http flow is finish
void checkFinish(mapIt &curHttp) {
    HttpReceive &curReceive = curHttp->second;
    if (curReceive.receive_ack - curReceive.start_seq == curReceive.total)
        clearHttp(curHttp);
}

// if there is an old httpflow not finish, we clear it
void checkOld(TcpFlow &curFlow) {
    p = flowReceive.find(curFlow);
    if (p != flowReceive.end())
        clearHttp(p);
}

// after roll over all package, we clear the package in our Map;
void finalClear() {
//    cout << flowReceive.size() << endl;
    for (mapIt i = flowReceive.begin(); i != flowReceive.end();) {
        i = clearHttp(i);
    }
}

void tcp_receive_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
    // Only consider a protocol stack of Ethernet, IPv4 and TCP
    const struct Ethernet *link = (struct Ethernet *)pkt;
    const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
    if(net->version != 0x4) return;
    if(net->protocol != 0x6) return;
    const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
    const char *app = (char *)((u_char *)trans + 4 * trans->doff);

    // get tcp flags
    const int high = *((u_char*)trans + 12);
    const int low = *((u_char*)trans + 13);
    const uint16_t tcp_flag = high * 16 + low;

    const int srcip = ntohl(net->srcip);
    const int dstip = ntohl(net->dstip);
    const int srcport = ntohs(trans->srcport);
    const int dstport = ntohs(trans->dstport);

    uint32_t seq = ntohl(trans->seq), tot_len = ntohs(net->tot_len);
    uint32_t ack = ntohl(trans->ackseq);

    //Use the length of http payload
    tot_len = tot_len - net->ihl*4 - trans->doff*4;

    //not http? return
    if(!ISHTTP(srcport) && !ISHTTP(dstport)) return;

    // no http data
//    if (tot_len == 0) return;

    // cerr << endl;

    // consider server-client flow
    if(ISHTTP(srcport)) {
        TcpFlow curFlow(srcip, dstip, srcport, dstport);
        char type[100],len[100];

        if (getField(type, app, "Content-Type: ") == 0) {
            // this is a header package
            totalHttpPackage++;

//            cout << totalHttpPackage << " " << noHttpLengthPackage << endl;
            if (getField(len, app, "Content-Length: ") < 0) {
                // but no length
//                cout << "in critial area " << totalHttpPackage << " " << noHttpLengthPackage << endl;
                noHttpLengthPackage++;
                return;
            }

            // cerr << "len " << len << endl;
            // cerr << " seq " << seq << endl;
            checkOld(curFlow);

            const char *httpBody = findHttpBody(app);
            int httpHeaderLen = httpBody - app;

            // cerr << "httpHeaderLen " << httpHeaderLen << endl; 
            HttpReceive httpReceive;
            httpReceive.total = atoi(len);
            httpReceive.http_type = type;
            httpReceive.start_seq = seq + httpHeaderLen;

            flowReceive[curFlow] = httpReceive;
            // cerr << "curFlow " << curFlow << "\n";
        }

        return;
    }

    // this is a client - server flow
    if (ISHTTP(dstport)) {
        TcpFlow curFlow(dstip, srcip, dstport, srcport);
        
        // this is a ack packet
        if ((tcp_flag & TH_ACK) == TH_ACK) {
            p = flowReceive.find(curFlow);
            if (p == flowReceive.end()) {
                // cerr << "died " << ack << endl;
                return;
            }
            p->second.receive_ack = ack;
            
            checkFinish(p);
        }
        else if (((tcp_flag & TH_ACK) == TH_ACK)
                 || ((tcp_flag & TH_FIN) == TH_FIN)) {

            p = flowReceive.find(curFlow);
            if (p != flowReceive.end())
                clearHttp(p);
        }
    }
}
