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

vector<double> recevieRatio;

int totalHttpPackage = 0;
int noHttpLengthPackage = 0;

map<TcpFlow, HttpReceive>::iterator p;
HttpReceive httpReceive;

const char* findHttpBody(const char *app) {
    const char *start = strstr(app, "\r\n\r\n");
    return start + 4;
}

// if there is an old httpflow not finish, we deal with it
void checkOld(TcpFlow &curFlow) {
    p = flowReceive.find(curFlow);
    if (p != flowReceive.end()) {
        httpReceive = p->second;
        double ratio = double(httpReceive.receive) / httpReceive.total;
        recevieRatio.push_back(ratio);
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

    const int srcip = ntohl(net->srcip);
    const int dstip = ntohl(net->dstip);
    const int srcport = ntohs(trans->srcport);
    const int dstport = ntohs(trans->dstport);

    uint32_t seq = ntohl(trans->seq), tot_len = ntohs(net->tot_len);

    //Use the length of http payload
    tot_len = tot_len - net->ihl*4 - trans->doff*4;

//    cout << "tot len : " << tot_len << endl;
    //not http? return
    if(!ISHTTP(srcport) && !ISHTTP(dstport))
     	return;

    if (tot_len == 0) return;
    // Only consider server-client flow
//    if(!ISUSR(srcip) && ISUSR(dstip)) {
        TcpFlow curFlow(srcip, dstip, srcport, dstport);
        char type[100],len[100];

        // this is a tcp close
//        cout << (trans->fin & TH_FIN) << endl;
//        cout << (trans->syn & TH_SYN) << endl;
//        if (ntohl(trans->fin)) {
//            checkOld(curFlow);
//            return;
//        }


        if (getField(type, app, "Content-Type: ") == 0) {
            // this is a header package
            totalHttpPackage++;
//            cout << totalHttpPackage << " " << noHttpLengthPackage << endl;
            if (getField(len, app, "Content-Length: ") < 0) {
                // but no length
                cout << "in critial area " << totalHttpPackage << " " << noHttpLengthPackage << endl;
                noHttpLengthPackage++;
                return;
            }

            checkOld(curFlow);

            const char *httpBody = findHttpBody(app);
            httpReceive.total = atoi(len);
            httpReceive.receive += app + tot_len - httpBody;
            cout << "receive " << app + tot_len - httpBody << endl;
            flowReceive[curFlow] = httpReceive;
        }
        else {
            // this is a package full of data
            p = flowReceive.find(curFlow);
            p->second.receive += tot_len;
        }

//    }
}
