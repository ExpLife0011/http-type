//
// Created by cz on 29/04/2018.
//

#ifndef PROJECT_TCP_RECEIVE_H
#define PROJECT_TCP_RECEIVE_H

#include "headers.h"
#include "utils.h"
#include <map>
#include <vector>

using std::map;
using std::vector;

struct TcpFlow {
    uint32_t srcip, dstip;
    uint16_t srcport, dstport;
    TcpFlow(uint32_t _srcip, uint32_t _dstip, uint16_t _srcport, uint16_t dstport) {
        srcip = _srcip;
        dstip = _dstip;
        srcport = _srcport;
        dstport = _srcport;
    }
    TcpFlow() {}

    friend bool operator< (TcpFlow a, TcpFlow b) {
        if (a.srcip != b.srcip) return a.srcip < b.srcip;
        if (a.dstip != b.dstip) return a.dstip < b.dstip;
        if (a.srcport != b.srcport) return a.srcport < b.srcport;
        return a.dstport < b.dstport;
    }
};

struct HttpReceive {
    uint32_t total, receive;
    HttpReceive() {}
};

extern map<TcpFlow, HttpReceive> flowReceive;

extern vector<double> recevieRatio;

extern int totalHttpPackage;
extern int noHttpLengthPackage;

void tcp_receive_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt);

#endif //PROJECT_TCP_RECEIVE_H
