//
// Created by cz on 29/04/2018.
//

#ifndef PROJECT_TCP_RECEIVE_H
#define PROJECT_TCP_RECEIVE_H

#include "headers.h"
#include "utils.h"
#include <map>
#include <vector>
#include <string>
#include <iostream>

using std::map;
using std::vector;
using std::string;
using std::ostream;
using std::cout;
using std::endl;

struct TcpFlow {
    uint32_t srcip, dstip;
    uint16_t srcport, dstport;
    TcpFlow(uint32_t _srcip, uint32_t _dstip, uint16_t _srcport, uint16_t _dstport) {
        srcip = _srcip;
        dstip = _dstip;
        srcport = _srcport;
        dstport = _dstport;
    }
    TcpFlow() {}

    friend bool operator< (TcpFlow a, TcpFlow b) {
        if (a.srcip != b.srcip) return a.srcip < b.srcip;
        if (a.dstip != b.dstip) return a.dstip < b.dstip;
        if (a.srcport != b.srcport) return a.srcport < b.srcport;
        return a.dstport < b.dstport;
    }

    friend ostream& operator<< (ostream &o, TcpFlow &cur) {
        o << cur.srcip << " " << cur.dstip << " " << cur.srcport << " " << cur.dstport;
        return o;
    }
};

struct HttpReceive {
    string http_type;

    uint32_t total;
    uint32_t start_seq;
    uint32_t receive_ack;

    HttpReceive() {}
    friend ostream& operator<< (ostream &o, HttpReceive &cur) {
        // o << cur.http_type << " " << cur.total << " " << cur.start_seq << " " << cur.receive_ack;
        o << cur.http_type << " " << cur.total << " " << cur.receive_ack - cur.start_seq;
        return o;
    }
};

extern map<TcpFlow, HttpReceive> flowReceive;

extern vector<HttpReceive> receiveRatio;

extern int totalHttpPackage;
extern int noHttpLengthPackage;

void tcp_receive_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt);

void finalClear();
#endif //PROJECT_TCP_RECEIVE_H
