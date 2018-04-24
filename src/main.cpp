#include "headers.h"
#include "roll.h"
#include "dns_trace.h"
#include "http_trace.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
using namespace std;

extern set<int> notInDnsDataSet;
int main(int argc, char *argv[]) {
	u_char err[100];
	FILE *infp;

	if(argc != 3) {
		printf("usage: http-type <interval>(second) <infile> <outfile>\n");
		exit(0);
	}

	char httpdata[100], dnsdata[100];
	strcpy(dnsdata, argv[2]);
	strcat(dnsdata, ".dns");

	strcpy(httpdata, argv[2]);
	strcat(httpdata, ".http");


	cout << endl;
	cout << argv[1] << endl;
	cout << argv[1] << " " <<  httpdata << " " << dnsdata << endl;

	roll(argv[1], dns_roller);

	cout << "---------- dns finish -----------\n";
	roll(argv[1], http_roller);
	cout << "---------- http finish -----------\n";



	ofstream fout(httpdata);
	ofstream fout2(dnsdata);

	// dnsData
    cout << "notInDnsDataSet: " << notInDnsDataSet.size() << endl;
    cout << "DnsData: " << dnsData.size() << endl;
	fout2 << "not in dns data: " << notInDnsData << endl;
	for (auto i: dnsData)
		fout2 << i.first << " " << i.second << endl;

	// httpData1
	// for (auto i: httpData)
	// 	cout << i.ip << " " << i.type << " " << i.len << endl;

	// httpData2
	// for (auto i: httpDataSum)
	// 	for (auto j: i.second)
	// 		cout << i.first << " " << j.first << " " << j.second << endl;

	// httpData3
	for (auto i: httpDataSumDns) {
		for (auto j: i.second)
			 fout << i.first << " " << j.first << " " << j.second << endl;
		fout << endl;
	}

	return 0;
}
