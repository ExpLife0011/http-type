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
using namespace std;

int main(int argc, char *argv[]) {
	u_char err[100];
	FILE *infp;

	if(argc != 3) {
		printf("usage: http-type <interval>(second) <infile> <outfile>\n");
		exit(0);
	}

	roll(argv[1], dns_roller);

	cout << "---------- dns finish -----------\n";
	roll(argv[1], http_roller);
	
	ofstream fout(argv[2]);

	// dnsData
	for (auto i: dnsData)
		cout << i.first << ":  " << i.second << endl;

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