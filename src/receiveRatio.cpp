//
// Created by cz on 29/04/2018.
//

#include "tcp_receive.h"
#include "roll.h"
#include <iostream>
#include <fstream>
using namespace std;
int main(int argc,char * argv[])
{
    if(argc != 3)
    {
        cerr<<"Usage : ./http <filename> <out>"<<endl;
        return 0;
    }

    ofstream fout(argv[2]);

//    cout << totalHttpPackage << " no length: " << noHttpLengthPackage << endl;
    roll(argv[1], tcp_receive_roller);
    finalClear();

    cout << "no length: " << noHttpLengthPackage << endl;
    cout << "http header tot: " << totalHttpPackage << endl;

    fout << "no length: " << noHttpLengthPackage << endl;
    fout << "http header tot: " << totalHttpPackage << endl;

    for (auto i: receiveRatio)
        cout << i.first << " " << i.second << endl;

    return 0;
}
