//
// Created by george on 16/11/2017.
//

#ifndef TServerT1V1_TServerT1V1_H
#define TServerT1V1_TServerT1V1_H

#include "iostream"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tserverfhesiutils.h"
#include "FHE-SI.h"
#include "FHEContext.h"
#include "Serialization.h"
#include <map>
#include "unistd.h"
using namespace std;

class TServerT1V1 {
private:
    unsigned k;
    map<unsigned,long> clusters_counter;
    map<unsigned,Ciphertext> point_distances;
    bool active;
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket;
    FHEcontext* client_context;
    FHESISecKey* t_server_seckey;
    FHESIPubKey* client_pubkey;
    KeySwitchSI* t_server_SM;
    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient(int);
    void initializeKM(int);
    void classifyToCluster(int);
    unsigned extractClusterIndex();
    void calculateCentroid(int);
    Plaintext newCentroid(const Plaintext &,long);
    ifstream centroidsToStream(const Ciphertext &);
public:
    TServerT1V1(string,int);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif //TServerT1V1_TServerT1V1_H
