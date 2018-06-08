//
// Created by george on 16/11/2017.
//

#ifndef TServer_TServer_H
#define TServer_TServer_H

#include "iostream"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tserverfhesiutils.h"
#include "FHE-SI.h"
#include "FHEContext.h"
#include "Serialization.h"
#include <map>
using namespace std;

class TServerV3 {
private:
    unsigned k;
    unsigned dim;
    map<uint32_t ,long> clusters_counter;
    map<uint32_t,Ciphertext> point_distances;
    bool active;
    bool verbose;
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
    void calculateVariance(int);
    Plaintext newCentroidCoef(const Plaintext &,long);
    ifstream centroidCoefToStream(const Ciphertext &);
    ifstream indexToStream(const Ciphertext &);
public:
    TServerV3(string,int, bool verbose=true);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif