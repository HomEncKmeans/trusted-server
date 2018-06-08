//
// Created by george on 16/11/2017.
//

#ifndef TSERVER_TSERVER_H
#define TSERVER_TSERVER_H

#include "iostream"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tserverfhesiutils.h"
#include "FHE-SI.h"
#include "FHEContext.h"
#include "Serialization.h"
#include <map>
#include <random>
#include "unistd.h"
using namespace std;

class TServerV1 {
private:
    // K-means
    unsigned k;
    map<uint32_t,bitset<6>> A;
    map<uint32_t ,bitset<6>> A_r;
    map<uint32_t ,vector<uint32_t >> points;
//    map<uint32_t ,vector<uint32_t >> centroids;
//    map<uint32_t ,int> centroids_clusters;
//    map<int,uint32_t > rev_centroids_clusters;

    int max_round;
    int variance_bound;
    map<unsigned,long> clusters_counter;
    unsigned dim;
    unsigned number_of_points;

    // Networking
    string u_serverIP;
    int u_serverPort;
    int u_serverSocket;
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket;
    int clientSocket;

    // Cryptography
    FHEcontext* client_context;
    FHESISecKey* t_server_seckey;
    FHESIPubKey* client_pubkey;
    KeySwitchSI* t_server_SM;

    //Control
    bool verbose;



    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient(int);
    void receiveUnEncryptedData(int);
    void connectToUServer();
    void initializeClusters();
    long calculateVariance();
    ifstream centroidCoefToStream(const Ciphertext &);
    unsigned extractClusterIndex(const map<uint32_t ,Ciphertext>);
    void swapA();
    void endKMToUserver();
    void resultsToKClient();



public:
    TServerV1(string,int,string,int,unsigned ,int max_round=5,int variance_bound=0,bool verbose=true);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif //TSERVER_TSERVER_H
