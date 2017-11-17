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
using namespace std;

class TServer {
private:
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket;
    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient();
public:
    TServer(string,int);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int);
    void log(int,string);




};


#endif //TSERVER_TSERVER_H
