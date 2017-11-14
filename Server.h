//
// Created by george on 7/11/2017.
//

#ifndef AUTH_THESIS_FHE_SI_SERVER_H
#define AUTH_THESIS_FHE_SI_SERVER_H

#include <iostream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

class Server {

private:
    string serverIp;
    int serverPort;
    int masterSocket;

    void SocketCreate();

    void SocketBind();

    void SocketListen();

    void SocketAccept();

    void SocketRead(int);


public:
    Server(string, int);

    void Send(int, string);

    void Log(int, string);

    void HandleRequest(int, string);


};


#endif //AUTH_THESIS_FHE_SI_SERVER_H
