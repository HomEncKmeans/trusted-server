//
// Created by george on 16/11/2017.
//

#include "TServer.h"
TServer::TServer(string t_serverIP, int t_serverPort) {
    this->t_serverIP= move(t_serverIP);
    this->t_serverPort=t_serverPort;
    print("TRUSTED SERVER");
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();
    this->handleRequest(this->t_serverSocket);
}


void TServer::socketCreate() {
    this->t_serverSocket=socket(AF_INET,SOCK_STREAM,0);
    if(this->t_serverSocket<0){
        perror("ERROR IN SOCKET CREATION");
        exit(1);
    }else{
        int opt=1;
        setsockopt(this->t_serverSocket,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        string message = "Socket created successfully. File descriptor: "+to_string(this->t_serverSocket);
        print(message);
    }

}

void TServer::socketBind() {
    struct sockaddr_in u_serverAddress;
    u_serverAddress.sin_family = AF_INET;
    u_serverAddress.sin_port = htons(static_cast<uint16_t>(this->t_serverPort));
    u_serverAddress.sin_addr.s_addr = inet_addr(this->t_serverIP.data());
    if (bind(this->t_serverSocket, (sockaddr *) &u_serverAddress, sizeof(u_serverAddress)) < 0) {
        perror("BIND ERROR");
        exit(1);
    } else {
        string message= "Socket bound successfully to :["+t_serverIP+":"+to_string(this->t_serverPort)+ "]";
        print(message);
    }

}

void TServer::socketListen() {
    listen(this->t_serverSocket,5);
    print("Server is listening...");

}

void TServer::socketAccept() {
    int socketFD;
    socketFD = accept(this->t_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void TServer::handleRequest(int socketFD) {
    string message = this->receiveMessage(socketFD);
    if(message=="C-PK"){
        this->receiveEncryptionParamFromClient();
    }else if(message=="U-START-KM"){

    }else if(message=="U-NEW-CENTROID"){

    }else{
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }
}

bool TServer::sendStream(ifstream data, int socket){
    streampos begin,end;
    begin =data.tellg();
    data.seekg(0,ios::end);
    end=data.tellg();
    streampos size = end-begin;
    streampos *sizeref = &size;
    print(size);
    auto * memblock = new char [size];
    data.seekg (0, std::ios::beg);
    data.read (memblock, size);
    data.close();
    if(0 > send(socket, sizeref, sizeof(size), 0)){
        perror("SEND FAILED.");
        return false;
    }else {
        if (send(socket, memblock, static_cast<size_t>(size), 0) < 0) {
            perror("SEND FAILED.");
            return false;
        } else {
            return true;
        }
    }
}

bool TServer::sendMessage(int socketFD, string message) {
    if( send(socketFD , message.c_str() , strlen( message.c_str() ) , 0) < 0){
        perror("SEND FAILED.");
        return false;
    }else{
        this->log(socketFD,"<--- "+message);
        return true;
    }
}

string TServer::receiveMessage(int socketFD, int buffersize) {
    char buffer[buffersize];
    string message;
    if(recv(socketFD, buffer, static_cast<size_t>(buffersize), 0) < 0){
        perror("RECEIVE FAILED");
    }
    message=buffer;
    this->log(socketFD,"---> "+message);
    return message;
}

ifstream TServer::receiveStream(int) {
    return std::ifstream();
}

void TServer::log(int socket, string message){
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "["+ip+":"+to_string(port)+"] "+message;
    print(msg);
}