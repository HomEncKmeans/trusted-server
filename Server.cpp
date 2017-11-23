//
// Created by george on 7/11/2017.
//

#include "Server.h"


struct ClientRequest {
    int socketFD;
    string request;
};

struct ServerAndSocket {
    Server *socketServer;
    int socketFD;
};


Server::Server(string serverIp, int serverPort) {
    this->serverIp = serverIp;
    this->serverPort = serverPort;

    this->SocketCreate();
    this->SocketBind();
    this->SocketListen();
    this->SocketAccept();

};

void Server::SocketCreate() {
    this->masterSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (this->masterSocket < 0) {
        perror("Socket Error");
        exit(1);
    } else {
        int opt = 1;
        setsockopt(this->masterSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        cout << "Socket created successfully with file descriptor " << this->masterSocket << "\n";
    };
};

void Server::SocketBind() {
    struct sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(this->serverPort);
    serverAddress.sin_addr.s_addr = inet_addr(this->serverIp.data());

    if (bind(this->masterSocket, (sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Bind Error");
        exit(1);
    } else {
        cout << "Socket bound successfully to the " << this->serverIp << ":" << this->serverPort << " address\n";
    };
};

void Server::SocketListen() {
    listen(this->masterSocket, 5);
    cout << "Socket is beeing listened now\n";
};

void Server::SocketAccept() {

    int socketFD;
    while (1) {
        socketFD = accept(this->masterSocket, NULL, NULL);
        if (socketFD < 0) {
            perror("Accept");
        } else {
            std::cout<<"CLIENT_CONNECTED"<<std::endl;
            this->SocketRead(socketFD);
            std::cout<<socketFD<<std::endl;
        };
    };
};

void Server::SocketRead(int socketPointer) {

    char input[64456];
    int inputLength;
    int socketFD;
    socketFD = socketPointer;
    std::cout<<socketFD<<std::endl;

    while (1) {
        memset((void *) &input, '\0', sizeof(input));
        inputLength = read(socketFD, (void *) &input, 64455);
        if (inputLength < 0) {
            perror("Read");
        } else if (inputLength == 0 || input[0] == '\0') {
            this->HandleRequest(socketFD, "CLIENT_DISCONNECTED");
            exit(0);
        } else {
            this->HandleRequest(socketFD, input);
        };
    };

};


void Server::HandleRequest(int socketFD, string message) {

    std::cout<<message<<std::endl;
    this->Send(socketFD,"Hello from Server");
}



void Server::Send(int socketFD, string message) {

    int bytesWritten;
    bytesWritten = write(socketFD, message.c_str(), message.size() + 1);
    if (bytesWritten < 0) {
        perror("Write");
    } else {
        Server::Log(socketFD, "<--- " + message);
    };
};

void Server::Log(int socketFD, string message) {
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socketFD, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    cout << ip << ":" << port << " " << message << "\n";
};


