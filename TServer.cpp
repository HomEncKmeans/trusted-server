//
// Created by george on 16/11/2017.
//

#include "TServer.h"

TServer::TServer(string t_serverIP, int t_serverPort) {
    this->active = true;
    this->t_serverIP = move(t_serverIP);
    this->t_serverPort = t_serverPort;
    print("TRUSTED SERVER");
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();
    print("CLIENT ENCRYPTION PARAMETERS");
    ifstream contextfile("context.dat");
    FHEcontext fhEcontext(contextfile);
    this->client_context = &fhEcontext;
    activeContext = &fhEcontext;
    ifstream pkC("pkC.dat");
    FHESIPubKey fhesiPubKey(fhEcontext);
    fhesiPubKey.Import(pkC);
    this->client_pubkey = &fhesiPubKey;
    ifstream skT("skT.dat");
    FHESISecKey fhesiSecKey(fhEcontext);
    fhesiSecKey.Import(skT);
    this->t_server_seckey = &fhesiSecKey;
    ifstream smT("smT.dat");
    KeySwitchSI keySwitchSI(fhEcontext);
    keySwitchSI.Import(smT);
    this->t_server_SM = &keySwitchSI;
    print("CONTEXT");
    print(fhEcontext);
    print("CLIENT PUBLIC KEY");
    print(fhesiPubKey);
    print("TSERVER SECRET KEY");
    print(fhesiSecKey);
    print("TSERVER SWITCH MATRIX ");
    print(keySwitchSI);

    while (this->active) {
        this->socketAccept();
    }

}


void TServer::socketCreate() {
    this->t_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (this->t_serverSocket < 0) {
        perror("ERROR IN SOCKET CREATION");
        exit(1);
    } else {
        int opt = 1;
        setsockopt(this->t_serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        string message = "Socket created successfully. File descriptor: " + to_string(this->t_serverSocket);
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
        string message = "Socket bound successfully to :[" + t_serverIP + ":" + to_string(this->t_serverPort) + "]";
        print(message);
    }

}

void TServer::socketListen() {
    listen(this->t_serverSocket, 5);
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
    string message = this->receiveMessage(socketFD, 4);
    if (message == "C-PK") {
        this->receiveEncryptionParamFromClient(socketFD);
    } else if (message == "U-KM") {
        this->initializeKM(socketFD);
    } else if (message == "U-DP") {
        this->classifyToCluster(socketFD);
    } else if (message == "U-NC") {
        this->calculateCentroid(socketFD);
    } else if (message == "UEKM") {
        this->sendMessage(socketFD, "T-END");
        this->active = false;
        print("TSERVER STOP AND EXIT");
    } else {
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }
}

bool TServer::sendStream(ifstream data, int socket) {
    streampos begin, end;
    begin = data.tellg();
    data.seekg(0, ios::end);
    end = data.tellg();
    streampos size = end - begin;
    uint32_t sizek = size;
    auto *memblock = new char[sizek];
    data.seekg(0, std::ios::beg);
    data.read(memblock, sizek);
    data.close();
    htonl(sizek);
    if (0 > send(socket, &sizek, sizeof(uint32_t), 0)) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + to_string(sizek));
        if (this->receiveMessage(socket, 7) == "SIZE-OK") {
            ssize_t r = (send(socket, memblock, static_cast<size_t>(size), 0));
            print(r); //for debugging
            if (r < 0) {
                perror("SEND FAILED.");
                return false;
            } else {
                return true;
            }
        } else {
            perror("SEND SIZE ERROR");
            return false;
        }
    }
}

bool TServer::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string TServer::receiveMessage(int socketFD, int buffersize) {
    char buffer[buffersize];
    string message;
    if (recv(socketFD, buffer, static_cast<size_t>(buffersize), 0) < 0) {
        perror("RECEIVE FAILED");
    }
    message = buffer;
    message.erase(static_cast<unsigned long>(buffersize));
    this->log(socketFD, "---> " + message);
    return message;
}

ifstream TServer::receiveStream(int socketFD, string filename) {
    uint32_t size;
    auto *data = (char *) &size;
    if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE SIZE ERROR");
    }
    ntohl(size);
    this->log(socketFD, "--> SIZE: " + to_string(size));
    this->sendMessage(socketFD, "SIZE-OK");
    char buffer[size];
    ssize_t r = recv(socketFD, buffer, size, 0);
    print(r);
    if (r < 0) {
        perror("RECEIVE STREAM ERROR");
    }
    ofstream temp(filename, ios::out | ios::binary);
    temp.write(buffer, size);
    temp.close();

    return ifstream("filename");
}

void TServer::log(int socket, string message) {
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "[" + ip + ":" + to_string(port) + "] " + message;
    print(msg);
}

void TServer::receiveEncryptionParamFromClient(int socketFD) {
    this->sendMessage(socketFD, "T-PK-READY");
    this->receiveStream(socketFD, "pkC.dat");
    this->sendMessage(socketFD, "T-PK-RECEIVED");
    string message = this->receiveMessage(socketFD, 5);
    if (message != "C-SMT") {
        perror("ERROR IN PROTOCOL 2-STEP 2");
        return;
    }
    this->sendMessage(socketFD, "T-SMT-READY");
    this->receiveStream(socketFD, "smT.dat");
    this->sendMessage(socketFD, "T-SMT-RECEIVED");
    string message1 = this->receiveMessage(socketFD, 5);
    if (message1 != "C-SKT") {
        perror("ERROR IN PROTOCOL 2-STEP 3");
        return;
    }
    this->sendMessage(socketFD, "T-SKT-READY");
    this->receiveStream(socketFD, "skT.dat");
    this->sendMessage(socketFD, "T-SKT-RECEIVED");
    string message2 = this->receiveMessage(socketFD, 9);
    if (message2 != "C-CONTEXT") {
        perror("ERROR IN PROTOCOL 2-STEP 4");
        return;
    }
    this->sendMessage(socketFD, "T-C-READY");
    this->receiveStream(socketFD, "context.dat");
    this->sendMessage(socketFD, "T-C-RECEIVED");
    print("PROTOCOL 2 COMPLETED");

}

void TServer::initializeKM(int socketFD) {
    this->sendMessage(socketFD, "T-READY");
    uint32_t size;
    auto *data = (char *) &size;
    if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE K ERROR");
    }
    ntohl(size);
    this->log(socketFD, "--> K: " + to_string(size));
    this->k = size;
    for (unsigned i = 0; i < this->k; i++) {
        this->clusters_counter[i] = 0;
    }
    this->sendMessage(socketFD, "T-K-RECEIVED");
    print("PROTOCOL 4 COMPLETED");
}

void TServer::classifyToCluster(int socketFD) {
    this->sendMessage(socketFD, "T-READY");
    for (int i = 0; i < this->k; i++) {
        uint32_t index;
        auto *data = (char *) &index;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE INDEX ERROR");
        }
        ntohl(index);
        this->sendMessage(socketFD, "T-RECEIVED-CI");
        Ciphertext distance(*this->client_pubkey);
        this->receiveStream(socketFD, to_string(index) + ".dat");
        ifstream in(to_string(index) + ".dat");
        Import(in, distance);
        this->point_distances[index] = distance;
        this->sendMessage(socketFD, "T-D-RECEIVED");
    }
    string message = this->receiveMessage(socketFD, 5);
    if (message != "U-R-I") {
        perror("ERROR IN PROTOCOL 5-STEP 1");
        return;
    }
    uint32_t index = extractClusterIndex();
    this->clusters_counter[index] += 1;
    if (0 > send(socketFD, &index, sizeof(uint32_t), 0)) {
        perror("SEND INDEX FAILED.");
        return;
    }
    string message1 = this->receiveMessage(socketFD, 12);
    if (message1 != "U-RECEIVED-I") {
        perror("ERROR IN PROTOCOL 5-STEP 2");
        return;
    }
}

unsigned TServer::extractClusterIndex() {
    map<unsigned, long> distancesHM;
    ZZ p = this->client_context->ModulusP();
    for (unsigned i = 0; i < this->k; i++) {
        Plaintext pdistance;
        Ciphertext cdistance = this->point_distances[i];
        this->t_server_SM->ApplyKeySwitch(cdistance);
        this->t_server_seckey->Decrypt(pdistance, cdistance);
        distancesHM[i] = extractHM(pdistance, p);
    }
    unsigned index = 0;
    long min = distancesHM[index];
    for (unsigned i = 0; i < this->k; i++) {
        if (min > distancesHM[i]) {
            index = i;
            min = distancesHM[i];
        }
    }
    return index;
}

void TServer::calculateCentroid(int socketFD) {
    this->sendMessage(socketFD, "T-NC-READY");
    for(unsigned i=0;i<this->k;i++) {
        uint32_t index;
        auto *data = (char *) &index;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE INDEX ERROR");
        }
        ntohl(index);
        this->sendMessage(socketFD,"T-RECEIVED-CI");
        Ciphertext centroidsum(*this->client_pubkey);
        this->receiveStream(socketFD, to_string(index) + "centroidsum.dat");
        ifstream in(to_string(index) + "centroidsum.dat");
        Import(in, centroidsum);
        this->sendMessage(socketFD,"T-RECEIVED-C");
        Plaintext pcentroidsum;
        this->t_server_SM->ApplyKeySwitch(centroidsum);
        this->t_server_seckey->Decrypt(pcentroidsum,centroidsum);
        Plaintext newcentroid=this->newCentroid(pcentroidsum,this->clusters_counter[index]);
        Ciphertext cnewcnetroid(*this->client_pubkey);
        this->client_pubkey->Encrypt(cnewcnetroid,newcentroid);
        this->sendStream(this->centroidsToStream(cnewcnetroid),socketFD);
        string message = this->receiveMessage(socketFD, 13);
        if (message != "U-NC-RECEIVED") {
            perror("ERROR IN PROTOCOL 6-STEP 4");
            return;
        }
    }
    string message1 = this->receiveMessage(socketFD, 11);
    if (message1 != "U-C-UPDATED") {
        perror("ERROR IN PROTOCOL 6-STEP 5");
        return;
    }
    for(auto &iter:this->clusters_counter){
        iter.second=0;
    }
    this->sendMessage(socketFD,"T-READY");
    print("K-MEANS ROUND FINISH");
}


Plaintext TServer::newCentroid(const Plaintext &sum, long mean) {
    ZZ_pX centroidx = sum.message;
    ZZ_pX new_centroid;
    ZZ_p coef;
    for (long i = 0; i < centroidx.rep.length(); i++) {
        coef = coeff(centroidx, i);
        ZZ x = rep(coef);
        long t = to_long(x) / mean;
        SetCoeff(new_centroid, i, t);
    }
    Plaintext centroid(*this->client_context, new_centroid);
    return centroid;
}


ifstream TServer::centroidsToStream(const Ciphertext &centroid) {
    ofstream ofstream1("centroid.dat");
    Export(ofstream1, centroid);
    return ifstream("centroid.dat");
}