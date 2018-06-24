//
// Created by george on 16/11/2017.
//

#include "TServerT1V3.h"

TServerT1V3::TServerT1V3(string t_serverIP, int t_serverPort, bool verbose) {
    this->active = true;
    this->t_serverIP = move(t_serverIP);
    this->t_serverPort = t_serverPort;
    this->verbose = verbose;
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
    print("TServerT1V3 SECRET KEY");
    print(fhesiSecKey);
    print("TServerT1V3 SWITCH MATRIX ");
    print(keySwitchSI);

    while (this->active) {
        this->socketAccept();
    }

}


void TServerT1V3::socketCreate() {
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

void TServerT1V3::socketBind() {
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

void TServerT1V3::socketListen() {
    listen(this->t_serverSocket, 5);
    print("Server is listening...");

}

void TServerT1V3::socketAccept() {
    int socketFD;
    socketFD = accept(this->t_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void TServerT1V3::handleRequest(int socketFD) {
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
        print("TServerT1V3 STOP AND EXIT");
    } else {
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }
}

bool TServerT1V3::sendStream(ifstream data, int socket) {
    uint32_t CHUNK_SIZE = 10000;
    streampos begin, end;
    begin = data.tellg();
    data.seekg(0, ios::end);
    end = data.tellg();
    streampos size = end - begin;
    uint32_t sizek;
    sizek = static_cast<uint32_t>(size);
    data.seekg(0, std::ios::beg);
    auto *memblock = new char[sizek];
    data.read(memblock, sizek);
    data.close();
    htonl(sizek);
    if (0 > send(socket, &sizek, sizeof(uint32_t), 0)) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + to_string(sizek));
        if (this->receiveMessage(socket, 7) == "SIZE-OK") {
            auto *buffer = new char[CHUNK_SIZE];
            uint32_t beginmem = 0;
            uint32_t endmem = 0;
            uint32_t num_of_blocks = sizek / CHUNK_SIZE;
            uint32_t rounds = 0;
            while (rounds <= num_of_blocks) {
                if (rounds == num_of_blocks) {
                    uint32_t rest = sizek - (num_of_blocks) * CHUNK_SIZE;
                    endmem += rest;
                    copy(memblock + beginmem, memblock + endmem, buffer);
                    ssize_t r = (send(socket, buffer, rest, 0));
                    rounds++;
                    if (r < 0) {
                        perror("SEND FAILED.");
                        return false;
                    }
                } else {
                    endmem += CHUNK_SIZE;
                    copy(memblock + beginmem, memblock + endmem, buffer);
                    beginmem = endmem;
                    ssize_t r = (send(socket, buffer, 10000, 0));
                    rounds++;
                    if (r < 0) {
                        perror("SEND FAILED.");
                        return false;
                    }
                }
            }
            return true;

        } else {
            perror("SEND SIZE ERROR");
            return false;
        }
    }
}

bool TServerT1V3::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string TServerT1V3::receiveMessage(int socketFD, int buffersize) {
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

ifstream TServerT1V3::receiveStream(int socketFD, string filename) {
    uint32_t size;
    auto *data = (char *) &size;
    if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE SIZE ERROR");
    }

    ntohl(size);
    this->log(socketFD, "--> SIZE: " + to_string(size));
    this->sendMessage(socketFD, "SIZE-OK");

    auto *memblock = new char[size];
    ssize_t expected_data=size;
    ssize_t received_data=0;
    while(received_data<expected_data){
        ssize_t data_fd=recv(socketFD, memblock+received_data, 10000, 0);
        received_data +=data_fd;

    }
    print(received_data);

    if (received_data!=expected_data ) {
        perror("RECEIVE STREAM ERROR");
        exit(1);
    }

    ofstream temp(filename, ios::out | ios::binary);
    temp.write(memblock, size);
    temp.close();
    return ifstream(filename);
}

void TServerT1V3::log(int socket, string message) {
    if (this->verbose) {
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
}

void TServerT1V3::receiveEncryptionParamFromClient(int socketFD) {
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

void TServerT1V3::initializeKM(int socketFD) {
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
    uint32_t dimension;
    auto *data1 = (char *) &dimension;
    if (recv(socketFD, data1, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE DIMENSION ERROR");
    }
    ntohl(dimension);
    this->log(socketFD, "--> DIMENSION: " + to_string(dimension));
    this->dim = dimension;
    this->sendMessage(socketFD, "T-DIM-RECEIVED");
    print("PROTOCOL 4 COMPLETED");
}

void TServerT1V3::classifyToCluster(int socketFD) {
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

unsigned TServerT1V3::extractClusterIndex() {
    map<unsigned, long> distancesEuclidean;
    for (unsigned i = 0; i < this->k; i++) {
        Plaintext pdistance;
        Ciphertext cdistance = this->point_distances[i];
        this->t_server_SM->ApplyKeySwitch(cdistance);
        this->t_server_seckey->Decrypt(pdistance, cdistance);
        distancesEuclidean[i] = extractDistance(pdistance);
    }
    unsigned index = 0;
    long min = distancesEuclidean[index];
    for (unsigned i = 0; i < this->k; i++) {
        if (min > distancesEuclidean[i]) {
            index = i;
            min = distancesEuclidean[i];
        }
    }
    return index;
}

void TServerT1V3::calculateCentroid(int socketFD) {
    this->sendMessage(socketFD, "T-NC-READY");
    for (unsigned i = 0; i < this->k; i++) {

        uint32_t cluster_index;
        auto *data = (char *) &cluster_index;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR");
        }
        ntohl(cluster_index);
        this->sendMessage(socketFD, "T-RECEIVED-CI");
        for (unsigned j = 0; j < this->dim; j++) {
            uint32_t coef_index;
            auto *data1 = (char *) &coef_index;
            if (recv(socketFD, data1, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE COEFFICIENT INDEX ERROR");
            }
            ntohl(coef_index);
            this->sendMessage(socketFD, "T-INDEX-RECEIVED");
            Ciphertext centroid_coef_sum(*this->client_pubkey);
            this->receiveStream(socketFD, to_string(cluster_index) + "centroidsum.dat");
            ifstream in(to_string(cluster_index) + "centroidsum.dat");
            Import(in, centroid_coef_sum);
            this->sendMessage(socketFD, "T-COEF-RECEIVED");
            string message = this->receiveMessage(socketFD, 5);
            if (message != "U-R-C") {
                perror("ERROR IN PROTOCOL 6-STEP 3");
                return;
            }
            Plaintext pcoefcentroidsum;
            this->t_server_SM->ApplyKeySwitch(centroid_coef_sum);
            this->t_server_seckey->Decrypt(pcoefcentroidsum, centroid_coef_sum);
            Plaintext newcentroid = this->newCentroidCoef(pcoefcentroidsum, this->clusters_counter[cluster_index]);
            Ciphertext cnewcnetroid(*this->client_pubkey);
            this->client_pubkey->Encrypt(cnewcnetroid, newcentroid);
            this->sendStream(this->centroidCoefToStream(cnewcnetroid), socketFD);
            string message1 = this->receiveMessage(socketFD, 8);
            if (message1 != "U-R-COEF") {
                perror("ERROR IN PROTOCOL 6-STEP 4");
                return;
            }
        }

        string message2 = this->receiveMessage(socketFD, 13);
        if (message2 != "U-NC-RECEIVED") {
            perror("ERROR IN PROTOCOL 6-STEP 4");
            return;
        }
    }
    string message3 = this->receiveMessage(socketFD, 11);
    if (message3 != "U-C-UPDATED") {
        perror("ERROR IN PROTOCOL 6-STEP 5");
        return;
    }
    for (auto &iter:this->clusters_counter) {
        iter.second = 0;
    }
    this->sendMessage(socketFD, "T-READY");
    print("K-MEANS ROUND FINISH");
}


Plaintext TServerT1V3::newCentroidCoef(const Plaintext &sum, long mean) {
    ZZ_pX centroidx = sum.message;
    ZZ_pX new_centroid_coef;
    ZZ_p coef;
    coef = coeff(centroidx, 0);
    const ZZ &x = rep(coef);
    long t;
    if (mean != 0) {
        t = to_long(x) / mean;
    } else {
        t = to_long(x);
    }
    SetCoeff(new_centroid_coef, 0, t);
    Plaintext centroid_coef(*this->client_context, new_centroid_coef);
    return centroid_coef;
}


ifstream TServerT1V3::centroidCoefToStream(const Ciphertext &centroid) {
    ofstream ofstream1("centroidcoef.dat");
    Export(ofstream1, centroid);
    return ifstream("centroidcoef.dat");
}