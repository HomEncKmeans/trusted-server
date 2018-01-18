//
// Created by george on 16/11/2017.
//

#include "TServerV1.h"

TServerV1::TServerV1(string t_serverIP, int t_serverPort, string u_serverIP, int u_serverPort, unsigned k,
                     int max_round,
                     int variance_bound, bool verbose) {
    this->k = k;
    this->max_round = max_round;
    this->variance_bound = variance_bound;
    this->verbose = true;
    this->u_serverIP = move(u_serverIP);
    this->u_serverPort = u_serverPort;
    this->t_serverIP = move(t_serverIP);
    this->t_serverPort = t_serverPort;
    this->t_serverSocket = -1;
    this->u_serverSocket=-1;
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
    print("TServerV1 SECRET KEY");
    print(fhesiSecKey);
    print("TServerV1 SWITCH MATRIX ");
    print(keySwitchSI);
    this->socketAccept();
    print("K-MEANS-INITIALIZATION");
    this->initializeClusters();
    print("END OF K-MEANS INITIALIZATION");
    print("STARTING K-MEANS ROUNDS");
    int r = 0;
    long s = this->calculateVariance();
    while (r < this->max_round && s >= this->variance_bound) {
        print("ROUND: " + to_string(r));

        this->connectToUServer();
        print("CREATE NEW CENTROIDS");
        this->sendMessage(this->u_serverSocket, "T-NC");
        string message = this->receiveMessage(this->u_serverSocket, 10);
        if (message != "U-NC-READY") {
            perror("ERROR IN PROTOCOL 6-STEP 1");
            return;
        }

        for (unsigned i = 0; i < this->k; i++) {
            //create and send centroids
            uint32_t index = i;
            htonl(index);
            if (0 > send(this->u_serverSocket, &index, sizeof(uint32_t), 0)) {
                perror("SEND INDEX FAILED.");
                return;
            }
            string message1 = this->receiveMessage(this->u_serverSocket, 13);
            if (message1 != "U-RECEIVED-CI") {
                perror("ERROR IN PROTOCOL 6-STEP 2");
                return;
            }
            vector<uint32_t> cluster_members;
            for (auto &iter:this->A) {
                if (iter.second[i] == 1) {
                    cluster_members.push_back(iter.first);
                }
            }

            //Create and send coef of the centroid;
            for (unsigned j = 0; j < this->dim; j++) {
                uint32_t coef = 0;
                for (unsigned t = 0; t < cluster_members.size(); t++) {
                    coef += this->points[cluster_members[t]][j];
                }
                long total_coef = coef / cluster_members.size();
                ZZ_pX coefX;
                SetCoeff(coefX, 0, total_coef);
                uint32_t coefindex = j;

                htonl(coefindex);

                if (0 > send(this->u_serverSocket, &coefindex, sizeof(uint32_t), 0)) {
                    perror("ERROR IN PROTOCOL 6-STEP 3.");
                    return;
                }
                string message2 = this->receiveMessage(this->u_serverSocket, 16);
                if (message2 != "U-INDEX-RECEIVED") {
                    perror("ERROR IN PROTOCOL 6-STEP 3.1");
                    return;
                }
                Ciphertext ciphertext(*this->client_pubkey);
                Plaintext plaintext(*this->client_context, coefX);
                this->client_pubkey->Encrypt(ciphertext, plaintext);
                this->sendStream(this->centroidCoefToStream(ciphertext), this->u_serverSocket);
                string message3 = this->receiveMessage(this->u_serverSocket, 15);
                if (message3 != "U-COEF-RECEIVED") {
                    perror("ERROR IN PROTOCOL 6-STEP 4");
                    return;
                }
            }
            if(i==this->k-1){
                this->sendMessage(this->u_serverSocket, "T-NC-UPD");
                string message5 = this->receiveMessage(this->u_serverSocket, 7);
                if (message5 != "U-READY") {
                    perror("ERROR IN PROTOCOL 6-STEP 6");
                    return;
                }
            }else {
                this->sendMessage(this->u_serverSocket, "T-NC-END");
                string message4 = this->receiveMessage(this->u_serverSocket, 13);
                if (message4 != "U-NC-RECEIVED") {
                    perror("ERROR IN PROTOCOL 6-STEP 5");
                    return;
                }
            }
        }
        close(this->u_serverSocket);
        this->u_serverSocket = -1;

        //Classify  points to clusters.
        this->connectToUServer();
        this->sendMessage(this->u_serverSocket, "T-DP");
        string message6 = this->receiveMessage(this->u_serverSocket, 7);
        if (message6 != "U-READY") {
            perror("ERROR IN PROTOCOL 5-STEP 1");
            return;
        }
        for(unsigned i=0;i<this->A_r.size();i++){
            uint32_t identifier;
            auto *data = (char *) &identifier;
            if (recv(this->u_serverSocket, data, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE IDENTIFIER ERROR. ERROR IN PROTOCOL 5-STEP 2");
            }
            ntohl(identifier);
            this->log(this->u_serverSocket, "--> POINT IDENTIFIER: " + to_string(identifier));
            map<uint32_t,Ciphertext> distances;
            this->sendMessage(this->u_serverSocket,"T-R-I");
            for(unsigned j = 0 ; j<this->k;j++){
                uint32_t index;
                auto *data1 = (char *) &index;
                if (recv(this->u_serverSocket, data1, sizeof(uint32_t), 0) < 0) {
                    perror("RECEIVE INDEX ERROR. ERROR IN PROTOCOL 5-STEP 3");
                }
                ntohl(index);
                this->log(this->u_serverSocket, "--> CLUSTER INDEX: " + to_string(index));
                this->sendMessage(this->u_serverSocket,"T-R-CI");
                string filename = "distance_" + to_string(index) + ".dat";
                ifstream cipher = this->receiveStream(this->u_serverSocket, filename);
                Ciphertext ciphertext(*this->client_pubkey);
                ifstream in(filename);
                Import(in, ciphertext);
                distances[index]=ciphertext;
                this->sendMessage(this->u_serverSocket,"T-R-D");
            }
            this->A_r[identifier][this->extractClusterIndex(distances)]=1;
            this->sendMessage(this->u_serverSocket,"T-R-D-P");
        }
        string message7 = this->receiveMessage(this->u_serverSocket, 5);
        if (message7 != "U-F-D") {
            perror("ERROR IN PROTOCOL 5-STEP 5");
            return;
        }
        this->sendMessage(this->u_serverSocket,"T-READY");
        close(this->u_serverSocket);
        this->u_serverSocket = -1;
        s = this->calculateVariance();
        r++;
        print(r);
        this->swapA();
    }

    this->endKMToUserver();
    this->resultsToKClient();
    print("END-OF-KMEANS");

}


void TServerV1::socketCreate() {
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

void TServerV1::socketBind() {
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

void TServerV1::socketListen() {
    listen(this->t_serverSocket, 5);
    print("Server is listening...");

}

void TServerV1::socketAccept() {
    int socketFD;
    socketFD = accept(this->t_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void TServerV1::handleRequest(int socketFD) {
    string message = this->receiveMessage(socketFD, 4);
    if (message == "C-PK") {
        this->receiveEncryptionParamFromClient(socketFD);
    } else if (message == "C-DA") {
        this->clientSocket = socketFD;
        this->receiveUnEncryptedData(socketFD);
    } else {
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }
}

bool TServerV1::sendStream(ifstream data, int socket) {
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

bool TServerV1::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string TServerV1::receiveMessage(int socketFD, int buffersize) {
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

ifstream TServerV1::receiveStream(int socketFD, string filename) {
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

void TServerV1::log(int socket, string message) {
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

void TServerV1::receiveEncryptionParamFromClient(int socketFD) {
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

void TServerV1::receiveUnEncryptedData(int socketFD) {
    this->sendMessage(socketFD, "T-DATA-READY");
    uint32_t dimension;
    auto *data1 = (char *) &dimension;
    if (recv(socketFD, data1, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 2");
    }
    ntohl(dimension);
    this->log(socketFD, "--> Data dimension: " + to_string(dimension));
    this->dim = dimension;
    this->sendMessage(socketFD, "T-D-RECEIVED");
    uint32_t numberofpoints;
    auto *data2 = (char *) &numberofpoints;
    if (recv(socketFD, data2, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 3");
    }
    ntohl(numberofpoints);
    this->log(socketFD, "--> Number of Points: " + to_string(numberofpoints));
    this->number_of_points = numberofpoints;
    this->sendMessage(socketFD, "T-N-RECEIVED");
    string message = this->receiveMessage(socketFD, 8);
    if (message != "C-DATA-P") {
        perror("ERROR IN PROTOCOL 3.1-STEP 4");
        return;
    }
    this->sendMessage(socketFD, "T-DATA-P-READY");
    for (unsigned i = 0; i < this->number_of_points; i++) {
        uint32_t identifier;
        auto *data = (char *) &identifier;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 5");
        }
        ntohl(identifier);
        this->sendMessage(socketFD, "T-P-I-RECEIVED");
        vector<uint32_t> point;
        for (unsigned j = 0; j < this->dim; j++) {
            uint32_t index;
            auto *data3 = (char *) &index;
            if (recv(socketFD, data3, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 6");
            }
            ntohl(index);
            this->sendMessage(socketFD, "T-INDEX-RECEIVED");
            uint32_t coef;
            auto *data4 = (char *) &coef;
            if (recv(socketFD, data4, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 6");
            }
            ntohl(coef);


            point.push_back(coef);
            this->sendMessage(socketFD, "T-COEF-RECEIVED");
        }
        this->points[identifier] = point;
        bitset<6> cluster;
        this->A[identifier] = cluster;
        this->A_r[identifier] = cluster;
    }

    string message1 = this->receiveMessage(socketFD, 8);
    if (message1 != "C-DATA-E") {
        perror("ERROR IN PROTOCOL 3.1-STEP 7");
        return;
    }
    this->sendMessage(socketFD, "T-DATA-RECEIVED");
    print("PROTOCOL 3 COMPLETED");

}

void TServerV1::connectToUServer() {
    struct sockaddr_in u_server_address;
    if (this->u_serverSocket == -1) {
        this->u_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (this->u_serverSocket < 0) {
            perror("ERROR ON USERVER SOCKET CREATION");
            exit(1);
        } else {
            string message =
                    "Socket for UServer created successfully. File descriptor: " + to_string(this->u_serverSocket);
            print(message);
        }

    }
    u_server_address.sin_addr.s_addr = inet_addr(this->u_serverIP.c_str());
    u_server_address.sin_family = AF_INET;
    u_server_address.sin_port = htons(static_cast<uint16_t>(this->u_serverPort));

    if (connect(this->u_serverSocket, (struct sockaddr *) &u_server_address, sizeof(u_server_address)) < 0) {
        perror("ERROR. CONNECTION FAILED TO USERVER");

    } else {
        print("TServerV1 CONNECTED TO USERVER");
    }

}

void TServerV1::initializeClusters() {
    default_random_engine generator;
    uniform_int_distribution<int> distribution(0, this->k - 1);
    int seed;
    for (auto &iter : this->A) {
        seed = distribution(generator);
        iter.second[seed] = 1;
    }
}

long TServerV1::calculateVariance() {
    int variance = 0;
    bitset<6> zeroset;
    for (auto &iter:this->A) {
        if (zeroset != (iter.second ^ this->A_r[iter.first])) {
            variance++;
        }
    }
    return variance;
}

ifstream TServerV1::centroidCoefToStream(const Ciphertext &centroid) {
    ofstream ofstream1("centroidcoef.dat");
    Export(ofstream1, centroid);
    return ifstream("centroidcoef.dat");
}

unsigned TServerV1::extractClusterIndex(map<uint32_t ,Ciphertext> distances) {
    map<unsigned, long> decrypted_distances;
    for (unsigned i = 0; i < this->k; i++) {
        Plaintext pdistance;
        Ciphertext cdistance = distances[i];
        this->t_server_SM->ApplyKeySwitch(cdistance);
        this->t_server_seckey->Decrypt(pdistance, cdistance);
        decrypted_distances[i] = extractDistance(pdistance);
    }
    unsigned index = 0;
    long min = decrypted_distances[index];
    for (unsigned i = 0; i < this->k; i++) {
        if (min > decrypted_distances[i]) {
            index = i;
            min = decrypted_distances[i];
        }
    }
    return index;
}

void TServerV1::swapA() {
    this->A = this->A_r;
    bitset<6> zeroset;
    for (auto &iter:this->A_r) {
        iter.second = zeroset;
    }
}

void TServerV1::endKMToUserver() {
    this->connectToUServer();
    this->sendMessage(this->u_serverSocket, "TEKM");
    string message = this->receiveMessage(this->u_serverSocket, 5);
    if (message != "U-END") {
        perror("ERROR IN PROTOCOL 7-STEP 1");
        return;
    }
}

void TServerV1::resultsToKClient() {
    this->sendMessage(this->clientSocket, "T-RESULT");
    string message = this->receiveMessage(this->clientSocket, 7);
    if (message != "C-READY") {
        perror("ERROR IN PROTOCOL 8-STEP 1");
        return;
    }
    for (auto &iter:this->A) {
        this->sendMessage(this->clientSocket, "T-P");
        string message1 = this->receiveMessage(this->clientSocket, 5);
        if (message1 != "C-P-R") {
            perror("ERROR IN PROTOCOL 8-STEP 2");
            return;
        }
        auto identity =(uint32_t) iter.first;
        htonl(identity);
        if (0 > send(this->clientSocket, &identity, sizeof(uint32_t), 0)) {
            perror("SEND IDENTITY FAILED.");
            return;
        }
        string message2 = this->receiveMessage(this->clientSocket, 5);
        if (message2 != "P-I-R") {
            perror("ERROR IN PROTOCOL 8-STEP 3");
            return;
        }
        uint32_t index;
        for (unsigned i = 0; i < this->k; i++) {
            if (iter.second[i] == 1) {
                index = i;
            }
        }
        htonl(index);
        if (0 > send(this->clientSocket, &index, sizeof(uint32_t), 0)) {
            perror("SEND CLUSTER INDEX FAILED.");
            return;
        }
        string message3 = this->receiveMessage(this->clientSocket, 6);
        if (message3 != "P-CI-R") {
            perror("ERROR IN PROTOCOL 8-STEP 3");
            return;
        }
    }
    this->sendMessage(this->clientSocket, "T-RESULT-E");
    string message4 = this->receiveMessage(this->clientSocket, 5);
    if (message4 != "C-END") {
        perror("ERROR IN PROTOCOL 8-STEP 3");
        return;
    }

}

