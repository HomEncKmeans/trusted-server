//
// Created by George Sakellariou on 29/09/2017.
//

#ifndef TSERVER_TSERVERFHESIUTILS_H
#define TSERVER_TSERVERFHESIUTILS_H

#include <string>
#include "FHEContext.h"
#include "Matrix.h"
#include <string>
#include <iostream>
#include <fstream>
#include "FHE-SI.h"
#include <bitset>
#include "ZZ_pX.h"
#include "Ciphertext.h"
#include "chrono"
#include "ctime"
#include "iomanip"
long extractHM(const Plaintext &distance,ZZ &p);
long extractHM1(const vector<Plaintext> &distance, ZZ &p);
long extractDistance(const Plaintext &distance);
void timeCalulator(const clock_t &c_start, const chrono::high_resolution_clock::time_point &t_start);
template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}


#endif
