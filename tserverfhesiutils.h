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
long extraxtHM(const Plaintext &distance,ZZ &p);

template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}


#endif
