//
// Created by George Sakellariou on 29/09/2017.
//

#include "tserverfhesiutils.h"

using namespace std;

long extraxtHM(const Plaintext &distance, ZZ &p) {
    ZZ_pX dp =distance.message;
    ZZ_p dhm;
    ZZ hmd=to_ZZ(0);
    for(long i=0;i<dp.rep.length();i++){
        dhm=coeff(dp,i);
        ZZ x= rep(dhm);
        if(x>p/2){
            ZZ t= x-p;
            t*=-1;
            hmd+=t;
        }else{
            hmd+=x;
        }
    }
    return to_long(hmd);
}
