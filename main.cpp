//#include "TServerT1V1.h"
//#include "TServerT1V2.h"
//#include "TServerT1V3.h"
#include "TServerT2V1.h"
//#include "TServerT2V2.h"
//#include "TServerT2V3.h"
#include <ctime>
#include <chrono>
#include <iomanip>
int main() {
    string version="T2V1";
    string dataset="1";
    string unit="TServer";
    double cpu_time;
    double wall_clock;

    clock_t c_start = clock();
    auto t_start = chrono::high_resolution_clock::now();
    //TServerT1V1 server("127.0.0.1",5002);
    //TServerT1V2 server("127.0.0.1",5002);
    //TServerT1V3 server("127.0.0.1",5002);
    TServerT2V1 server("127.0.0.1",5002);
    //TServerT2V2 server("127.0.0.1",5002);
    //TServerT2V3 server("127.0.0.1",5002);


    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();
    cpu_time=1000.0 * (c_end-c_start) / CLOCKS_PER_SEC;
    wall_clock=chrono::duration<double, milli>(t_end-t_start).count();
    std::cout << fixed << setprecision(2) << "CPU time used: "
              << cpu_time << " ms\n"
              << "Wall clock time passed: "
              << wall_clock
              << " ms"<<endl;
    string result= unit+","+version+","+dataset+","+to_string(cpu_time)+","+to_string(wall_clock)+"\n";
    ofstream myfile;
    myfile.open ("exp_"+unit+"_"+version+"_"+dataset+".csv");
    myfile << result;
    myfile.close();

    return 0;
}