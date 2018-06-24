cmake_minimum_required(VERSION 3.8)
project(TServer)

set(CMAKE_CXX_STANDARD 11)
include_directories(/usr/local/include/FHESI)
include_directories(/usr/local/include/NTL)
set(SOURCE_FILES main.cpp tserverfhesiutils.cpp tserverfhesiutils.h TServerT1V1.h TServerT1V1.cpp)
add_executable(TServer ${SOURCE_FILES})
target_link_libraries(TServer libfhesi.a libntl.a libgmp.a libm.a)