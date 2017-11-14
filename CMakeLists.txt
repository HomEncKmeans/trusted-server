cmake_minimum_required(VERSION 3.8)
project(TServer)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Server.h Server.cpp)
add_executable(TServer ${SOURCE_FILES})