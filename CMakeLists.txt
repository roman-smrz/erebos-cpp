cmake_minimum_required(VERSION 3.10)
project(Erebos)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_library(B2_LIBRARY b2 REQUIRED)

add_subdirectory(src)
