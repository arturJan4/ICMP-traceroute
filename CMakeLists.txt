cmake_minimum_required(VERSION 3.16)
project(traceroute C)

set(CMAKE_C_STANDARD 11)

add_executable(traceroute main.c receive.h send.h receive.c send.c)