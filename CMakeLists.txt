cmake_minimum_required(VERSION 4.2)
project(ebpf_Agent C)

set(CMAKE_C_STANDARD 99)

add_executable(ebpf_Agent main.c)
