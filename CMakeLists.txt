cmake_minimum_required(VERSION 3.20)

project(ebpf_Agent C)

set(CMAKE_C_STANDARD 99)

add_executable(ebpf_Agent
        collector/main.c
)

target_include_directories(ebpf_Agent PRIVATE
        include
)

target_link_libraries(ebpf_Agent
        bpf
        elf
        z
)