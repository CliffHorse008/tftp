cmake_minimum_required(VERSION 3.16)

project(tftp_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(tftp_server server.c)

target_compile_options(tftp_server PRIVATE
    -Wall
    -Wextra
    -Werror
    -O2
)
