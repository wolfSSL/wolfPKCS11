cmake_minimum_required(VERSION 3.16)

project(wolfpkcs11_consumer C)

find_package(wolfpkcs11 REQUIRED)

add_executable(wolfpkcs11_consumer main.c)
target_link_libraries(wolfpkcs11_consumer PRIVATE wolfpkcs11::wolfpkcs11)
