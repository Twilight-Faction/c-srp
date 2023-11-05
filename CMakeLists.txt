cmake_minimum_required(VERSION 3.26)
project(csrp C)

set(CMAKE_C_STANDARD 23)

add_compile_options(-Wall -Wextra -Wpedantic -v -DCSRP_SERVER -DCSRP_CLIENT -DTESTING)

link_directories(
        ${CMAKE_SOURCE_DIR}/third_party/openssl/
)

add_executable(csrp
        include/csrp_error.h
        include/group.h
        include/byte_array.h
        include/bignum_utils.h
        include/hash_utils.h
        include/srp.h
        include/srp_client.h
        main.c
        src/group.c
        src/bignum_utils.c
        src/hash_utils.c
        src/byte_array.c
        src/srp.c
        src/srp_client.c
        src/bignum_pair.c
        include/bignum_pair.h
)

target_include_directories(csrp PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/third_party/openssl/include
)

target_link_libraries(csrp PUBLIC
        libcrypto.a
        libssl.a
        icudata
        icuuc
        icui18n
)
