cmake_minimum_required(VERSION 3.16)
project(MusigClient)

# Set C++20 standard for the entire project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options to decide if secp256k1-zkp should be built or cleaned
option(BUILD_SECP256K1 "Build secp256k1-zkp" ON)
option(CLEAN_SECP256K1 "Clean secp256k1-zkp" OFF)

# Fetch the libcpr/cpr content
include(FetchContent)
FetchContent_Declare(cpr 
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 2553fc41450301cd09a9271c8d2c3e0cf3546b73)
FetchContent_MakeAvailable(cpr)

FetchContent_Declare(
    sqlite3
    URL "https://www.sqlite.org/2023/sqlite-amalgamation-3420000.zip"
)
FetchContent_MakeAvailable(sqlite3)

if(BUILD_SECP256K1)
    # Add the secp256k1-zkp library
    add_custom_target(
        secp256k1-zkp-build
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/secp256k1-zkp
        COMMAND ./autogen.sh
        COMMAND ./configure --enable-module-schnorrsig --enable-experimental --enable-module-musig
        COMMAND make
    )
endif()

if(CLEAN_SECP256K1)
    # Add the secp256k1-zkp clean custom target
    add_custom_target(
        secp256k1-zkp-clean
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/secp256k1-zkp
        COMMAND make clean
    )
endif()

# Add main.cpp to the executable "client"
add_executable(client main.cpp utils/strencodings.cpp fmt/format.cc)

# If the BUILD_SECP256K1 option is turned on, client will depend on secp256k1-zkp-build
if(BUILD_SECP256K1)
    add_dependencies(client secp256k1-zkp-build)
endif()

# Create a static library for sqlite3
add_library(sqlite3_static STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_static PRIVATE ${sqlite3_SOURCE_DIR})
target_compile_definitions(sqlite3_static PRIVATE SQLITE_API=)

# Link the secp256k1-zkp library and libcpr/cpr to the client executable
target_link_libraries(client 
    PRIVATE ${CMAKE_SOURCE_DIR}/secp256k1-zkp/.libs/libsecp256k1.a 
    cpr::cpr
    PRIVATE sqlite3_static)

# Add the necessary include directories
target_include_directories(
    client 
    PRIVATE ${CMAKE_SOURCE_DIR}/secp256k1-zkp/include)

