cmake_minimum_required(VERSION 3.10)
project(pesC_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON) 

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
set(CROW_USE_STANDALONE_ASIO OFF CACHE BOOL "" FORCE)
set(CROW_USE_BOOST ON CACHE BOOL "" FORCE)

add_subdirectory(../crow/ ../build/crow-build)
add_executable(pesC_server src/test.cpp)
target_link_libraries(pesC_server PRIVATE
    Crow::Crow
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
)
