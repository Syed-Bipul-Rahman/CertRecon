cmake_minimum_required(VERSION 3.14)
project(certrecon VERSION 1.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

file(GLOB CERTRECON_SOURCES src/*.cpp)
add_executable(certrecon ${CERTRECON_SOURCES})
target_link_libraries(certrecon PRIVATE CURL::libcurl Threads::Threads resolv)
target_compile_options(certrecon PRIVATE -Wall -Wextra)

install(TARGETS certrecon RUNTIME DESTINATION bin)
