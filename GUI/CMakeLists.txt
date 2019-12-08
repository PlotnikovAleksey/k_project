cmake_minimum_required(VERSION 3.4)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


project(GUI)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")

set(LIBPCAP ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)  

find_package(Boost 1.58.0 REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

add_library(kp_analysis_from_dump STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/kp_analysis_from_dump.cpp
)

add_library(sniffer STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/kp_sniffer_stable.cpp
)

add_library(server STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/server.cpp
)

add_library(client STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/client.cpp
)

target_include_directories(kp_analysis_from_dump 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(sniffer 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(server 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(client 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_subdirectory(libpcap)
target_link_libraries(kp_analysis_from_dump pcap)
target_link_libraries(sniffer pcap)
target_link_libraries(server pcap)
target_link_libraries(client pcap)
target_link_libraries(server kp_analysis_from_dump)
target_link_libraries(client sniffer)
target_link_libraries(server ${Boost_LIBRARIES})
target_link_libraries(client ${Boost_LIBRARIES})

include_directories(${LIBPCAP})

