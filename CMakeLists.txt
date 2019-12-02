cmake_minimum_required(VERSION 3.4)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" OFF)

project(analysis_form_dump)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")

set(LIBPCAP ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)  
set(LIBPCAP_STATIC ${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.a)

add_custom_command(
    OUTPUT  ${LIBPCAP_STATIC}
    COMMAND cwd=$(pwd) && cd ${LIBPCAP} && pwd && ./configure --enable-dbus=no --enable-bluetooth=no --enable-usb=no && make && cd ${cwd}
)

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

include_directories(include)

add_library (cpppcap STATIC ${LIBPCAP_STATIC})
target_link_libraries(cpppcap kp_analysis_from_dump)
target_link_libraries(cpppcap sniffer)

add_library (pcap STATIC IMPORTED GLOBAL)
set_target_properties(pcap PROPERTIES IMPORTED_LOCATION ${LIBPCAP_STATIC})
link_directories(${LIBPCAP})
include_directories(${LIBPCAP})

if(BUILD_TESTS)
        enable_testing()
        add_subdirectory(third-party/gtest)
        add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.cpp)
        target_link_libraries(tests kp_analysis_from_dump gtest_main cpppcap pcap ${LIBPCAP})
        add_test(NAME it_is_real COMMAND tests)
endif()

#target_link_libraries(cpppcap server)
#target_link_libraries(cpppcap client)
#target_link_libraries(server kp_analysis_from_dump)
#target_link_libraries(client sniffer)
#target_link_libraries(server ${Boost_LIBRARIES})
#target_link_libraries(client ${Boost_LIBRARIES})

