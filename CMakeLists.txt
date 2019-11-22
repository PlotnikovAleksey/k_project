cmake_minimum_required(VERSION 3.4)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" OFF)

project(analysis_form_dump)

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter -fsanitize=address")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")

set(LIBPCAP ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)  
set(LIBPCAP_STATIC ${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.a)

add_library (pcap STATIC IMPORTED GLOBAL)
set_target_properties(pcap PROPERTIES IMPORTED_LOCATION ${LIBPCAP_STATIC})
link_directories(${LIBPCAP})

add_executable(analysis_from_dump STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/kp_analysis_from_dump.cpp
)

target_link_libraries(analysis_from_dump pcap)

#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

#if(BUILD_TESTS)
#        enable_testing()
#        add_subdirectory(third-party/gtest)
#        add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.cpp)
#        target_link_libraries(tests exmpl gtest_main)
#        add_test(NAME Test1 COMMAND tests)
#endif()
