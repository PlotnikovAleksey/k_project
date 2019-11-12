cmake_minimum_required(VERSION 3.4)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" OFF)

project(analysis_form_dump)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmakefile/FindPCAP.cmake)

add_executable(analysis_form_dump STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/kp_analysis_from_dump.cpp
)

target_link_libraries(analysis_form_dump ${PCAP_LIBRARY})

#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

#if(BUILD_TESTS)
#        enable_testing()
#        add_subdirectory(third-party/gtest)
#        add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.cpp)
#        target_link_libraries(tests exmpl gtest_main)
#        add_test(NAME Test1 COMMAND tests)
#endif()