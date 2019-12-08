cmake_minimum_required(VERSION 3.4)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(GUI)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")

set(LIBPCAP ${CMAKE_CURRENT_SOURCE_DIR}/../libpcap)  

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5Widgets REQUIRED)
find_package(Qt5Core REQUIRED)
find_package(Qt5Gui REQUIRED)
find_package(Boost 1.58.0 REQUIRED)

set(CMAKE_CXX_FLAGS "${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${Qt5Core_EXECUTABLE_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${Qt5Gui_EXECUTABLE_COMPILE_FLAGS}")

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

add_library(kp_analysis_from_dump STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/kp_analysis_from_dump.cpp
)

add_library(server STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/server.cpp
)

add_library(mainwindow STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/mainwindow.cpp
)

add_library(emitter STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/emitter.cpp
)

target_include_directories(kp_analysis_from_dump 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(server 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(mainwindow 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(emitter 
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_subdirectory(../libpcap ${CMAKE_CURRENT_BINARY_DIR}/pcap)
target_link_libraries(kp_analysis_from_dump pcap)
target_link_libraries(server pcap)

target_link_libraries(server ${Boost_LIBRARIES} -lpthread -lm -lboost_system)
target_link_libraries(mainwindow ${Boost_LIBRARIES} -lboost_system)
target_link_libraries(kp_analysis_from_dump ${Boost_LIBRARIES})
target_link_libraries(mainwindow kp_analysis_from_dump)

add_executable(exec sources/main.cpp include/mainwindow.hpp include/emitter.hpp)
target_link_libraries(exec server kp_analysis_from_dump mainwindow emitter)

qt5_use_modules(server Widgets Core Gui)
qt5_use_modules(mainwindow Widgets Core Gui)
qt5_use_modules(emitter Widgets Core Gui)
qt5_use_modules(kp_analysis_from_dump Widgets Core Gui)
qt5_use_modules(exec Widgets Core Gui)

include_directories(${LIBPCAP})
