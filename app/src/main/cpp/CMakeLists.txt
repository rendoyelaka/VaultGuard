cmake_minimum_required(VERSION 3.18)
project(np_loader)

add_library(np_loader SHARED np_loader.c)

# np_loader_class.h is written by build_module.py before CMake runs —
# include the cpp/ directory so the generated header is found.
target_include_directories(np_loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(np_loader ${log-lib} ${android-lib})
