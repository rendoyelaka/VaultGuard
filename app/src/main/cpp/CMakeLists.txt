cmake_minimum_required(VERSION 3.18)
project(np_loader)

add_library(np_loader SHARED np_loader.c)

# np_loader_class.h is written by build_module.py before CMake runs —
# include the cpp/ directory so the generated header is found.
target_include_directories(np_loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(android-lib android)

# Fix 3: liblog linked only for debug builds.
# Release builds define NDEBUG → LOG() macro expands to nothing →
# __android_log_print is never called → liblog import removed from .so.
# Result: nm/objdump shows no __android_log_print symbol in release binary.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(np_loader PRIVATE NDEBUG)
    target_link_libraries(np_loader ${android-lib})
else()
    find_library(log-lib log)
    target_link_libraries(np_loader ${log-lib} ${android-lib})
endif()

# Fix 5: Strip debug symbols and toolchain metadata in release.
# --strip-all   : removes all symbol table entries + debug sections
# --gc-sections : dead code elimination (compiler must emit -ffunction-sections)
# Combined with the post-build objcopy task in build.gradle that removes
# the .comment section (clang version + toolchain path string).
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(np_loader PRIVATE
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
    )
    target_link_options(np_loader PRIVATE
        -Wl,--strip-all
        -Wl,--gc-sections
    )
endif()
