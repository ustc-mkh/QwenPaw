cmake_minimum_required(VERSION 3.16)
project(QwenPawSandboxHook CXX)

# This builds the sandbox_hook.dll for Windows x64
# Build with: cmake -B build -A x64 -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#             cmake --build build --config Release

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies via vcpkg
# Detours: vcpkg port does not provide a CMake config, use manual find
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY_RELEASE detours PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib" NO_DEFAULT_PATH)
find_library(DETOURS_LIBRARY_DEBUG detours PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib" NO_DEFAULT_PATH)
if(NOT DETOURS_LIBRARY_RELEASE)
    find_library(DETOURS_LIBRARY_RELEASE detours REQUIRED)
endif()

# cJSON: provides a proper CMake config via vcpkg
find_package(cJSON CONFIG REQUIRED)

add_library(sandbox_hook SHARED
    sandbox_hook.cpp
    sandbox_hook.h
)

target_include_directories(sandbox_hook PRIVATE ${DETOURS_INCLUDE_DIRS})

target_link_libraries(sandbox_hook PRIVATE
    $<IF:$<CONFIG:Debug>,${DETOURS_LIBRARY_DEBUG},${DETOURS_LIBRARY_RELEASE}>
    cjson
    kernel32
)

if(MSVC)
    # Static CRT to avoid vcruntime DLL dependency in injected DLL
    set_property(TARGET sandbox_hook PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(sandbox_hook PRIVATE /O2 /utf-8)
endif()

# Output DLL next to Python package
set_target_properties(sandbox_hook PROPERTIES
    OUTPUT_NAME "sandbox_hook"
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
