cmake_minimum_required(VERSION 3.16)
project(QwenPawSandboxHook C)

# This builds the sandbox_hook.dll for Windows x64
# Build with: cmake -B build -A x64 && cmake --build build --config Release

set(CMAKE_C_STANDARD 11)

add_library(sandbox_hook SHARED
    sandbox_hook.c
    sandbox_hook.h
)

# Link against kernel32 (always available on Windows)
target_link_libraries(sandbox_hook PRIVATE kernel32)

# No C runtime dependency if possible (smaller DLL, fewer imports)
if(MSVC)
    # Use static CRT to avoid vcruntime DLL dependency
    set_property(TARGET sandbox_hook PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    # /utf-8: treat source as UTF-8 (avoids C4819 on CJK code pages)
    # /O2: optimize for speed, /GS-: no buffer security check overhead
    target_compile_options(sandbox_hook PRIVATE /O2 /GS- /utf-8)
    target_link_options(sandbox_hook PRIVATE /NODEFAULTLIB:msvcrt)
endif()

if(MINGW)
    target_compile_options(sandbox_hook PRIVATE -O2 -Wall)
    target_link_options(sandbox_hook PRIVATE -static-libgcc -s)
endif()

# Output DLL next to Python package
set_target_properties(sandbox_hook PROPERTIES
    OUTPUT_NAME "sandbox_hook"
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# Test harness executable
add_executable(test_hook test_hook.c sandbox_hook.h)
target_link_libraries(test_hook PRIVATE kernel32)

if(MSVC)
    target_compile_options(test_hook PRIVATE /O2 /utf-8)
    set_property(TARGET test_hook PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set_target_properties(test_hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
