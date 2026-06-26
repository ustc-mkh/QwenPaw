@echo off
REM Build sandbox_hook.dll using MSVC + vcpkg
REM Requires: vcpkg installed, VCPKG_ROOT environment variable set
REM Run from VS Developer Command Prompt (x64)

echo Building sandbox_hook.dll...

if "%VCPKG_ROOT%"=="" (
    echo ERROR: VCPKG_ROOT environment variable not set.
    echo Set it to your vcpkg installation directory.
    exit /b 1
)

if exist build rmdir /s /q build
mkdir build
cd build

cmake .. -A x64 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static
if errorlevel 1 (
    echo CMake configuration failed!
    cd ..
    exit /b 1
)

cmake --build . --config Release
if errorlevel 1 (
    echo Build failed!
    cd ..
    exit /b 1
)

copy /y Release\sandbox_hook.dll ..\ 2>nul
copy /y sandbox_hook.dll ..\ 2>nul
cd ..

echo Build complete: sandbox_hook.dll
dir sandbox_hook.dll
