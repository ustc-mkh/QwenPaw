@echo off
REM Build sandbox_hook.dll using MSVC (run from VS Developer Command Prompt)
REM Or use cmake for cross-platform build.

echo Building sandbox_hook.dll...

if exist build rmdir /s /q build
mkdir build
cd build

cmake .. -A x64
if errorlevel 1 (
    echo CMake configuration failed. Trying direct cl.exe...
    cd ..
    cl /O2 /LD /GS- sandbox_hook.c /link /OUT:sandbox_hook.dll kernel32.lib
    goto :done
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

:done
echo Build complete: sandbox_hook.dll
dir sandbox_hook.dll
