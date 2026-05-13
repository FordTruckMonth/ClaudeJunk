cmake_minimum_required(VERSION 3.16)
project(GreenPlasma)

# Static runtime (/MT) — bundles the CRT into the exe so MSVCP140.dll /
# MSVCR140.dll are not required on the target machine.
# If building directly in VS (not via CMake): Project Properties ->
# C/C++ -> Code Generation -> Runtime Library -> Multi-threaded (/MT)
if(MSVC)
    set_property(DIRECTORY PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(GreenPlasma GreenPlasma.cpp)
target_link_libraries(GreenPlasma ntdll advapi32 shell32)
set_property(TARGET GreenPlasma PROPERTY CXX_STANDARD 17)

add_executable(JoeysCode JoeysCode.cpp)
target_link_libraries(JoeysCode ntdll advapi32 shell32)
set_property(TARGET JoeysCode PROPERTY CXX_STANDARD 17)

add_executable(CloudPivot CloudPivot.cpp)
target_link_libraries(CloudPivot ntdll advapi32 shell32 CldApi)
set_property(TARGET CloudPivot PROPERTY CXX_STANDARD 17)
