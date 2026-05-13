cmake_minimum_required(VERSION 3.16)
project(CloudPivot)

if(MSVC)
    set_property(DIRECTORY PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(CloudPivot CloudPivot.cpp)
target_link_libraries(CloudPivot ntdll advapi32 shell32 CldApi)
set_property(TARGET CloudPivot PROPERTY CXX_STANDARD 17)
