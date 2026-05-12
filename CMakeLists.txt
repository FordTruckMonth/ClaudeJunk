cmake_minimum_required(VERSION 3.10)

project(EDRTestSuite)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific configuration
if(WIN32)
    # Add compile definitions
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

    # Create executable
    add_executable(edr_test_cleaned edr_test_cleaned.cpp)

    # Link required Windows libraries
    target_link_libraries(edr_test_cleaned
        synchronization
        ntdll
        CldApi
    )

    # Set Windows subsystem to console
    set_property(TARGET edr_test_cleaned PROPERTY
        WIN32_EXECUTABLE FALSE
    )

else()
    message(WARNING "This project is designed for Windows systems only")
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(edr_test_cleaned PRIVATE /W4)
else()
    target_compile_options(edr_test_cleaned PRIVATE -Wall -Wextra)
endif()