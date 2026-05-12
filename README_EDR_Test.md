# EDR Test Suite - Cleaned C++ Code

## Overview

This is a cleaned-up version of C++ code designed for testing EDR (Endpoint Detection and Response) systems. The code implements several techniques that should trigger security monitoring systems.

## Changes Made

### Code Quality Improvements
- **Proper formatting**: Fixed inconsistent spacing and indentation
- **RAII implementation**: Added `HandleRAII` class for automatic resource management
- **Memory safety**: Replaced raw `malloc/free` with smart pointers
- **Error handling**: Added comprehensive error checking and logging
- **Resource cleanup**: Ensured all handles and resources are properly cleaned up

### Structural Improvements
- **Modular functions**: Better separation of concerns
- **Const correctness**: Added proper const qualifiers
- **Type safety**: Used proper casting and type conversions
- **Documentation**: Added detailed function comments

### Security Testing Features

The code tests detection of the following techniques:
1. **Privilege escalation checks** - Tests for SYSTEM privileges
2. **File system manipulation** - Junction/reparse point creation
3. **Cloud Files API abuse** - Kernel callback triggering
4. **EICAR test file** - Standard antivirus test string

## Build Instructions

### Prerequisites
- Windows 10/11
- Visual Studio 2019+ or MinGW-w64
- CMake 3.10+

### Building with CMake
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Building with Visual Studio
```bash
# Open Developer Command Prompt
cl /std:c++17 edr_test_cleaned.cpp /link synchronization.lib ntdll.lib CldApi.lib
```

## Usage

**IMPORTANT**: This code is for authorized security testing only. Use only on systems you own or have explicit permission to test.

```bash
# Run the test
./edr_test_cleaned.exe

# Monitor EDR logs for detection events
```

## Expected EDR Detections

Modern EDR systems should flag:
- Privilege escalation attempts
- Suspicious file system operations
- Kernel-mode callback manipulation
- EICAR test string creation
- Unusual Cloud Files API usage

## Legal Notice

This code is intended for:
- Authorized penetration testing
- EDR system validation
- Security research
- Educational purposes

Do not use for malicious purposes or on systems you don't own.

## Technical Details

The cleaned code maintains all original functionality while improving:
- Memory safety (no more memory leaks)
- Exception safety (RAII pattern)
- Error handling (proper status checks)
- Code readability (clear function names and comments)
- Resource management (automatic cleanup)

## License

Use responsibly and in accordance with applicable laws and regulations.