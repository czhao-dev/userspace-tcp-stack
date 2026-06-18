cmake_minimum_required(VERSION 3.20)
project(minitcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Core library: everything except main.cpp, so both the main binary
# and apps/tests can link against the same protocol implementation.
add_library(minitcp_core
    src/tun.cpp
    src/ip.cpp
    src/icmp.cpp
    src/udp.cpp
)
target_include_directories(minitcp_core PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Main stack binary
add_executable(minitcp src/main.cpp)
target_link_libraries(minitcp PRIVATE minitcp_core)

# Demo apps
add_subdirectory(apps)

# Tests
enable_testing()
add_subdirectory(tests)
