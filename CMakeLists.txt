project(netsuspend)

# CMake 2.6 is the oldest version of CMake that still has documentation
# available online
cmake_minimum_required(VERSION 2.6)

include(tools-cmake/ProjectCommon.cmake)

# This project outputs this executable
add_executable(${PROJECT_NAME} netsuspend.cpp)

# Add the tools-cpp library directory and link it
add_subdirectory(tools-cpp)
target_link_libraries(${PROJECT_NAME} tools-cpp)
