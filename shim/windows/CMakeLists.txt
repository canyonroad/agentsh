# shim/windows/CMakeLists.txt
# Build the environment variable interception shim for Windows
# Requires Microsoft Detours: https://github.com/microsoft/Detours

cmake_minimum_required(VERSION 3.16)
project(agentsh-envshim VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find or fetch Detours
find_path(DETOURS_INCLUDE_DIR detours.h
    PATHS
        "${CMAKE_SOURCE_DIR}/detours/include"
        "$ENV{DETOURS_PATH}/include"
        "C:/Program Files/Detours/include"
)

find_library(DETOURS_LIBRARY detours
    PATHS
        "${CMAKE_SOURCE_DIR}/detours/lib.X64"
        "$ENV{DETOURS_PATH}/lib.X64"
        "C:/Program Files/Detours/lib.X64"
)

if(NOT DETOURS_INCLUDE_DIR OR NOT DETOURS_LIBRARY)
    message(STATUS "Detours not found, fetching from GitHub...")
    include(FetchContent)
    FetchContent_Declare(
        detours
        GIT_REPOSITORY https://github.com/microsoft/Detours.git
        GIT_TAG v4.0.1
    )
    FetchContent_MakeAvailable(detours)

    # Build Detours
    add_custom_command(
        OUTPUT ${detours_SOURCE_DIR}/lib.X64/detours.lib
        COMMAND nmake
        WORKING_DIRECTORY ${detours_SOURCE_DIR}/src
        COMMENT "Building Microsoft Detours"
    )

    set(DETOURS_INCLUDE_DIR ${detours_SOURCE_DIR}/src)
    set(DETOURS_LIBRARY ${detours_SOURCE_DIR}/lib.X64/detours.lib)
endif()

# Create the DLL
add_library(envshim SHARED envshim.cpp)

target_include_directories(envshim PRIVATE ${DETOURS_INCLUDE_DIR})
target_link_libraries(envshim PRIVATE ${DETOURS_LIBRARY})

# Windows-specific settings
if(MSVC)
    target_compile_options(envshim PRIVATE /W4 /WX- /O2)
    target_compile_definitions(envshim PRIVATE
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
    )
endif()

# Install
install(TARGETS envshim
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Create injector helper
add_executable(envshim-inject inject.cpp)
target_include_directories(envshim-inject PRIVATE ${DETOURS_INCLUDE_DIR})
target_link_libraries(envshim-inject PRIVATE ${DETOURS_LIBRARY})

install(TARGETS envshim-inject RUNTIME DESTINATION bin)
