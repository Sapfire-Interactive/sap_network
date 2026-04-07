cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)
project(sap_network VERSION 0.1)

find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    # Update submodules as needed
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()

option(SAP_NETWORK_BUILD_TESTS "Build sap_network tests" On)

if(NOT TARGET sap::core)
    add_subdirectory(sap_core)
endif()

add_library(sap_network_lib STATIC
    src/platform.cpp
    src/tcp_socket.cpp
    src/udp_socket.cpp
)
add_library(sap::network ALIAS sap_network_lib)

target_include_directories(sap_network_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sap_core/include>
        $<INSTALL_INTERFACE:include>
        $<INSTALL_INTERFACE:sap_core/include>
)

target_compile_features(sap_network_lib PUBLIC cxx_std_20)
set_target_properties(sap_network_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sap_network_lib PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(sap_network_lib PRIVATE /W4)
endif()

if(SAP_NETWORK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS sap_network_lib
    RUNTIME DESTINATION bin
)