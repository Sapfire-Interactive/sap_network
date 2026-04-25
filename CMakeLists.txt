cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)
project(sap_network VERSION 0.1)

find_package(OpenSSL 3.0 REQUIRED)

option(SAP_NETWORK_BUILD_TESTS "Build sap_network tests" On)

if(NOT TARGET sap::core)
    add_subdirectory(sap_core)
endif()

add_library(sap_network_lib STATIC
    src/platform.cpp
    src/tcp_socket.cpp
    src/udp_socket.cpp
    src/tls_socket.cpp
    src/tls_internal.cpp
    $<$<PLATFORM_ID:Linux>:src/tls_trust_store_posix.cpp>
    $<$<PLATFORM_ID:Windows>:src/tls_trust_store_windows.cpp>
)
add_library(sap::network ALIAS sap_network_lib)

target_include_directories(sap_network_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(sap_network_lib PUBLIC cxx_std_20)
set_target_properties(sap_network_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sap_network_lib PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(sap_network_lib PRIVATE /W4)
endif()

target_compile_definitions(sap_network_lib
    PUBLIC
        $<$<OR:$<CONFIG:Debug>,$<BOOL:${SAP_TLS_WIRE_LOGGING}>>:SAP_TLS_WIRE_LOGGING>
)

target_link_libraries(sap_network_lib 
    PUBLIC 
    sap::core
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(sap_network_lib PRIVATE Crypt32)
endif()

if(SAP_NETWORK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS sap_network_lib
    EXPORT sap_network_targets
    RUNTIME DESTINATION bin
)

install(EXPORT sap_network_targets
    FILE sap_network_targets.cmake
    NAMESPACE sap::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sap_network
)