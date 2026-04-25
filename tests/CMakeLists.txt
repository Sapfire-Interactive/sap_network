include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# Prevent overriding the parent project's compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(sap_network_tests
    test_tcp_socket.cpp
    test_udp_socket.cpp
    test_tls_socket.cpp
)

target_link_libraries(sap_network_tests
    PRIVATE
        sap_network_lib
        GTest::gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_include_directories(sap_network_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/sap_core/include
)

include(GoogleTest)
gtest_discover_tests(sap_network_tests)
