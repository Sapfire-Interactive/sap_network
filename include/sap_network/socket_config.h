#pragma once

#include <sap_core/stl/string.h>
#include <sap_core/types.h>

#include <chrono>
namespace sap::network {

    struct SocketConfig {
        stl::string host;
        u16 port = 0;
        std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{0}; // 0 = no timeout (blocking)
        std::chrono::milliseconds recv_timeout = std::chrono::milliseconds{0}; // 0 = no timeout
        std::chrono::milliseconds send_timeout = std::chrono::milliseconds{0}; // 0 = no timeout
        i32 listen_backlog = 128;
        bool reuse_addr = false;
    };

} // namespace sap::network
