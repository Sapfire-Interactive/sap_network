#pragma once
#include "sap_core/types.h"

#include <chrono>
#include <string>

namespace sap::network {

struct SocketConfig {
    std::string               host;
    u16                       port            = 0;
    std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{0}; // 0 = no timeout (blocking)
    i32                       listen_backlog  = 128;
    bool                      reuse_addr      = false;
};

} // namespace sap::network
