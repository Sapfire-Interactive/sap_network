#pragma once

#include "sap_network/socket_config.h"

#include <sap_core/async/stop_token.h>
#include <sap_core/async/task.h>
#include <sap_core/stl/result.h>
#include <sap_core/stl/span.h>

#include <concepts>
#include <cstddef>

namespace sap::network {
    template <typename S>
    concept SocketAsync = requires(S& s,
                                   stl::span<const stl::byte> out_buf,
                                   stl::span<stl::byte>       in_buf,
                                   sap::async::StopToken      tok) {
        { s.connect(tok) }       -> std::same_as<sap::async::Task<stl::result<>>>;
        { s.read(in_buf, tok) }  -> std::same_as<sap::async::Task<stl::result<size_t>>>;
        { s.write(out_buf, tok) }-> std::same_as<sap::async::Task<stl::result<size_t>>>;
        { s.valid() }            -> std::convertible_to<bool>;
        { s.config() }           -> std::convertible_to<const SocketConfig&>;
    };
} // namespace sap::network
