#pragma once

#include <sap_core/types.h>

namespace sap::network {
    template <typename S>
    concept Socket = requires(S& s, stl::span<stl::const stl::byte> out_buf, stl::span<stl::byte> in_buf) {
        { s.connect() } -> std::convertible_to<bool>;
        { s.send(out_buf) } -> std::convertible_to<size_t>;
        { s.recv(in_buf) } -> std::convertible_to<size_t>;
        { s.close() } -> std::same_as<void>;
        { s.valid() } -> std::convertible_to<bool>;
        { s.config() } -> std::convertible_to<const SocketConfig&>;
    };
} // namespace sap::network
