#pragma once
#include "sap_network/platform.h"
#include "sap_network/socket_config.h"

#include <sap_core/stl/result.h>

namespace sap::network {

    class UDPSocket {
    public:
        explicit UDPSocket(SocketConfig config);
        UDPSocket(UDPSocket&&) noexcept;
        UDPSocket& operator=(UDPSocket&&) noexcept;
        UDPSocket(const UDPSocket&) = delete;
        UDPSocket& operator=(const UDPSocket&) = delete;
        ~UDPSocket();

        bool bind();
        bool connect();
        size_t send(stl::span<const std::byte> data);
        size_t recv(stl::span<std::byte> data);
        void close();

        void set_recv_timeout(std::chrono::milliseconds ms);
        void set_send_timeout(std::chrono::milliseconds ms);
        bool valid() const;
        inline const SocketConfig& config() const { return m_config; }

    private:
        SocketHandle m_handle{INVALID_SOCKET_HANDLE};
        SocketConfig m_config;
    };

} // namespace sap::network
