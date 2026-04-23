#pragma once
#include "sap_network/platform.h"
#include "sap_network/socket_config.h"

#include <sap_core/stl/result.h>

namespace sap::network {

    class TCPSocket {
    public:
        explicit TCPSocket(SocketConfig config);
        TCPSocket(TCPSocket&&) noexcept;
        TCPSocket& operator=(TCPSocket&&) noexcept;
        TCPSocket(const TCPSocket&) = delete;
        TCPSocket& operator=(const TCPSocket&) = delete;
        ~TCPSocket();

        bool bind();
        bool listen();
        bool connect();
        stl::result<TCPSocket> accept();
        size_t send(stl::span<const std::byte> data);
        size_t recv(stl::span<std::byte> data);
        void close();
        bool valid() const;
        inline const SocketConfig& config() const { return m_config; }

        void set_recv_timeout(std::chrono::milliseconds ms);
        void set_send_timeout(std::chrono::milliseconds ms);

    private:
        explicit TCPSocket(SocketHandle handle);

        SocketHandle m_handle{INVALID_SOCKET_HANDLE};
        SocketConfig m_config;
    };

} // namespace sap::network
