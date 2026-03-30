#pragma once
#include "sap_network/isocket.h"
#include "sap_network/platform.h"
#include "sap_network/socket_config.h"

namespace sap::network {

    class TCPSocket : public ISocket {
    public:
        explicit TCPSocket(SocketConfig config);
        ~TCPSocket() override;

        bool bind() override;
        bool listen() override;
        bool connect() override;
        stl::unique_ptr<ISocket> accept() override;
        size_t send(stl::span<const std::byte> data) override;
        size_t recv(stl::span<std::byte> data) override;
        void close() override;
        bool valid() const override;

    private:
        explicit TCPSocket(SocketHandle handle);
        bool connect_with_timeout(const sockaddr* addr, socklen_t len) const;

        SocketHandle m_handle;
        SocketConfig m_config;
    };

} // namespace sap::network
