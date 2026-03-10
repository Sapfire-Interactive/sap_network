#pragma once
#include "sap_network/isocket.h"
#include "sap_network/platform.h"
#include "sap_network/socket_config.h"

namespace sap::network {

class UDPSocket : public ISocket {
public:
    explicit UDPSocket(SocketConfig config);
    ~UDPSocket() override;

    bool bind() override;
    bool listen() override; // no-op for UDP, always returns false
    bool connect() override;
    stl::unique_ptr<ISocket> accept() override; // not applicable for UDP, always returns nullptr
    size_t send(stl::span<const std::byte> data) override;
    size_t recv(stl::span<std::byte> data) override;
    void close() override;
    bool valid() const override;

private:
    SocketHandle m_handle;
    SocketConfig m_config;
};

} // namespace sap::network
