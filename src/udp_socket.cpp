#include "sap_network/udp_socket.h"

#include <string>

#ifndef _WIN32
#include <netdb.h>
#endif

namespace sap::network {

UDPSocket::UDPSocket(SocketConfig config)
    : m_handle(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))
    , m_config(std::move(config)) {}

UDPSocket::~UDPSocket() { close(); }

bool UDPSocket::bind() {
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(m_config.port);
    return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
}

bool UDPSocket::listen() {
    return false; // UDP is connectionless
}

bool UDPSocket::connect() {
    std::string port_str = std::to_string(m_config.port);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return false;

    bool ok = ::connect(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
    ::freeaddrinfo(res);
    return ok;
}

stl::unique_ptr<ISocket> UDPSocket::accept() {
    return nullptr; // UDP is connectionless
}

size_t UDPSocket::send(stl::span<const std::byte> data) {
    auto result = ::send(m_handle,
        reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()), 0);
    return result < 0 ? 0 : static_cast<size_t>(result);
}

size_t UDPSocket::recv(stl::span<std::byte> data) {
    auto result = ::recv(m_handle,
        reinterpret_cast<char*>(data.data()),
        static_cast<int>(data.size()), 0);
    return result < 0 ? 0 : static_cast<size_t>(result);
}

void UDPSocket::close() {
    if (m_handle == INVALID_SOCKET_HANDLE) return;
#ifdef _WIN32
    ::closesocket(m_handle);
#else
    ::close(m_handle);
#endif
    m_handle = INVALID_SOCKET_HANDLE;
}

bool UDPSocket::valid() const {
    return m_handle != INVALID_SOCKET_HANDLE;
}

} // namespace sap::network
