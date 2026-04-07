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
    if (m_config.reuse_addr) {
        int opt = 1;
        ::setsockopt(m_handle, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&opt), sizeof(opt));
    }

    if (m_config.host.empty()) {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(m_config.port);
        return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    }

    std::string port_str = std::to_string(m_config.port);
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE;

    addrinfo* res = nullptr;
    if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return false;
    bool ok = ::bind(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
    ::freeaddrinfo(res);
    return ok;
}

void UDPSocket::set_recv_timeout(std::chrono::milliseconds ms) {
    auto count = ms.count();
    timeval tv{};
    tv.tv_sec  = static_cast<long>(count / 1000);
    tv.tv_usec = static_cast<long>((count % 1000) * 1000);
    ::setsockopt(m_handle, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
}

void UDPSocket::set_send_timeout(std::chrono::milliseconds ms) {
    auto count = ms.count();
    timeval tv{};
    tv.tv_sec  = static_cast<long>(count / 1000);
    tv.tv_usec = static_cast<long>((count % 1000) * 1000);
    ::setsockopt(m_handle, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
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
    ::shutdown(m_handle, SD_BOTH);
    ::closesocket(m_handle);
#else
    ::shutdown(m_handle, SHUT_RDWR);
    ::close(m_handle);
#endif
    m_handle = INVALID_SOCKET_HANDLE;
}

bool UDPSocket::valid() const {
    return m_handle != INVALID_SOCKET_HANDLE;
}

} // namespace sap::network
