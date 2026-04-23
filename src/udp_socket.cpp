#include "sap_network/udp_socket.h"

#include "socket_internal.h"

#include <string>
#include <utility>

namespace sap::network {

    using internal::apply_recv_timeout;
    using internal::apply_send_timeout;
    using internal::close_handle;
    using internal::error_message;
    using internal::last_error;

    UDPSocket::UDPSocket(SocketConfig config) : m_handle(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)), m_config(std::move(config)) {}

    UDPSocket::UDPSocket(UDPSocket&& other) noexcept : m_handle(other.m_handle), m_config(std::move(other.m_config)) {
        other.m_handle = INVALID_SOCKET_HANDLE;
    }

    UDPSocket& UDPSocket::operator=(UDPSocket&& other) noexcept {
        if (this == &other)
            return *this;
        if (m_handle != INVALID_SOCKET_HANDLE)
            close();
        m_handle = other.m_handle;
        other.m_handle = INVALID_SOCKET_HANDLE;
        m_config = std::move(other.m_config);
        return *this;
    }

    UDPSocket::~UDPSocket() { close(); }

    bool UDPSocket::bind() {
        if (m_config.reuse_addr) {
            int opt = 1;
            ::setsockopt(m_handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
        if (m_config.host.empty()) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(m_config.port);
            return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        }
        std::string port_str = std::to_string(m_config.port);
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo* res = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = ::bind(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    bool UDPSocket::connect() {
        std::string port_str = std::to_string(m_config.port);
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = ::connect(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    stl::result<size_t> UDPSocket::send(stl::span<const stl::byte> data) {
        auto result = ::send(m_handle, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        if (result < 0)
            return stl::make_error<size_t>("UDP send failed: {}", error_message(last_error()));
        return static_cast<size_t>(result);
    }

    stl::result<size_t> UDPSocket::recv(stl::span<stl::byte> data) {
        auto result = ::recv(m_handle, reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()), 0);
        if (result < 0)
            return stl::make_error<size_t>("UDP recv failed: {}", error_message(last_error()));
        return static_cast<size_t>(result);
    }

    void UDPSocket::close() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return;
        close_handle(m_handle);
        m_handle = INVALID_SOCKET_HANDLE;
    }

    bool UDPSocket::valid() const { return m_handle != INVALID_SOCKET_HANDLE; }

    void UDPSocket::set_recv_timeout(std::chrono::milliseconds ms) { apply_recv_timeout(m_handle, ms); }
    void UDPSocket::set_send_timeout(std::chrono::milliseconds ms) { apply_send_timeout(m_handle, ms); }

} // namespace sap::network
