#include "sap_network/tcp_socket.h"

#include "socket_internal.h"

#include <string>
#include <utility>

namespace sap::network {

    using internal::apply_recv_timeout;
    using internal::apply_send_timeout;
    using internal::close_handle;
    using internal::error_message;
    using internal::last_error;
    using internal::set_nonblocking;
    using internal::wait_writable;
    using internal::would_block;

    namespace {

        bool connect_blocking(SocketHandle h, const sockaddr* addr, socklen_t len) {
            return ::connect(h, addr, len) == 0;
        }

        bool connect_with_timeout(SocketHandle h, const sockaddr* addr, socklen_t len, std::chrono::milliseconds timeout) {
            set_nonblocking(h, true);
            bool connected = (::connect(h, addr, len) == 0);
            if (!connected && would_block(last_error()))
                connected = wait_writable(h, static_cast<long>(timeout.count()));
            set_nonblocking(h, false);
            return connected;
        }

    } // namespace

    TCPSocket::TCPSocket(SocketConfig config) : m_handle(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), m_config(std::move(config)) {}

    TCPSocket::TCPSocket(SocketHandle handle) : m_handle(handle) {}

    TCPSocket::TCPSocket(TCPSocket&& other) noexcept : m_handle(other.m_handle), m_config(std::move(other.m_config)) {
        other.m_handle = INVALID_SOCKET_HANDLE;
    }

    TCPSocket& TCPSocket::operator=(TCPSocket&& other) noexcept {
        if (this == &other)
            return *this;
        if (m_handle != INVALID_SOCKET_HANDLE)
            close();
        m_handle = other.m_handle;
        other.m_handle = INVALID_SOCKET_HANDLE;
        m_config = std::move(other.m_config);
        return *this;
    }

    TCPSocket::~TCPSocket() { close(); }

    bool TCPSocket::bind() {
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
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        addrinfo* res = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = ::bind(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    bool TCPSocket::listen() { return ::listen(m_handle, m_config.listen_backlog) == 0; }

    bool TCPSocket::connect() {
        std::string port_str = std::to_string(m_config.port);
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = m_config.connect_timeout.count() > 0
                      ? connect_with_timeout(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen), m_config.connect_timeout)
                      : connect_blocking(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
        ::freeaddrinfo(res);
        return ok;
    }

    stl::result<TCPSocket> TCPSocket::accept() {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        SocketHandle client = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
        if (client == INVALID_SOCKET_HANDLE)
            return stl::make_error<TCPSocket>("Failed to accept TCP socket: {}", error_message(last_error()));
        TCPSocket sock{client};
        sock.m_config = m_config;
        if (m_config.recv_timeout.count() > 0)
            sock.set_recv_timeout(m_config.recv_timeout);
        if (m_config.send_timeout.count() > 0)
            sock.set_send_timeout(m_config.send_timeout);
        return sock;
    }

    stl::result<size_t> TCPSocket::send(stl::span<const stl::byte> data) {
        auto result = ::send(m_handle, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        if (result < 0)
            return stl::make_error<size_t>("TCP send failed: {}", error_message(last_error()));
        return static_cast<size_t>(result);
    }

    stl::result<size_t> TCPSocket::recv(stl::span<stl::byte> data) {
        auto result = ::recv(m_handle, reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()), 0);
        if (result < 0)
            return stl::make_error<size_t>("TCP recv failed: {}", error_message(last_error()));
        return static_cast<size_t>(result);
    }

    void TCPSocket::close() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return;
        // shutdown() before close() so any thread blocked in accept()/recv() on this
        // fd is woken immediately. close() alone leaves blocked syscalls hanging
        // because the kernel keeps the descriptor alive while a syscall holds a ref.
        close_handle(m_handle);
        m_handle = INVALID_SOCKET_HANDLE;
    }

    bool TCPSocket::valid() const { return m_handle != INVALID_SOCKET_HANDLE; }

    void TCPSocket::set_recv_timeout(std::chrono::milliseconds ms) { apply_recv_timeout(m_handle, ms); }
    void TCPSocket::set_send_timeout(std::chrono::milliseconds ms) { apply_send_timeout(m_handle, ms); }

} // namespace sap::network
