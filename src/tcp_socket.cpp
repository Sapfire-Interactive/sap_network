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
    using internal::would_block;

    namespace {

        bool connect_blocking(SocketHandle h, const sockaddr* addr, socklen_t len) { return ::connect(h, addr, len) == 0; }

        bool connect_with_deadline(SocketHandle h, const sockaddr* addr, socklen_t len, Deadline deadline) {
            if (internal::expired(deadline) || !set_nonblocking(h, true))
                return false;
            bool connected = (::connect(h, addr, len) == 0);
            if (!connected && would_block(last_error()))
                connected = internal::connect_ready(h, deadline);
            return set_nonblocking(h, false) && connected && !internal::expired(deadline);
        }

    } // namespace

    TCPSocket::TCPSocket(SocketConfig config) : m_handle(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), m_config(std::move(config)) {
        if (valid() && (m_config.connect_timeout.count() < 0 || !apply_recv_timeout(m_handle, m_config.recv_timeout) ||
                        !apply_send_timeout(m_handle, m_config.send_timeout)))
            close();
    }

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
        if (m_config.connect_timeout.count() < 0)
            return false;
        return connect_until(deadline_after(m_config.connect_timeout));
    }

    bool TCPSocket::connect_until(Deadline deadline) {
        if (!valid() || internal::expired(deadline) || m_config.host.empty() || m_config.host.find('\0') != stl::string::npos)
            return false;
        // A finite operation never enters the synchronous resolver. Supply a
        // numeric endpoint and use TlsClientConfig::sni_hostname for DNS identity.
        if (deadline != (Deadline::max)()) {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(m_config.port);
            if (::inet_pton(AF_INET, m_config.host.c_str(), &address.sin_addr) != 1)
                return false;
            bool ok = connect_with_deadline(m_handle, reinterpret_cast<sockaddr*>(&address), sizeof(address), deadline);
            if (!ok)
                close();
            return ok;
        }
        std::string port_str = std::to_string(m_config.port);
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = false;
        unsigned attempts = 0;
        for (auto* entry = res; entry && attempts < 16; entry = entry->ai_next, ++attempts) {
            if (attempts != 0) {
                close();
                m_handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (!valid() || !apply_recv_timeout(m_handle, m_config.recv_timeout) ||
                    !apply_send_timeout(m_handle, m_config.send_timeout))
                    break;
            }
            if (connect_blocking(m_handle, entry->ai_addr, static_cast<socklen_t>(entry->ai_addrlen))) {
                ok = true;
                break;
            }
        }
        ::freeaddrinfo(res);
        if (!ok)
            close();
        return ok;
    }

    stl::result<TCPSocket> TCPSocket::accept() { return accept_until((Deadline::max)()); }

    stl::result<TCPSocket> TCPSocket::accept_until(Deadline deadline) {
        if (!valid() || internal::expired(deadline) || !set_nonblocking(m_handle, true))
            return stl::make_error<TCPSocket>("Invalid listener or expired accept deadline");
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        SocketHandle client;
        for (;;) {
            client = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
            if (client != INVALID_SOCKET_HANDLE || !would_block(last_error()) || !internal::wait_ready(m_handle, false, deadline))
                break;
        }
        bool restored = set_nonblocking(m_handle, false);
        if (!restored || internal::expired(deadline)) {
            if (client != INVALID_SOCKET_HANDLE)
                close_handle(client);
            return stl::make_error<TCPSocket>("Accept deadline or socket setup failed");
        }
        if (client == INVALID_SOCKET_HANDLE)
            return stl::make_error<TCPSocket>("Failed to accept TCP socket: {}", error_message(last_error()));
        TCPSocket sock{client};
        sock.m_config = m_config;
        if (!set_nonblocking(client, false) || !apply_recv_timeout(client, m_config.recv_timeout) ||
            !apply_send_timeout(client, m_config.send_timeout))
            return stl::make_error<TCPSocket>("Accepted socket setup failed");
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

    void TCPSocket::set_recv_timeout(std::chrono::milliseconds ms) {
        if (!apply_recv_timeout(m_handle, ms)) {
            close();
            return;
        }
        m_config.recv_timeout = ms;
    }
    void TCPSocket::set_send_timeout(std::chrono::milliseconds ms) {
        if (!apply_send_timeout(m_handle, ms)) {
            close();
            return;
        }
        m_config.send_timeout = ms;
    }

} // namespace sap::network
