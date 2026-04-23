#include "sap_network/tcp_socket.h"

#include <string>
#include <winsock2.h>

namespace sap::network {

    TCPSocket::TCPSocket(SocketConfig config) : m_handle(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), m_config(std::move(config)) {}

    TCPSocket::TCPSocket(SocketHandle handle) : m_handle(handle) {}

    TCPSocket::TCPSocket(TCPSocket&& other) noexcept : m_handle(std::move(other.m_handle)), m_config(std::move(other.m_config)) {
        other.m_handle = INVALID_SOCKET_HANDLE;
    }

    TCPSocket& TCPSocket::operator=(TCPSocket&& other) noexcept {
        m_handle = std::move(other.m_handle);
        other.m_handle = INVALID_SOCKET_HANDLE;
        m_config = std::move(other.m_config);
        return *this;
    }

    TCPSocket::~TCPSocket() {
        if (m_handle != INVALID_SOCKET_HANDLE)
            close();
    }

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

    void TCPSocket::set_recv_timeout(std::chrono::milliseconds ms) {
        auto count = ms.count();
        timeval tv{};
        tv.tv_sec = static_cast<long>(count / 1000);
        tv.tv_usec = static_cast<long>((count % 1000) * 1000);
        ::setsockopt(m_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    }

    void TCPSocket::set_send_timeout(std::chrono::milliseconds ms) {
        auto count = ms.count();
        timeval tv{};
        tv.tv_sec = static_cast<long>(count / 1000);
        tv.tv_usec = static_cast<long>((count % 1000) * 1000);
        ::setsockopt(m_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
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
        bool ok;
        if (m_config.connect_timeout.count() > 0)
            ok = connect_with_timeout(res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
        else
            ok = ::connect(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    bool TCPSocket::connect_with_timeout(const sockaddr* addr, socklen_t len) const {
        // Switch to non-blocking mode.
        u_long nb = 1;
        ::ioctlsocket(m_handle, FIONBIO, &nb);
        bool connected = false;
        if (::connect(m_handle, addr, len) == 0) {
            connected = true;
        } else {
            bool in_progress = (WSAGetLastError() == WSAEWOULDBLOCK);
            if (in_progress) {
                auto ms = m_config.connect_timeout.count();
                timeval tv{};
                tv.tv_sec = static_cast<long>(ms / 1000);
                tv.tv_usec = static_cast<long>((ms % 1000) * 1000);
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(m_handle, &write_fds);
                int nfds = 0; // ignored on Windows
                if (::select(nfds, nullptr, &write_fds, nullptr, &tv) == 1) {
                    int err = 0;
                    socklen_t err_len = sizeof(err);
                    ::getsockopt(m_handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len);
                    connected = (err == 0);
                }
            }
        }
        // Restore blocking mode.
        u_long bl = 0;
        ::ioctlsocket(m_handle, FIONBIO, &bl);
        return connected;
    }

    stl::result<TCPSocket> TCPSocket::accept() {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        SocketHandle client = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
        if (client == INVALID_SOCKET_HANDLE)
            return stl::make_error<TCPSocket>("Failed to accept TCP socket: {}", WSAGetLastError());
        TCPSocket sock{client};
        sock.m_config = m_config;
        if (m_config.recv_timeout.count() > 0)
            sock.set_recv_timeout(m_config.recv_timeout);
        if (m_config.send_timeout.count() > 0)
            sock.set_send_timeout(m_config.send_timeout);
        return sock;
    }

    size_t TCPSocket::send(stl::span<const std::byte> data) {
        auto result = ::send(m_handle, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        return result < 0 ? 0 : static_cast<size_t>(result);
    }

    size_t TCPSocket::recv(stl::span<std::byte> data) {
        auto result = ::recv(m_handle, reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()), 0);
        return result < 0 ? 0 : static_cast<size_t>(result);
    }

    void TCPSocket::close() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return;
        // shutdown() before close() so any thread blocked in accept()/recv() on this
        // fd is woken immediately. close() alone leaves blocked syscalls hanging
        // because the kernel keeps the descriptor alive while a syscall holds a ref.
        ::shutdown(m_handle, SD_BOTH);
        ::closesocket(m_handle);
        m_handle = INVALID_SOCKET_HANDLE;
    }

    bool TCPSocket::valid() const { return m_handle != INVALID_SOCKET_HANDLE; }

} // namespace sap::network
