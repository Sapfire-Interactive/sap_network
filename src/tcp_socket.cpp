#include "sap_network/tcp_socket.h"

#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <netdb.h>
#endif

namespace sap::network {

TCPSocket::TCPSocket(SocketConfig config)
    : m_handle(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
    , m_config(std::move(config)) {}

TCPSocket::TCPSocket(SocketHandle handle)
    : m_handle(handle) {}

TCPSocket::~TCPSocket() { close(); }

bool TCPSocket::bind() {
    if (m_config.reuse_addr) {
        int opt = 1;
        ::setsockopt(m_handle, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&opt), sizeof(opt));
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(m_config.port);
    return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
}

bool TCPSocket::listen() {
    return ::listen(m_handle, m_config.listen_backlog) == 0;
}

bool TCPSocket::connect() {
    std::string port_str = std::to_string(m_config.port);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
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
#ifdef _WIN32
    u_long nb = 1;
    ::ioctlsocket(m_handle, FIONBIO, &nb);
#else
    int flags = ::fcntl(m_handle, F_GETFL, 0);
    ::fcntl(m_handle, F_SETFL, flags | O_NONBLOCK);
#endif

    bool connected = false;
    if (::connect(m_handle, addr, len) == 0) {
        connected = true;
    } else {
#ifdef _WIN32
        bool in_progress = (WSAGetLastError() == WSAEWOULDBLOCK);
#else
        bool in_progress = (errno == EINPROGRESS);
#endif
        if (in_progress) {
            auto ms = m_config.connect_timeout.count();
            timeval tv{};
            tv.tv_sec  = static_cast<long>(ms / 1000);
            tv.tv_usec = static_cast<long>((ms % 1000) * 1000);

            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(m_handle, &write_fds);

#ifdef _WIN32
            int nfds = 0; // ignored on Windows
#else
            int nfds = static_cast<int>(m_handle) + 1;
#endif
            if (::select(nfds, nullptr, &write_fds, nullptr, &tv) == 1) {
                int err = 0;
                socklen_t err_len = sizeof(err);
                ::getsockopt(m_handle, SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&err), &err_len);
                connected = (err == 0);
            }
        }
    }

    // Restore blocking mode.
#ifdef _WIN32
    u_long bl = 0;
    ::ioctlsocket(m_handle, FIONBIO, &bl);
#else
    int flags2 = ::fcntl(m_handle, F_GETFL, 0);
    ::fcntl(m_handle, F_SETFL, flags2 & ~O_NONBLOCK);
#endif

    return connected;
}

stl::unique_ptr<ISocket> TCPSocket::accept() {
    sockaddr_in  addr{};
    socklen_t    len    = sizeof(addr);
    SocketHandle client = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
    if (client == INVALID_SOCKET_HANDLE)
        return nullptr;
    return stl::unique_ptr<ISocket>(new TCPSocket(client));
}

size_t TCPSocket::send(stl::span<const std::byte> data) {
    auto result = ::send(m_handle,
        reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()), 0);
    return result < 0 ? 0 : static_cast<size_t>(result);
}

size_t TCPSocket::recv(stl::span<std::byte> data) {
    auto result = ::recv(m_handle,
        reinterpret_cast<char*>(data.data()),
        static_cast<int>(data.size()), 0);
    return result < 0 ? 0 : static_cast<size_t>(result);
}

void TCPSocket::close() {
    if (m_handle == INVALID_SOCKET_HANDLE) return;
#ifdef _WIN32
    ::closesocket(m_handle);
#else
    ::close(m_handle);
#endif
    m_handle = INVALID_SOCKET_HANDLE;
}

bool TCPSocket::valid() const {
    return m_handle != INVALID_SOCKET_HANDLE;
}

} // namespace sap::network
