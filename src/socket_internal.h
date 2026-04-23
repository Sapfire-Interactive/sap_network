#pragma once

#include "sap_network/platform.h"

#include <sap_core/stl/string.h>

#include <cerrno>
#include <cstring>
#include <string>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

namespace sap::network::internal {

    inline int last_error() {
#ifdef _WIN32
        return ::WSAGetLastError();
#else
        return errno;
#endif
    }

    inline bool would_block(int err) {
#ifdef _WIN32
        return err == WSAEWOULDBLOCK;
#else
        return err == EINPROGRESS || err == EWOULDBLOCK || err == EAGAIN;
#endif
    }

    inline void set_nonblocking(SocketHandle h, bool enable) {
#ifdef _WIN32
        u_long mode = enable ? 1u : 0u;
        ::ioctlsocket(h, FIONBIO, &mode);
#else
        int flags = ::fcntl(h, F_GETFL, 0);
        if (flags < 0) return;
        ::fcntl(h, F_SETFL, enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
    }

    inline void close_handle(SocketHandle h) {
#ifdef _WIN32
        ::shutdown(h, SD_BOTH);
        ::closesocket(h);
#else
        ::shutdown(h, SHUT_RDWR);
        ::close(h);
#endif
    }

    inline std::string error_message(int err) {
#ifdef _WIN32
        char buf[256]{};
        ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         nullptr, static_cast<DWORD>(err), 0, buf, sizeof(buf), nullptr);
        std::string msg{buf};
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ' || msg.back() == '.'))
            msg.pop_back();
        return msg.empty() ? ("WSA error " + std::to_string(err)) : msg;
#else
        return ::strerror(err);
#endif
    }

    // Wait up to `timeout_ms` for fd to become writable. Returns true if the
    // socket is writable and has no pending SO_ERROR. Used for non-blocking
    // connect() to implement a connect timeout.
    inline bool wait_writable(SocketHandle h, long timeout_ms) {
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(h, &write_fds);
#ifdef _WIN32
        int nfds = 0; // ignored on Windows
#else
        int nfds = static_cast<int>(h) + 1;
#endif
        if (::select(nfds, nullptr, &write_fds, nullptr, &tv) != 1)
            return false;
        int err = 0;
        socklen_t err_len = sizeof(err);
        ::getsockopt(h, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len);
        return err == 0;
    }

    inline void apply_recv_timeout(SocketHandle h, std::chrono::milliseconds ms) {
        auto count = ms.count();
        timeval tv{};
        tv.tv_sec = static_cast<long>(count / 1000);
        tv.tv_usec = static_cast<long>((count % 1000) * 1000);
        ::setsockopt(h, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    }

    inline void apply_send_timeout(SocketHandle h, std::chrono::milliseconds ms) {
        auto count = ms.count();
        timeval tv{};
        tv.tv_sec = static_cast<long>(count / 1000);
        tv.tv_usec = static_cast<long>((count % 1000) * 1000);
        ::setsockopt(h, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    }

} // namespace sap::network::internal
