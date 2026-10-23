#pragma once

#include "sap_network/platform.h"
#include "sap_network/deadline.h"

#include <sap_core/stl/string.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <algorithm>
#include <limits>

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
#include <poll.h>
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

    inline bool set_nonblocking(SocketHandle h, bool enable) {
#ifdef _WIN32
        u_long mode = enable ? 1u : 0u;
        return ::ioctlsocket(h, FIONBIO, &mode) == 0;
#else
        int flags = ::fcntl(h, F_GETFL, 0);
        if (flags < 0)
            return false;
        return ::fcntl(h, F_SETFL, enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
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

    inline void shutdown(SocketHandle h) {
#ifdef _WIN32
        ::shutdown(h, SD_BOTH);
#else
        ::shutdown(h, SHUT_RDWR);
#endif
    }

    // Shut down only the read side. Wakes a thread blocked in recv()/SSL_read()
    // (the kernel delivers SOCK_WAKE_WAITD and the blocking recv returns 0),
    // while leaving the write side intact so SSL_shutdown can still send a
    // close_notify without raising SIGPIPE.
    inline void shutdown_rd(SocketHandle h) {
#ifdef _WIN32
        ::shutdown(h, SD_RECEIVE);
#else
        ::shutdown(h, SHUT_RD);
#endif
    }

    inline std::string error_message(int err) {
#ifdef _WIN32
        char buf[256]{};
        ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, static_cast<DWORD>(err), 0, buf, sizeof(buf),
                         nullptr);
        std::string msg{buf};
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ' || msg.back() == '.'))
            msg.pop_back();
        return msg.empty() ? ("WSA error " + std::to_string(err)) : msg;
#else
        return ::strerror(err);
#endif
    }

    inline bool expired(Deadline deadline) { return std::chrono::steady_clock::now() >= deadline; }

    // EINTR and TLS retries retain the original deadline. poll avoids FD_SETSIZE
    // limitations on POSIX; Windows select stores SOCKETs without narrowing.
    inline bool wait_ready(SocketHandle h, bool write, Deadline deadline) {
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline)
                return false;
            auto ms =
                deadline == (Deadline::max)()
                    ? 60000LL
                    : (std::min)(60000LL, static_cast<long long>(std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count()));
#ifdef _WIN32
            timeval tv{static_cast<long>(ms / 1000), static_cast<long>((ms % 1000) * 1000)};
            fd_set fds, errors;
            FD_ZERO(&fds);
            FD_ZERO(&errors);
            FD_SET(h, &fds);
            FD_SET(h, &errors);
            int rc = ::select(0, write ? nullptr : &fds, write ? &fds : nullptr, &errors, &tv);
            if (rc < 0 && last_error() == WSAEINTR)
                continue;
#else
            pollfd fd{h, static_cast<short>(write ? POLLOUT : POLLIN), 0};
            int rc = ::poll(&fd, 1, static_cast<int>(ms));
            if (rc < 0 && errno == EINTR)
                continue;
#endif
            if (rc > 0)
                return !expired(deadline);
            if (rc < 0)
                return false;
        }
    }

    inline bool connect_ready(SocketHandle h, Deadline deadline) {
        if (!wait_ready(h, true, deadline))
            return false;
        int err = 0;
        socklen_t err_len = sizeof(err);
        return ::getsockopt(h, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len) == 0 && err == 0;
    }

    inline bool apply_timeout(SocketHandle h, int option, std::chrono::milliseconds ms) {
        if (ms.count() < 0)
            return false;
#ifdef _WIN32
        DWORD value = static_cast<DWORD>((std::min)(ms.count(), static_cast<decltype(ms.count())>((std::numeric_limits<DWORD>::max)())));
        return ::setsockopt(h, SOL_SOCKET, option, reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
#else
        auto count = ms.count();
        timeval tv{};
        tv.tv_sec = static_cast<long>(count / 1000);
        tv.tv_usec = static_cast<long>((count % 1000) * 1000);
        return ::setsockopt(h, SOL_SOCKET, option, reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#endif
    }

    inline bool apply_recv_timeout(SocketHandle h, std::chrono::milliseconds ms) { return apply_timeout(h, SO_RCVTIMEO, ms); }

    inline bool apply_send_timeout(SocketHandle h, std::chrono::milliseconds ms) { return apply_timeout(h, SO_SNDTIMEO, ms); }

} // namespace sap::network::internal
