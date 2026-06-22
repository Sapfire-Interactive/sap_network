#include "sap_network/tcp_socket_async.h"

#include "socket_internal.h"

#include <sap_core/async/executor.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/stl/utility.h>

#include <string>
#include <utility>

namespace sap::network {

    using internal::close_handle;
    using internal::error_message;
    using internal::last_error;
    using internal::set_nonblocking;
    using internal::would_block;

    namespace {

        SocketHandle create_socket_nonblocking() {
            SocketHandle h = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (h != INVALID_SOCKET_HANDLE)
                set_nonblocking(h, true);
            return h;
        }

    } // namespace

    TCPSocketAsync::TCPSocketAsync(sap::async::Executor& ex, SocketConfig config)
        : m_ex(&ex), m_handle(create_socket_nonblocking()), m_config(stl::move(config)) {}

    TCPSocketAsync::TCPSocketAsync(sap::async::Executor& ex, SocketHandle h, SocketConfig config) noexcept
        : m_ex(&ex), m_handle(h), m_config(stl::move(config)) {}

    TCPSocketAsync TCPSocketAsync::adopt(sap::async::Executor& ex, SocketHandle h, SocketConfig config) {
        if (h != INVALID_SOCKET_HANDLE)
            set_nonblocking(h, true);
        return TCPSocketAsync(ex, h, stl::move(config));
    }

    TCPSocketAsync::TCPSocketAsync(TCPSocketAsync&& o) noexcept
        : m_ex(o.m_ex), m_handle(o.m_handle), m_config(stl::move(o.m_config)) {
        o.m_handle = INVALID_SOCKET_HANDLE;
    }

    TCPSocketAsync& TCPSocketAsync::operator=(TCPSocketAsync&& o) noexcept {
        if (this == &o)
            return *this;
        close();
        m_ex       = o.m_ex;
        m_handle   = o.m_handle;
        m_config   = stl::move(o.m_config);
        o.m_handle = INVALID_SOCKET_HANDLE;
        return *this;
    }

    TCPSocketAsync::~TCPSocketAsync() { close(); }

    bool TCPSocketAsync::bind() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return false;
        if (m_config.reuse_addr) {
            int opt = 1;
            ::setsockopt(m_handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
        if (m_config.host.empty()) {
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port        = htons(m_config.port);
            return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        }
        std::string port_str = std::to_string(m_config.port);
        addrinfo    hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;
        addrinfo* res     = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = ::bind(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    bool TCPSocketAsync::listen() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return false;
        return ::listen(m_handle, m_config.listen_backlog) == 0;
    }

    sap::async::Task<stl::result<>> TCPSocketAsync::connect(sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<>("socket not valid");

        std::string port_str = std::to_string(m_config.port);
        addrinfo    hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res     = nullptr;
        if (::getaddrinfo(m_config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            co_return stl::make_error<>("getaddrinfo failed for {}:{}", m_config.host, m_config.port);

        int rc  = ::connect(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
        int err = (rc < 0) ? last_error() : 0;
        ::freeaddrinfo(res);

        if (rc == 0)
            co_return stl::result<>{};

        if (!would_block(err))
            co_return stl::make_error<>("connect: {}", error_message(err));

        {
            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Writable, stl::move(tok));
            co_await awaiter;
        }

        int       so_err = 0;
        socklen_t so_len = sizeof(so_err);
        ::getsockopt(m_handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
        if (so_err != 0)
            co_return stl::make_error<>("connect: {}", error_message(so_err));

        co_return stl::result<>{};
    }

    sap::async::Task<stl::result<TCPSocketAsync>> TCPSocketAsync::accept(sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<TCPSocketAsync>("socket not valid");

        for (;;) {
            sockaddr_in  addr{};
            socklen_t    len   = sizeof(addr);
            SocketHandle child = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
            if (child != INVALID_SOCKET_HANDLE)
                co_return stl::result<TCPSocketAsync>{stl::success, TCPSocketAsync::adopt(*m_ex, child, m_config)};

            int err = last_error();
            if (!would_block(err))
                co_return stl::make_error<TCPSocketAsync>("accept: {}", error_message(err));

            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Readable, tok);
            co_await awaiter;
        }
    }

    sap::async::Task<stl::result<size_t>> TCPSocketAsync::read(stl::span<stl::byte> buf, sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<size_t>("socket not valid");

        for (;;) {
            auto n = ::recv(m_handle, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
            if (n >= 0)
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(n)};
            int err = last_error();
            if (!would_block(err))
                co_return stl::make_error<size_t>("recv: {}", error_message(err));

            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Readable, tok);
            co_await awaiter;
        }
    }

    sap::async::Task<stl::result<size_t>> TCPSocketAsync::write(stl::span<const stl::byte> buf, sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<size_t>("socket not valid");

        for (;;) {
            auto n = ::send(m_handle, reinterpret_cast<const char*>(buf.data()), static_cast<int>(buf.size()), 0);
            if (n >= 0)
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(n)};
            int err = last_error();
            if (!would_block(err))
                co_return stl::make_error<size_t>("send: {}", error_message(err));

            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Writable, tok);
            co_await awaiter;
        }
    }

    void TCPSocketAsync::close() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return;
        close_handle(m_handle);
        m_handle = INVALID_SOCKET_HANDLE;
    }

} // namespace sap::network
