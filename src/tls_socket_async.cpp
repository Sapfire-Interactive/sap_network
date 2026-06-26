#include "sap_network/tls_socket_async.h"

#include "socket_internal.h"
#include "tls_internal.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sap_core/async/executor.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/stl/atomic.h>
#include <sap_core/stl/utility.h>

#include <format>
#include <string>
#include <utility>

namespace sap::network {

    using internal::acquire_ctx;
    using internal::close_handle;
    using internal::drain_ssl_errors;
    using internal::error_message;
    using internal::format_handshake_error;
    using internal::last_error;
    using internal::set_nonblocking;
    using internal::setup_client_ssl;
    using internal::would_block;

    namespace {

        struct op_lock_releaser {
            stl::atomic<bool>* f;
            ~op_lock_releaser() noexcept { f->store(false, std::memory_order_release); }
        };

        SocketHandle create_socket_nonblocking() {
            SocketHandle h = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (h != INVALID_SOCKET_HANDLE)
                set_nonblocking(h, true);
            return h;
        }

        const SocketConfig& tcp_of(const TLSSocketAsync::ConfigVariant& v) {
            return std::visit([](const auto& c) -> const SocketConfig& { return c.tcp; }, v);
        }

    } // namespace

    TLSSocketAsync::TLSSocketAsync(sap::async::Executor& ex, TlsClientConfig config)
        : m_ex(&ex), m_handle(create_socket_nonblocking()), m_config(stl::move(config)) {}

    TLSSocketAsync::TLSSocketAsync(sap::async::Executor& ex, TlsServerConfig config)
        : m_ex(&ex), m_handle(create_socket_nonblocking()), m_config(stl::move(config)) {}

    TLSSocketAsync::TLSSocketAsync(sap::async::Executor& ex, SocketHandle handle, ssl_st* ssl, TlsAcceptedConfig cfg) noexcept
        : m_ex(&ex), m_handle(handle), m_ssl(ssl), m_config(stl::move(cfg)) {}

    TLSSocketAsync::TLSSocketAsync(TLSSocketAsync&& o) noexcept
        : m_ex(o.m_ex), m_handle(o.m_handle), m_ssl(o.m_ssl), m_config(stl::move(o.m_config)), m_handshake_error(stl::move(o.m_handshake_error)) {
        m_op_in_flight.store(o.m_op_in_flight.load(std::memory_order_relaxed), std::memory_order_relaxed);
        o.m_handle = INVALID_SOCKET_HANDLE;
        o.m_ssl    = nullptr;
    }

    TLSSocketAsync& TLSSocketAsync::operator=(TLSSocketAsync&& o) noexcept {
        if (this == &o)
            return *this;
        close();
        m_ex              = o.m_ex;
        m_handle          = o.m_handle;
        m_ssl             = o.m_ssl;
        m_config          = stl::move(o.m_config);
        m_handshake_error = stl::move(o.m_handshake_error);
        m_op_in_flight.store(o.m_op_in_flight.load(std::memory_order_relaxed), std::memory_order_relaxed);
        o.m_handle = INVALID_SOCKET_HANDLE;
        o.m_ssl    = nullptr;
        return *this;
    }

    TLSSocketAsync::~TLSSocketAsync() { close(); }

    const SocketConfig& TLSSocketAsync::config() const noexcept { return tcp_of(m_config); }

    bool TLSSocketAsync::bind() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return false;
        const SocketConfig& cfg = tcp_of(m_config);
        if (cfg.reuse_addr) {
            int opt = 1;
            ::setsockopt(m_handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
        if (cfg.host.empty()) {
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port        = htons(cfg.port);
            return ::bind(m_handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        }
        std::string port_str = std::to_string(cfg.port);
        addrinfo    hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;
        addrinfo* res     = nullptr;
        if (::getaddrinfo(cfg.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            return false;
        bool ok = ::bind(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0;
        ::freeaddrinfo(res);
        return ok;
    }

    bool TLSSocketAsync::listen() {
        if (m_handle == INVALID_SOCKET_HANDLE)
            return false;
        return ::listen(m_handle, tcp_of(m_config).listen_backlog) == 0;
    }

    sap::async::Task<stl::result<>> TLSSocketAsync::connect(sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<>("socket not valid");
        if (m_op_in_flight.exchange(true, std::memory_order_acquire))
            co_return stl::make_error<>("operation already in flight");
        op_lock_releaser releaser{&m_op_in_flight};

        m_handshake_error.clear();
        const auto* cfg = std::get_if<TlsClientConfig>(&m_config);
        if (cfg == nullptr) {
            m_handshake_error = "TLSSocketAsync::connect called on non-client config";
            co_return stl::make_error<>("{}", m_handshake_error);
        }

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr) {
            m_handshake_error = "SSL_CTX build failed: " + drain_ssl_errors();
            co_return stl::make_error<>("{}", m_handshake_error);
        }

        std::string port_str = std::to_string(cfg->tcp.port);
        addrinfo    hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res     = nullptr;
        if (::getaddrinfo(cfg->tcp.host.c_str(), port_str.c_str(), &hints, &res) != 0)
            co_return stl::make_error<>("getaddrinfo failed for {}:{}", cfg->tcp.host, cfg->tcp.port);

        int tcp_rc  = ::connect(m_handle, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
        int tcp_err = (tcp_rc < 0) ? last_error() : 0;
        ::freeaddrinfo(res);

        if (tcp_rc != 0) {
            if (!would_block(tcp_err))
                co_return stl::make_error<>("tcp connect: {}", error_message(tcp_err));
            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Writable, tok);
            if (auto r = co_await awaiter; !r) {
                m_handshake_error = std::format("tcp connect: {}", r.error().c_str());
                co_return stl::make_error<>("tcp connect: {}", r.error());
            }
            int       so_err = 0;
            socklen_t so_len = sizeof(so_err);
            ::getsockopt(m_handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
            if (so_err != 0)
                co_return stl::make_error<>("tcp connect: {}", error_message(so_err));
        }

        m_ssl = ::SSL_new(ctx);
        if (m_ssl == nullptr) {
            m_handshake_error = "SSL_new failed: " + drain_ssl_errors();
            co_return stl::make_error<>("{}", m_handshake_error);
        }
        setup_client_ssl(m_ssl, *cfg, m_handle);

        for (;;) {
            int rc = ::SSL_connect(m_ssl);
            if (rc == 1)
                co_return stl::result<>{};
            int sslerr = ::SSL_get_error(m_ssl, rc);
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                auto interest = (sslerr == SSL_ERROR_WANT_READ) ? sap::io::Event::Readable : sap::io::Event::Writable;
                sap::async::IoAwaiter awaiter(*m_ex, m_handle, interest, tok);
                if (auto r = co_await awaiter; !r) {
                    m_handshake_error = std::format("SSL_connect: {}", r.error().c_str());
                    co_return stl::make_error<>("SSL_connect: {}", r.error());
                }
                continue;
            }
            m_handshake_error = format_handshake_error("SSL_connect", m_ssl);
            co_return stl::make_error<>("{}", m_handshake_error);
        }
    }

    sap::async::Task<stl::result<TLSSocketAsync>> TLSSocketAsync::accept(sap::async::StopToken tok) {
        if (m_handle == INVALID_SOCKET_HANDLE)
            co_return stl::make_error<TLSSocketAsync>("socket not valid");
        if (m_op_in_flight.exchange(true, std::memory_order_acquire))
            co_return stl::make_error<TLSSocketAsync>("operation already in flight");
        op_lock_releaser releaser{&m_op_in_flight};

        const auto* cfg = std::get_if<TlsServerConfig>(&m_config);
        if (cfg == nullptr)
            co_return stl::make_error<TLSSocketAsync>("TLSSocketAsync::accept called on non-server config");

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr)
            co_return stl::make_error<TLSSocketAsync>("SSL_CTX build failed: {}", drain_ssl_errors());

        SocketHandle child_fd = INVALID_SOCKET_HANDLE;
        for (;;) {
            sockaddr_in addr{};
            socklen_t   len = sizeof(addr);
            child_fd        = ::accept(m_handle, reinterpret_cast<sockaddr*>(&addr), &len);
            if (child_fd != INVALID_SOCKET_HANDLE)
                break;
            int err = last_error();
            if (!would_block(err))
                co_return stl::make_error<TLSSocketAsync>("accept: {}", error_message(err));
            sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Readable, tok);
            if (auto r = co_await awaiter; !r)
                co_return stl::make_error<TLSSocketAsync>("accept: {}", r.error());
        }

        set_nonblocking(child_fd, true);

        SSL* child_ssl = ::SSL_new(ctx);
        if (child_ssl == nullptr) {
            close_handle(child_fd);
            co_return stl::make_error<TLSSocketAsync>("SSL_new failed: {}", drain_ssl_errors());
        }
        ::SSL_set_fd(child_ssl, static_cast<int>(child_fd));

        for (;;) {
            int rc = ::SSL_accept(child_ssl);
            if (rc == 1)
                break;
            int sslerr = ::SSL_get_error(child_ssl, rc);
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                auto interest = (sslerr == SSL_ERROR_WANT_READ) ? sap::io::Event::Readable : sap::io::Event::Writable;
                sap::async::IoAwaiter awaiter(*m_ex, child_fd, interest, tok);
                if (auto r = co_await awaiter; !r) {
                    ::SSL_free(child_ssl);
                    close_handle(child_fd);
                    co_return stl::make_error<TLSSocketAsync>("SSL_accept: {}", r.error());
                }
                continue;
            }
            stl::string err_msg = format_handshake_error("SSL_accept", child_ssl);
            ::SSL_free(child_ssl);
            close_handle(child_fd);
            co_return stl::make_error<TLSSocketAsync>("{}", err_msg);
        }

        TlsAcceptedConfig accepted_cfg{
            .tcp = cfg->tcp,
#ifdef SAP_TLS_WIRE_LOGGING
            .wire_log = cfg->wire_log,
#endif
        };
        co_return stl::result<TLSSocketAsync>{stl::success, TLSSocketAsync{*m_ex, child_fd, child_ssl, stl::move(accepted_cfg)}};
    }

    sap::async::Task<stl::result<size_t>> TLSSocketAsync::read(stl::span<stl::byte> buf, sap::async::StopToken tok) {
        if (m_ssl == nullptr)
            co_return stl::make_error<size_t>("TLS read: handshake not complete");
        if (m_op_in_flight.exchange(true, std::memory_order_acquire))
            co_return stl::make_error<size_t>("operation already in flight");
        op_lock_releaser releaser{&m_op_in_flight};

        for (;;) {
            int n = ::SSL_read(m_ssl, buf.data(), static_cast<int>(buf.size()));
            if (n > 0)
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(n)};

            int sslerr = ::SSL_get_error(m_ssl, n);
            if (sslerr == SSL_ERROR_ZERO_RETURN)
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(0)};
            if (sslerr == SSL_ERROR_SYSCALL && n == 0) {
                ::ERR_clear_error();
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(0)};
            }
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                auto interest = (sslerr == SSL_ERROR_WANT_READ) ? sap::io::Event::Readable : sap::io::Event::Writable;
                sap::async::IoAwaiter awaiter(*m_ex, m_handle, interest, tok);
                if (auto r = co_await awaiter; !r)
                    co_return stl::make_error<size_t>("read: {}", r.error());
                continue;
            }
            co_return stl::make_error<size_t>("SSL_read: {}", drain_ssl_errors());
        }
    }

    sap::async::Task<stl::result<size_t>> TLSSocketAsync::write(stl::span<const stl::byte> buf, sap::async::StopToken tok) {
        if (m_ssl == nullptr)
            co_return stl::make_error<size_t>("TLS write: handshake not complete");
        if (m_op_in_flight.exchange(true, std::memory_order_acquire))
            co_return stl::make_error<size_t>("operation already in flight");
        op_lock_releaser releaser{&m_op_in_flight};

        for (;;) {
            int n = ::SSL_write(m_ssl, buf.data(), static_cast<int>(buf.size()));
            if (n > 0)
                co_return stl::result<size_t>{stl::success, static_cast<size_t>(n)};

            int sslerr = ::SSL_get_error(m_ssl, n);
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                auto interest = (sslerr == SSL_ERROR_WANT_READ) ? sap::io::Event::Readable : sap::io::Event::Writable;
                sap::async::IoAwaiter awaiter(*m_ex, m_handle, interest, tok);
                if (auto r = co_await awaiter; !r)
                    co_return stl::make_error<size_t>("write: {}", r.error());
                continue;
            }
            co_return stl::make_error<size_t>("SSL_write: {}", drain_ssl_errors());
        }
    }

    sap::async::Task<stl::result<>> TLSSocketAsync::shutdown(sap::async::StopToken tok) {
        if (m_ssl == nullptr)
            co_return stl::result<>{};
        if (m_op_in_flight.exchange(true, std::memory_order_acquire))
            co_return stl::make_error<>("operation already in flight");
        op_lock_releaser releaser{&m_op_in_flight};

        for (;;) {
            int rc = ::SSL_shutdown(m_ssl);
            if (rc == 1)
                co_return stl::result<>{};
            if (rc == 0) {
                sap::async::IoAwaiter awaiter(*m_ex, m_handle, sap::io::Event::Readable, tok);
                if (auto r = co_await awaiter; !r)
                    co_return stl::make_error<>("shutdown: {}", r.error());
                continue;
            }
            int sslerr = ::SSL_get_error(m_ssl, rc);
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                auto interest = (sslerr == SSL_ERROR_WANT_READ) ? sap::io::Event::Readable : sap::io::Event::Writable;
                sap::async::IoAwaiter awaiter(*m_ex, m_handle, interest, tok);
                if (auto r = co_await awaiter; !r)
                    co_return stl::make_error<>("shutdown: {}", r.error());
                continue;
            }
            co_return stl::make_error<>("SSL_shutdown: {}", drain_ssl_errors());
        }
    }

    void TLSSocketAsync::close() {
        if (m_ssl != nullptr) {
            ::ERR_clear_error();
            ::SSL_free(m_ssl);
            m_ssl = nullptr;
        }
        if (m_handle != INVALID_SOCKET_HANDLE) {
            close_handle(m_handle);
            m_handle = INVALID_SOCKET_HANDLE;
        }
    }

    stl::string TLSSocketAsync::negotiated_protocol() const {
        if (m_ssl == nullptr)
            return {};
        const unsigned char* alpn = nullptr;
        unsigned int         len  = 0;
        ::SSL_get0_alpn_selected(m_ssl, &alpn, &len);
        return (alpn && len) ? stl::string{reinterpret_cast<const char*>(alpn), len} : stl::string{};
    }

    stl::string TLSSocketAsync::negotiated_cipher() const {
        if (m_ssl == nullptr)
            return {};
        const SSL_CIPHER* c = ::SSL_get_current_cipher(m_ssl);
        if (c == nullptr)
            return {};
        const char* name = ::SSL_CIPHER_get_name(c);
        return name ? stl::string{name} : stl::string{};
    }

    stl::string TLSSocketAsync::negotiated_tls_version() const {
        if (m_ssl == nullptr)
            return {};
        const char* v = ::SSL_get_version(m_ssl);
        return v ? stl::string{v} : stl::string{};
    }

    stl::string TLSSocketAsync::peer_cert_subject() const {
        if (m_ssl == nullptr)
            return {};
        X509* cert = ::SSL_get1_peer_certificate(m_ssl);
        if (cert == nullptr)
            return {};
        char buf[512];
        ::X509_NAME_oneline(::X509_get_subject_name(cert), buf, sizeof(buf));
        ::X509_free(cert);
        return stl::string{buf};
    }

    stl::string TLSSocketAsync::peer_cert_issuer() const {
        if (m_ssl == nullptr)
            return {};
        X509* cert = ::SSL_get1_peer_certificate(m_ssl);
        if (cert == nullptr)
            return {};
        char buf[512];
        ::X509_NAME_oneline(::X509_get_issuer_name(cert), buf, sizeof(buf));
        ::X509_free(cert);
        return stl::string{buf};
    }

} // namespace sap::network
