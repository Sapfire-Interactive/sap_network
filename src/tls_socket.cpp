#include "sap_network/tls_socket.h"

#include "tls_internal.h"
#include "socket_internal.h"

#include <cstring>
#include <utility>

namespace sap::network {

    using internal::acquire_ctx;
    using internal::drain_ssl_errors;
    using internal::format_handshake_error;

    namespace {

        struct TlsResult {
            int count;
            int error;
            bool timed_out;
        };

        // Socket stays nonblocking for its TLS lifetime. Never renew the budget
        // when OpenSSL consumes only part of a record or changes WANT direction.
        template <class Operation> TlsResult run_tls(SSL* ssl, SocketHandle socket, Deadline deadline, Operation operation) {
            for (;;) {
                if (internal::expired(deadline))
                    return {-1, SSL_ERROR_SYSCALL, true};
                ::ERR_clear_error();
                int count = operation();
                if (count > 0)
                    return internal::expired(deadline) ? TlsResult{-1, SSL_ERROR_SYSCALL, true} : TlsResult{count, SSL_ERROR_NONE, false};
                int error = ::SSL_get_error(ssl, count);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {count, error, false};
                if (!internal::wait_ready(socket, error == SSL_ERROR_WANT_WRITE, deadline))
                    return {-1, SSL_ERROR_SYSCALL, true};
            }
        }

        void discard_tls(SSL*& ssl, TCPSocket& tcp) {
            // No shutdown after an incomplete write, failed handshake or fatal I/O.
            if (ssl)
                ::SSL_free(ssl);
            ssl = nullptr;
            tcp.close();
        }

        const SocketConfig& tcp_of(const TLSSocket::ConfigVariant& v) {
            return std::visit([](const auto& c) -> const SocketConfig& { return c.tcp; }, v);
        }

#ifdef SAP_TLS_WIRE_LOGGING
        const TlsWireLogFn& wire_log_of(const TLSSocket::ConfigVariant& v) {
            return std::visit([](const auto& c) -> const TlsWireLogFn& { return c.wire_log; }, v);
        }
#endif

    } // namespace

    TLSSocket::TLSSocket(TlsClientConfig config) : m_config(std::move(config)), m_tcp(tcp_of(m_config)) {}
    TLSSocket::TLSSocket(TlsServerConfig config) : m_config(std::move(config)), m_tcp(tcp_of(m_config)) {}

    TLSSocket::TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsAcceptedConfig config)
        : m_config(std::move(config)), m_tcp(std::move(tcp)), m_ssl(ssl) {}

    TLSSocket::TLSSocket(TLSSocket&& other) noexcept
        : m_config(std::move(other.m_config)), m_tcp(std::move(other.m_tcp)), m_ssl(other.m_ssl),
          m_handshake_error(std::move(other.m_handshake_error)) {
        other.m_ssl = nullptr;
    }

    TLSSocket& TLSSocket::operator=(TLSSocket&& other) noexcept {
        if (this == &other)
            return *this;
        close();
        m_config = std::move(other.m_config);
        m_tcp = std::move(other.m_tcp);
        m_ssl = other.m_ssl;
        other.m_ssl = nullptr;
        m_handshake_error = std::move(other.m_handshake_error);
        return *this;
    }

    TLSSocket::~TLSSocket() { close(); }

    bool TLSSocket::valid() const { return m_tcp.valid(); }

    const SocketConfig& TLSSocket::config() const { return tcp_of(m_config); }

    void TLSSocket::interrupt_blocking_io() {
        // Shut down only the read side. The kernel wakes any thread blocked in
        // recv()/SSL_read() and makes it return 0 (EOF). Leaving the write side
        // intact means close(), which the owning thread calls next, can still
        // send a TLS close_notify without SIGPIPE.
        SocketHandle fd = m_tcp.native_handle();
        if (fd != INVALID_SOCKET_HANDLE)
            internal::shutdown_rd(fd);
    }

    void TLSSocket::close() {
        if (m_ssl != nullptr) {
            const auto deadline = deadline_after(std::chrono::milliseconds{500});
            while (!internal::expired(deadline)) {
                ::ERR_clear_error();
                int rc = ::SSL_shutdown(m_ssl);
                if (rc == 1)
                    break;
                // First zero sends close_notify; immediately drive the second
                // half (it may already be buffered inside OpenSSL).
                if (rc == 0)
                    continue;
                int error = ::SSL_get_error(m_ssl, rc);
                if ((error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) ||
                    !internal::wait_ready(m_tcp.native_handle(), error == SSL_ERROR_WANT_WRITE, deadline))
                    break;
            }
            ::ERR_clear_error();
            ::SSL_free(m_ssl);
            m_ssl = nullptr;
        }
        m_tcp.close();
    }

    bool TLSSocket::bind() { return m_tcp.bind(); }
    bool TLSSocket::listen() { return m_tcp.listen(); }

    void TLSSocket::set_recv_timeout(std::chrono::milliseconds ms) {
        if (ms.count() < 0) {
            discard_tls(m_ssl, m_tcp);
            return;
        }
        std::visit([&](auto& cfg) { cfg.tcp.recv_timeout = ms; }, m_config);
    }
    void TLSSocket::set_send_timeout(std::chrono::milliseconds ms) {
        if (ms.count() < 0) {
            discard_tls(m_ssl, m_tcp);
            return;
        }
        std::visit([&](auto& cfg) { cfg.tcp.send_timeout = ms; }, m_config);
    }

    bool TLSSocket::connect() {
        if (config().connect_timeout.count() < 0) {
            m_handshake_error = "Negative connect timeout";
            return false;
        }
        return connect_until(deadline_after(config().connect_timeout));
    }

    bool TLSSocket::connect_until(Deadline deadline) {
        m_handshake_error.clear();

        const auto* cfg = std::get_if<TlsClientConfig>(&m_config);
        if (cfg == nullptr) {
            m_handshake_error = "TLSSocket::connect() called on non-client config";
            return false;
        }
        if (m_ssl != nullptr || internal::expired(deadline)) {
            m_handshake_error = "Already connected or expired deadline";
            return false;
        }

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr) {
            m_handshake_error = "SSL_CTX build failed: " + drain_ssl_errors();
            return false;
        }

        if (!m_tcp.connect_until(deadline)) {
            m_handshake_error = "TCP connect failed (finite deadlines require a numeric IPv4 endpoint)";
            return false;
        }

        m_ssl = ::SSL_new(ctx);
        if (m_ssl == nullptr) {
            m_handshake_error = "SSL_new failed: " + drain_ssl_errors();
            m_tcp.close();
            return false;
        }

        if (!internal::set_nonblocking(m_tcp.native_handle(), true) || !internal::setup_client_ssl(m_ssl, *cfg, m_tcp.native_handle())) {
            m_handshake_error = "TLS setup failed: " + drain_ssl_errors();
            discard_tls(m_ssl, m_tcp);
            return false;
        }

        auto result = run_tls(m_ssl, m_tcp.native_handle(), deadline, [&] { return ::SSL_connect(m_ssl); });
        if (result.count != 1) {
            m_handshake_error = result.timed_out ? "TLS handshake deadline or wait failed" : format_handshake_error("SSL_connect", m_ssl);
            discard_tls(m_ssl, m_tcp);
            return false;
        }
        return true;
    }

    stl::result<TLSSocket> TLSSocket::accept() { return accept_impl((Deadline::max)(), false); }

    stl::result<TLSSocket> TLSSocket::accept_until(Deadline deadline) { return accept_impl(deadline, true); }

    stl::result<TLSSocket> TLSSocket::accept_impl(Deadline deadline, bool include_wait) {
        const auto* cfg = std::get_if<TlsServerConfig>(&m_config);
        if (cfg == nullptr)
            return stl::make_error<TLSSocket>("TLSSocket::accept() called on non-server config");

        auto tcp_result = m_tcp.accept_until(deadline);
        if (!tcp_result)
            return stl::make_error<TLSSocket>("TCP accept failed: {}", tcp_result.error());

        if (!include_wait) {
            auto timeout = cfg->tcp.connect_timeout.count() > 0 ? cfg->tcp.connect_timeout : cfg->tcp.recv_timeout;
            deadline = deadline_after(timeout);
        }

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr)
            return stl::make_error<TLSSocket>("SSL_CTX build failed: {}", drain_ssl_errors());

        SSL* ssl = ::SSL_new(ctx);
        if (ssl == nullptr)
            return stl::make_error<TLSSocket>("SSL_new failed: {}", drain_ssl_errors());

        TCPSocket accepted = std::move(tcp_result.value());
        if (!internal::set_nonblocking(accepted.native_handle(), true) || !internal::attach_socket(ssl, accepted.native_handle())) {
            ::SSL_free(ssl);
            return stl::make_error<TLSSocket>("TLS socket setup failed");
        }

        auto result = run_tls(ssl, accepted.native_handle(), deadline, [&] { return ::SSL_accept(ssl); });
        if (result.count != 1) {
            stl::string err = result.timed_out ? "TLS handshake deadline or wait failed" : format_handshake_error("SSL_accept", ssl);
            ::SSL_free(ssl);
            return stl::make_error<TLSSocket>("{}", err);
        }

        TlsAcceptedConfig accepted_cfg{
            .tcp = cfg->tcp,
#ifdef SAP_TLS_WIRE_LOGGING
            .wire_log = cfg->wire_log,
#endif
        };
        return TLSSocket(std::move(accepted), ssl, std::move(accepted_cfg));
    }

    stl::result<size_t> TLSSocket::send(stl::span<const stl::byte> data) { return send_until(data, deadline_after(config().send_timeout)); }

    stl::result<size_t> TLSSocket::send_until(stl::span<const stl::byte> data, Deadline deadline) {
        if (m_ssl == nullptr)
            return stl::make_error<size_t>("TLS send: handshake not complete");
        if (data.empty())
            return size_t{0};

        const auto length = static_cast<int>((std::min)(data.size(), size_t{65536}));
        auto result = run_tls(m_ssl, m_tcp.native_handle(), deadline, [&] { return ::SSL_write(m_ssl, data.data(), length); });
        int n = result.count;
        if (n <= 0) {
            auto error = result.timed_out ? stl::string{"deadline or wait failed"} : drain_ssl_errors();
            discard_tls(m_ssl, m_tcp);
            return stl::make_error<size_t>("SSL_write failed: {}", error);
        }

#ifdef SAP_TLS_WIRE_LOGGING
        if (const auto& fn = wire_log_of(m_config))
            fn(ETlsWireDirection::Send, data.first(static_cast<size_t>(n)));
#endif
        return static_cast<size_t>(n);
    }

    stl::result<size_t> TLSSocket::recv(stl::span<stl::byte> data) { return recv_until(data, deadline_after(config().recv_timeout)); }

    stl::result<size_t> TLSSocket::recv_until(stl::span<stl::byte> data, Deadline deadline) {
        if (m_ssl == nullptr)
            return stl::make_error<size_t>("TLS recv: handshake not complete");
        if (data.empty())
            return size_t{0};

        const auto length = static_cast<int>((std::min)(data.size(), size_t{65536}));
        auto result = run_tls(m_ssl, m_tcp.native_handle(), deadline, [&] { return ::SSL_read(m_ssl, data.data(), length); });
        int n = result.count;
        if (n <= 0) {
            if (result.error == SSL_ERROR_ZERO_RETURN)
                return static_cast<size_t>(0);
            auto error = result.timed_out ? stl::string{"deadline or wait failed"} : drain_ssl_errors();
            discard_tls(m_ssl, m_tcp);
            return stl::make_error<size_t>("SSL_read failed: {}", error);
        }

#ifdef SAP_TLS_WIRE_LOGGING
        if (const auto& fn = wire_log_of(m_config))
            fn(ETlsWireDirection::Recv, data.first(static_cast<size_t>(n)));
#endif
        return static_cast<size_t>(n);
    }

    stl::string TLSSocket::negotiated_protocol() const {
        if (m_ssl == nullptr)
            return {};
        const unsigned char* alpn = nullptr;
        unsigned int len = 0;
        ::SSL_get0_alpn_selected(m_ssl, &alpn, &len);
        return (alpn && len) ? stl::string{reinterpret_cast<const char*>(alpn), len} : stl::string{};
    }

    stl::string TLSSocket::negotiated_cipher() const {
        if (m_ssl == nullptr)
            return {};
        const SSL_CIPHER* c = ::SSL_get_current_cipher(m_ssl);
        if (c == nullptr)
            return {};
        const char* name = ::SSL_CIPHER_get_name(c);
        return name ? stl::string{name} : stl::string{};
    }

    stl::string TLSSocket::negotiated_tls_version() const {
        if (m_ssl == nullptr)
            return {};
        const char* v = ::SSL_get_version(m_ssl);
        return v ? stl::string{v} : stl::string{};
    }

    stl::string TLSSocket::peer_cert_subject() const {
        if (m_ssl == nullptr)
            return {};
        X509* cert = ::SSL_get1_peer_certificate(m_ssl); // OpenSSL 3.0+
        if (cert == nullptr)
            return {};
        char buf[512];
        ::X509_NAME_oneline(::X509_get_subject_name(cert), buf, sizeof(buf));
        ::X509_free(cert);
        return stl::string{buf};
    }

    stl::string TLSSocket::peer_cert_issuer() const {
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
