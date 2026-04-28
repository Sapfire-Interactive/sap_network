#include "sap_network/tls_socket.h"

#include "tls_internal.h"

#include <cstring>
#include <format>
#include <utility>

namespace sap::network {

    using internal::acquire_ctx;
    using internal::drain_ssl_errors;

    namespace {

        const SocketConfig& tcp_of(const TLSSocket::ConfigVariant& v) {
            return std::visit([](const auto& c) -> const SocketConfig& { return c.tcp; }, v);
        }

#ifdef SAP_TLS_WIRE_LOGGING
        const TlsWireLogFn& wire_log_of(const TLSSocket::ConfigVariant& v) {
            return std::visit([](const auto& c) -> const TlsWireLogFn& { return c.wire_log; }, v);
        }
#endif

        stl::string format_handshake_error(const char* stage, SSL* ssl) {
            long verify = ::SSL_get_verify_result(ssl);
            stl::string err = drain_ssl_errors();
            if (verify != X509_V_OK) {
                const char* reason = ::X509_verify_cert_error_string(verify);
                return std::format("{} failed (verify {}: {}): {}", stage, verify, reason, err);
            }
            return std::format("{} failed: {}", stage, err);
        }

    } // namespace

    TLSSocket::TLSSocket(TlsClientConfig config) : m_config(std::move(config)), m_tcp(tcp_of(m_config)) {}
    TLSSocket::TLSSocket(TlsServerConfig config) : m_config(std::move(config)), m_tcp(tcp_of(m_config)) {}

    TLSSocket::TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsAcceptedConfig config) :
        m_config(std::move(config)), m_tcp(std::move(tcp)), m_ssl(ssl) {}

    TLSSocket::TLSSocket(TLSSocket&& other) noexcept :
        m_config(std::move(other.m_config)), m_tcp(std::move(other.m_tcp)), m_ssl(other.m_ssl),
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

    void TLSSocket::close() {
        if (m_ssl != nullptr) {
            // Bidirectional shutdown: SSL_shutdown returns 0 when our
            // close_notify has been sent but we haven't seen the peer's yet.
            // Calling it a second time blocks reading the peer's close_notify
            // (and incidentally discarding any data still in flight from the
            // peer). Without this second call, our close races with the peer's
            // recv loop and data we previously committed via SSL_write can be
            // lost when shutdown(SHUT_RDWR) tears down TCP.
            //
            // Cap the wait so a vanished peer can't make close() hang.
            int r = ::SSL_shutdown(m_ssl);
            if (r == 0) {
                m_tcp.set_recv_timeout(std::chrono::milliseconds{500});
                ::SSL_shutdown(m_ssl);
            }
            ::ERR_clear_error();
            ::SSL_free(m_ssl);
            m_ssl = nullptr;
        }
        m_tcp.close();
    }

    bool TLSSocket::bind() { return m_tcp.bind(); }
    bool TLSSocket::listen() { return m_tcp.listen(); }

    void TLSSocket::set_recv_timeout(std::chrono::milliseconds ms) { m_tcp.set_recv_timeout(ms); }
    void TLSSocket::set_send_timeout(std::chrono::milliseconds ms) { m_tcp.set_send_timeout(ms); }

    bool TLSSocket::connect() {
        m_handshake_error.clear();

        const auto* cfg = std::get_if<TlsClientConfig>(&m_config);
        if (cfg == nullptr) {
            m_handshake_error = "TLSSocket::connect() called on non-client config";
            return false;
        }

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr) {
            m_handshake_error = "SSL_CTX build failed: " + drain_ssl_errors();
            return false;
        }

        if (!m_tcp.connect()) {
            m_handshake_error = "TCP connect failed";
            return false;
        }

        m_ssl = ::SSL_new(ctx);
        if (m_ssl == nullptr) {
            m_handshake_error = "SSL_new failed: " + drain_ssl_errors();
            return false;
        }

        ::SSL_set_fd(m_ssl, static_cast<int>(m_tcp.native_handle()));

        const stl::string& host = cfg->sni_hostname.empty() ? cfg->tcp.host : cfg->sni_hostname;
        if (!host.empty()) {
            ::SSL_set_tlsext_host_name(m_ssl, host.c_str());
            if (cfg->verify_hostname)
                ::SSL_set1_host(m_ssl, host.c_str());
        }

        if (!cfg->alpn_protocols.empty()) {
            stl::vector<unsigned char> wire;
            for (const auto& p : cfg->alpn_protocols) {
                wire.push_back(static_cast<unsigned char>(p.size()));
                wire.insert(wire.end(), p.begin(), p.end());
            }
            ::SSL_set_alpn_protos(m_ssl, wire.data(), static_cast<unsigned int>(wire.size()));
        }

        if (::SSL_connect(m_ssl) != 1) {
            m_handshake_error = format_handshake_error("SSL_connect", m_ssl);
            return false;
        }
        return true;
    }

    stl::result<TLSSocket> TLSSocket::accept() {
        const auto* cfg = std::get_if<TlsServerConfig>(&m_config);
        if (cfg == nullptr)
            return stl::make_error<TLSSocket>("TLSSocket::accept() called on non-server config");

        auto tcp_result = m_tcp.accept();
        if (!tcp_result)
            return stl::make_error<TLSSocket>("TCP accept failed: {}", tcp_result.error());

        SSL_CTX* ctx = acquire_ctx(*cfg);
        if (ctx == nullptr)
            return stl::make_error<TLSSocket>("SSL_CTX build failed: {}", drain_ssl_errors());

        SSL* ssl = ::SSL_new(ctx);
        if (ssl == nullptr)
            return stl::make_error<TLSSocket>("SSL_new failed: {}", drain_ssl_errors());

        TCPSocket accepted = std::move(tcp_result.value());
        ::SSL_set_fd(ssl, static_cast<int>(accepted.native_handle()));

        if (::SSL_accept(ssl) != 1) {
            stl::string err = format_handshake_error("SSL_accept", ssl);
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

    stl::result<size_t> TLSSocket::send(stl::span<const stl::byte> data) {
        if (m_ssl == nullptr)
            return stl::make_error<size_t>("TLS send: handshake not complete");

        int n = ::SSL_write(m_ssl, data.data(), static_cast<int>(data.size()));
        if (n <= 0) {
            int err = ::SSL_get_error(m_ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN)
                return static_cast<size_t>(0);
            return stl::make_error<size_t>("SSL_write failed: {}", drain_ssl_errors());
        }

#ifdef SAP_TLS_WIRE_LOGGING
        if (const auto& fn = wire_log_of(m_config))
            fn(ETlsWireDirection::Send, data.first(static_cast<size_t>(n)));
#endif
        return static_cast<size_t>(n);
    }

    stl::result<size_t> TLSSocket::recv(stl::span<stl::byte> data) {
        if (m_ssl == nullptr)
            return stl::make_error<size_t>("TLS recv: handshake not complete");

        int n = ::SSL_read(m_ssl, data.data(), static_cast<int>(data.size()));
        if (n <= 0) {
            int err = ::SSL_get_error(m_ssl, n);
            // Treat both clean (close_notify) and unclean (peer dropped TCP
            // without close_notify) shutdowns as EOF — matches the TCP
            // recv() shape, which returns 0 in both cases.
            if (err == SSL_ERROR_ZERO_RETURN)
                return static_cast<size_t>(0);
            if (err == SSL_ERROR_SYSCALL && n == 0) {
                ::ERR_clear_error();
                return static_cast<size_t>(0);
            }
            return stl::make_error<size_t>("SSL_read failed: {}", drain_ssl_errors());
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
