#pragma once

#include "sap_network/platform.h"
#include "sap_network/socket_concept.h"
#include "sap_network/socket_config.h"
#include "sap_network/tcp_socket.h"

#include <sap_core/stl/result.h>
#include <sap_core/stl/string.h>
#include <sap_core/stl/vector.h>
#include <sap_core/types.h>

#include <chrono>
#include <variant>

struct ssl_st;
struct ssl_ctx_st;

namespace sap::network {

    // TLSSocket has three internal states encoded in the config variant:
    //   - TlsClientConfig: an outbound socket. connect() is meaningful.
    //   - TlsServerConfig: a listening socket. bind/listen/accept are meaningful.
    //   - TlsAcceptedConfig: a server-side accepted connection (returned from
    //     accept()). send/recv/close/introspection are meaningful.
    // Calling a method against the wrong variant fails gracefully (connect()
    // returns false with an error in handshake_error(); accept() returns an
    // error result), but the type system steers callers to the right shape via
    // the two public constructors.
    class TLSSocket {
    public:
        explicit TLSSocket(TlsClientConfig config);
        explicit TLSSocket(TlsServerConfig config);

        ~TLSSocket();
        TLSSocket(const TLSSocket&) = delete;
        TLSSocket& operator=(const TLSSocket&) = delete;
        TLSSocket(TLSSocket&&) noexcept;
        TLSSocket& operator=(TLSSocket&&) noexcept;

        // Socket concept surface (mirrors TCPSocket's common methods).
        bool connect(); // Client-only: TCP connect + SSL_connect + verify.
        stl::result<size_t> send(stl::span<const stl::byte> data); // SSL_write.
        stl::result<size_t> recv(stl::span<stl::byte> data); // SSL_read; 0 = peer-closed.
        void close(); // SSL_shutdown → TCP close.
        bool valid() const;
        const SocketConfig& config() const;

        // Server-side additions (beyond the Socket concept).
        bool bind();
        bool listen();
        stl::result<TLSSocket> accept(); // Server-only: TCP accept + SSL_accept.

        // Timeouts apply to the underlying TCP layer; TLS inherits them.
        void set_recv_timeout(std::chrono::milliseconds ms);
        void set_send_timeout(std::chrono::milliseconds ms);

        // Post-handshake introspection. Empty until handshake completes.
        stl::string negotiated_protocol() const; // ALPN result, e.g. "http/1.1".
        stl::string negotiated_cipher() const; // e.g. "TLS_AES_256_GCM_SHA384".
        stl::string negotiated_tls_version() const; // e.g. "TLSv1.3".
        stl::string peer_cert_subject() const; // Client: server's cert. Server: client's cert if present.
        stl::string peer_cert_issuer() const;

        // Detail for the most recent connect()/accept() failure. Empty when
        // the handshake succeeded or hasn't run.
        const stl::string& handshake_error() const { return m_handshake_error; }

    private:
        // Used by accept() to wrap a freshly-accepted server-side TCP
        // connection + its SSL*.
        TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsAcceptedConfig config);

    public:
        // Public so free helpers in the .cpp can std::visit it without needing
        // friend declarations. Not part of the user-facing API surface.
        using ConfigVariant = std::variant<TlsClientConfig, TlsServerConfig, TlsAcceptedConfig>;

    private:
        // Member declaration order is load-bearing: m_tcp's ctor reads the
        // tcp field of whichever variant is active, so m_config MUST be
        // declared (and initialized) first.
        ConfigVariant m_config;
        TCPSocket m_tcp;
        ssl_st* m_ssl = nullptr; // Opaque; defined by OpenSSL in tls_socket.cpp.
        stl::string m_handshake_error;
    };

    // Compile-time check: TLSSocket satisfies the common Socket concept.
    static_assert(Socket<TLSSocket>);

} // namespace sap::network
