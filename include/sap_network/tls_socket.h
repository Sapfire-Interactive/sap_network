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

struct ssl_st;
struct ssl_ctx_st;

namespace sap::network {

    class TLSSocket {
    public:
        explicit TLSSocket(TlsConfig config);
        ~TLSSocket();
        TLSSocket(const TLSSocket&) = delete;
        TLSSocket& operator=(const TLSSocket&) = delete;
        TLSSocket(TLSSocket&&) noexcept;
        TLSSocket& operator=(TLSSocket&&) noexcept;

        // Socket concept surface (mirrors TCPSocket's common methods).
        bool connect(); // Client: TCP connect + SSL_connect + verify.
        stl::result<size_t> send(stl::span<const stl::byte> data); // SSL_write.
        stl::result<size_t> recv(stl::span<stl::byte> data); // SSL_read; 0 = peer-closed.
        void close(); // SSL_shutdown → TCP close.
        bool valid() const;
        const SocketConfig& config() const { return m_config.tcp; }

        // Server-side additions (beyond the Socket concept).
        bool bind(); // Delegates to m_tcp.
        bool listen(); // Delegates to m_tcp.
        stl::result<TLSSocket> accept(); // TCP accept + SSL_accept. Inherits server config.

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
        // the handshake succeeded or hasn't run. Populated from the OpenSSL
        // error stack. send/recv errors live in their own result<>.
        const stl::string& handshake_error() const { return m_handshake_error; }

    private:
        // Private constructor used by accept() to wrap a freshly-accepted
        // server-side TCP connection + its SSL*.
        TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsConfig config);

        // Member declaration order is load-bearing: m_tcp's ctor reads
        // m_config.tcp, so m_config MUST be declared (and therefore
        // initialized) first.
        TlsConfig m_config;
        TCPSocket m_tcp;
        ssl_st* m_ssl = nullptr; // Opaque; defined by OpenSSL in tls_socket.cpp.
        stl::string m_handshake_error;
    };

    // Compile-time check: TLSSocket satisfies the common Socket concept.
    static_assert(Socket<TLSSocket>);

} // namespace sap::network
