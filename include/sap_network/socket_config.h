#pragma once

#include <sap_core/stl/string.h>
#include <sap_core/stl/vector.h>
#include <sap_core/types.h>

#include <chrono>
#include <cstddef>
#include <functional>

namespace sap::network {

    struct SocketConfig {
        stl::string host;
        u16 port = 0;
        std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{0}; // 0 = no timeout (blocking)
        std::chrono::milliseconds recv_timeout = std::chrono::milliseconds{0}; // 0 = no timeout
        std::chrono::milliseconds send_timeout = std::chrono::milliseconds{0}; // 0 = no timeout
        i32 listen_backlog = 128;
        bool reuse_addr = false;
    };

    // Minimum acceptable TLS protocol version. Hoisted out of the (now split)
    // TLS configs because both sides share it.
    enum class ETlsMinVersion { TLS_1_2, TLS_1_3 };

#ifdef SAP_TLS_WIRE_LOGGING
    enum class ETlsWireDirection { Send, Recv };
    // Debug hook signature, compiled in only when SAP_TLS_WIRE_LOGGING is
    // defined (auto-enabled in Debug builds). Called once per successful
    // send / recv with the decrypted plaintext.
    using TlsWireLogFn = std::function<void(ETlsWireDirection, stl::span<const std::byte>)>;
#endif

    // Configuration for an outbound TLS connection (client role). Drives
    // TLSSocket::connect(); none of these fields are meaningful when the
    // socket is acting as a server.
    struct TlsClientConfig {
        SocketConfig tcp;

        // SNI hostname sent during handshake. If empty, uses tcp.host.
        stl::string sni_hostname;
        // Verify the server presented a certificate chaining to a trusted root.
        bool verify_peer = true;
        // Verify the server's cert matches sni_hostname (or tcp.host if empty).
        bool verify_hostname = true;
        // Optional explicit CA bundle file (PEM). Falls back to ca_dir then OS store.
        stl::string ca_file;
        // Optional explicit CA directory (hashed certs, OpenSSL layout).
        stl::string ca_dir;
        // Optional client cert + key for mutual TLS. Both set or both empty.
        stl::string client_cert_file;
        stl::string client_key_file;

        // ALPN protocols offered in preference order.
        stl::vector<stl::string> alpn_protocols;
        ETlsMinVersion min_version = ETlsMinVersion::TLS_1_2;

#ifdef SAP_TLS_WIRE_LOGGING
        TlsWireLogFn wire_log;
#endif
    };

    // Configuration for a listening TLS server. Drives TLSSocket::bind(),
    // listen() and accept(); none of these fields are meaningful on a client
    // socket.
    struct TlsServerConfig {
        SocketConfig tcp;

        // Path to server certificate chain (PEM). Required.
        stl::string cert_file;
        // Path to server private key (PEM). Required.
        stl::string key_file;

        // Trust roots for verifying client certs (consulted only when
        // require_client_cert is true). Field order is deliberate: tests and
        // call sites read more naturally with the cert paths flowing
        // cert/key → trust roots → policy toggle.
        stl::string ca_file;
        stl::string ca_dir;
        // When true, the server sends a CertificateRequest and refuses the
        // handshake if the client doesn't present a cert that verifies against
        // ca_file / ca_dir. Default false = no client-cert verification.
        // Setting this without ca_file or ca_dir is a misconfiguration that
        // causes acquire_ctx to fail fast — no client cert can ever verify
        // without trust roots.
        bool require_client_cert = false;

        // ALPN preference order; the server picks the first match from the
        // client's offer.
        stl::vector<stl::string> alpn_protocols;
        ETlsMinVersion min_version = ETlsMinVersion::TLS_1_2;

#ifdef SAP_TLS_WIRE_LOGGING
        TlsWireLogFn wire_log;
#endif
    };

    // Carrier for the post-handshake state of a TLSSocket returned from
    // accept(). Users never construct this directly; accept() forwards the
    // listening socket's tcp + wire_log into it. Pre-handshake config (cert
    // paths, CA, ALPN list, version) is no longer relevant once the SSL
    // session is established.
    struct TlsAcceptedConfig {
        SocketConfig tcp;
#ifdef SAP_TLS_WIRE_LOGGING
        TlsWireLogFn wire_log;
#endif
    };

} // namespace sap::network
