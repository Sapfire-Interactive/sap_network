#pragma once

#include <sap_core/stl/string.h>
#include <sap_core/stl/vector.h>
#include <sap_core/types.h>

#include <chrono>
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

    enum class ETlsRole { Client, Server };

    struct TlsConfig {
        // Underlying TCP configuration. TLSSocket owns a TCPSocket by value.
        SocketConfig tcp;

        ETlsRole role = ETlsRole::Client;

        // --- Client-side knobs (ignored when role == Server) ----------------
        // SNI hostname sent during handshake. If empty, uses tcp.host.
        stl::string sni_hostname;
        // Verify the peer presented a certificate chaining to a trusted root.
        bool verify_peer = true;
        // Verify the peer's cert matches sni_hostname (or tcp.host if empty).
        bool verify_hostname = true;
        // Optional explicit CA bundle file (PEM). Falls back to ca_dir then OS store.
        stl::string ca_file;
        // Optional explicit CA directory (hashed certs, OpenSSL layout).
        stl::string ca_dir;
        // Optional client cert + key for mutual TLS. Both set or both empty.
        stl::string client_cert_file;
        stl::string client_key_file;

        // --- Server-side knobs (ignored when role == Client) ----------------
        // Path to server certificate chain (PEM). Required for Server role.
        stl::string server_cert_file;
        // Path to server private key (PEM). Required for Server role.
        stl::string server_key_file;

        // --- Shared knobs ---------------------------------------------------
        // ALPN protocols. On client: offered in preference order. On server:
        // selected from the client's offer in this preference order.
        stl::vector<stl::string> alpn_protocols;
        // Minimum acceptable protocol version. Defaults to TLS 1.2.
        enum class EMinVersion { TLS_1_2, TLS_1_3 };
        EMinVersion min_version = EMinVersion::TLS_1_2;

#ifdef SAP_TLS_WIRE_LOGGING
        // Debug hook, compiled in only when SAP_TLS_WIRE_LOGGING is defined
        // (auto-enabled in Debug builds; see §4). Called once per successful
        // send / recv with the decrypted plaintext. Empty by default = no-op.
        enum class EWireDirection { Send, Recv };
        std::function<void(EWireDirection, stl::span<const stl::byte>)> wire_log;
#endif
    };

} // namespace sap::network
