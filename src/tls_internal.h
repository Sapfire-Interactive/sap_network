#pragma once

#include "sap_network/platform.h"
#include "sap_network/tls_socket.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sap_core/stl/string.h>

namespace sap::network::internal {

    // Drain and format the OpenSSL error stack into a single string.
    // Always clears the thread's error queue.
    stl::string drain_ssl_errors();

    // Resolve (or build) the shared SSL_CTX for the given config equivalence
    // class. Lifetimes managed by an internal cache; do not SSL_CTX_free.
    // Client and server contexts live in separate caches; the role is encoded
    // in the choice of overload.
    SSL_CTX* acquire_ctx(const TlsClientConfig& cfg);
    SSL_CTX* acquire_ctx(const TlsServerConfig& cfg);

    // Windows trust-store import, defined in tls_trust_store_windows.cpp
    // (no-op implementation in tls_trust_store_posix.cpp). Returns number
    // of certs added.
    int load_system_trust_store(SSL_CTX* ctx);

    // Wires fd, SNI, ALPN, and hostname verification on a freshly-created
    // client SSL*. Caller still drives SSL_connect.
    void setup_client_ssl(SSL* ssl, const TlsClientConfig& cfg, SocketHandle fd);

    // Pulls verify result + error stack into a human-readable message for
    // failed SSL_connect / SSL_accept calls.
    stl::string format_handshake_error(const char* stage, SSL* ssl);

} // namespace sap::network::internal

