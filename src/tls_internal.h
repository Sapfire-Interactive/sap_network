#pragma once

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sap_core/stl/string.h>

#include "sap_network/tls_socket.h"

namespace sap::network::internal {

    // Drain and format the OpenSSL error stack into a single string.
    // Always clears the thread's error queue.
    stl::string drain_ssl_errors();

    // Resolve (or build) the shared SSL_CTX for this TlsConfig equivalence
    // class. Lifetimes managed by an internal cache; do not SSL_CTX_free.
    SSL_CTX* acquire_ctx(const TlsConfig& cfg);

    // Windows trust-store import, defined in tls_trust_store_windows.cpp
    // (no-op implementation in tls_trust_store_posix.cpp). Returns number
    // of certs added.
    int load_system_trust_store(SSL_CTX* ctx);

} // namespace sap::network::internal