#include "sap_network/platform.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <csignal>
#endif

#include <openssl/ssl.h>

namespace sap::network {
    void SocketPlatform::init() { static SocketPlatform platform; }

    SocketPlatform::SocketPlatform() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#else
        // Ignore SIGPIPE process-wide so OpenSSL (and plain send/recv) can
        // safely write to a closed peer. Without this, SSL_shutdown / SSL_write
        // against a half-closed connection raises SIGPIPE and kills us.
        std::signal(SIGPIPE, SIG_IGN);
#endif
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }

    SocketPlatform::~SocketPlatform() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
} // namespace sap::network
