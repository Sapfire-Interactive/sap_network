#include "sap_network/platform.h"

namespace sap::network {
    void SocketPlatform::init() { static SocketPlatform platform; }

    SocketPlatform::SocketPlatform() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    SocketPlatform::~SocketPlatform() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
} // namespace sap::network