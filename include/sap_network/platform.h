#pragma once

#include <cstdint>

namespace sap::network {

#ifdef _WIN32
    // SOCKET is UINT_PTR (== uintptr_t) on both x86 and x64 Windows. Alias
    // instead of pulling in <winsock2.h> so consumers of this header don't
    // inherit Winsock macros (min/max, etc.).
    using SocketHandle = std::uintptr_t;
    inline constexpr SocketHandle INVALID_SOCKET_HANDLE = static_cast<SocketHandle>(~0);
#else
    using SocketHandle = int;
    inline constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

    class SocketPlatform {
    public:
        static void init();

    private:
        SocketPlatform();
        ~SocketPlatform();
    };

} // namespace sap::network
