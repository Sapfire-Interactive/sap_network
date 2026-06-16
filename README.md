# sap_network

Cross-platform C++20 networking library providing TCP, UDP, and TLS sockets with a uniform interface enforced by a C++20 concept. Error handling uses `stl::result<T>` from [sap_core](https://github.com/Sapfire-Interactive/sap_core) — no exceptions.

Part of the [Sapfire](https://github.com/Sapfire-Interactive) library ecosystem.

## What's inside

### Sockets
- **`TCPSocket`** — stream socket. `bind`, `listen`, `connect`, `accept`, `send`, `recv`, `close`. Configurable send/recv timeouts.
- **`UDPSocket`** — datagram socket.
- **`TLSSocket`** — TLS 1.2/1.3 over TCP via OpenSSL. Supports both client and server roles, ALPN negotiation, post-handshake cipher/protocol/certificate introspection.

### Socket concept
```cpp
template<typename T>
concept Socket = requires(T s, stl::span<const stl::byte> data, stl::span<stl::byte> buf) {
    { s.send(data) } -> std::same_as<stl::result<size_t>>;
    { s.recv(buf)  } -> std::same_as<stl::result<size_t>>;
    { s.close()    } -> std::same_as<void>;
    { s.valid()    } -> std::same_as<bool>;
};
```
Both `TCPSocket` and `TLSSocket` satisfy `Socket`, verified with `static_assert` at compile time.

### Platform abstraction
`platform.h` normalises socket handles and errno across Windows (WinSock2) and POSIX. All platform differences are isolated to `*_windows.cpp` / `*_posix.cpp` translation units.

## TLS design

`TLSSocket` has three internal states encoded in a `std::variant<TlsClientConfig, TlsServerConfig, TlsAcceptedConfig>`:
- **Client** — `connect()` performs TCP connect + TLS handshake + certificate verification.
- **Server** — `bind()` / `listen()` / `accept()` accept incoming TCP connections and complete the TLS handshake.
- **Accepted** — returned from `accept()`, ready for `send()` / `recv()`.

The config variant is declared before the `TCPSocket` member — member initialisation order is load-bearing here since the TCP socket constructor reads from the active variant.

Post-handshake you can query `negotiated_protocol()` (ALPN result), `negotiated_cipher()`, `negotiated_tls_version()`, `peer_cert_subject()`, and `peer_cert_issuer()`.

## Build

Requires CMake 3.20+, C++20, OpenSSL, and [sap_core](https://github.com/Sapfire-Interactive/sap_core).

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

## Usage example

```cpp
#include <sap_network/tcp_socket.h>

sap::network::TCPSocket sock{SocketConfig{.host = "127.0.0.1", .port = 8080}};
if (!sock.connect())
    return;

std::array<std::byte, 1024> buf;
auto result = sock.recv(buf);
if (!result)
    std::println("recv error: {}", result.error());
else
    std::println("received {} bytes", result.value());
```

```cpp
#include <sap_network/tls_socket.h>

// TLS client
sap::network::TLSSocket tls{TlsClientConfig{.host = "example.com", .port = 443}};
if (!tls.connect()) {
    std::println("handshake failed: {}", tls.handshake_error());
    return;
}
std::println("cipher: {}", tls.negotiated_cipher());
```
