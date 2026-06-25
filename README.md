# sap_network

Cross-platform C++20 networking library providing TCP, UDP, and TLS sockets — both blocking and reactor-driven async variants — with a uniform interface enforced by C++20 concepts. Error handling uses `stl::result<T>` from [sap_core](https://github.com/Sapfire-Interactive/sap_core) — no exceptions.

Part of the [Sapfire](https://github.com/Sapfire-Interactive) library ecosystem.

## What's inside

### Blocking sockets
- **`TCPSocket`** — stream socket. `bind`, `listen`, `connect`, `accept`, `send`, `recv`, `close`. Configurable send/recv timeouts.
- **`UDPSocket`** — datagram socket.
- **`TLSSocket`** — TLS 1.2/1.3 over TCP via OpenSSL. Supports both client and server roles, ALPN negotiation, post-handshake cipher/protocol/certificate introspection.

### Async sockets (reactor + C++20 coroutines)
- **`TCPSocketAsync`** — non-blocking TCP. Same lifecycle as `TCPSocket` but `connect` / `accept` / `read` / `write` are coroutines returning `sap::async::Task<stl::result<...>>`. Driven by a `sap::async::Executor` and the underlying `sap::io::Reactor` (epoll on Linux, IOCP+AFD on Windows).
- **`TLSSocketAsync`** — non-blocking TLS. OpenSSL `BIO` driven by a WANT_READ / WANT_WRITE state machine, so handshake / read / write / close all suspend on the reactor instead of blocking.

Both async sockets:
- Take a `sap::async::Executor&` at construction; they don't own the loop.
- Accept an optional `sap::async::StopToken` per operation; cancellation throws `CancelledError` at the await boundary.
- Use a single in-flight flag to enforce one outstanding operation per direction (no concurrent reads / no concurrent writes on the same socket).

### Socket concepts
```cpp
template<typename T>
concept Socket = requires(T s, stl::span<const stl::byte> data, stl::span<stl::byte> buf) {
    { s.send(data) } -> std::same_as<stl::result<size_t>>;
    { s.recv(buf)  } -> std::same_as<stl::result<size_t>>;
    { s.close()    } -> std::same_as<void>;
    { s.valid()    } -> std::same_as<bool>;
};

template<typename T>
concept SocketAsync = requires(T s, stl::span<const stl::byte> wdata, stl::span<stl::byte> rdata, sap::async::StopToken tok) {
    { s.connect(tok) } -> std::same_as<sap::async::Task<stl::result<>>>;
    { s.read(rdata, tok) }  -> std::same_as<sap::async::Task<stl::result<size_t>>>;
    { s.write(wdata, tok) } -> std::same_as<sap::async::Task<stl::result<size_t>>>;
    { s.close()    } -> std::same_as<void>;
    { s.valid()    } -> std::same_as<bool>;
};
```
`TCPSocket` and `TLSSocket` satisfy `Socket`; `TCPSocketAsync` and `TLSSocketAsync` satisfy `SocketAsync`. Both checks are verified by `static_assert` in the relevant headers.

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

```cpp
#include <sap_network/tcp_socket_async.h>
#include <sap_core/async/executor.h>
#include <sap_core/async/spawn.h>

auto ex_r = sap::async::Executor::create();
auto& ex  = ex_r.value();

sap::network::TCPSocketAsync sock(ex, sap::network::SocketConfig{.host = "127.0.0.1", .port = 8080});

auto fetch = [&]() -> sap::async::Task<stl::result<>> {
    if (auto r = co_await sock.connect(); !r) co_return r;
    const char* msg = "ping";
    auto w = co_await sock.write(stl::span<const stl::byte>(reinterpret_cast<const stl::byte*>(msg), 4));
    if (!w) co_return stl::make_error<>("{}", w.error());
    stl::byte buf[64];
    auto      r = co_await sock.read(stl::span<stl::byte>(buf, sizeof(buf)));
    if (!r) co_return stl::make_error<>("{}", r.error());
    co_return stl::result<>{};
};

auto handle = sap::async::spawn(ex, fetch());
sap::async::sync_wait(stl::move(handle));   // drives the executor
```
