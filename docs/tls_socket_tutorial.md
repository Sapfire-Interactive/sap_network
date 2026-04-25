# `TLSSocket` — A Walkthrough

This guide walks through `sap::network::TLSSocket` end to end, in the same
spirit as the [OpenSSL TLS client tutorial][openssl-guide]. The goal is for
a reader new to either the codebase or to OpenSSL to be able to follow what
each piece does, why it exists, and what trade-offs were made.

[openssl-guide]: https://docs.openssl.org/3.3/man7/ossl-guide-tls-client-block/

The relevant files:

| File | Purpose |
|---|---|
| [`include/sap_network/tls_socket.h`](../include/sap_network/tls_socket.h) | Public header: `TLSSocket` class. |
| [`include/sap_network/socket_config.h`](../include/sap_network/socket_config.h) | `TlsConfig`, `ETlsRole`, `TlsConfig::EWireDirection`. |
| [`src/tls_socket.cpp`](../src/tls_socket.cpp) | All of `TLSSocket`'s methods. |
| [`src/tls_internal.h`](../src/tls_internal.h) | Private API: `acquire_ctx`, `drain_ssl_errors`, `load_system_trust_store`. |
| [`src/tls_internal.cpp`](../src/tls_internal.cpp) | The `SSL_CTX` cache and ALPN-select callback. |
| [`src/tls_trust_store_posix.cpp`](../src/tls_trust_store_posix.cpp) | No-op on POSIX (uses `SSL_CTX_set_default_verify_paths`). |
| [`src/tls_trust_store_windows.cpp`](../src/tls_trust_store_windows.cpp) | Imports the Windows ROOT cert store. |
| [`src/platform.cpp`](../src/platform.cpp) | OpenSSL init + Winsock startup + `SIGPIPE` ignore. |

---

## 1. The shape of the class

`TLSSocket` looks deliberately like `TCPSocket` so consumers can swap one for
the other through the `Socket` concept:

```cpp
class TLSSocket {
public:
    explicit TLSSocket(TlsConfig config);
    ~TLSSocket();
    TLSSocket(TLSSocket&&) noexcept;
    TLSSocket& operator=(TLSSocket&&) noexcept;
    // ... copies deleted ...

    // Socket concept surface
    bool                connect();
    stl::result<size_t> send(stl::span<const stl::byte>);
    stl::result<size_t> recv(stl::span<stl::byte>);
    void                close();
    bool                valid() const;
    const SocketConfig& config() const;

    // Server-side additions
    bool                bind();
    bool                listen();
    stl::result<TLSSocket> accept();

    // ... timeouts, introspection, handshake_error ...

private:
    TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsConfig config);

    TlsConfig    m_config;   // declared first: m_tcp's ctor reads m_config.tcp
    TCPSocket    m_tcp;
    ssl_st*      m_ssl = nullptr;
    stl::string  m_handshake_error;
};

static_assert(Socket<TLSSocket>);
```

A few things worth pointing out:

- **No pimpl, no inheritance.** `m_ssl` is a forward-declared opaque pointer
  (`struct ssl_st;` at file scope). The full OpenSSL header stays inside
  `src/`, so consumers of `tls_socket.h` don't transitively pull
  `<openssl/ssl.h>`. Same trick `platform.h` uses to keep Winsock private.
- **Member declaration order is load-bearing.** `m_tcp` is constructed from
  `m_config.tcp`, so `m_config` must be initialised first, which means it
  must be *declared* first (member init order follows declaration order, not
  init-list order).
- **`static_assert(Socket<TLSSocket>)`** catches concept-shape regressions at
  compile time.

---

## 2. Configuration: `TlsConfig`

[`socket_config.h`](../include/sap_network/socket_config.h) defines:

```cpp
enum class ETlsRole { Client, Server };

struct TlsConfig {
    SocketConfig tcp;                // host, port, timeouts, etc.
    ETlsRole     role = ETlsRole::Client;

    // Client-only
    stl::string sni_hostname;        // empty => use tcp.host
    bool        verify_peer = true;
    bool        verify_hostname = true;
    stl::string ca_file;
    stl::string ca_dir;
    stl::string client_cert_file;
    stl::string client_key_file;

    // Server-only
    stl::string server_cert_file;
    stl::string server_key_file;

    // Shared
    stl::vector<stl::string> alpn_protocols;
    enum class EMinVersion { TLS_1_2, TLS_1_3 };
    EMinVersion min_version = EMinVersion::TLS_1_2;

#ifdef SAP_TLS_WIRE_LOGGING
    enum class EWireDirection { Send, Recv };
    std::function<void(EWireDirection, stl::span<const stl::byte>)> wire_log;
#endif
};
```

Defaults are tuned for the most common case — client, verify everything,
TLS 1.2+. The `wire_log` member is conditionally compiled (see §10).

---

## 3. One-time init: `SocketPlatform::init()`

Before any `TLSSocket` work, the platform layer needs to start:

```cpp
SocketPlatform::SocketPlatform() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    // OpenSSL (and plain send/recv) write to closed peers in normal flows;
    // without this, SSL_shutdown on a half-closed conn raises SIGPIPE and
    // kills the process.
    std::signal(SIGPIPE, SIG_IGN);
#endif
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
        nullptr);
}
```

Three things land here:

- `WSAStartup` / `WSACleanup` for Winsock (carried over from the TCP layer).
- `signal(SIGPIPE, SIG_IGN)` so `SSL_write`/`SSL_shutdown` against a
  half-closed peer doesn't kill the process. Without this you get baffling
  test failures that look like "process disappeared mid-handshake."
- `OPENSSL_init_ssl(...)` is a no-op on subsequent calls (3.x is
  ref-counted) but surfaces init errors at startup rather than deep inside
  some unrelated `TLSSocket` ctor.

`SocketPlatform::init()` is idempotent — it's gated by a `static
SocketPlatform platform;` so callers can invoke it from every thread or
test fixture without coordination.

---

## 4. Building the `SSL_CTX` (the cache)

Each TLS connection needs an `SSL*`, and each `SSL*` is created from an
`SSL_CTX*`. Building a fresh `SSL_CTX` for every connection is expensive
(~30 ms — OS file I/O for the trust store, etc.). For a process that opens
many TLS connections (e.g., an HTTPS client) we want one `SSL_CTX` per
*equivalence class of `TlsConfig`* and reuse it.

[`src/tls_internal.cpp`](../src/tls_internal.cpp) keeps a process-wide
hash map keyed on the parts of `TlsConfig` that affect the context:

```cpp
struct CtxKey {
    ETlsRole role;
    bool verify_peer, verify_hostname;
    stl::string ca_file, ca_dir;
    stl::string client_cert_file, client_key_file;
    stl::string server_cert_file, server_key_file;
    stl::vector<stl::string> alpn;
    TlsConfig::EMinVersion min_version;
    bool operator==(const CtxKey&) const = default;
};

struct CtxEntry {
    SSL_CTX* ctx = nullptr;
    stl::vector<stl::string> alpn;          // stable storage, see §6
    ~CtxEntry() { if (ctx) ::SSL_CTX_free(ctx); }
};

std::mutex g_mu;
std::unordered_map<CtxKey, std::unique_ptr<CtxEntry>, CtxKeyHash> g_cache;
```

`acquire_ctx(cfg)` looks up the key, builds a new `SSL_CTX` on miss, returns
the cached pointer. Callers do **not** `SSL_CTX_free` the result — the cache
owns it and tears it down at process exit.

`build_ctx` is where the OpenSSL setup happens:

```cpp
SSL_CTX* build_ctx(const TlsConfig& cfg, CtxEntry& entry) {
    const SSL_METHOD* method = (cfg.role == ETlsRole::Server)
        ? ::TLS_server_method()
        : ::TLS_client_method();
    SSL_CTX* ctx = ::SSL_CTX_new(method);
    if (ctx == nullptr) return nullptr;

    int min_version = (cfg.min_version == TlsConfig::EMinVersion::TLS_1_3)
        ? TLS1_3_VERSION : TLS1_2_VERSION;
    ::SSL_CTX_set_min_proto_version(ctx, min_version);
    ::SSL_CTX_set_max_early_data(ctx, 0);   // disable 0-RTT replay surface

    if (cfg.role == ETlsRole::Server) { /* see §5 */ }
    else                              { /* see §6 */ }

    return ctx;
}
```

`SSL_CTX_set_max_early_data(ctx, 0)` switches off TLS 1.3 0-RTT — we never
opted into that, and a "quietly enabled" 0-RTT would be a foot-gun for
replay-sensitive request paths.

---

## 5. Server-mode `SSL_CTX`: cert + key + ALPN

For `ETlsRole::Server`, `build_ctx` loads the server certificate chain and
private key, then registers the ALPN-select callback:

```cpp
if (cfg.server_cert_file.empty() || cfg.server_key_file.empty()) {
    ::SSL_CTX_free(ctx);
    return nullptr;                          // mis-configured
}
if (::SSL_CTX_use_certificate_chain_file(ctx, cfg.server_cert_file.c_str()) != 1
 || ::SSL_CTX_use_PrivateKey_file       (ctx, cfg.server_key_file.c_str(),  SSL_FILETYPE_PEM) != 1
 || ::SSL_CTX_check_private_key         (ctx) != 1) {
    ::SSL_CTX_free(ctx);
    return nullptr;
}
if (!entry.alpn.empty())
    ::SSL_CTX_set_alpn_select_cb(ctx, server_alpn_select_cb, &entry.alpn);
```

`SSL_CTX_check_private_key` catches "the cert and key don't match" at config
time rather than at handshake time, which makes operator errors visible
much earlier.

The ALPN select callback walks the client's offer list and returns the
server's first preference that the client also offered:

```cpp
extern "C" int server_alpn_select_cb(SSL*, const unsigned char** out,
                                     unsigned char* outlen,
                                     const unsigned char* in, unsigned int inlen,
                                     void* arg) {
    const auto* server_alpn = static_cast<const stl::vector<stl::string>*>(arg);
    for (const auto& proto : *server_alpn) {
        for (unsigned int i = 0; i < inlen;) {
            unsigned int len = in[i];
            if (i + 1u + len > inlen) break;
            if (len == proto.size() &&
                std::memcmp(in + i + 1, proto.data(), len) == 0) {
                *out = in + i + 1;
                *outlen = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }
            i += 1u + len;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
}
```

The ALPN list lives in `CtxEntry::alpn`, not in the original `TlsConfig`,
so its address is stable for as long as the `SSL_CTX` is in the cache —
which is what OpenSSL needs for the `void* arg` it stores in the context.

---

## 6. Client-mode `SSL_CTX`: trust store + ALPN

For `ETlsRole::Client`, `build_ctx`:

```cpp
::SSL_CTX_set_verify(ctx,
    cfg.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
    nullptr);

if (!cfg.ca_file.empty()) {
    ::SSL_CTX_load_verify_locations(ctx, cfg.ca_file.c_str(), nullptr);
} else if (!cfg.ca_dir.empty()) {
    ::SSL_CTX_load_verify_locations(ctx, nullptr, cfg.ca_dir.c_str());
} else {
#ifdef _WIN32
    load_system_trust_store(ctx);            // tls_trust_store_windows.cpp
#else
    ::SSL_CTX_set_default_verify_paths(ctx); // /etc/ssl/certs etc.
#endif
}

if (!cfg.client_cert_file.empty() && !cfg.client_key_file.empty()) {
    ::SSL_CTX_use_certificate_chain_file(ctx, cfg.client_cert_file.c_str());
    ::SSL_CTX_use_PrivateKey_file       (ctx, cfg.client_key_file.c_str(),
                                         SSL_FILETYPE_PEM);
}
```

The Windows path is the gnarly bit. OpenSSL's `set_default_verify_paths`
does the right thing on Linux (it finds `/etc/ssl/certs/...`) but on
Windows it points at paths baked in at build time (e.g.
`C:\Program Files\OpenSSL\ssl\...`) that usually don't exist. So
[`tls_trust_store_windows.cpp`](../src/tls_trust_store_windows.cpp) walks
the Windows `ROOT` cert store via `CertOpenSystemStoreW` and pushes each
cert into the OpenSSL `X509_STORE`:

```cpp
int load_system_trust_store(SSL_CTX* ctx) {
    HCERTSTORE store = ::CertOpenSystemStoreW(0, L"ROOT");
    if (store == nullptr) return 0;

    X509_STORE* x509_store = ::SSL_CTX_get_cert_store(ctx);
    int added = 0;
    PCCERT_CONTEXT cert = nullptr;
    while ((cert = ::CertEnumCertificatesInStore(store, cert)) != nullptr) {
        const unsigned char* der = cert->pbCertEncoded;
        X509* x = ::d2i_X509(nullptr, &der,
                             static_cast<long>(cert->cbCertEncoded));
        if (x != nullptr) {
            if (::X509_STORE_add_cert(x509_store, x) == 1) ++added;
            ::X509_free(x);
        }
    }
    ::CertCloseStore(store, 0);
    return added;
}
```

Client ALPN is set per-connection rather than on the `SSL_CTX` (see §8) —
the wire-format encoding is shared with `encode_alpn` in the same file.

---

## 7. Constructing the socket

The public ctor is small — it just constructs the underlying TCP socket from
the TLS config's `tcp` field. No SSL state yet; that's lazy until `connect`
or `accept`:

```cpp
TLSSocket::TLSSocket(TlsConfig config)
    : m_config(std::move(config))
    , m_tcp(m_config.tcp) {}
```

The private ctor used by `accept()` takes a freshly-accepted `TCPSocket`
plus its `SSL*`:

```cpp
TLSSocket::TLSSocket(TCPSocket tcp, ssl_st* ssl, TlsConfig config)
    : m_config(std::move(config))
    , m_tcp(std::move(tcp))
    , m_ssl(ssl) {}
```

The move ops follow the same shape as `TCPSocket`'s — null the source's
`m_ssl` so the destructor doesn't double-free, and close the existing
state on move-assign before stealing:

```cpp
TLSSocket& TLSSocket::operator=(TLSSocket&& other) noexcept {
    if (this == &other) return *this;
    close();                                 // releases existing SSL + TCP
    m_config           = std::move(other.m_config);
    m_tcp              = std::move(other.m_tcp);
    m_ssl              = other.m_ssl;
    other.m_ssl        = nullptr;
    m_handshake_error  = std::move(other.m_handshake_error);
    return *this;
}
```

---

## 8. The client handshake: `connect()`

```cpp
bool TLSSocket::connect() {
    m_handshake_error.clear();

    SSL_CTX* ctx = acquire_ctx(m_config);
    if (ctx == nullptr) {
        m_handshake_error = "SSL_CTX build failed: " + drain_ssl_errors();
        return false;
    }

    if (!m_tcp.connect()) {
        m_handshake_error = "TCP connect failed";
        return false;
    }

    m_ssl = ::SSL_new(ctx);
    if (m_ssl == nullptr) {
        m_handshake_error = "SSL_new failed: " + drain_ssl_errors();
        return false;
    }

    ::SSL_set_fd(m_ssl, static_cast<int>(m_tcp.native_handle()));

    // SNI + hostname verification.
    const stl::string& host = m_config.sni_hostname.empty()
        ? m_config.tcp.host
        : m_config.sni_hostname;
    if (!host.empty()) {
        ::SSL_set_tlsext_host_name(m_ssl, host.c_str());
        if (m_config.verify_hostname)
            ::SSL_set1_host(m_ssl, host.c_str());
    }

    // Client ALPN — encoded as length-prefixed octet string.
    if (!m_config.alpn_protocols.empty()) {
        stl::vector<unsigned char> wire;
        for (const auto& p : m_config.alpn_protocols) {
            wire.push_back(static_cast<unsigned char>(p.size()));
            wire.insert(wire.end(), p.begin(), p.end());
        }
        ::SSL_set_alpn_protos(m_ssl, wire.data(),
                              static_cast<unsigned int>(wire.size()));
    }

    if (::SSL_connect(m_ssl) != 1) {
        m_handshake_error = format_handshake_error("SSL_connect", m_ssl);
        return false;
    }
    return true;
}
```

Things worth noticing:

- **Two distinct hostname knobs.** `SSL_set_tlsext_host_name` is the SNI
  field in ClientHello (what the *server* uses to pick which cert to serve).
  `SSL_set1_host` is the hostname OpenSSL checks against the cert's SAN/CN
  during verification. Both must agree, but they're separate calls.
- **`SSL_set_fd(int)` and a `uintptr_t` handle.** On Windows, `SocketHandle`
  is `uintptr_t` (the underlying type of `SOCKET`) but `SSL_set_fd` takes
  an `int`. The cast truncates the high bits; in practice every Windows
  socket handle returned by `socket()`/`accept()` fits in 32 bits, and
  OpenSSL's BSS layer reverses the cast when it calls `recv`/`send`. This
  is the same approach OpenSSL itself takes; if it ever bites, the fix is
  `BIO_new_socket` + `SSL_set_bio`.
- **All OpenSSL error reporting funnels through `drain_ssl_errors()`** and
  lands in `m_handshake_error` for the caller to inspect:

  ```cpp
  stl::string drain_ssl_errors() {
      stl::string out;
      char buf[256];
      unsigned long err;
      while ((err = ::ERR_get_error()) != 0) {
          ::ERR_error_string_n(err, buf, sizeof(buf));
          if (!out.empty()) out += "; ";
          out += buf;
      }
      return out.empty() ? stl::string{"<no openssl error>"} : out;
  }
  ```

  The function is required to *clear* the thread's queue before returning —
  otherwise stale errors from an earlier call show up in the next one.

`format_handshake_error` adds a verify-result string when the queue is
about cert verification, so messages like
`SSL_connect failed (verify 10: certificate has expired): ...` get
surfaced verbatim through `handshake_error()`. That's the substring real
operators grep for in incidents.

---

## 9. The server handshake: `accept()`

```cpp
stl::result<TLSSocket> TLSSocket::accept() {
    auto tcp_result = m_tcp.accept();
    if (!tcp_result)
        return stl::make_error<TLSSocket>("TCP accept failed: {}",
                                          tcp_result.error());

    SSL_CTX* ctx = acquire_ctx(m_config);
    if (ctx == nullptr)
        return stl::make_error<TLSSocket>("SSL_CTX build failed: {}",
                                          drain_ssl_errors());

    SSL* ssl = ::SSL_new(ctx);
    if (ssl == nullptr)
        return stl::make_error<TLSSocket>("SSL_new failed: {}",
                                          drain_ssl_errors());

    TCPSocket accepted = std::move(tcp_result.value());
    ::SSL_set_fd(ssl, static_cast<int>(accepted.native_handle()));

    if (::SSL_accept(ssl) != 1) {
        stl::string err = format_handshake_error("SSL_accept", ssl);
        ::SSL_free(ssl);
        return stl::make_error<TLSSocket>("{}", err);
    }

    return TLSSocket(std::move(accepted), ssl, m_config);
}
```

The shape mirrors `TCPSocket::accept` — one `stl::result<TLSSocket>` either
way. The new `TLSSocket` is built via the private 3-arg constructor and
inherits the listener's `TlsConfig` (so it picks up the same cert paths,
ALPN list, etc., and shares the same cached `SSL_CTX`).

---

## 10. Sending and receiving data

`send` and `recv` are the most boring part of the file — they map straight
to `SSL_write` / `SSL_read` plus error fan-out into `stl::result<size_t>`:

```cpp
stl::result<size_t> TLSSocket::send(stl::span<const stl::byte> data) {
    if (m_ssl == nullptr)
        return stl::make_error<size_t>("TLS send: handshake not complete");

    int n = ::SSL_write(m_ssl, data.data(), static_cast<int>(data.size()));
    if (n <= 0) {
        int err = ::SSL_get_error(m_ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN)
            return static_cast<size_t>(0);
        return stl::make_error<size_t>(
            "SSL_write failed: {}", drain_ssl_errors());
    }

#ifdef SAP_TLS_WIRE_LOGGING
    if (m_config.wire_log)
        m_config.wire_log(TlsConfig::EWireDirection::Send,
                          data.first(static_cast<size_t>(n)));
#endif
    return static_cast<size_t>(n);
}
```

`recv` is identical in shape but with one extra branch for the
"peer disappeared without close_notify" case:

```cpp
int n = ::SSL_read(m_ssl, data.data(), static_cast<int>(data.size()));
if (n <= 0) {
    int err = ::SSL_get_error(m_ssl, n);
    // Treat both clean (close_notify) and unclean (peer dropped TCP without
    // close_notify) shutdowns as EOF — matches plain TCP recv(), which
    // returns 0 in both cases.
    if (err == SSL_ERROR_ZERO_RETURN)
        return static_cast<size_t>(0);
    if (err == SSL_ERROR_SYSCALL && n == 0) {
        ::ERR_clear_error();
        return static_cast<size_t>(0);
    }
    return stl::make_error<size_t>(
        "SSL_read failed: {}", drain_ssl_errors());
}
```

Without that second branch, a peer that ungracefully drops the TCP
connection (e.g., `close()` without `SSL_shutdown`) shows up as
`SSL_ERROR_SYSCALL` rather than `SSL_ERROR_ZERO_RETURN`, and naive recv
loops break early. We unify the two so callers can write idiomatic
"loop until recv returns 0" code that works against any peer.

The `wire_log` hook fires *after* a successful read/write, with the bytes
actually transferred. It only exists when `SAP_TLS_WIRE_LOGGING` is defined
(see §12).

---

## 11. Closing — the bidirectional shutdown trap

This is the interesting bit, and where a naive implementation will silently
lose your data.

```cpp
void TLSSocket::close() {
    if (m_ssl != nullptr) {
        // Bidirectional shutdown: SSL_shutdown returns 0 when our
        // close_notify has been sent but we haven't seen the peer's yet.
        // Calling it a second time blocks reading the peer's close_notify
        // (and incidentally discarding any data still in flight from the
        // peer). Without this second call, our close races with the peer's
        // recv loop and data we previously committed via SSL_write can be
        // lost when shutdown(SHUT_RDWR) tears down TCP.
        //
        // Cap the wait so a vanished peer can't make close() hang.
        int r = ::SSL_shutdown(m_ssl);
        if (r == 0) {
            m_tcp.set_recv_timeout(std::chrono::milliseconds{500});
            ::SSL_shutdown(m_ssl);
        }
        ::ERR_clear_error();
        ::SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    m_tcp.close();
}
```

What's actually going on:

1. `SSL_shutdown` writes our close_notify alert. It returns:
   - `1` — clean: we already saw the peer's close_notify too, full
     bidirectional shutdown is done.
   - `0` — half-done: we sent ours, haven't seen theirs yet.
   - `-1` — error.

2. After step 1 returns `0`, the obvious thing is to stop. **Don't** —
   this is where data loss creeps in. Here's the failure mode:
   - Client `SSL_write(256 KB)` returns 256 KB (everything is in the
     kernel's TCP send buffer / on the wire / in the server's TCP recv
     buffer).
   - Client calls `close()`. Single-call `SSL_shutdown` writes close_notify
     into TCP and returns immediately.
   - Client's `m_tcp.close()` runs `shutdown(SHUT_RDWR)` then `close()`.
     The kernel queues a FIN.
   - On most kernels this *should* still deliver the queued data. In
     practice, when the server is mid-`SSL_read` against a partial record
     and the FIN reaches its BIO before all encrypted bytes are decrypted,
     `SSL_read` returns `SSL_ERROR_SYSCALL` mid-stream. Recv loop breaks.
     A chunk of bytes near the tail of the stream is lost.

3. The fix is the second `SSL_shutdown` call. It internally does an
   `SSL_read` waiting for the peer's close_notify. The peer can only send
   close_notify after it has read all our data and itself called
   `SSL_shutdown` (which it does inside its own `close()`). So by the
   time the second shutdown returns, we know the peer drained.

4. The 500 ms recv timeout is a circuit breaker. A peer that vanished
   (network partition, process killed) will never send close_notify, and
   without the timeout `close()` would block forever. 500 ms is generous
   for an in-process loopback test and unobjectionable for real network
   teardown.

The regression test is
[`TLSSocketTest.CloseImmediatelyAfterSendDeliversAllBytes`][test-close-race]
in `tests/test_tls_socket.cpp`. It wires a slow-drip server (1 KB chunks
with 1 ms pauses) so the close-race window is wide, then has the client
bulk-write 64 KB and call `close()` with no application-level ack. With
the second `SSL_shutdown` removed, that test fails by ~1.5 KB to ~100 KB
(it varies — that's the smoking gun for a timing race rather than a
deterministic bug).

[test-close-race]: ../tests/test_tls_socket.cpp

---

## 12. Wire logging in Debug builds

Debugging encrypted protocols is miserable. `TlsConfig::wire_log` exists to
make it less so:

```cpp
#ifdef SAP_TLS_WIRE_LOGGING
    enum class EWireDirection { Send, Recv };
    std::function<void(EWireDirection, stl::span<const stl::byte>)> wire_log;
#endif
```

Gated by `SAP_TLS_WIRE_LOGGING`, which the CMake build sets on Debug
configurations and as an explicit option:

```cmake
target_compile_definitions(sap_network_lib
    PUBLIC
        $<$<OR:$<CONFIG:Debug>,$<BOOL:${SAP_TLS_WIRE_LOGGING}>>:SAP_TLS_WIRE_LOGGING>
)
```

The compile-definition is **PUBLIC** intentionally — `sap_http` and other
consumers must agree with `sap_network` on whether `TlsConfig` has a
`wire_log` member, or you get a silent ODR violation that explodes only at
link time on a different machine.

When the macro is defined, `send` and `recv` invoke the hook on each
*successful* call with the decrypted plaintext that crossed the boundary:

```cpp
#ifdef SAP_TLS_WIRE_LOGGING
    if (m_config.wire_log)
        m_config.wire_log(TlsConfig::EWireDirection::Send,
                          data.first(static_cast<size_t>(n)));
#endif
```

A `wire_log` that writes to disk will spill production credentials onto
disk. Don't do that. The "off by default" + Debug-only gating is the
guard rail.

---

## 13. Putting it together — a minimal client

```cpp
#include "sap_network/platform.h"
#include "sap_network/tls_socket.h"

using namespace sap::network;

int main() {
    SocketPlatform::init();

    TLSSocket sock({
        .tcp             = {.host = "example.com", .port = 443,
                             .connect_timeout = std::chrono::seconds{2}},
        .verify_peer     = true,
        .verify_hostname = true,
        .alpn_protocols  = {"http/1.1"},
    });

    if (!sock.connect()) {
        std::println("handshake failed: {}", sock.handshake_error());
        return 1;
    }

    std::string_view req = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    sock.send({reinterpret_cast<const stl::byte*>(req.data()), req.size()});

    std::array<stl::byte, 8192> buf;
    while (auto r = sock.recv(buf)) {
        if (r.value() == 0) break;          // EOF
        std::cout.write(reinterpret_cast<const char*>(buf.data()),
                        r.value());
    }
    sock.close();                            // bidirectional shutdown
    return 0;
}
```

…and a minimal server:

```cpp
TLSSocket listener({
    .tcp              = {.port = 8443, .listen_backlog = 16, .reuse_addr = true},
    .role             = ETlsRole::Server,
    .server_cert_file = "/etc/ssl/server.pem",
    .server_key_file  = "/etc/ssl/server.key",
    .alpn_protocols   = {"http/1.1"},
});
listener.bind();
listener.listen();

while (auto r = listener.accept()) {
    auto& peer = r.value();
    // serve...
    peer.close();
}
```

Both compile against the same `Socket<S>` templates as `TCPSocket` thanks
to the concept; the only differences are the `TlsConfig` flags and which
side of the handshake is being initiated.

---

## 14. What this guide doesn't cover

- **Mutual TLS** (`client_cert_file` / `client_key_file`) is wired in the
  context loader but not exercised in tests beyond compile coverage.
  Plug a real client cert and it should work; needs a focused integration
  test.
- **Async I/O.** The whole library is blocking. If async ever lands, the
  shutdown semantics in §11 will need to be re-thought (probably a
  `close_async()` returning a future).
- **OCSP / CRL revocation** is out of scope for the MVP.
- **0-RTT / early data** is explicitly disabled in §4 and we don't intend
  to support it.

For the long-form discussion of those, see
[`.claude/SAP_NETWORK_TLS_PLAN.md`](../.claude/SAP_NETWORK_TLS_PLAN.md).
