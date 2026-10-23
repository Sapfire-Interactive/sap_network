# Bounded synchronous TLS

`TLSSocket` uses nonblocking native sockets internally while exposing synchronous
operations. `SSL_connect`, `SSL_accept`, `SSL_read` and `SSL_write` retry both
`WANT_READ` and `WANT_WRITE` under one steady-clock deadline. Interrupted waits
retain that deadline. Each transfer is capped at 64 KiB and may return fewer
bytes than requested. An I/O timeout or fatal TLS error invalidates the connection;
construct a new socket to retry. Failed handshakes never expose application I/O.

```cpp
using namespace sap::network;
using namespace std::chrono_literals;
SocketPlatform::init();
TlsClientConfig cfg;
cfg.tcp.host = "127.0.0.1"; // Numeric endpoint; no synchronous DNS in a finite operation.
cfg.tcp.port = 7443;
cfg.tcp.connect_timeout = 5s;
cfg.tcp.recv_timeout = 5s;
cfg.tcp.send_timeout = 5s;
cfg.sni_hostname = "localhost"; // Certificate identity independent of the endpoint.
cfg.ca_file = "test-ca.pem";
cfg.min_version = ETlsMinVersion::TLS_1_3;
cfg.alpn_protocols = {"svc/3"};
TLSSocket socket(std::move(cfg));
if (!socket.connect() || socket.negotiated_protocol() != "svc/3")
    return; // No application bytes before both checks succeed.
const Deadline deadline = deadline_after(5s);
// Reuse deadline for every short read of a frame's header AND payload:
// socket.recv_until(remaining_bytes, deadline);
```

`connect()` derives a deadline from `tcp.connect_timeout`, shared by TCP connect
and the TLS handshake. `send()` and `recv()` derive deadlines from their respective
timeouts. `connect_until`, `send_until`, and `recv_until` take an absolute deadline
so callers can bound a larger operation without restarting the budget on every
short transfer. Zero configuration timeouts preserve unbounded behavior.
Negative timeouts are invalid. Empty transfers on established connections succeed
with zero bytes without invoking OpenSSL.

`accept()` waits for a connection without a deadline, then bounds its handshake
with `connect_timeout`, falling back to `recv_timeout`. `accept_until(deadline)`
bounds the combined wait and handshake. Only one operation may run on each socket
at a time, including the listener; callers must bound worker/connection counts.
`close()` gives bidirectional TLS shutdown one 500 ms budget. Fatal or timed-out
operations free TLS directly, avoiding an unsafe shutdown after incomplete writes.

## Resolution and scope

Finite synchronous connections **require a numeric IPv4 `tcp.host`**. A DNS name
fails immediately instead of entering blocking `getaddrinfo`. Use `sni_hostname`
for the independent DNS certificate identity. This is an intentional compatibility
change for callers that previously supplied a DNS name and a finite timeout.
There is no resolver thread pool, abandoned DNS work, or hidden fallback to an
unbounded call. The existing zero-timeout connection path still supports blocking
DNS and attempts up to 16 returned IPv4 addresses. IPv6 network endpoints and
deadline-aware DNS resolution remain unsupported.

Deadlines bound peer-driven network waits, not OS scheduling, context-cache lock
acquisition or loading local certificate/trust files. Configure trusted local
certificate paths and provision the TLS context before serving remote clients.
The coroutine APIs retain their existing cancellation contract; they share the
TLS setup validation but do not gain these synchronous deadline guarantees.

## Verification and setup

- Trust-store, certificate/key, protocol-version, ALPN, identity and socket setup
  failures fail closed. A partial or mismatched client certificate/key pair fails.
- DNS identities use hostname verification and SNI. Numeric IPv4/IPv6 identities
  use `X509_VERIFY_PARAM_set1_ip_asc` and omit SNI. Empty verified identities and
  embedded NULs are rejected. Hostname verification requires peer verification.
- Socket attachment checks the return from `SSL_set_fd` and rejects handles that
  cannot fit its `int` parameter, including oversized Windows `SOCKET` values.
- Windows `SO_RCVTIMEO`/`SO_SNDTIMEO` use DWORD milliseconds. Client TCP sockets
  apply configured timeouts immediately; accepted sockets check setup failures.
- Mutual TLS works with a TLS 1.3 minimum. Server `accept()` is authoritative for
  client-certificate rejection; TLS 1.3 clients may see the alert on their next I/O.
- ALPN is optional in this general-purpose library. An absent common protocol is
  reported as an empty `negotiated_protocol()`; applications requiring a protocol
  must reject it before sending application bytes.
- Plaintext wire callbacks are disabled in Debug and Release by default. Enabling
  `SAP_TLS_WIRE_LOGGING=ON` is an explicit opt-in affecting library and consumer ABI.

The implementation follows OpenSSL's [nonblocking TLS guidance](https://docs.openssl.org/3.3/man7/ossl-guide-tls-client-non-block/)
and [socket attachment contract](https://docs.openssl.org/3.1/man3/SSL_set_fd/),
and Microsoft's [socket timeout types](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-setsockopt).

Regression tests cover slow partial handshakes, slow encrypted records, repeated
reads sharing a deadline, backpressured writes, listener/accepted-handshake
timeouts, bounded shutdown, native Windows timeouts, invalid setup, IP/SNI
handling, expired/wrong-IP certificates, TLS 1.2 rejection, ALPN absence/mismatch,
and TLS 1.3 mutual authentication alongside the existing TCP/UDP/TLS suites.

Validated on Windows x64 with MSVC 19.44 and the installed OpenSSL 4.0.1:
97/97 tests passed in Debug and Release, with the final hostname-verification
change additionally checked by all 45 synchronous TLS tests in Debug. Wire
logging was disabled in both generated builds. OpenSSL 3 and POSIX were not
executed in this environment.
