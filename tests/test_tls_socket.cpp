#include <gtest/gtest.h>

#include "sap_network/platform.h"
#include "sap_network/socket_concept.h"
#include "sap_network/tls_socket.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <future>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace sap::network;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

// Each test owns a distinct port so a half-cleaned-up TIME_WAIT from a previous
// run never bleeds into the next one.
static constexpr u16 TLS_PORT_BIND      = 19300;
static constexpr u16 TLS_PORT_HANDSHAKE = 19301;
static constexpr u16 TLS_PORT_ECHO      = 19302;
static constexpr u16 TLS_PORT_LARGE     = 19303;
static constexpr u16 TLS_PORT_ALPN      = 19304;
static constexpr u16 TLS_PORT_VERIFY    = 19305;
static constexpr u16 TLS_PORT_CIPHER    = 19306;
static constexpr u16 TLS_PORT_VERSION   = 19307;
static constexpr u16 TLS_PORT_NOCERT    = 19308;
static constexpr u16 TLS_PORT_BAD_PROTO = 19309;
static constexpr u16 TLS_PORT_HOSTNAME  = 19310;
static constexpr u16 TLS_PORT_WIRELOG   = 19311;
static constexpr u16 TLS_PORT_CONCEPT   = 19312;
static constexpr u16 TLS_PORT_REUSE     = 19313;
static constexpr u16 TLS_PORT_CLOSE_RACE = 19314;

// ---------------------------------------------------------------------------
// Concept compile-time check
// ---------------------------------------------------------------------------

static_assert(Socket<TLSSocket>);

// ---------------------------------------------------------------------------
// Self-signed cert helper
// ---------------------------------------------------------------------------

class SelfSignedCert {
public:
    SelfSignedCert() {
        // Per-instance temp dir to keep parallel runs isolated.
        std::random_device rd;
        m_dir = fs::temp_directory_path() / fs::path{"sap_tls_test_" + std::to_string(rd())};
        fs::create_directories(m_dir);
        cert_file = (m_dir / "cert.pem").string();
        key_file  = (m_dir / "key.pem").string();
        generate();
    }

    ~SelfSignedCert() {
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }

    SelfSignedCert(const SelfSignedCert&) = delete;
    SelfSignedCert& operator=(const SelfSignedCert&) = delete;

    std::string cert_file;
    std::string key_file;

private:
    void generate() {
        EVP_PKEY* pkey = ::EVP_RSA_gen(2048);
        ASSERT_NE(pkey, nullptr);

        X509* x509 = ::X509_new();
        ASSERT_NE(x509, nullptr);

        ::ASN1_INTEGER_set(::X509_get_serialNumber(x509), 1);
        ::X509_gmtime_adj(::X509_getm_notBefore(x509), 0);
        ::X509_gmtime_adj(::X509_getm_notAfter(x509), 31536000L); // 1 year
        ::X509_set_pubkey(x509, pkey);

        X509_NAME* name = ::X509_get_subject_name(x509);
        ::X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
        ::X509_set_issuer_name(x509, name);

        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx); // macro — must not be qualified with ::
        ::X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
        if (X509_EXTENSION* ext = ::X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1")) {
            ::X509_add_ext(x509, ext, -1);
            ::X509_EXTENSION_free(ext);
        }

        ::X509_sign(x509, pkey, ::EVP_sha256());

        FILE* fp = std::fopen(cert_file.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        ::PEM_write_X509(fp, x509);
        std::fclose(fp);

        fp = std::fopen(key_file.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        ::PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(fp);

        ::X509_free(x509);
        ::EVP_PKEY_free(pkey);
    }

    fs::path m_dir;
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class TLSSocketTest : public ::testing::Test {
protected:
    void SetUp() override { SocketPlatform::init(); }
};

// Shorthand to fire up a loopback TLS server in a thread that runs `body`
// against the first accepted client. Joining is the caller's job.
template <typename Body>
static std::thread spawn_loopback_server(TLSSocket& server, Body body) {
    return std::thread{[&server, body = std::move(body)] {
        auto r = server.accept();
        if (!r)
            return;
        body(r.value());
    }};
}

// ---------------------------------------------------------------------------
// Construction / lifecycle
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, ClientConstructionProducesValidTcp) {
    TLSSocket sock({.tcp = {.host = "127.0.0.1", .port = TLS_PORT_BIND}});
    EXPECT_TRUE(sock.valid());
}

TEST_F(TLSSocketTest, ServerConstructionProducesValidTcp) {
    SelfSignedCert cert;
    TLSSocket sock({.tcp              = {.port = TLS_PORT_BIND, .reuse_addr = true},
                    .role             = ETlsRole::Server,
                    .server_cert_file = cert.cert_file,
                    .server_key_file  = cert.key_file});
    EXPECT_TRUE(sock.valid());
}

TEST_F(TLSSocketTest, CloseInvalidates) {
    TLSSocket sock({.tcp = {.port = TLS_PORT_BIND}});
    sock.close();
    EXPECT_FALSE(sock.valid());
}

TEST_F(TLSSocketTest, DoubleCloseIsSafe) {
    TLSSocket sock({.tcp = {.port = TLS_PORT_BIND}});
    sock.close();
    EXPECT_NO_FATAL_FAILURE(sock.close());
    EXPECT_FALSE(sock.valid());
}

TEST_F(TLSSocketTest, DestructorCleansUp) {
    { TLSSocket sock({.tcp = {.port = TLS_PORT_BIND}}); }
}

TEST_F(TLSSocketTest, MoveConstructionTransfersOwnership) {
    TLSSocket a({.tcp = {.port = TLS_PORT_BIND}});
    ASSERT_TRUE(a.valid());
    TLSSocket b(std::move(a));
    EXPECT_TRUE(b.valid());
    EXPECT_FALSE(a.valid());
}

TEST_F(TLSSocketTest, MoveAssignmentTransfersOwnership) {
    TLSSocket a({.tcp = {.port = TLS_PORT_BIND}});
    TLSSocket b({.tcp = {.port = static_cast<u16>(TLS_PORT_BIND + 1)}});
    b = std::move(a);
    EXPECT_TRUE(b.valid());
    EXPECT_FALSE(a.valid());
}

TEST_F(TLSSocketTest, MoveAssignmentClosesOldHandle) {
    TLSSocket a({.tcp = {.port = TLS_PORT_REUSE, .reuse_addr = true}});
    TLSSocket b({.tcp = {.port = TLS_PORT_REUSE, .reuse_addr = true}});
    // a's TCP fd is alive; move-assign should close it before taking b's.
    a = std::move(b);
    EXPECT_TRUE(a.valid());
    EXPECT_FALSE(b.valid());
}

// ---------------------------------------------------------------------------
// Send/recv before handshake completes — must error, never crash
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, SendBeforeHandshakeFails) {
    TLSSocket sock({.tcp = {.host = "127.0.0.1", .port = 19999}});
    std::vector<std::byte> buf{std::byte{1}, std::byte{2}};
    auto r = sock.send(buf);
    EXPECT_FALSE(r);
    EXPECT_NE(r.error().find("handshake not complete"), std::string::npos);
}

TEST_F(TLSSocketTest, RecvBeforeHandshakeFails) {
    TLSSocket sock({.tcp = {.host = "127.0.0.1", .port = 19999}});
    std::vector<std::byte> buf(16);
    auto r = sock.recv(buf);
    EXPECT_FALSE(r);
    EXPECT_NE(r.error().find("handshake not complete"), std::string::npos);
}

// ---------------------------------------------------------------------------
// Send/recv on closed socket
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, SendOnClosedSocketFails) {
    TLSSocket sock({.tcp = {.port = TLS_PORT_BIND}});
    sock.close();
    std::vector<std::byte> buf{std::byte{1}, std::byte{2}};
    EXPECT_FALSE(sock.send(buf));
}

TEST_F(TLSSocketTest, RecvOnClosedSocketFails) {
    TLSSocket sock({.tcp = {.port = TLS_PORT_BIND}});
    sock.close();
    std::vector<std::byte> buf(16);
    EXPECT_FALSE(sock.recv(buf));
}

// ---------------------------------------------------------------------------
// Connect failure cases
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, ConnectToClosedPortFails) {
    TLSSocket sock(
        {.tcp = {.host = "127.0.0.1", .port = 19998, .connect_timeout = 200ms}, .verify_peer = false, .verify_hostname = false});
    EXPECT_FALSE(sock.connect());
    EXPECT_FALSE(sock.handshake_error().empty());
}

TEST_F(TLSSocketTest, ServerWithoutCertFailsAtAccept) {
    // Server has role=Server but no server_cert_file/key. acquire_ctx returns
    // nullptr; accept() must report this rather than dispatching SSL_accept.
    TLSSocket server({.tcp  = {.port = TLS_PORT_NOCERT, .listen_backlog = 1, .reuse_addr = true},
                      .role = ETlsRole::Server});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<bool> got_error;
    std::thread server_thread([&] {
        auto r = server.accept();
        got_error.set_value(!r);
    });

    // Trigger a connection so the server's accept() unblocks. We don't care
    // whether the client handshake succeeds.
    TLSSocket client({.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_NOCERT, .connect_timeout = 500ms},
                      .verify_peer     = false,
                      .verify_hostname = false});
    client.connect();

    server_thread.join();
    EXPECT_TRUE(got_error.get_future().get());
}

TEST_F(TLSSocketTest, ConnectToPlainTcpServerFails) {
    // Stand up a plain TCP listener that closes connections immediately.
    // SSL_connect against it must fail cleanly with a non-empty error string.
    TCPSocket plain_server({.port = TLS_PORT_BAD_PROTO, .listen_backlog = 1, .reuse_addr = true});
    ASSERT_TRUE(plain_server.bind());
    ASSERT_TRUE(plain_server.listen());

    std::thread server_thread([&] {
        auto r = plain_server.accept();
        if (r)
            r.value().close(); // FIN immediately, no TLS bytes
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client({.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_BAD_PROTO, .connect_timeout = 1000ms},
                      .verify_peer     = false,
                      .verify_hostname = false});
    EXPECT_FALSE(client.connect());
    EXPECT_FALSE(client.handshake_error().empty());

    server_thread.join();
}

// ---------------------------------------------------------------------------
// Bind / listen / accept negative case
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, AcceptOnNonListeningSocketFails) {
    SelfSignedCert cert;
    TLSSocket server({.tcp              = {.port = TLS_PORT_BIND, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    auto r = server.accept();
    EXPECT_FALSE(r);
}

// ---------------------------------------------------------------------------
// Loopback round-trip — the happy path
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, ClientServerRoundTrip) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_HANDSHAKE, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<bool> server_ok;
    auto server_thread = spawn_loopback_server(server, [&](TLSSocket& peer) {
        std::vector<std::byte> buf(256);
        auto recvd = peer.recv(buf);
        if (!recvd || recvd.value() == 0) {
            server_ok.set_value(false);
            return;
        }
        peer.send({buf.data(), recvd.value()});
        server_ok.set_value(true);
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client(
        {.tcp = {.host = "127.0.0.1", .port = TLS_PORT_HANDSHAKE}, .verify_peer = false, .verify_hostname = false});
    ASSERT_TRUE(client.connect()) << client.handshake_error();

    const std::string payload = "Hello, TLS!";
    std::vector<std::byte> sbuf(payload.size());
    std::memcpy(sbuf.data(), payload.data(), payload.size());
    auto sent = client.send(sbuf);
    ASSERT_TRUE(sent);
    EXPECT_EQ(sent.value(), payload.size());

    std::vector<std::byte> rbuf(256);
    auto received = client.recv(rbuf);
    ASSERT_TRUE(received);
    ASSERT_EQ(received.value(), payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(rbuf.data()), received.value()), payload);

    client.close();
    server_thread.join();
    EXPECT_TRUE(server_ok.get_future().get());
}

// ---------------------------------------------------------------------------
// Cert verification — self-signed must fail when verify_peer=true
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, SelfSignedFailsWhenVerifyPeerIsOn) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_VERIFY, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::thread server_thread([&] { (void)server.accept(); }); // expected to fail; we only care it doesn't hang

    std::this_thread::sleep_for(50ms);

    TLSSocket client({.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_VERIFY, .connect_timeout = 1000ms},
                      .verify_peer     = true,
                      .verify_hostname = false});
    EXPECT_FALSE(client.connect());
    // OpenSSL surfaces "self-signed" / "self signed" verbatim; either spelling
    // is acceptable across versions.
    const auto& err = client.handshake_error();
    EXPECT_FALSE(err.empty());

    server_thread.join();
}

// ---------------------------------------------------------------------------
// Hostname verification — wrong hostname against a localhost cert fails
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, HostnameMismatchFails) {
    SelfSignedCert cert;

    // Cert has SAN=localhost,127.0.0.1. We connect to 127.0.0.1 but tell the
    // verifier to check for "wrong.example" — must fail.
    TLSSocket server({.tcp              = {.port = TLS_PORT_HOSTNAME, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::thread server_thread([&] { (void)server.accept(); });

    std::this_thread::sleep_for(50ms);

    TLSSocket client({.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_HOSTNAME, .connect_timeout = 1000ms},
                      .sni_hostname    = "wrong.example",
                      .verify_peer     = false, // skip CA chain check; isolate the hostname check
                      .verify_hostname = true,
                      .ca_file         = cert.cert_file}); // trust the self-signed root for hostname-only test
    // verify_peer=false but verify_hostname=true would normally still pass
    // because OpenSSL only enforces hostname when verify_peer is on. Force the
    // chain through ca_file + verify_peer to make this a tight check:
    TlsConfig tighter{.tcp              = {.host = "127.0.0.1", .port = TLS_PORT_HOSTNAME, .connect_timeout = 1000ms},
                      .sni_hostname     = "wrong.example",
                      .verify_peer      = true,
                      .verify_hostname  = true,
                      .ca_file          = cert.cert_file};
    TLSSocket strict{tighter};
    EXPECT_FALSE(strict.connect());
    EXPECT_FALSE(strict.handshake_error().empty());

    server_thread.join();
}

// ---------------------------------------------------------------------------
// ALPN — server picks from its preference list given client's offer
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, AlpnNegotiation) {
    SelfSignedCert cert;

    TlsConfig server_cfg{.tcp              = {.port = TLS_PORT_ALPN, .listen_backlog = 1, .reuse_addr = true},
                         .role             = ETlsRole::Server,
                         .server_cert_file = cert.cert_file,
                         .server_key_file  = cert.key_file};
    server_cfg.alpn_protocols.push_back("h2");
    server_cfg.alpn_protocols.push_back("http/1.1");
    TLSSocket server(std::move(server_cfg));
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<std::string> server_proto;
    auto server_thread =
        spawn_loopback_server(server, [&](TLSSocket& peer) { server_proto.set_value(peer.negotiated_protocol()); });

    std::this_thread::sleep_for(50ms);

    TlsConfig client_cfg{.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_ALPN},
                         .verify_peer     = false,
                         .verify_hostname = false};
    // Client offers both; server's first preference (h2) wins.
    client_cfg.alpn_protocols.push_back("http/1.1");
    client_cfg.alpn_protocols.push_back("h2");
    TLSSocket client(std::move(client_cfg));
    ASSERT_TRUE(client.connect()) << client.handshake_error();
    EXPECT_EQ(client.negotiated_protocol(), "h2");

    client.close();
    server_thread.join();
    EXPECT_EQ(server_proto.get_future().get(), "h2");
}

// ---------------------------------------------------------------------------
// Cipher / version / cert introspection
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, IntrospectionPopulatedAfterHandshake) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_CIPHER, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    auto server_thread = spawn_loopback_server(server, [](TLSSocket& peer) {
        std::vector<std::byte> buf(16);
        (void)peer.recv(buf);
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client(
        {.tcp = {.host = "127.0.0.1", .port = TLS_PORT_CIPHER}, .verify_peer = false, .verify_hostname = false});
    ASSERT_TRUE(client.connect()) << client.handshake_error();

    EXPECT_FALSE(client.negotiated_cipher().empty());
    EXPECT_FALSE(client.negotiated_tls_version().empty());
    EXPECT_FALSE(client.peer_cert_subject().empty());
    EXPECT_FALSE(client.peer_cert_issuer().empty());

    client.close();
    server_thread.join();
}

TEST_F(TLSSocketTest, IntrospectionEmptyBeforeHandshake) {
    TLSSocket sock({.tcp = {.host = "127.0.0.1", .port = 19999}});
    EXPECT_TRUE(sock.negotiated_protocol().empty());
    EXPECT_TRUE(sock.negotiated_cipher().empty());
    EXPECT_TRUE(sock.negotiated_tls_version().empty());
    EXPECT_TRUE(sock.peer_cert_subject().empty());
    EXPECT_TRUE(sock.peer_cert_issuer().empty());
}

// ---------------------------------------------------------------------------
// Min version: forced TLS 1.3
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, MinVersionTls13Negotiates) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_VERSION, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file,
                      .min_version      = TlsConfig::EMinVersion::TLS_1_3});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    auto server_thread = spawn_loopback_server(server, [](TLSSocket& peer) {
        std::vector<std::byte> buf(16);
        (void)peer.recv(buf);
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client({.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_VERSION},
                      .verify_peer     = false,
                      .verify_hostname = false,
                      .min_version     = TlsConfig::EMinVersion::TLS_1_3});
    ASSERT_TRUE(client.connect()) << client.handshake_error();
    EXPECT_EQ(client.negotiated_tls_version(), "TLSv1.3");

    client.close();
    server_thread.join();
}

// ---------------------------------------------------------------------------
// Large payload — exercises multiple SSL_write/read cycles
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, LargePayloadRoundTrip) {
    SelfSignedCert cert;

    constexpr size_t DATA_SIZE = 256 * 1024;
    std::vector<std::byte> data(DATA_SIZE);
    for (size_t i = 0; i < DATA_SIZE; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    TLSSocket server({.tcp              = {.port = TLS_PORT_LARGE, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<std::vector<std::byte>> received_promise;
    auto server_thread = spawn_loopback_server(server, [&](TLSSocket& peer) {
        std::vector<std::byte> accumulated;
        std::vector<std::byte> buf(8192);
        while (accumulated.size() < DATA_SIZE) {
            auto r = peer.recv(buf);
            if (!r || r.value() == 0)
                break;
            accumulated.insert(accumulated.end(), buf.begin(), buf.begin() + r.value());
        }
        received_promise.set_value(std::move(accumulated));
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client(
        {.tcp = {.host = "127.0.0.1", .port = TLS_PORT_LARGE}, .verify_peer = false, .verify_hostname = false});
    ASSERT_TRUE(client.connect()) << client.handshake_error();

    size_t total_sent = 0;
    while (total_sent < DATA_SIZE) {
        auto r = client.send({data.data() + total_sent, DATA_SIZE - total_sent});
        ASSERT_TRUE(r);
        ASSERT_GT(r.value(), 0u);
        total_sent += r.value();
    }
    client.close();
    server_thread.join();

    auto received = received_promise.get_future().get();
    ASSERT_EQ(received.size(), DATA_SIZE);
    EXPECT_EQ(received, data);
}

// ---------------------------------------------------------------------------
// Close-race regression: a client that calls close() immediately after
// committing bytes via send() must not lose any of those bytes, even if the
// peer is a slow consumer. This pins the bidirectional SSL_shutdown in
// TLSSocket::close() — without it, the TCP teardown overtakes the server's
// SSL_read loop and we silently drop in-flight records (the symptom that
// originally led to introducing the second SSL_shutdown call).
// ---------------------------------------------------------------------------

TEST_F(TLSSocketTest, CloseImmediatelyAfterSendDeliversAllBytes) {
    SelfSignedCert cert;

    constexpr size_t DATA_SIZE = 64 * 1024;
    std::vector<std::byte> data(DATA_SIZE);
    for (size_t i = 0; i < DATA_SIZE; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    TLSSocket server({.tcp              = {.port = TLS_PORT_CLOSE_RACE, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    // Slow-drip server widens the close-race window: small reads with a
    // tiny pause between each. A correct close() blocks until the peer
    // signals close_notify, so the slow consumer still gets all bytes.
    std::promise<std::vector<std::byte>> received_promise;
    auto server_thread = spawn_loopback_server(server, [&](TLSSocket& peer) {
        std::vector<std::byte> accumulated;
        std::vector<std::byte> buf(1024);
        while (true) {
            auto r = peer.recv(buf);
            if (!r || r.value() == 0)
                break;
            accumulated.insert(accumulated.end(), buf.begin(), buf.begin() + r.value());
            std::this_thread::sleep_for(1ms);
        }
        received_promise.set_value(std::move(accumulated));
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket client(
        {.tcp = {.host = "127.0.0.1", .port = TLS_PORT_CLOSE_RACE}, .verify_peer = false, .verify_hostname = false});
    ASSERT_TRUE(client.connect()) << client.handshake_error();

    // Bulk send, then close immediately — NO application-level ack. The
    // bidirectional SSL_shutdown inside close() is the only thing keeping
    // bytes in flight from being torn down with the TCP connection.
    size_t total_sent = 0;
    while (total_sent < DATA_SIZE) {
        auto r = client.send({data.data() + total_sent, DATA_SIZE - total_sent});
        ASSERT_TRUE(r);
        ASSERT_GT(r.value(), 0u);
        total_sent += r.value();
    }
    client.close();

    server_thread.join();
    auto received = received_promise.get_future().get();
    ASSERT_EQ(received.size(), DATA_SIZE) << "lost " << (DATA_SIZE - received.size()) << " bytes — "
                                          << "TLSSocket::close() likely skipped its second SSL_shutdown";
    EXPECT_EQ(received, data);
}

// ---------------------------------------------------------------------------
// Concept substitutability — same template instantiated for TCP and TLS
// ---------------------------------------------------------------------------

template <Socket S>
static stl::result<size_t> echo_once(S& sock, stl::span<const std::byte> payload, std::vector<std::byte>& out) {
    auto sent = sock.send(payload);
    if (!sent)
        return stl::make_error<size_t>("send: {}", sent.error());

    std::vector<std::byte> buf(payload.size());
    auto recvd = sock.recv(buf);
    if (!recvd)
        return stl::make_error<size_t>("recv: {}", recvd.error());
    out.assign(buf.begin(), buf.begin() + recvd.value());
    return recvd.value();
}

TEST_F(TLSSocketTest, ConceptSubstitutability) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_CONCEPT, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    auto server_thread = spawn_loopback_server(server, [](TLSSocket& peer) {
        std::vector<std::byte> buf(64);
        auto r = peer.recv(buf);
        if (r && r.value() > 0)
            peer.send({buf.data(), r.value()});
    });

    std::this_thread::sleep_for(50ms);

    TLSSocket tls(
        {.tcp = {.host = "127.0.0.1", .port = TLS_PORT_CONCEPT}, .verify_peer = false, .verify_hostname = false});
    ASSERT_TRUE(tls.connect()) << tls.handshake_error();

    const std::string payload = "concept";
    std::vector<std::byte> in(payload.size());
    std::memcpy(in.data(), payload.data(), payload.size());

    std::vector<std::byte> out;
    auto r = echo_once(tls, in, out);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value(), payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(out.data()), out.size()), payload);

    tls.close();
    server_thread.join();
}

// ---------------------------------------------------------------------------
// Wire log (Debug builds / SAP_TLS_WIRE_LOGGING)
// ---------------------------------------------------------------------------

#ifdef SAP_TLS_WIRE_LOGGING
TEST_F(TLSSocketTest, WireLogReceivesPlaintextOnSendAndRecv) {
    SelfSignedCert cert;

    TLSSocket server({.tcp              = {.port = TLS_PORT_WIRELOG, .listen_backlog = 1, .reuse_addr = true},
                      .role             = ETlsRole::Server,
                      .server_cert_file = cert.cert_file,
                      .server_key_file  = cert.key_file});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    auto server_thread = spawn_loopback_server(server, [](TLSSocket& peer) {
        std::vector<std::byte> buf(256);
        auto r = peer.recv(buf);
        if (r && r.value() > 0)
            peer.send({buf.data(), r.value()});
    });

    std::this_thread::sleep_for(50ms);

    std::mutex log_mu;
    std::vector<std::byte> sent_seen;
    std::vector<std::byte> recv_seen;
    std::atomic<int> sent_calls{0};
    std::atomic<int> recv_calls{0};

    TlsConfig client_cfg{.tcp             = {.host = "127.0.0.1", .port = TLS_PORT_WIRELOG},
                         .verify_peer     = false,
                         .verify_hostname = false};
    client_cfg.wire_log = [&](TlsConfig::EWireDirection dir, stl::span<const std::byte> data) {
        std::lock_guard lk(log_mu);
        if (dir == TlsConfig::EWireDirection::Send) {
            ++sent_calls;
            sent_seen.insert(sent_seen.end(), data.begin(), data.end());
        } else {
            ++recv_calls;
            recv_seen.insert(recv_seen.end(), data.begin(), data.end());
        }
    };

    TLSSocket client(client_cfg);
    ASSERT_TRUE(client.connect()) << client.handshake_error();

    const std::string payload = "wirelog";
    std::vector<std::byte> sbuf(payload.size());
    std::memcpy(sbuf.data(), payload.data(), payload.size());
    ASSERT_TRUE(client.send(sbuf));

    std::vector<std::byte> rbuf(256);
    auto r = client.recv(rbuf);
    ASSERT_TRUE(r);

    client.close();
    server_thread.join();

    EXPECT_EQ(sent_calls.load(), 1);
    EXPECT_EQ(recv_calls.load(), 1);
    ASSERT_EQ(sent_seen.size(), payload.size());
    ASSERT_EQ(recv_seen.size(), payload.size());
    EXPECT_EQ(std::memcmp(sent_seen.data(), payload.data(), payload.size()), 0);
    EXPECT_EQ(std::memcmp(recv_seen.data(), payload.data(), payload.size()), 0);
}
#endif
