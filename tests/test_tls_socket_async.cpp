#include <gtest/gtest.h>

#include "sap_network/platform.h"
#include "sap_network/socket_config.h"
#include "sap_network/tls_socket_async.h"

#include <sap_core/async/executor.h>
#include <sap_core/async/sleep_for.h>
#include <sap_core/async/spawn.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/async/sync_wait.h>
#include <sap_core/async/task.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

using namespace sap::network;
using namespace std::chrono_literals;
using sap::async::Executor;
using sap::async::sleep_for;
using sap::async::spawn;
using sap::async::StopSource;
using sap::async::StopToken;
using sap::async::sync_wait;
using sap::async::Task;
namespace fs = std::filesystem;

namespace {

    constexpr u16 PORT_TLS_ECHO       = 19400;
    constexpr u16 PORT_TLS_HANDSHAKE  = 19401;
    constexpr u16 PORT_TLS_PEER_CLOSE = 19402;
    constexpr u16 PORT_TLS_CLOSE      = 19403;
    constexpr u16 PORT_TLS_CONCURRENT = 19404;
    constexpr u16 PORT_TLS_REFUSED    = 19405;

    class SelfSignedCert {
    public:
        SelfSignedCert() {
            std::random_device rd;
            m_dir     = fs::temp_directory_path() / fs::path{"sap_tls_async_test_" + std::to_string(rd())};
            fs::create_directories(m_dir);
            cert_file = (m_dir / "cert.pem").string();
            key_file  = (m_dir / "key.pem").string();
            generate();
        }
        ~SelfSignedCert() {
            std::error_code ec;
            fs::remove_all(m_dir, ec);
        }
        SelfSignedCert(const SelfSignedCert&)            = delete;
        SelfSignedCert& operator=(const SelfSignedCert&) = delete;

        std::string cert_file;
        std::string key_file;

    private:
        void generate() {
            EVP_PKEY* pkey = ::EVP_RSA_gen(2048);
            X509*     x509 = ::X509_new();
            ::ASN1_INTEGER_set(::X509_get_serialNumber(x509), 1);
            ::X509_gmtime_adj(::X509_getm_notBefore(x509), 0);
            ::X509_gmtime_adj(::X509_getm_notAfter(x509), 31536000L);
            ::X509_set_pubkey(x509, pkey);
            X509_NAME* name = ::X509_get_subject_name(x509);
            ::X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
            ::X509_set_issuer_name(x509, name);
            X509V3_CTX v3ctx;
            X509V3_set_ctx_nodb(&v3ctx);
            ::X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
            if (X509_EXTENSION* ext = ::X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1")) {
                ::X509_add_ext(x509, ext, -1);
                ::X509_EXTENSION_free(ext);
            }
            ::X509_sign(x509, pkey, ::EVP_sha256());

            FILE* fp = std::fopen(cert_file.c_str(), "wb");
            ::PEM_write_X509(fp, x509);
            std::fclose(fp);

            fp = std::fopen(key_file.c_str(), "wb");
            ::PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
            std::fclose(fp);

            ::X509_free(x509);
            ::EVP_PKEY_free(pkey);
        }

        fs::path m_dir;
    };

    TlsServerConfig server_cfg(const SelfSignedCert& cert, u16 port) {
        TlsServerConfig cfg;
        cfg.tcp.host       = "127.0.0.1";
        cfg.tcp.port       = port;
        cfg.tcp.reuse_addr = true;
        cfg.cert_file      = cert.cert_file;
        cfg.key_file       = cert.key_file;
        return cfg;
    }

    TlsClientConfig client_cfg(const SelfSignedCert& cert, u16 port) {
        TlsClientConfig cfg;
        cfg.tcp.host  = "127.0.0.1";
        cfg.tcp.port  = port;
        cfg.verify_peer = true;
        cfg.ca_file     = cert.cert_file;
        cfg.sni_hostname = "localhost";
        return cfg;
    }

    Task<stl::result<>> fire_stop_after(Executor& ex, std::chrono::milliseconds dt, StopSource& src) {
        if (auto r = co_await sleep_for(ex, dt); !r)
            co_return r;
        src.request_stop();
        co_return stl::success;
    }

    Task<stl::result<>> hold_until_stopped(Executor& ex, TLSSocketAsync /*sock*/, StopToken tok) {
        if (auto r = co_await sleep_for(ex, 1h, tok); !r && !tok.stop_requested())
            co_return r;
        co_return stl::result<>{};
    }

} // namespace

class TLSSocketAsyncTest : public ::testing::Test {
protected:
    void SetUp() override { SocketPlatform::init(); }
};

TEST_F(TLSSocketAsyncTest, EchoLoopback) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        TLSSocketAsync listener(e, server_cfg(c, PORT_TLS_ECHO));
        EXPECT_TRUE(listener.bind());
        EXPECT_TRUE(listener.listen());

        auto server = spawn(e, [](TLSSocketAsync l) -> Task<stl::result<>> {
            auto child = co_await l.accept();
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            std::byte buf[256];
            auto      r = co_await child.value().read(stl::span<stl::byte>(buf, sizeof(buf)));
            if (!r)
                co_return stl::make_error<>("read: {}", r.error());
            auto w = co_await child.value().write(stl::span<const stl::byte>(buf, r.value()));
            if (!w)
                co_return stl::make_error<>("write: {}", w.error());
            co_return stl::result<>{};
        }(stl::move(listener)));

        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_ECHO));
        auto           cr = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        const std::string msg = "hello tls";
        auto              w   = co_await client.write(stl::span<const stl::byte>(reinterpret_cast<const std::byte*>(msg.data()), msg.size()));
        if (!w)
            co_return stl::make_error<>("client write: {}", w.error());

        std::byte buf[64];
        auto      r = co_await client.read(stl::span<stl::byte>(buf, sizeof(buf)));
        if (!r)
            co_return stl::make_error<>("client read: {}", r.error());
        EXPECT_EQ(r.value(), msg.size());
        EXPECT_EQ(std::memcmp(buf, msg.data(), msg.size()), 0);

        co_return co_await stl::move(server);
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}

TEST_F(TLSSocketAsyncTest, HandshakeCancellable) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        StopSource src;
        // No server here — client connect will park on TCP connect, never reach TLS handshake,
        // but cancel should still propagate.
        auto canceller = spawn(e, fire_stop_after(e, 30ms, src));

        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_HANDSHAKE));
        auto           cr = co_await client.connect(src.token());
        EXPECT_FALSE(cr.has_value());

        co_await stl::move(canceller);
        co_return stl::result<>{};
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TLSSocketAsyncTest, PeerCloseNotify_ReturnsZeroBytes) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        TLSSocketAsync listener(e, server_cfg(c, PORT_TLS_PEER_CLOSE));
        EXPECT_TRUE(listener.bind());
        EXPECT_TRUE(listener.listen());

        auto server = spawn(e, [](TLSSocketAsync l) -> Task<stl::result<>> {
            auto child = co_await l.accept();
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            // Reads until peer sends close_notify (returns 0), then sends ours.
            std::byte buf[32];
            auto      r = co_await child.value().read(stl::span<stl::byte>(buf, sizeof(buf)));
            if (!r)
                co_return stl::make_error<>("server read: {}", r.error());
            EXPECT_EQ(r.value(), 0u);
            auto sd = co_await child.value().shutdown();
            (void)sd;
            co_return stl::result<>{};
        }(stl::move(listener)));

        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_PEER_CLOSE));
        auto           cr = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        // Client initiates close_notify; server's read sees 0 bytes, server replies
        // with its own close_notify, client's shutdown completes bidirectionally.
        auto sd = co_await client.shutdown();
        (void)sd;

        co_await stl::move(server);
        co_return stl::result<>{};
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}

TEST_F(TLSSocketAsyncTest, Close_DrivesShutdownHandshake) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        TLSSocketAsync listener(e, server_cfg(c, PORT_TLS_CLOSE));
        EXPECT_TRUE(listener.bind());
        EXPECT_TRUE(listener.listen());

        auto server = spawn(e, [](TLSSocketAsync l) -> Task<stl::result<>> {
            auto child = co_await l.accept();
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            std::byte buf[32];
            auto      r = co_await child.value().read(stl::span<stl::byte>(buf, sizeof(buf)));
            if (!r)
                co_return stl::make_error<>("read: {}", r.error());
            EXPECT_EQ(r.value(), 0u);
            auto sd = co_await child.value().shutdown();
            (void)sd;
            co_return stl::result<>{};
        }(stl::move(listener)));

        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_CLOSE));
        auto           cr = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        auto sd = co_await client.shutdown();
        EXPECT_TRUE(sd.has_value()) << (sd.has_value() ? "" : sd.error());

        co_await stl::move(server);
        co_return stl::result<>{};
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}

TEST_F(TLSSocketAsyncTest, SecondConcurrentOp_ReturnsError) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        StopSource keep_alive;

        TLSSocketAsync listener(e, server_cfg(c, PORT_TLS_CONCURRENT));
        EXPECT_TRUE(listener.bind());
        EXPECT_TRUE(listener.listen());

        auto server = spawn(e, [](Executor& ex_in, TLSSocketAsync l, StopToken k) -> Task<stl::result<>> {
            auto child = co_await l.accept();
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            co_return co_await hold_until_stopped(ex_in, stl::move(child.value()), k);
        }(e, stl::move(listener), keep_alive.token()));

        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_CONCURRENT));
        auto           cr = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        StopSource cancel_first;
        std::byte  buf1[32];
        auto       first = spawn(e, client.read(stl::span<stl::byte>(buf1, sizeof(buf1)), cancel_first.token()));
        if (auto r = co_await sleep_for(e, 10ms); !r)
            co_return stl::make_error<>("sleep_for: {}", r.error());

        std::byte buf2[32];
        auto      r = co_await client.read(stl::span<stl::byte>(buf2, sizeof(buf2)));
        EXPECT_FALSE(r.has_value());

        cancel_first.request_stop();
        (void)co_await stl::move(first);
        keep_alive.request_stop();
        co_await stl::move(server);
        co_return stl::result<>{};
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TLSSocketAsyncTest, ConnectRefused_ReturnsError) {
    SelfSignedCert cert;
    auto           exr = Executor::create();
    auto&          ex  = exr.value();

    auto driver = [](Executor& e, SelfSignedCert& c) -> Task<stl::result<>> {
        TLSSocketAsync client(e, client_cfg(c, PORT_TLS_REFUSED));
        auto           cr = co_await client.connect();
        EXPECT_FALSE(cr.has_value());
        co_return stl::result<>{};
    }(ex, cert);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}
