#include <gtest/gtest.h>

#include "sap_network/platform.h"
#include "sap_network/socket_config.h"
#include "sap_network/tcp_socket_async.h"

#include <sap_core/async/executor.h>
#include <sap_core/async/sleep_for.h>
#include <sap_core/async/spawn.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/async/sync_wait.h>
#include <sap_core/async/task.h>

#include <sys/socket.h>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

using namespace sap::network;
using namespace std::chrono_literals;
using sap::async::CancelledError;
using sap::async::Executor;
using sap::async::ReactorError;
using sap::async::sleep_for;
using sap::async::spawn;
using sap::async::SpawnHandle;
using sap::async::StopSource;
using sap::async::StopToken;
using sap::async::sync_wait;
using sap::async::Task;

namespace {

    constexpr u16 PORT_ECHO            = 19200;
    constexpr u16 PORT_PEER_CLOSE      = 19201;
    constexpr u16 PORT_CANCEL_READ     = 19202;
    constexpr u16 PORT_LARGE_WRITE     = 19203;
    constexpr u16 PORT_CONNECT_REFUSED = 19204;
    constexpr u16 PORT_CANCEL_ACCEPT   = 19205;
    constexpr u16 PORT_CONCURRENT_OP   = 19206;
    constexpr u16 PORT_WRITE_PARKS     = 19207;

    TCPSocketAsync make_listener(Executor& ex, u16 port) {
        SocketConfig cfg;
        cfg.host       = "127.0.0.1";
        cfg.port       = port;
        cfg.reuse_addr = true;
        TCPSocketAsync sock(ex, stl::move(cfg));
        EXPECT_TRUE(sock.bind());
        EXPECT_TRUE(sock.listen());
        return sock;
    }

    TCPSocketAsync make_client(Executor& ex, u16 port) {
        SocketConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = port;
        return TCPSocketAsync(ex, stl::move(cfg));
    }

    Task<stl::result<>> echo_once(TCPSocketAsync sock) {
        std::byte buf[256];
        auto      r = co_await sock.read(stl::span<stl::byte>(buf, sizeof(buf)));
        if (!r)
            co_return stl::make_error<>("read: {}", r.error());
        if (r.value() == 0)
            co_return stl::result<>{};
        size_t total = 0;
        while (total < r.value()) {
            auto w = co_await sock.write(stl::span<const stl::byte>(buf + total, r.value() - total));
            if (!w)
                co_return stl::make_error<>("write: {}", w.error());
            total += w.value();
        }
        co_return stl::result<>{};
    }

    Task<stl::result<TCPSocketAsync>> accept_one(TCPSocketAsync l) {
        auto child = co_await l.accept();
        if (!child)
            co_return stl::make_error<TCPSocketAsync>("accept: {}", child.error());
        co_return stl::move(child);
    }

    Task<void> fire_stop_after(Executor& ex, std::chrono::milliseconds dt, StopSource& src) {
        co_await sleep_for(ex, dt);
        src.request_stop();
    }

    Task<stl::result<>> hold_until_stopped(Executor& ex, TCPSocketAsync /*sock*/, StopToken tok) {
        try {
            co_await sleep_for(ex, 1h, tok);
        } catch (const CancelledError&) {
        }
        co_return stl::result<>{};
    }

    Task<stl::result<size_t>> drain_all(TCPSocketAsync sock, size_t expect_at_least) {
        std::vector<std::byte> buf(8 * 1024);
        size_t                 got = 0;
        while (got < expect_at_least) {
            auto r = co_await sock.read(stl::span<stl::byte>(buf.data(), buf.size()));
            if (!r)
                co_return stl::make_error<size_t>("read: {}", r.error());
            if (r.value() == 0)
                break;
            got += r.value();
        }
        co_return stl::result<size_t>{stl::success, got};
    }

} // namespace

class TCPSocketAsyncTest : public ::testing::Test {
protected:
    void SetUp() override { SocketPlatform::init(); }
};

TEST_F(TCPSocketAsyncTest, EchoLoopback) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        auto listener = make_listener(e, PORT_ECHO);

        auto server = spawn(e, [](TCPSocketAsync l) -> Task<stl::result<>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            co_return co_await echo_once(stl::move(child.value()));
        }(stl::move(listener)));

        auto client = make_client(e, PORT_ECHO);
        auto cr     = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        const std::string msg = "hello";
        auto w = co_await client.write(stl::span<const stl::byte>(reinterpret_cast<const std::byte*>(msg.data()), msg.size()));
        if (!w)
            co_return stl::make_error<>("write: {}", w.error());

        std::byte buf[32];
        auto      r = co_await client.read(stl::span<stl::byte>(buf, sizeof(buf)));
        if (!r)
            co_return stl::make_error<>("read: {}", r.error());
        EXPECT_EQ(r.value(), msg.size());
        EXPECT_EQ(std::memcmp(buf, msg.data(), msg.size()), 0);

        co_return co_await stl::move(server);
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}

TEST_F(TCPSocketAsyncTest, ReadPeerClose) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        auto listener = make_listener(e, PORT_PEER_CLOSE);
        auto server   = spawn(e, [](TCPSocketAsync l) -> Task<stl::result<>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            child.value().close();
            co_return stl::result<>{};
        }(stl::move(listener)));

        auto client = make_client(e, PORT_PEER_CLOSE);
        auto cr     = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        std::byte buf[32];
        auto      r = co_await client.read(stl::span<stl::byte>(buf, sizeof(buf)));
        if (!r)
            co_return stl::make_error<>("read: {}", r.error());
        EXPECT_EQ(r.value(), 0u);

        co_return co_await stl::move(server);
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value());
}

TEST_F(TCPSocketAsyncTest, CancellableRead_ThrowsCancelled) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        StopSource keep_alive;
        StopSource read_cancel;

        auto listener = make_listener(e, PORT_CANCEL_READ);
        auto server   = spawn(e, [](Executor& ex_in, TCPSocketAsync l, StopToken k) -> Task<stl::result<>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            co_return co_await hold_until_stopped(ex_in, stl::move(child.value()), k);
        }(e, stl::move(listener), keep_alive.token()));

        auto client = make_client(e, PORT_CANCEL_READ);
        auto cr     = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        auto canceller = spawn(e, fire_stop_after(e, 30ms, read_cancel));

        std::byte buf[32];
        bool      threw = false;
        try {
            auto r = co_await client.read(stl::span<stl::byte>(buf, sizeof(buf)), read_cancel.token());
            (void)r;
        } catch (const CancelledError&) {
            threw = true;
        }
        EXPECT_TRUE(threw);

        co_await stl::move(canceller);
        keep_alive.request_stop();
        co_await stl::move(server);
        co_return stl::result<>{};
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TCPSocketAsyncTest, WriteLargeBuffer_HandlesPartial) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e, size_t total) -> Task<stl::result<>> {
        auto listener = make_listener(e, PORT_LARGE_WRITE);
        auto server   = spawn(e, [](TCPSocketAsync l, size_t expected) -> Task<stl::result<size_t>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<size_t>("accept: {}", child.error());
            co_return co_await drain_all(stl::move(child.value()), expected);
        }(stl::move(listener), total));

        auto client = make_client(e, PORT_LARGE_WRITE);
        auto cr     = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        std::vector<std::byte> data(total, std::byte{0xab});
        size_t                 sent = 0;
        while (sent < total) {
            auto w = co_await client.write(stl::span<const stl::byte>(data.data() + sent, total - sent));
            if (!w)
                co_return stl::make_error<>("write: {}", w.error());
            if (w.value() == 0)
                break;
            sent += w.value();
        }
        EXPECT_EQ(sent, total);
        client.close();

        auto sr = co_await stl::move(server);
        if (!sr)
            co_return stl::make_error<>("server: {}", sr.error());
        EXPECT_EQ(sr.value(), total);
        co_return stl::result<>{};
    }(ex, 256 * 1024);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}

TEST_F(TCPSocketAsyncTest, ConnectRefused_ReturnsError) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        auto client = make_client(e, PORT_CONNECT_REFUSED);
        auto cr     = co_await client.connect();
        EXPECT_FALSE(cr.has_value());
        co_return stl::result<>{};
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TCPSocketAsyncTest, AcceptCancellable) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        StopSource src;
        auto       listener  = make_listener(e, PORT_CANCEL_ACCEPT);
        auto       canceller = spawn(e, fire_stop_after(e, 30ms, src));

        bool threw = false;
        try {
            auto r = co_await listener.accept(src.token());
            (void)r;
        } catch (const CancelledError&) {
            threw = true;
        }
        EXPECT_TRUE(threw);
        co_await stl::move(canceller);
        co_return stl::result<>{};
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TCPSocketAsyncTest, SecondConcurrentOp_ThrowsReactorError) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e) -> Task<stl::result<>> {
        StopSource keep_alive;
        StopSource cancel_first;

        auto listener = make_listener(e, PORT_CONCURRENT_OP);
        auto server   = spawn(e, [](Executor& ex_in, TCPSocketAsync l, StopToken k) -> Task<stl::result<>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<>("accept: {}", child.error());
            co_return co_await hold_until_stopped(ex_in, stl::move(child.value()), k);
        }(e, stl::move(listener), keep_alive.token()));

        auto client = make_client(e, PORT_CONCURRENT_OP);
        auto cr     = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        std::byte buf1[32];
        auto      first = spawn(e, client.read(stl::span<stl::byte>(buf1, sizeof(buf1)), cancel_first.token()));
        co_await sleep_for(e, 10ms);

        std::byte buf2[32];
        bool      threw = false;
        try {
            auto r = co_await client.read(stl::span<stl::byte>(buf2, sizeof(buf2)));
            (void)r;
        } catch (const ReactorError&) {
            threw = true;
        }
        EXPECT_TRUE(threw);

        cancel_first.request_stop();
        try {
            (void)co_await stl::move(first);
        } catch (const CancelledError&) {
        }

        keep_alive.request_stop();
        co_await stl::move(server);
        co_return stl::result<>{};
    }(ex);

    auto h = spawn(ex, stl::move(driver));
    sync_wait(stl::move(h));
}

TEST_F(TCPSocketAsyncTest, WriteParksWhenSendBufferFull) {
    auto exr = Executor::create();
    auto& ex = exr.value();

    auto driver = [](Executor& e, size_t total) -> Task<stl::result<>> {
        auto listener = make_listener(e, PORT_WRITE_PARKS);
        auto server   = spawn(e, [](Executor& ex_in, TCPSocketAsync l, size_t expected) -> Task<stl::result<size_t>> {
            auto child = co_await accept_one(stl::move(l));
            if (!child)
                co_return stl::make_error<size_t>("accept: {}", child.error());
            co_await sleep_for(ex_in, 30ms);
            co_return co_await drain_all(stl::move(child.value()), expected);
        }(e, stl::move(listener), total));

        auto client = make_client(e, PORT_WRITE_PARKS);
        int  small  = 8 * 1024;
        ::setsockopt(client.native_handle(), SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
        auto cr = co_await client.connect();
        if (!cr)
            co_return stl::make_error<>("connect: {}", cr.error());

        std::vector<std::byte> data(total, std::byte{0xcd});
        size_t                 sent = 0;
        while (sent < data.size()) {
            auto w = co_await client.write(stl::span<const stl::byte>(data.data() + sent, data.size() - sent));
            if (!w)
                co_return stl::make_error<>("write: {}", w.error());
            if (w.value() == 0)
                break;
            sent += w.value();
        }
        EXPECT_EQ(sent, data.size());
        client.close();

        auto sr = co_await stl::move(server);
        if (!sr)
            co_return stl::make_error<>("server: {}", sr.error());
        EXPECT_EQ(sr.value(), data.size());
        co_return stl::result<>{};
    }(ex, 1024 * 1024);

    auto h = spawn(ex, stl::move(driver));
    auto r = sync_wait(stl::move(h));
    EXPECT_TRUE(r.has_value()) << (r.has_value() ? "" : r.error());
}
