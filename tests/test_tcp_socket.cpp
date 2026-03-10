#include <gtest/gtest.h>

#include "sap_network/platform.h"
#include "sap_network/socket_config.h"
#include "sap_network/tcp_socket.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace sap::network;
using namespace std::chrono_literals;

// Ports reserved for these tests — picked to avoid common service ports.
static constexpr u16 TCP_PORT_BIND        = 19100;
static constexpr u16 TCP_PORT_LISTEN      = 19101;
static constexpr u16 TCP_PORT_ECHO        = 19102;
static constexpr u16 TCP_PORT_MULTI       = 19103;
static constexpr u16 TCP_PORT_LARGE       = 19104;
static constexpr u16 TCP_PORT_CLOSE_SEND  = 19105;

class TCPSocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        SocketPlatform::init();
    }
};

// ---------------------------------------------------------------------------
// Construction / lifecycle
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, ConstructionProducesValidSocket) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    EXPECT_TRUE(sock.valid());
}

TEST_F(TCPSocketTest, CloseInvalidatesSocket) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    ASSERT_TRUE(sock.valid());
    sock.close();
    EXPECT_FALSE(sock.valid());
}

TEST_F(TCPSocketTest, DoubleCloseIsSafe) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    sock.close();
    EXPECT_NO_FATAL_FAILURE(sock.close());
    EXPECT_FALSE(sock.valid());
}

TEST_F(TCPSocketTest, DestructorClosesSocket) {
    { TCPSocket sock({.port = TCP_PORT_BIND}); }
}

// ---------------------------------------------------------------------------
// Bind
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, BindToPortSucceeds) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    EXPECT_TRUE(sock.bind());
}

TEST_F(TCPSocketTest, BindToSamePortTwiceFails) {
    TCPSocket a({.port = TCP_PORT_BIND}), b({.port = TCP_PORT_BIND});
    ASSERT_TRUE(a.bind());
    EXPECT_FALSE(b.bind());
}

TEST_F(TCPSocketTest, BindToPortZeroSucceeds) {
    TCPSocket sock({.port = 0});
    EXPECT_TRUE(sock.bind());
}

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, ListenAfterBindSucceeds) {
    TCPSocket sock({.port = TCP_PORT_LISTEN});
    ASSERT_TRUE(sock.bind());
    EXPECT_TRUE(sock.listen());
}

TEST_F(TCPSocketTest, ListenWithCustomBacklog) {
    TCPSocket sock({.port = TCP_PORT_LISTEN, .listen_backlog = 5});
    ASSERT_TRUE(sock.bind());
    EXPECT_TRUE(sock.listen());
}

// ---------------------------------------------------------------------------
// Connect — negative cases
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, ConnectToClosedPortFails) {
    // 127.0.0.1 on an unused port gives immediate ECONNREFUSED — no timeout needed.
    TCPSocket sock({.host = "127.0.0.1", .port = 19998});
    EXPECT_FALSE(sock.connect());
}

TEST_F(TCPSocketTest, ConnectToInvalidHostnameFails) {
    TCPSocket sock({.host = "this.host.does.not.exist.invalid", .port = 80});
    EXPECT_FALSE(sock.connect());
}

TEST_F(TCPSocketTest, ConnectWithTimeoutFails) {
    // 192.0.2.1 is TEST-NET (unroutable). With a short timeout connect must
    // return false well within the timeout period rather than hanging.
    TCPSocket sock({.host = "192.0.2.1", .port = 9999, .connect_timeout = 200ms});
    EXPECT_FALSE(sock.connect());
}

// ---------------------------------------------------------------------------
// Accept — negative cases
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, AcceptOnNonListeningSocketReturnsNull) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    EXPECT_EQ(sock.accept(), nullptr);
}

// ---------------------------------------------------------------------------
// Full echo: bind → listen → [thread] accept → echo / connect → send → recv
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, EchoRoundTrip) {
    const std::string payload = "Hello, TCP!";

    TCPSocket server({.port = TCP_PORT_ECHO, .listen_backlog = 1});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<bool> server_ok;
    std::thread server_thread([&] {
        auto client = server.accept();
        if (!client) { server_ok.set_value(false); return; }

        std::vector<std::byte> buf(256);
        size_t n = client->recv(buf);
        if (n > 0)
            client->send({buf.data(), n});

        server_ok.set_value(true);
    });

    std::this_thread::sleep_for(10ms);

    TCPSocket client({.host = "127.0.0.1", .port = TCP_PORT_ECHO});
    ASSERT_TRUE(client.connect());

    std::vector<std::byte> send_buf(payload.size());
    std::memcpy(send_buf.data(), payload.data(), payload.size());
    EXPECT_EQ(client.send(send_buf), payload.size());

    std::vector<std::byte> recv_buf(256);
    size_t received = client.recv(recv_buf);
    ASSERT_EQ(received, payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(recv_buf.data()), received), payload);

    client.close();
    server_thread.join();
    EXPECT_TRUE(server_ok.get_future().get());
}

// ---------------------------------------------------------------------------
// Multiple sequential clients
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, MultipleSequentialClients) {
    const std::vector<std::string> messages = {"first", "second", "third"};

    TCPSocket server({.port = TCP_PORT_MULTI, .listen_backlog = 10});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::thread server_thread([&] {
        for (size_t i = 0; i < messages.size(); ++i) {
            auto client = server.accept();
            if (!client) continue;
            std::vector<std::byte> buf(256);
            size_t n = client->recv(buf);
            if (n > 0) client->send({buf.data(), n});
        }
    });

    std::this_thread::sleep_for(10ms);

    for (const auto& msg : messages) {
        TCPSocket client({.host = "127.0.0.1", .port = TCP_PORT_MULTI});
        ASSERT_TRUE(client.connect());

        std::vector<std::byte> sbuf(msg.size());
        std::memcpy(sbuf.data(), msg.data(), msg.size());
        client.send(sbuf);

        std::vector<std::byte> rbuf(256);
        size_t n = client.recv(rbuf);
        EXPECT_EQ(std::string(reinterpret_cast<char*>(rbuf.data()), n), msg);
        client.close();
    }

    server_thread.join();
}

// ---------------------------------------------------------------------------
// Large payload (> typical MTU)
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, LargePayloadTransfer) {
    constexpr size_t DATA_SIZE = 64 * 1024;
    std::vector<std::byte> send_data(DATA_SIZE);
    for (size_t i = 0; i < DATA_SIZE; ++i)
        send_data[i] = static_cast<std::byte>(i & 0xFF);

    TCPSocket server({.port = TCP_PORT_LARGE, .listen_backlog = 1});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<std::vector<std::byte>> received_promise;
    std::thread server_thread([&] {
        auto client = server.accept();
        if (!client) { received_promise.set_value({}); return; }

        std::vector<std::byte> accumulated;
        std::vector<std::byte> buf(4096);
        while (accumulated.size() < DATA_SIZE) {
            size_t n = client->recv(buf);
            if (n == 0) break;
            accumulated.insert(accumulated.end(), buf.begin(), buf.begin() + n);
        }
        received_promise.set_value(std::move(accumulated));
    });

    std::this_thread::sleep_for(10ms);

    TCPSocket client({.host = "127.0.0.1", .port = TCP_PORT_LARGE});
    ASSERT_TRUE(client.connect());

    size_t total_sent = 0;
    while (total_sent < DATA_SIZE) {
        size_t n = client.send({send_data.data() + total_sent, DATA_SIZE - total_sent});
        ASSERT_GT(n, 0u);
        total_sent += n;
    }
    client.close();

    server_thread.join();
    auto received = received_promise.get_future().get();
    ASSERT_EQ(received.size(), DATA_SIZE);
    EXPECT_EQ(received, send_data);
}

// ---------------------------------------------------------------------------
// Send / recv on closed socket
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, SendOnClosedSocketReturnsZero) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    sock.close();
    std::vector<std::byte> buf = {std::byte{1}, std::byte{2}};
    EXPECT_EQ(sock.send(buf), 0u);
}

TEST_F(TCPSocketTest, RecvOnClosedSocketReturnsZero) {
    TCPSocket sock({.port = TCP_PORT_BIND});
    sock.close();
    std::vector<std::byte> buf(16);
    EXPECT_EQ(sock.recv(buf), 0u);
}

// ---------------------------------------------------------------------------
// Accepted socket lifecycle
// ---------------------------------------------------------------------------

TEST_F(TCPSocketTest, AcceptedSocketIsValid) {
    TCPSocket server({.port = TCP_PORT_CLOSE_SEND, .listen_backlog = 1});
    ASSERT_TRUE(server.bind());
    ASSERT_TRUE(server.listen());

    std::promise<bool> accepted_valid;
    std::thread server_thread([&] {
        auto client = server.accept();
        accepted_valid.set_value(client != nullptr && client->valid());
    });

    std::this_thread::sleep_for(10ms);

    TCPSocket client({.host = "127.0.0.1", .port = TCP_PORT_CLOSE_SEND});
    ASSERT_TRUE(client.connect());
    client.close();

    server_thread.join();
    EXPECT_TRUE(accepted_valid.get_future().get());
}
