#include <gtest/gtest.h>

#include "sap_network/platform.h"
#include "sap_network/socket_config.h"
#include "sap_network/udp_socket.h"

#include <chrono>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace sap::network;
using namespace std::chrono_literals;

static constexpr u16 UDP_PORT_BIND_A  = 19200;
static constexpr u16 UDP_PORT_BIND_B  = 19201;
static constexpr u16 UDP_PORT_RX      = 19202;
static constexpr u16 UDP_PORT_BIDIR_A = 19203;
static constexpr u16 UDP_PORT_BIDIR_B = 19204;
static constexpr u16 UDP_PORT_MULTI   = 19205;
static constexpr u16 UDP_PORT_LARGE   = 19206;
static constexpr u16 UDP_PORT_THREAD  = 19207;

class UDPSocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        SocketPlatform::init();
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<std::byte> to_bytes(std::string_view s) {
    std::vector<std::byte> v(s.size());
    std::memcpy(v.data(), s.data(), s.size());
    return v;
}

static std::string from_bytes(const std::vector<std::byte>& v, size_t n) {
    return {reinterpret_cast<const char*>(v.data()), n};
}

// ---------------------------------------------------------------------------
// Construction / lifecycle
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, ConstructionProducesValidSocket) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    EXPECT_TRUE(sock.valid());
}

TEST_F(UDPSocketTest, CloseInvalidatesSocket) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    sock.close();
    EXPECT_FALSE(sock.valid());
}

TEST_F(UDPSocketTest, DoubleCloseIsSafe) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    sock.close();
    EXPECT_NO_FATAL_FAILURE(sock.close());
}

TEST_F(UDPSocketTest, DestructorClosesSocket) {
    { UDPSocket sock({.port = UDP_PORT_BIND_A}); }
}

// ---------------------------------------------------------------------------
// Bind
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, BindToPortSucceeds) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    EXPECT_TRUE(sock.bind());
}

TEST_F(UDPSocketTest, BindToPortZeroSucceeds) {
    UDPSocket sock({.port = 0});
    EXPECT_TRUE(sock.bind());
}

TEST_F(UDPSocketTest, BindToSamePortTwiceFails) {
    UDPSocket a({.port = UDP_PORT_BIND_A}), b({.port = UDP_PORT_BIND_A});
    ASSERT_TRUE(a.bind());
    EXPECT_FALSE(b.bind());
}

// ---------------------------------------------------------------------------
// Connect — negative case
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, ConnectToInvalidHostnameFails) {
    UDPSocket sock({.host = "this.host.does.not.exist.invalid", .port = 9999});
    EXPECT_FALSE(sock.connect());
}

// ---------------------------------------------------------------------------
// One-way send → recv
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, SendRecvRoundTrip) {
    const std::string payload = "Hello, UDP!";

    UDPSocket receiver({.port = UDP_PORT_RX, .reuse_addr = true});
    ASSERT_TRUE(receiver.bind());

    UDPSocket sender({.host = "127.0.0.1", .port = UDP_PORT_RX});
    ASSERT_TRUE(sender.connect());

    auto sbuf = to_bytes(payload);
    auto sent = sender.send(sbuf);
    ASSERT_TRUE(sent);
    EXPECT_EQ(sent.value(), payload.size());

    std::vector<std::byte> rbuf(256);
    auto r = receiver.recv(rbuf);
    ASSERT_TRUE(r);
    ASSERT_EQ(r.value(), payload.size());
    EXPECT_EQ(from_bytes(rbuf, r.value()), payload);
}

// ---------------------------------------------------------------------------
// Bidirectional exchange
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, BidirectionalExchange) {
    const std::string ping = "ping";
    const std::string pong = "pong";

    UDPSocket rx_a({.port = UDP_PORT_BIDIR_A, .reuse_addr = true});
    UDPSocket rx_b({.port = UDP_PORT_BIDIR_B, .reuse_addr = true});
    ASSERT_TRUE(rx_a.bind());
    ASSERT_TRUE(rx_b.bind());

    UDPSocket tx_ab({.host = "127.0.0.1", .port = UDP_PORT_BIDIR_B});
    ASSERT_TRUE(tx_ab.connect());
    auto sent_ab = tx_ab.send(to_bytes(ping));
    ASSERT_TRUE(sent_ab);
    EXPECT_EQ(sent_ab.value(), ping.size());

    std::vector<std::byte> rbuf(256);
    auto rb = rx_b.recv(rbuf);
    ASSERT_TRUE(rb);
    ASSERT_EQ(rb.value(), ping.size());
    EXPECT_EQ(from_bytes(rbuf, rb.value()), ping);

    UDPSocket tx_ba({.host = "127.0.0.1", .port = UDP_PORT_BIDIR_A});
    ASSERT_TRUE(tx_ba.connect());
    auto sent_ba = tx_ba.send(to_bytes(pong));
    ASSERT_TRUE(sent_ba);
    EXPECT_EQ(sent_ba.value(), pong.size());

    auto ra = rx_a.recv(rbuf);
    ASSERT_TRUE(ra);
    ASSERT_EQ(ra.value(), pong.size());
    EXPECT_EQ(from_bytes(rbuf, ra.value()), pong);
}

// ---------------------------------------------------------------------------
// Threaded recv
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, ThreadedSendRecv) {
    const std::string payload = "threaded-udp";

    UDPSocket receiver({.port = UDP_PORT_THREAD, .reuse_addr = true});
    ASSERT_TRUE(receiver.bind());

    std::promise<std::string> result_promise;
    std::thread recv_thread([&] {
        std::vector<std::byte> buf(256);
        auto r = receiver.recv(buf);
        result_promise.set_value(r ? from_bytes(buf, r.value()) : std::string{});
    });

    std::this_thread::sleep_for(10ms);

    UDPSocket sender({.host = "127.0.0.1", .port = UDP_PORT_THREAD});
    ASSERT_TRUE(sender.connect());
    ASSERT_TRUE(sender.send(to_bytes(payload)));

    recv_thread.join();
    EXPECT_EQ(result_promise.get_future().get(), payload);
}

// ---------------------------------------------------------------------------
// Multiple datagrams in sequence
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, MultipleDatagramsInSequence) {
    const std::vector<std::string> messages = {"one", "two", "three", "four", "five"};

    UDPSocket receiver({.port = UDP_PORT_MULTI, .reuse_addr = true});
    ASSERT_TRUE(receiver.bind());

    UDPSocket sender({.host = "127.0.0.1", .port = UDP_PORT_MULTI});
    ASSERT_TRUE(sender.connect());

    for (const auto& msg : messages) {
        auto sent = sender.send(to_bytes(msg));
        ASSERT_TRUE(sent);
        EXPECT_EQ(sent.value(), msg.size());

        std::vector<std::byte> rbuf(256);
        auto r = receiver.recv(rbuf);
        ASSERT_TRUE(r);
        ASSERT_EQ(r.value(), msg.size());
        EXPECT_EQ(from_bytes(rbuf, r.value()), msg);
    }
}

// ---------------------------------------------------------------------------
// Large datagram (near typical UDP payload limit on loopback)
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, LargeDatagramTransfer) {
    constexpr size_t DATA_SIZE = 8 * 1024;
    std::vector<std::byte> send_data(DATA_SIZE);
    for (size_t i = 0; i < DATA_SIZE; ++i)
        send_data[i] = static_cast<std::byte>(i & 0xFF);

    UDPSocket receiver({.port = UDP_PORT_LARGE, .reuse_addr = true});
    ASSERT_TRUE(receiver.bind());

    UDPSocket sender({.host = "127.0.0.1", .port = UDP_PORT_LARGE});
    ASSERT_TRUE(sender.connect());

    auto sent = sender.send(send_data);
    ASSERT_TRUE(sent);
    ASSERT_EQ(sent.value(), DATA_SIZE);

    std::vector<std::byte> recv_buf(DATA_SIZE);
    auto r = receiver.recv(recv_buf);
    ASSERT_TRUE(r);
    ASSERT_EQ(r.value(), DATA_SIZE);
    EXPECT_EQ(recv_buf, send_data);
}

// ---------------------------------------------------------------------------
// SO_REUSEADDR
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, ReuseAddrAllowsRebindAfterClose) {
    {
        UDPSocket first({.port = UDP_PORT_BIND_A, .reuse_addr = true});
        ASSERT_TRUE(first.bind());
    }
    UDPSocket second({.port = UDP_PORT_BIND_A, .reuse_addr = true});
    EXPECT_TRUE(second.bind());
}

TEST_F(UDPSocketTest, ReuseAddrDefaultsToFalse) {
    SocketConfig cfg{.port = UDP_PORT_BIND_A};
    EXPECT_FALSE(cfg.reuse_addr);
}

// ---------------------------------------------------------------------------
// Send / recv on closed socket
// ---------------------------------------------------------------------------

TEST_F(UDPSocketTest, SendOnClosedSocketFails) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    sock.close();
    std::vector<std::byte> buf = {std::byte{0xAB}, std::byte{0xCD}};
    EXPECT_FALSE(sock.send(buf));
}

TEST_F(UDPSocketTest, RecvOnClosedSocketFails) {
    UDPSocket sock({.port = UDP_PORT_BIND_A});
    sock.close();
    std::vector<std::byte> buf(16);
    EXPECT_FALSE(sock.recv(buf));
}
