#pragma once

#include "sap_network/platform.h"
#include "sap_network/socket_async_concept.h"
#include "sap_network/socket_config.h"
#include "sap_network/tls_socket.h"

#include <sap_core/async/executor.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/async/task.h>
#include <sap_core/stl/atomic.h>
#include <sap_core/stl/result.h>
#include <sap_core/stl/span.h>
#include <sap_core/stl/string.h>

#include <cstddef>
#include <variant>

struct ssl_st;

namespace sap::network {

    class TLSSocketAsync {
    public:
        explicit TLSSocketAsync(sap::async::Executor& ex, TlsClientConfig config);
        explicit TLSSocketAsync(sap::async::Executor& ex, TlsServerConfig config);

        TLSSocketAsync(const TLSSocketAsync&)            = delete;
        TLSSocketAsync& operator=(const TLSSocketAsync&) = delete;
        TLSSocketAsync(TLSSocketAsync&&) noexcept;
        TLSSocketAsync& operator=(TLSSocketAsync&&) noexcept;
        ~TLSSocketAsync();

        bool bind();
        bool listen();

        sap::async::Task<stl::result<>>               connect(sap::async::StopToken tok = {});
        sap::async::Task<stl::result<TLSSocketAsync>> accept(sap::async::StopToken tok = {});
        sap::async::Task<stl::result<size_t>>         read(stl::span<stl::byte> buf,
                                                          sap::async::StopToken tok = {});
        sap::async::Task<stl::result<size_t>>         write(stl::span<const stl::byte> buf,
                                                           sap::async::StopToken tok = {});

        sap::async::Task<stl::result<>> shutdown(sap::async::StopToken tok = {});
        void                            close();

        bool                valid() const noexcept { return m_handle != INVALID_SOCKET_HANDLE; }
        SocketHandle        native_handle() const noexcept { return m_handle; }
        const SocketConfig& config() const noexcept;

        stl::string        negotiated_protocol() const;
        stl::string        negotiated_cipher() const;
        stl::string        negotiated_tls_version() const;
        stl::string        peer_cert_subject() const;
        stl::string        peer_cert_issuer() const;
        const stl::string& handshake_error() const noexcept { return m_handshake_error; }

    public:
        using ConfigVariant = std::variant<TlsClientConfig, TlsServerConfig, TlsAcceptedConfig>;

    private:
        TLSSocketAsync(sap::async::Executor& ex, SocketHandle handle, ssl_st* ssl, TlsAcceptedConfig cfg) noexcept;

        sap::async::Executor* m_ex     = nullptr;
        SocketHandle          m_handle = INVALID_SOCKET_HANDLE;
        ssl_st*               m_ssl    = nullptr;
        ConfigVariant         m_config;
        stl::atomic<bool>     m_op_in_flight{false};
        stl::string           m_handshake_error;
    };

    static_assert(SocketAsync<TLSSocketAsync>);

} // namespace sap::network
