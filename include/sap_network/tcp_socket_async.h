#pragma once

#include "sap_network/platform.h"
#include "sap_network/socket_async_concept.h"
#include "sap_network/socket_config.h"

#include <sap_core/async/executor.h>
#include <sap_core/async/stop_token.h>
#include <sap_core/async/task.h>
#include <sap_core/stl/result.h>
#include <sap_core/stl/span.h>
#include <sap_core/stl/string.h>
#include <sap_core/types.h>

#include <cstddef>

namespace sap::network {

    class TCPSocketAsync {
    public:
        explicit TCPSocketAsync(sap::async::Executor& ex, SocketConfig config);

        static TCPSocketAsync adopt(sap::async::Executor& ex, SocketHandle h, SocketConfig config);

        TCPSocketAsync(const TCPSocketAsync&)            = delete;
        TCPSocketAsync& operator=(const TCPSocketAsync&) = delete;
        TCPSocketAsync(TCPSocketAsync&&) noexcept;
        TCPSocketAsync& operator=(TCPSocketAsync&&) noexcept;
        ~TCPSocketAsync();

        bool bind();
        bool listen();

        sap::async::Task<stl::result<>>               connect(sap::async::StopToken tok = {});
        sap::async::Task<stl::result<TCPSocketAsync>> accept(sap::async::StopToken tok = {});
        sap::async::Task<stl::result<size_t>>         read(stl::span<stl::byte> buf,
                                                          sap::async::StopToken tok = {});
        sap::async::Task<stl::result<size_t>>         write(stl::span<const stl::byte> buf,
                                                           sap::async::StopToken tok = {});

        void close();

        bool                valid() const noexcept { return m_handle != INVALID_SOCKET_HANDLE; }
        SocketHandle        native_handle() const noexcept { return m_handle; }
        const SocketConfig& config() const noexcept { return m_config; }

    private:
        TCPSocketAsync(sap::async::Executor& ex, SocketHandle h, SocketConfig config) noexcept;

        sap::async::Executor* m_ex     = nullptr;
        SocketHandle          m_handle = INVALID_SOCKET_HANDLE;
        SocketConfig          m_config;
    };

    static_assert(SocketAsync<TCPSocketAsync>);

} // namespace sap::network
