#pragma once
#include "sap_core/types.h"
#include "sap_network/types.h"

#include <sap_core/stl/unique_ptr.h>

class ISocket {
public:
    virtual ~ISocket() = default;

    virtual bool bind() = 0;
    virtual bool listen() = 0;
    virtual bool connect() = 0;
    virtual stl::unique_ptr<ISocket> accept() = 0;
    virtual size_t send(stl::span<const std::byte>) = 0;
    virtual size_t recv(stl::span<std::byte>) = 0;
    virtual void close() = 0;
    virtual bool valid() const = 0;
};