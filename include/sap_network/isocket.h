#include "sap_core/types.h"
#include "sap_network/types.h"

class ISocket {
public:
    virtual ~ISocket() = default;

    virtual bool bind(u16 port) = 0;
    virtual bool listen(i32 backlog = 128) = 0;
    virtual bool connect(stl::string_view host, u16 port) = 0;
    virtual ISocket* accept() = 0;
    virtual size_t send(stl::span<const std::byte>) = 0;
    virtual size_t recv(stl::span<std::byte>) = 0;
    virtual void close() = 0;
    virtual bool valid() const = 0;
};