#include "tls_internal.h"

namespace sap::network::internal {

    // Posix uses SSL_CTX_set_default_verify_paths() in build_ctx; this stub
    // exists only so acquire_ctx can call load_system_trust_store() on
    // Windows without a build-time #ifdef in the cross-platform code path.
    int load_system_trust_store(SSL_CTX*) { return 0; }

} // namespace sap::network::internal
