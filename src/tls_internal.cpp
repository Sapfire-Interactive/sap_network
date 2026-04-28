#include "tls_internal.h"

#include <cstring>
#include <sap_core/stl/string.h>
#include <sap_core/stl/unordered_map.h>
#include <sap_core/stl/unique_ptr.h>
#include <sap_core/types.h>

#include <string>

namespace sap::network::internal {

    stl::string drain_ssl_errors() {
        stl::string out;
        char buf[256];
        unsigned long err;
        while ((err = ::ERR_get_error()) != 0) {
            ::ERR_error_string_n(err, buf, sizeof(buf));
            if (!out.empty())
                out += "; ";
            out += buf;
        }
        return out.empty() ? stl::string{"<no openssl error>"} : out;
    }

    namespace {

        // ---- shared helpers ------------------------------------------------

        void mix_hash(size_t& h, size_t v) {
            h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        }

        int min_proto_version_int(ETlsMinVersion v) {
            return v == ETlsMinVersion::TLS_1_3 ? TLS1_3_VERSION : TLS1_2_VERSION;
        }

        // ---- client cache --------------------------------------------------

        struct ClientCtxKey {
            bool verify_peer;
            bool verify_hostname;
            stl::string ca_file;
            stl::string ca_dir;
            stl::string client_cert_file;
            stl::string client_key_file;
            stl::vector<stl::string> alpn;
            ETlsMinVersion min_version;

            bool operator==(const ClientCtxKey&) const = default;
        };

        struct ClientCtxKeyHash {
            size_t operator()(const ClientCtxKey& k) const noexcept {
                size_t h = std::hash<bool>{}(k.verify_peer);
                mix_hash(h, std::hash<bool>{}(k.verify_hostname));
                mix_hash(h, std::hash<stl::string>{}(k.ca_file));
                mix_hash(h, std::hash<stl::string>{}(k.ca_dir));
                mix_hash(h, std::hash<stl::string>{}(k.client_cert_file));
                mix_hash(h, std::hash<stl::string>{}(k.client_key_file));
                for (const auto& p : k.alpn)
                    mix_hash(h, std::hash<stl::string>{}(p));
                mix_hash(h, std::hash<int>{}(static_cast<int>(k.min_version)));
                return h;
            }
        };

        struct ClientCtxEntry {
            SSL_CTX* ctx = nullptr;
            ~ClientCtxEntry() {
                if (ctx)
                    ::SSL_CTX_free(ctx);
            }
        };

        ClientCtxKey make_client_key(const TlsClientConfig& cfg) {
            return {cfg.verify_peer,
                    cfg.verify_hostname,
                    cfg.ca_file,
                    cfg.ca_dir,
                    cfg.client_cert_file,
                    cfg.client_key_file,
                    cfg.alpn_protocols,
                    cfg.min_version};
        }

        SSL_CTX* build_client_ctx(const TlsClientConfig& cfg) {
            SSL_CTX* ctx = ::SSL_CTX_new(::TLS_client_method());
            if (ctx == nullptr)
                return nullptr;

            ::SSL_CTX_set_min_proto_version(ctx, min_proto_version_int(cfg.min_version));
            ::SSL_CTX_set_max_early_data(ctx, 0); // disable 0-RTT replay surface

            ::SSL_CTX_set_verify(ctx, cfg.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

            if (!cfg.ca_file.empty()) {
                ::SSL_CTX_load_verify_locations(ctx, cfg.ca_file.c_str(), nullptr);
            } else if (!cfg.ca_dir.empty()) {
                ::SSL_CTX_load_verify_locations(ctx, nullptr, cfg.ca_dir.c_str());
            } else {
#ifdef _WIN32
                load_system_trust_store(ctx);
#else
                ::SSL_CTX_set_default_verify_paths(ctx);
#endif
            }

            if (!cfg.client_cert_file.empty() && !cfg.client_key_file.empty()) {
                ::SSL_CTX_use_certificate_chain_file(ctx, cfg.client_cert_file.c_str());
                ::SSL_CTX_use_PrivateKey_file(ctx, cfg.client_key_file.c_str(), SSL_FILETYPE_PEM);
            }

            return ctx;
        }

        // ---- server cache --------------------------------------------------

        struct ServerCtxKey {
            stl::string cert_file;
            stl::string key_file;
            stl::string ca_file;
            stl::string ca_dir;
            bool require_client_cert;
            stl::vector<stl::string> alpn;
            ETlsMinVersion min_version;

            bool operator==(const ServerCtxKey&) const = default;
        };

        struct ServerCtxKeyHash {
            size_t operator()(const ServerCtxKey& k) const noexcept {
                size_t h = std::hash<stl::string>{}(k.cert_file);
                mix_hash(h, std::hash<stl::string>{}(k.key_file));
                mix_hash(h, std::hash<stl::string>{}(k.ca_file));
                mix_hash(h, std::hash<stl::string>{}(k.ca_dir));
                mix_hash(h, std::hash<bool>{}(k.require_client_cert));
                for (const auto& p : k.alpn)
                    mix_hash(h, std::hash<stl::string>{}(p));
                mix_hash(h, std::hash<int>{}(static_cast<int>(k.min_version)));
                return h;
            }
        };

        // Owns the SSL_CTX plus the alpn list in stable storage so the
        // server-side ALPN-select callback can reach the list via the
        // SSL_CTX_set_alpn_select_cb arg pointer.
        struct ServerCtxEntry {
            SSL_CTX* ctx = nullptr;
            stl::vector<stl::string> alpn;
            ~ServerCtxEntry() {
                if (ctx)
                    ::SSL_CTX_free(ctx);
            }
        };

        ServerCtxKey make_server_key(const TlsServerConfig& cfg) {
            return {cfg.cert_file,
                    cfg.key_file,
                    cfg.ca_file,
                    cfg.ca_dir,
                    cfg.require_client_cert,
                    cfg.alpn_protocols,
                    cfg.min_version};
        }

        extern "C" int server_alpn_select_cb(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                                             unsigned int inlen, void* arg) {
            const auto* server_alpn = static_cast<const stl::vector<stl::string>*>(arg);
            for (const auto& proto : *server_alpn) {
                for (unsigned int i = 0; i < inlen;) {
                    unsigned int len = in[i];
                    if (i + 1u + len > inlen)
                        break;
                    if (len == proto.size() && std::memcmp(in + i + 1, proto.data(), len) == 0) {
                        *out = in + i + 1;
                        *outlen = static_cast<unsigned char>(len);
                        return SSL_TLSEXT_ERR_OK;
                    }
                    i += 1u + len;
                }
            }
            return SSL_TLSEXT_ERR_NOACK;
        }

        SSL_CTX* build_server_ctx(const TlsServerConfig& cfg, ServerCtxEntry& entry) {
            SSL_CTX* ctx = ::SSL_CTX_new(::TLS_server_method());
            if (ctx == nullptr)
                return nullptr;

            ::SSL_CTX_set_min_proto_version(ctx, min_proto_version_int(cfg.min_version));
            ::SSL_CTX_set_max_early_data(ctx, 0); // disable 0-RTT replay surface

            if (cfg.cert_file.empty() || cfg.key_file.empty()) {
                ::SSL_CTX_free(ctx);
                return nullptr;
            }
            if (::SSL_CTX_use_certificate_chain_file(ctx, cfg.cert_file.c_str()) != 1 ||
                ::SSL_CTX_use_PrivateKey_file(ctx, cfg.key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
                ::SSL_CTX_check_private_key(ctx) != 1) {
                ::SSL_CTX_free(ctx);
                return nullptr;
            }
            if (!entry.alpn.empty())
                ::SSL_CTX_set_alpn_select_cb(ctx, server_alpn_select_cb, &entry.alpn);

            if (cfg.require_client_cert) {
                // require_client_cert without trust roots is a misconfiguration
                // — no client cert can ever verify. Fail fast at ctx-build time.
                if (cfg.ca_file.empty() && cfg.ca_dir.empty()) {
                    ::SSL_CTX_free(ctx);
                    return nullptr;
                }
                const char* ca_file = cfg.ca_file.empty() ? nullptr : cfg.ca_file.c_str();
                const char* ca_dir  = cfg.ca_dir.empty() ? nullptr : cfg.ca_dir.c_str();
                if (::SSL_CTX_load_verify_locations(ctx, ca_file, ca_dir) != 1) {
                    ::SSL_CTX_free(ctx);
                    return nullptr;
                }
                // Send CertificateRequest and reject if the client doesn't
                // present a cert that verifies against the trust roots above.
                ::SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

                // Tell the client which CA names we accept. Without this a
                // client with multiple certs has to guess. Optional but free.
                // SSL_CTX_set_client_CA_list takes ownership of `names`.
                if (ca_file != nullptr) {
                    if (STACK_OF(X509_NAME)* names = ::SSL_load_client_CA_file(ca_file))
                        ::SSL_CTX_set_client_CA_list(ctx, names);
                }
            } else {
                ::SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
            }

            return ctx;
        }

        // ---- caches --------------------------------------------------------

        stl::mutex g_mu;
        stl::unordered_map<ClientCtxKey, stl::unique_ptr<ClientCtxEntry>, ClientCtxKeyHash> g_client_cache;
        stl::unordered_map<ServerCtxKey, stl::unique_ptr<ServerCtxEntry>, ServerCtxKeyHash> g_server_cache;

    } // namespace

    SSL_CTX* acquire_ctx(const TlsClientConfig& cfg) {
        ClientCtxKey key = make_client_key(cfg);
        stl::lock_guard lock(g_mu);
        if (auto it = g_client_cache.find(key); it != g_client_cache.end())
            return it->second->ctx;

        auto entry = stl::make_unique<ClientCtxEntry>();
        entry->ctx = build_client_ctx(cfg);
        if (entry->ctx == nullptr)
            return nullptr;

        SSL_CTX* result = entry->ctx;
        g_client_cache.emplace(std::move(key), std::move(entry));
        return result;
    }

    SSL_CTX* acquire_ctx(const TlsServerConfig& cfg) {
        ServerCtxKey key = make_server_key(cfg);
        stl::lock_guard lock(g_mu);
        if (auto it = g_server_cache.find(key); it != g_server_cache.end())
            return it->second->ctx;

        auto entry = stl::make_unique<ServerCtxEntry>();
        entry->alpn = cfg.alpn_protocols;
        entry->ctx = build_server_ctx(cfg, *entry);
        if (entry->ctx == nullptr)
            return nullptr;

        SSL_CTX* result = entry->ctx;
        g_server_cache.emplace(std::move(key), std::move(entry));
        return result;
    }

} // namespace sap::network::internal
