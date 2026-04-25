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

        struct CtxKey {
            ETlsRole role;
            bool verify_peer;
            bool verify_hostname;
            stl::string ca_file;
            stl::string ca_dir;
            stl::string client_cert_file;
            stl::string client_key_file;
            stl::string server_cert_file;
            stl::string server_key_file;
            stl::vector<stl::string> alpn;
            TlsConfig::EMinVersion min_version;

            bool operator==(const CtxKey&) const = default;
        };

        struct CtxKeyHash {
            size_t operator()(const CtxKey& k) const noexcept {
                size_t h = std::hash<int>{}(static_cast<int>(k.role));
                auto mix = [&](size_t v) { h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2); };
                mix(std::hash<bool>{}(k.verify_peer));
                mix(std::hash<bool>{}(k.verify_hostname));
                mix(std::hash<stl::string>{}(k.ca_file));
                mix(std::hash<stl::string>{}(k.ca_dir));
                mix(std::hash<stl::string>{}(k.client_cert_file));
                mix(std::hash<stl::string>{}(k.client_key_file));
                mix(std::hash<stl::string>{}(k.server_cert_file));
                mix(std::hash<stl::string>{}(k.server_key_file));
                for (const auto& p : k.alpn)
                    mix(std::hash<stl::string>{}(p));
                mix(std::hash<int>{}(static_cast<int>(k.min_version)));
                return h;
            }
        };

        // Owns the SSL_CTX plus the alpn list in stable storage so the
        // server-side ALPN-select callback can reach the list via the
        // SSL_CTX_set_alpn_select_cb arg pointer.
        struct CtxEntry {
            SSL_CTX* ctx = nullptr;
            stl::vector<stl::string> alpn;
            ~CtxEntry() {
                if (ctx)
                    ::SSL_CTX_free(ctx);
            }
        };

        CtxKey make_key(const TlsConfig& cfg) {
            return {cfg.role,
                    cfg.verify_peer,
                    cfg.verify_hostname,
                    cfg.ca_file,
                    cfg.ca_dir,
                    cfg.client_cert_file,
                    cfg.client_key_file,
                    cfg.server_cert_file,
                    cfg.server_key_file,
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

        SSL_CTX* build_ctx(const TlsConfig& cfg, CtxEntry& entry) {
            const SSL_METHOD* method = (cfg.role == ETlsRole::Server) ? ::TLS_server_method() : ::TLS_client_method();
            SSL_CTX* ctx = ::SSL_CTX_new(method);
            if (ctx == nullptr)
                return nullptr;

            int min_version = (cfg.min_version == TlsConfig::EMinVersion::TLS_1_3) ? TLS1_3_VERSION : TLS1_2_VERSION;
            ::SSL_CTX_set_min_proto_version(ctx, min_version);
            ::SSL_CTX_set_max_early_data(ctx, 0); // disable 0-RTT replay surface

            if (cfg.role == ETlsRole::Server) {
                if (cfg.server_cert_file.empty() || cfg.server_key_file.empty()) {
                    ::SSL_CTX_free(ctx);
                    return nullptr;
                }
                if (::SSL_CTX_use_certificate_chain_file(ctx, cfg.server_cert_file.c_str()) != 1 ||
                    ::SSL_CTX_use_PrivateKey_file(ctx, cfg.server_key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
                    ::SSL_CTX_check_private_key(ctx) != 1) {
                    ::SSL_CTX_free(ctx);
                    return nullptr;
                }
                if (!entry.alpn.empty())
                    ::SSL_CTX_set_alpn_select_cb(ctx, server_alpn_select_cb, &entry.alpn);
            } else {
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
            }

            return ctx;
        }

        stl::mutex g_mu;
        stl::unordered_map<CtxKey, stl::unique_ptr<CtxEntry>, CtxKeyHash> g_cache;

    } // namespace

    SSL_CTX* acquire_ctx(const TlsConfig& cfg) {
        CtxKey key = make_key(cfg);
        stl::lock_guard lock(g_mu);
        if (auto it = g_cache.find(key); it != g_cache.end())
            return it->second->ctx;

        auto entry = stl::make_unique<CtxEntry>();
        entry->alpn = cfg.alpn_protocols;
        entry->ctx = build_ctx(cfg, *entry);
        if (entry->ctx == nullptr)
            return nullptr;

        SSL_CTX* result = entry->ctx;
        g_cache.emplace(std::move(key), std::move(entry));
        return result;
    }

} // namespace sap::network::internal
