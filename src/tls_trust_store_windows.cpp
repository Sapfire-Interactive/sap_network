#include "tls_internal.h"

#include <wincrypt.h>
#include <windows.h>

namespace sap::network::internal {

    int load_system_trust_store(SSL_CTX* ctx) {
        HCERTSTORE store = ::CertOpenSystemStoreW(0, L"ROOT");
        if (store == nullptr)
            return 0;

        X509_STORE* x509_store = ::SSL_CTX_get_cert_store(ctx);
        int added = 0;
        PCCERT_CONTEXT cert = nullptr;
        while ((cert = ::CertEnumCertificatesInStore(store, cert)) != nullptr) {
            const unsigned char* der = cert->pbCertEncoded;
            X509* x = ::d2i_X509(nullptr, &der, static_cast<long>(cert->cbCertEncoded));
            if (x != nullptr) {
                if (::X509_STORE_add_cert(x509_store, x) == 1)
                    ++added;
                ::X509_free(x);
            }
        }
        ::CertCloseStore(store, 0);
        return added;
    }

} // namespace sap::network::internal
