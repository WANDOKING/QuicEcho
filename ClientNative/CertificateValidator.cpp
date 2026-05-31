#include "CertificateValidator.h"

#include "Assert.h"

#if _WIN32
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

// wincrypt.h defines these as macros; undef before OpenSSL redefines them as types
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#elif __linux__
#include <filesystem>
#include <fstream>

#endif

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void CertificateValidator::Initialize()
{
    Terminate();

    store = X509_STORE_new();
    LIVE_ASSERT(store != nullptr, "X509_STORE_new failed");

    std::vector<std::string> rootCertificates = GetSystemRootCertificates();

    for (const auto& pemStr : rootCertificates)
    {
        AddPemCertificate(pemStr);
    }
}

bool CertificateValidator::AddPemCertificate(const std::string& PemCertificate)
{
    BIO* bio = BIO_new_mem_buf(PemCertificate.data(), static_cast<int>(PemCertificate.size()));
    LIVE_ASSERT(bio != nullptr, "BIO_new_mem_buf failed");

    X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (x509 == nullptr)
    {
        ERR_clear_error();
        return false;
    }

    X509_STORE_add_cert(store, x509);
    ERR_clear_error();
    X509_free(x509);

    return true;
}

void CertificateValidator::Terminate()
{
    if (store)
    {
        X509_STORE_free(store);
    }

    store = nullptr;
}

int CertificateValidator::ValidateCertificate(X509* Certificate) const
{
    LIVE_ASSERT(store != nullptr, "store is nullptr - Initialize() was not called");
    LIVE_ASSERT(Certificate != nullptr, "Certificate is nullptr");

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    LIVE_ASSERT(ctx != nullptr, "X509_STORE_CTX_new failed");

    int retCtxInit = X509_STORE_CTX_init(ctx, store, Certificate, nullptr);
    LIVE_ASSERT(retCtxInit == 1, "X509_STORE_CTX_init failed");

    int retVerify = X509_verify_cert(ctx);
    if (retVerify == 1)
    {
        X509_STORE_CTX_free(ctx);
        return X509_V_OK;
    }

    int errorCode = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);

    return errorCode;
}

std::vector<std::string> CertificateValidator::GetSystemRootCertificates()
{
    std::vector<std::string> certs;

#if _WIN32
    HCERTSTORE hCertStore = CertOpenSystemStoreW(NULL, L"ROOT");
    LIVE_ASSERT(hCertStore != NULL, "CertOpenSystemStoreW failed");

    PCCERT_CONTEXT pCertContext = nullptr;
    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != nullptr)
    {
        const uint8_t* der = pCertContext->pbCertEncoded;
        X509* x509 = d2i_X509(nullptr, &der, static_cast<long>(pCertContext->cbCertEncoded));
        if (x509 == nullptr)
        {
            ERR_clear_error();
            continue;
        }

        BIO* bio = BIO_new(BIO_s_mem());
        LIVE_ASSERT(bio != nullptr, "BIO_new failed");

        PEM_write_bio_X509(bio, x509);
        X509_free(x509);

        char* pemData = nullptr;
        long pemLen = BIO_get_mem_data(bio, &pemData);
        certs.emplace_back(pemData, pemLen);

        BIO_free(bio);
    }

    CertCloseStore(hCertStore, 0);

#elif __linux__
    const std::filesystem::path certsDir = "/etc/ssl/certs";

    if (!std::filesystem::exists(certsDir))
    {
        return certs;
    }

    for (const auto& entry : std::filesystem::directory_iterator(certsDir))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        const auto& ext = entry.path().extension();
        if (ext != ".pem" && ext != ".crt")
        {
            continue;
        }

        std::ifstream file(entry.path(), std::ios::binary);
        if (!file.is_open())
        {
            continue;
        }

        certs.emplace_back(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
#else
#error "Unsupported platform"
#endif

    return certs;
}

const char* CertificateValidator::GetInformationForCertificateValidation(int ErrorCode)
{
    return X509_verify_cert_error_string(ErrorCode);
}
