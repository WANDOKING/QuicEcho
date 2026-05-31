#pragma once

#include <vector>
#include <string>

struct x509_st;
typedef struct x509_st X509;

struct x509_store_st;
typedef struct x509_store_st X509_STORE;

class CertificateValidator final
{
public:
    static std::vector<std::string> GetSystemRootCertificates();
    static const char* GetInformationForCertificateValidation(int ErrorCode);

public:
    void Initialize();
    void Terminate();

    int ValidateCertificate(X509* Certificate) const;

    bool AddPemCertificate(const std::string& PemCertificate);
private:
    X509_STORE* store = nullptr;
};