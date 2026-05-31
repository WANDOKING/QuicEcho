#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <format>
#include <conio.h>

#include <openssl/x509_vfy.h>

#include "QuicWrapper.h"
#include "QuicClient.h"
#include "CertificateValidator.h"

class TestQuicClient final : public QuicClient
{
public:
    TestQuicClient(HQUIC Configuration) : QuicClient(Configuration)
    {
        std::cout << "TestQuicClient Created\n";

        CertValidator.Initialize();
    }

    ~TestQuicClient()
    {
        CertValidator.Terminate();
    }

protected:
    void OnConnected(bool isConnectSucceed) override
    {
        std::cout << std::format("Connected: {}\n", isConnectSucceed ? "Success" : "Failure");
    }

    void OnClosed(EQuicError Error) override
    {
        std::cout << std::format("Closed: {}\n", QuicWrapper::QuicErrorToString(Error));
    }

    void OnReceived(uint8_t* Data, int32_t Count) override
    {
        std::string received(reinterpret_cast<const char*>(Data), static_cast<size_t>(Count));
        std::cout << std::format("Received: {} | {}\n", Count, received);
    }

    bool OnCertificateReceived(QUIC_CERTIFICATE* Certificate, QUIC_CERTIFICATE_CHAIN* Chain, QUIC_STATUS DeferredStatus) override
    {
        std::cout << "OnCertificateReceived called in TestQuicClient\n";

        int validationResult = CertValidator.ValidateCertificate(reinterpret_cast<X509*>(Certificate));
        if (validationResult == X509_V_OK)
        {
            return true;
        }

        std::cout << std::format("Certificate validation failed with error code: {}, Detail: {}\n", validationResult, CertificateValidator::GetInformationForCertificateValidation(validationResult));
        return false;
    }

private:
    CertificateValidator CertValidator;
};

int main(void)
{
    // QUIC Initialize
    QuicWrapper::Startup();

    if (QuicWrapper::UseOpenSSL())
    {
        std::cout << "Using OpenSSL as TLS Provider\n";
    }
    else
    {
        std::cout << "Using Schannel as TLS Provider\n";
    }

    // Configuration Open
    HQUIC Configuration = QuicWrapper::OpenConfigurationOrNull(0, 10'000, 5'000, true);

    // Client Create
    TestQuicClient Client(Configuration);

    std::cout << "Press '1' to Connect\n";
    std::cout << "Press '2' to Close\n";
    std::cout << "Press 's' to Send\n";
    std::cout << "Press 'p' to Print System Root Certificates\n";

    while (true)
    {
        if (_kbhit())
        {
            int Input = _getch();
            char LowerInput = static_cast<char>(std::tolower(static_cast<unsigned char>(Input)));

            switch (LowerInput)
            {
            case '1':
                if (Client.IsConnected())
                {
                    break;
                }

                Client.Connect("127.0.0.1", 23456);
                break;

            case '2':
                if (!Client.IsConnected())
                {
                    break;
                }

                Client.Close();
                goto END;
                break;

            case 's':
            {
                const int32_t MessageLength = 100;
                std::string HelloMessage(MessageLength, 'a');
                Client.Send(reinterpret_cast<const uint8_t*>(HelloMessage.c_str()), MessageLength);
            }
            break;

            case 'p':
            {
                std::vector<std::string> RootCerts = CertificateValidator::GetSystemRootCertificates();
                for (const auto& cert : RootCerts)
                {
                    std::cout << "Root Certificate:\n" << cert << "\n";
                }
            }
            break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

END:
    // Cleanup
    QuicWrapper::CloseConfiguration(Configuration);
    QuicWrapper::Cleanup();
}