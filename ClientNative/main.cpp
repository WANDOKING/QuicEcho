#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <format>
#include <conio.h>

#include "ClientNative/QuicWrapper.h"
#include "ClientNative/QuicClient.h"
#include "ClientNative/Assert.h"

#pragma comment(lib, "msquic.dll")

class TestQuicClient final : public QuicClient
{
public:
    TestQuicClient(HQUIC Configuration)
        : QuicClient(Configuration)
    {
        std::cout << "TestQuicClient Created\n";
    }

protected:
    // Inherited via QuicClient
    void OnConnected(bool isConnectSucceed) override
    {
        std::cout << std::format("Connected: {}\n", isConnectSucceed ? "Success" : "Failure");
    }

    void OnClosed(EQuicError error) override
    {
        std::cout << std::format("Closed: {}\n", QuicWrapper::QuicErrorToString(error));
    }

    void OnReceived(uint8_t* data, int32_t count) override
    {
        std::string received(reinterpret_cast<const char*>(data), static_cast<size_t>(count));
        std::cout << std::format("Received: {} | {}\n", count, received);
    }
};


int main(void)
{
    // QUIC Initialize
    QuicWrapper::Startup();

    // Configuration Open
    HQUIC Configuration = QuicWrapper::OpenConfigurationOrNull();

    // Client Create
    TestQuicClient client(Configuration);

    const int32_t messageLength = 100;
    std::string helloMessage(messageLength, 'a');

    // Non-blocking key check loop: send when 'q' or 'Q' is pressed.
    while (true)
    {
        if (_kbhit())
        {
            int input = _getch();
            char lowerInput = static_cast<char>(std::tolower(static_cast<unsigned char>(input)));

            switch (lowerInput)
            {
            case '1':
                if (client.IsConnected())
                {
                    break;
                }

                client.Connect("127.0.0.1", 23456);
                break;

            case '2':
                if (!client.IsConnected())
                {
                    break;
                }

                client.Close();
                goto END;
                break;

            case 's':
                client.Send(reinterpret_cast<const uint8_t*>(helloMessage.c_str()), messageLength);
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