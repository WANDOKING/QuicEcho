#pragma once

#include "../../ThirdParty/ClientNative/include/msquic.h"

#include <atomic>
#include <functional>
#include <vector>
#include <string>

enum class EQuicError;

struct QUIC_HANDLE;
typedef QUIC_HANDLE* HQUIC;
typedef long HRESULT;
struct QUIC_CONNECTION_EVENT;
struct QUIC_STREAM_EVENT;
struct QUIC_BUFFER;

class QuicClient
{
public:
    QuicClient(HQUIC Configuration);
    ~QuicClient();

    QuicClient(const QuicClient&) = delete;
    QuicClient& operator=(const QuicClient&) = delete;

    QuicClient(QuicClient&&) = delete;
    QuicClient& operator=(QuicClient&&) = delete;

public:
    bool Connect(const std::string& ipAddress, uint16_t port);
    bool ConnectAsync(const std::string& ipAddress, uint16_t port);

    void Close();
    void CloseAsync();

    bool Send(const uint8_t* data, const uint32_t count);
    bool SendAsync(uint8_t* data, const uint32_t count);
    bool SendAsync(std::vector<uint8_t>* data, std::function<void(bool)> onSent);

    bool IsConnected() const { return bIsConnected.load(); }
    EQuicError GetLastQuicError() const { return lastQuicError; }

protected:
    virtual void OnConnected(bool isConnectSucceed) = 0;
    virtual void OnClosed(EQuicError error) = 0;
    virtual void OnReceived(uint8_t* data, int32_t count) = 0;
    virtual void OnRemoteCertificateReceived(
        QUIC_CERTIFICATE* certificate,
        uint32_t deferredErrorFlags,
        HRESULT deferredStatus,
        QUIC_CERTIFICATE_CHAIN* chain);

public:
    static EQuicError ConvertQuicStatus(HRESULT status);

private:
    static HRESULT ConnectionCallback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event);
    static HRESULT StreamCallback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event);

    void SetLastQuicError(const EQuicError error) { lastQuicError = error; }

    void OnConnected(const uint8_t* negotiatedAlpn, const uint8_t negotiatedAlpnLength, const bool sessionResumed);

    void OnStreamReceived(const uint64_t absoluteOffset, const uint64_t totalBufferLength, const QUIC_BUFFER* buffers, const uint32_t bufferCount);
    void OnStreamSendComplete(void* clientContext, const bool isCanceled);

private:
    std::atomic<bool> bIsConnected;
    std::atomic<bool> bIsConnecting;

    /// <summary>
    /// 연결 설정을 나타내며, TLS 구성, 타임아웃 시간 등 QUIC 계층의 설정이 포함됩니다.
    /// </summary>
    HQUIC Configuration;

    HQUIC connection;
    HQUIC stream;

    EQuicError lastQuicError;

    std::function<void(bool)> onConnected;
    std::function<void(QuicClient*, EQuicError)> onClosed;
    std::function<void(QuicClient*, uint8_t*, int32_t)> onReceived;
};