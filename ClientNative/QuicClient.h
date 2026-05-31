#pragma once

#include <msquic.h>

#include <atomic>
#include <functional>
#include <vector>
#include <string>

enum class EQuicError : int;

class QuicClient
{
public:
    QuicClient(HQUIC Configuration);
    virtual ~QuicClient();

    QuicClient(const QuicClient&) = delete;
    QuicClient& operator=(const QuicClient&) = delete;

    QuicClient(QuicClient&&) = delete;
    QuicClient& operator=(QuicClient&&) = delete;

public:
    bool Connect(const std::string& InServerName, uint16_t InServerPort);
    bool ConnectAsync(const std::string& InServerName, uint16_t InServerPort);

    void Close();
    void CloseAsync();

    bool Send(const uint8_t* Data, const uint32_t Count);
    bool SendAsync(uint8_t* Data, const uint32_t Count);
    bool SendAsync(std::vector<uint8_t>* Data, std::function<void(bool)> OnSentCallback);

    bool IsConnected() const { return bIsConnected.load(); }
    EQuicError GetLastQuicError() const { return LastQuicError; }

protected:
    virtual void OnConnected(bool bIsConnectedSuccessfully) = 0;
    virtual void OnClosed(EQuicError Error) = 0;
    virtual void OnReceived(uint8_t* Data, int32_t Count) = 0;

    virtual bool OnCertificateReceived(QUIC_CERTIFICATE* Certificate, QUIC_CERTIFICATE_CHAIN* Chain, QUIC_STATUS DeferredStatus);

private:
    void SetLastQuicError(const EQuicError InError) { LastQuicError = InError; }

private:
    /*
     * Connection Callbacks
     * 변수명은 MsQuic에서 사용하는 것을 그대로 사용
     */
    static QUIC_STATUS ConnectionCallback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event);

    void OnConnected(const uint8_t* negotiatedAlpn, const uint8_t negotiatedAlpnLength, const bool sessionResumed);
    void OnShutdownInitiatedByTransport(QUIC_STATUS status, QUIC_UINT62 errorCode);
    void OnShutdownInitiatedByPeer(QUIC_UINT62 errorCode);
    void OnShutdownComplete(bool handshakeCompleted, bool peerAcknowledgedShutdown, bool appCloseInProgress);
    void OnLocalAddressChanged(const QUIC_ADDR* address);
    void OnStreamsAvailable(uint16_t bidirectionalCount, uint16_t unidirectionalCount);
    void OnPeerNeedsStreams(bool isBidirectional);
    void OnIdealProcessorChanged(uint16_t idealProcessor);
    void OnDatagramStateChanged(bool sendEnabled, uint16_t maxSendLength);
    void OnDatagramReceived(const QUIC_BUFFER* buffer, QUIC_RECEIVE_FLAGS flags);
    void OnDatagramSendStateChanged(void* clientContext, QUIC_DATAGRAM_SEND_STATE state);
    void OnResumptionTicketReceived(const uint8_t* resumptionTicket, uint32_t resumptionTicketLength);
    void OnRemoteCertificateReceived(QUIC_CERTIFICATE* certificate, uint32_t deferredErrorFlags, QUIC_STATUS deferredStatus, QUIC_CERTIFICATE_CHAIN* chain);

private:
    /*
     * Stream Callbacks
     * 변수명은 MsQuic에서 사용하는 것을 그대로 사용
     */
    static QUIC_STATUS StreamCallback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event);

    void OnStreamStartComplete(QUIC_STATUS status, QUIC_UINT62 id, bool peerAccepted);
    void OnStreamReceived(const uint64_t absoluteOffset, const uint64_t totalBufferLength, const QUIC_BUFFER* buffers, const uint32_t bufferCount, const QUIC_RECEIVE_FLAGS flags);
    void OnStreamSendComplete(void* clientContext, const bool isCanceled);
    void OnStreamPeerSendShutdown();
    void OnStreamPeerSendAborted(QUIC_UINT62 errorCode);
    void OnStreamPeerReceiveAborted(QUIC_UINT62 errorCode);
    void OnStreamSendShutdownComplete(bool graceful);
    void OnStreamShutdownComplete(bool connectionShutdown, bool appCloseInProgress, bool connectionShutdownByApp, bool connectionClosedRemotely, QUIC_UINT62 connectionErrorCode, QUIC_STATUS connectionCloseStatus);
    void OnStreamIdealSendBufferSize(uint64_t byteCount);
    void OnStreamPeerAccepted();

private:
    std::atomic<bool> bIsCertificateAccepted;
    std::atomic<bool> bIsConnected;
    std::atomic<bool> bIsConnecting;
    EQuicError LastQuicError;
    HQUIC Configuration;
    HQUIC Connection;
    HQUIC Stream;
};