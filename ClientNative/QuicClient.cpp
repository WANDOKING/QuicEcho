#include "QuicClient.h"

#include <iostream>
#include <format>
#include <thread>
#include <chrono>

#include "QuicWrapper.h"
#include "Assert.h"

// QUIC 콜백 메서드에 대한 SAL 주석 경고를 무시한다.
#pragma warning(disable : 28301)

// QUIC 전송 컨텍스트
struct QuicSendContext
{
    QUIC_BUFFER Buffer = {};
    bool* IsSendCompleted = nullptr;
    std::vector<uint8_t>* DataToDelete = nullptr;
    std::function<void(bool)> OnSent = nullptr;
};

_Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
QuicClient::ConnectionCallback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event)
{
    // Context로 QuicClient의 주소를 사용합니다.
    QuicClient* Client = static_cast<QuicClient*>(context);

    switch (event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        Client->OnConnected(
            event->CONNECTED.NegotiatedAlpn,
            event->CONNECTED.NegotiatedAlpnLength,
            event->CONNECTED.SessionResumed);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        Client->OnShutdownInitiatedByTransport(
            event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status,
            event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        Client->OnShutdownInitiatedByPeer(
            event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        Client->OnShutdownComplete(
            event->SHUTDOWN_COMPLETE.HandshakeCompleted,
            event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown,
            event->SHUTDOWN_COMPLETE.AppCloseInProgress);
        break;

    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        Client->OnLocalAddressChanged(
            event->LOCAL_ADDRESS_CHANGED.Address);
        break;

    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        Client->OnStreamsAvailable(
            event->STREAMS_AVAILABLE.BidirectionalCount,
            event->STREAMS_AVAILABLE.UnidirectionalCount);
        break;

    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
        Client->OnPeerNeedsStreams(
            event->PEER_NEEDS_STREAMS.Bidirectional);
        break;

    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        Client->OnIdealProcessorChanged(
            event->IDEAL_PROCESSOR_CHANGED.IdealProcessor);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        Client->OnDatagramStateChanged(
            event->DATAGRAM_STATE_CHANGED.SendEnabled,
            event->DATAGRAM_STATE_CHANGED.MaxSendLength);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        Client->OnDatagramReceived(
            event->DATAGRAM_RECEIVED.Buffer,
            event->DATAGRAM_RECEIVED.Flags);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        Client->OnDatagramSendStateChanged(
            event->DATAGRAM_SEND_STATE_CHANGED.ClientContext,
            event->DATAGRAM_SEND_STATE_CHANGED.State);
        break;

    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        Client->OnResumptionTicketReceived(
            event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
            event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        break;

    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        Client->OnRemoteCertificateReceived(
            event->PEER_CERTIFICATE_RECEIVED.Certificate,
            event->PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags,
            event->PEER_CERTIFICATE_RECEIVED.DeferredStatus,
            event->PEER_CERTIFICATE_RECEIVED.Chain);

        // NOTE: 바로 위인 OnRemoteCertificateReceived의 결과
        if (false == Client->bIsCertificateAccepted)
        {
            return QUIC_STATUS_BAD_CERTIFICATE;
        }

        break;

    case QUIC_CONNECTION_EVENT_RESUMED:
        LIVE_ASSERT(false, "QUIC_CONNECTION_EVENT_RESUMED is only for server.");
        break;

    default:
        LIVE_ASSERT(false, "Unknown QUIC_CONNECTION_EVENT");
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
QuicClient::StreamCallback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event)
{
    // Context로 QuicClient의 주소를 사용합니다.
    QuicClient* Client = static_cast<QuicClient*>(context);

    switch (event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        Client->OnStreamStartComplete(
            event->START_COMPLETE.Status,
            event->START_COMPLETE.ID,
            event->START_COMPLETE.PeerAccepted);
        // TODO: RESERVED가 뭔지 체크좀
        break;

    case QUIC_STREAM_EVENT_RECEIVE:
        Client->OnStreamReceived(
            event->RECEIVE.AbsoluteOffset,
            event->RECEIVE.TotalBufferLength,
            event->RECEIVE.Buffers,
            event->RECEIVE.BufferCount,
            event->RECEIVE.Flags);
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        Client->OnStreamSendComplete(
            event->SEND_COMPLETE.ClientContext,
            event->SEND_COMPLETE.Canceled);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        Client->OnStreamPeerSendShutdown();
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        Client->OnStreamPeerSendAborted(
            event->PEER_SEND_ABORTED.ErrorCode);
        break;

    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        Client->OnStreamPeerReceiveAborted(
            event->PEER_RECEIVE_ABORTED.ErrorCode);
        break;

    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        Client->OnStreamSendShutdownComplete(
            event->SEND_SHUTDOWN_COMPLETE.Graceful);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        Client->OnStreamShutdownComplete(
            event->SHUTDOWN_COMPLETE.ConnectionShutdown,
            event->SHUTDOWN_COMPLETE.AppCloseInProgress,
            event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp,
            event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely,
            event->SHUTDOWN_COMPLETE.ConnectionErrorCode,
            event->SHUTDOWN_COMPLETE.ConnectionCloseStatus);
        break;

    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        Client->OnStreamIdealSendBufferSize(
            event->IDEAL_SEND_BUFFER_SIZE.ByteCount);
        break;

    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
        Client->OnStreamPeerAccepted();
        break;

    default:
        LIVE_ASSERT(false, "Unknown QUIC_STREAM_EVENT");
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

void QuicClient::OnConnected(const uint8_t* negotiatedAlpn, const uint8_t negotiatedAlpnLength, const bool sessionResumed)
{
    NegotiatedAlpn = std::string(reinterpret_cast<const char*>(negotiatedAlpn), negotiatedAlpnLength);
    std::cout << std::format("OnConnected called: ALPN:{}, sessionResumed={}\n", NegotiatedAlpn, sessionResumed);

    bIsConnected.store(true);
    bIsConnecting.store(false);
    OnConnected(true);
}

void QuicClient::OnShutdownInitiatedByTransport(QUIC_STATUS status, QUIC_UINT62 errorCode)
{
    std::cout << "OnShutdownInitiatedByTransport called\n";

    SetLastQuicError(QuicWrapper::ConvertQuicStatus(status));
}

void QuicClient::OnShutdownInitiatedByPeer(QUIC_UINT62 errorCode)
{
    std::cout << "OnShutdownInitiatedByPeer called\n";

    SetLastQuicError(EQuicError::Aborted);
}

void QuicClient::OnShutdownComplete(bool handshakeCompleted, bool peerAcknowledgedShutdown, bool appCloseInProgress)
{
    std::cout << "OnShutdownComplete called:\n";

    bIsConnecting.store(false);
    bIsConnected.store(false);

    if (handshakeCompleted)
    {
        OnClosed(LastQuicError);
    }
    else
    {
        OnConnected(false);
    }

    // NOTE: appCloseInProgress
    // A flag indicating that the application called ConnectionClose on this connection.
    if (appCloseInProgress)
    {
        QuicWrapper::CloseConnection(Connection);
        Connection = nullptr;
    }
}

void QuicClient::OnStreamStartComplete(QUIC_STATUS status, QUIC_UINT62 id, bool peerAccepted)
{
    std::cout << "OnStreamStartComplete called\n";
}

void QuicClient::OnStreamReceived(const uint64_t absoluteOffset, const uint64_t totalBufferLength, const QUIC_BUFFER* buffers, const uint32_t bufferCount, const QUIC_RECEIVE_FLAGS flags)
{
    std::cout << "OnStreamReceived called\n";

    for (uint32_t i = 0; i < bufferCount; i++)
    {
        OnReceived(buffers[i].Buffer, buffers[i].Length);
    }
}

void QuicClient::OnStreamSendComplete(void* clientContext, const bool isCanceled)
{
    std::cout << "OnStreamSendComplete called\n";

    QuicSendContext* sendContext = static_cast<QuicSendContext*>(clientContext);

    if (sendContext->IsSendCompleted != nullptr)
    {
        *(sendContext->IsSendCompleted) = true;
    }

    if (sendContext->OnSent != nullptr)
    {
        sendContext->OnSent(true);
    }

    delete sendContext->DataToDelete;
    delete sendContext;
}

void QuicClient::OnStreamPeerSendShutdown()
{
    std::cout << "OnStreamPeerSendShutdown called\n";
}

void QuicClient::OnStreamPeerSendAborted(QUIC_UINT62 errorCode)
{
    std::cout << std::format("OnStreamPeerSendAborted called: errorCode={}\n", errorCode);
}

void QuicClient::OnStreamPeerReceiveAborted(QUIC_UINT62 errorCode)
{
    std::cout << std::format("OnStreamPeerReceiveAborted called: errorCode={}\n", errorCode);
}

void QuicClient::OnStreamSendShutdownComplete(bool graceful)
{
    std::cout << std::format("OnStreamSendShutdownComplete called: graceful={}\n", graceful);
}

void QuicClient::OnStreamShutdownComplete(bool connectionShutdown, bool appCloseInProgress, bool connectionShutdownByApp, bool connectionClosedRemotely, QUIC_UINT62 connectionErrorCode, QUIC_STATUS connectionCloseStatus)
{
    QuicWrapper::CloseStream(Stream);
}

void QuicClient::OnStreamIdealSendBufferSize(uint64_t byteCount)
{
    std::cout << std::format("OnStreamIdealSendBufferSize called: ideal send buffer size={}\n", byteCount);
}

void QuicClient::OnStreamPeerAccepted()
{
    std::cout << "OnStreamPeerAccepted called\n";
}

QuicClient::QuicClient(HQUIC Configuration)
    : Configuration(Configuration)
    , Connection(nullptr)
    , Stream(nullptr)
    , LastQuicError(EQuicError::Success)
{
    bIsCertificateAccepted.store(false);
    bIsConnected.store(false);
    bIsConnecting.store(false);
}

QuicClient::~QuicClient()
{
    Close();
}

bool QuicClient::Connect(const std::string& InServerName, uint16_t InServerPort)
{
    bIsConnecting.store(true);

    bool retConnectAsync = ConnectAsync(InServerName, InServerPort);
    if (false == retConnectAsync)
    {
        bIsConnecting.store(false);
        return false;
    }

    while (bIsConnecting.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return bIsConnected.load();
}

bool QuicClient::ConnectAsync(const std::string& InServerName, uint16_t InServerPort)
{
    QuicWrapper::CreateConnection(ConnectionCallback, this, &Connection);
    QuicWrapper::OpenStream(Connection, &Stream, this, StreamCallback);
    return QuicWrapper::Connect(Connection, Configuration, InServerName.c_str(), InServerPort);
}

void QuicClient::Close()
{
    CloseAsync();

    while (IsConnected())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void QuicClient::CloseAsync()
{
    if (Connection)
    {
        QuicWrapper::ShutdownConnection(Connection);
        Connection = nullptr;
    }
}

bool QuicClient::Send(const uint8_t* data, const uint32_t count)
{
    bool isSendCompleted = false;

    QuicSendContext* context = new QuicSendContext;
    context->Buffer.Buffer = const_cast<uint8_t*>(data);
    context->Buffer.Length = count;
    context->IsSendCompleted = &isSendCompleted;

    if (false == QuicWrapper::Send(Stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
    {
        delete context;
        return false;
    }

    while (!isSendCompleted)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return true;
}

bool QuicClient::SendAsync(uint8_t* data, const uint32_t count)
{
    QuicSendContext* context = new QuicSendContext;
    context->Buffer.Buffer = data;
    context->Buffer.Length = count;

    if (false == QuicWrapper::Send(Stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
    {
        delete context;
        return false;
    }

    return true;
}

bool QuicClient::SendAsync(std::vector<uint8_t>* data, std::function<void(bool)> onSent)
{
    QuicSendContext* context = new QuicSendContext;
    context->Buffer.Buffer = data->data();
    context->Buffer.Length = static_cast<uint32_t>(data->size());
    context->DataToDelete = data;
    context->OnSent = onSent;

    if (false == QuicWrapper::Send(Stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
    {
        delete context;
        delete data;
        return false;
    }

    return true;
}

bool QuicClient::OnCertificateReceived(QUIC_CERTIFICATE* Certificate, QUIC_CERTIFICATE_CHAIN* Chain, QUIC_STATUS DeferredStatus)
{
    if (QUIC_FAILED(DeferredStatus))
    {
        if (DeferredStatus == QUIC_STATUS_CERT_EXPIRED)
        {
            std::cout << "Certificate validation failed with error. QUIC_STATUS_CERT_EXPIRED.\n";
        }
        else if (DeferredStatus == QUIC_STATUS_CERT_UNTRUSTED_ROOT)
        {
            std::cout << "Certificate validation failed with TLS error. QUIC_STATUS_CERT_UNTRUSTED_ROOT.\n";
        }
        else if (DeferredStatus == QUIC_STATUS_CERT_NO_CERT)
        {
            std::cout << "Certificate validation failed with error. QUIC_STATUS_CERT_NO_CERT.\n";
        }
        else
        {
            std::cout << "Certificate validation failed with unknown error.\n";
        }

        return false;
    }

    return true;
}

void QuicClient::OnRemoteCertificateReceived(QUIC_CERTIFICATE* certificate, uint32_t deferredErrorFlags, QUIC_STATUS deferredStatus, QUIC_CERTIFICATE_CHAIN* chain)
{
    LIVE_ASSERT(deferredErrorFlags == 0, "deferredErrorFlags only supported at SChannel.");
    std::cout << std::format("OnRemoteCertificateReceived called: deferredErrorFlags={}, deferredStatus={}\n", deferredErrorFlags, deferredStatus);
    bIsCertificateAccepted = OnCertificateReceived(certificate, chain, deferredStatus);
}

void QuicClient::OnLocalAddressChanged(const QUIC_ADDR* address)
{
    std::cout << std::format("OnLocalAddressChanged called: {}:{}\n", address->Ipv4.sin_port, address->Ipv4.sin_addr.S_un.S_addr);
}

void QuicClient::OnStreamsAvailable(uint16_t bidirectionalCount, uint16_t unidirectionalCount)
{
    std::cout << std::format("OnStreamsAvailable called: {} bidirectional, {} unidirectional\n", bidirectionalCount, unidirectionalCount);
}

void QuicClient::OnPeerNeedsStreams(bool isBidirectional)
{
    std::cout << std::format("OnPeerNeedsStreams called: needs {} streams\n", isBidirectional ? "bidirectional" : "unidirectional");
}

void QuicClient::OnIdealProcessorChanged(uint16_t idealProcessor)
{
    std::cout << std::format("OnIdealProcessorChanged called: ideal processor={}\n", idealProcessor);
}

void QuicClient::OnDatagramStateChanged(bool sendEnabled, uint16_t maxSendLength)
{
    std::cout << std::format("OnDatagramStateChanged called: sendEnabled={}, maxSendLength={}\n", sendEnabled, maxSendLength);
}

void QuicClient::OnDatagramReceived(const QUIC_BUFFER* buffer, QUIC_RECEIVE_FLAGS flags)
{
    std::string received(reinterpret_cast<const char*>(buffer->Buffer), static_cast<size_t>(buffer->Length));
    std::cout << std::format("OnDatagramReceived called: {} | {} | flags={}\n", buffer->Length, received, static_cast<uint32_t>(flags));
}

void QuicClient::OnDatagramSendStateChanged(void* clientContext, QUIC_DATAGRAM_SEND_STATE state)
{
    std::cout << std::format("OnDatagramSendStateChanged called: state={}\n", static_cast<uint32_t>(state));
}

void QuicClient::OnResumptionTicketReceived(const uint8_t* resumptionTicket, uint32_t resumptionTicketLength)
{
    std::cout << std::format("OnResumptionTicketReceived called: length={}\n", resumptionTicketLength);
}
