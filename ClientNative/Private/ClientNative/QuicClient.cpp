#include "ClientNative/QuicClient.h"

#include <iostream>
#include <thread>
#include <chrono>

#include "ClientNative/QuicWrapper.h"
#include "ClientNative/Assert.h"

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
    QuicClient* client = static_cast<QuicClient*>(context);

    switch (event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        client->OnConnected(event->CONNECTED.NegotiatedAlpn, event->CONNECTED.NegotiatedAlpnLength, event->CONNECTED.SessionResumed);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        client->SetLastQuicError(QuicClient::ConvertQuicStatus(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        client->SetLastQuicError(EQuicError::Aborted);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        client->bIsConnected.store(false);

        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            QuicWrapper::CloseConnection(connection);
        }

        if (event->SHUTDOWN_COMPLETE.HandshakeCompleted)
        {
            client->OnConnected(false);
            client->OnClosed(client->lastQuicError);
        }
        else
        {
            // 연결 실패 상황
            client->bIsConnecting.store(false);
            client->OnClosed(client->lastQuicError);
        }

        break;

    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        client->OnRemoteCertificateReceived(
            event->PEER_CERTIFICATE_RECEIVED.Certificate,
            event->PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags,
            event->PEER_CERTIFICATE_RECEIVED.DeferredStatus,
            event->PEER_CERTIFICATE_RECEIVED.Chain);
        break;

        // 사용하지 않는 이벤트
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
    case QUIC_CONNECTION_EVENT_RESUMED:
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
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
    QuicClient* client = static_cast<QuicClient*>(context);

    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        // QUIC_RECEIVE_FLAGS는 귀찮아서 제외.
        client->OnStreamReceived(event->RECEIVE.AbsoluteOffset, event->RECEIVE.TotalBufferLength, event->RECEIVE.Buffers, event->RECEIVE.BufferCount);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        client->OnStreamSendComplete(event->SEND_COMPLETE.ClientContext, event->SEND_COMPLETE.Canceled);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        QuicWrapper::CloseStream(stream);
        break;

        // 사용하지 않는 이벤트
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_START_COMPLETE:
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        break;

    default:
        LIVE_ASSERT(false, "Unknown QUIC_STREAM_EVENT");
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

void QuicClient::OnConnected(const uint8_t* negotiatedAlpn, const uint8_t negotiatedAlpnLength, const bool sessionResumed)
{
    bIsConnected.store(true);
    bIsConnecting.store(false);
    OnConnected(true);
}

void QuicClient::OnStreamReceived(const uint64_t absoluteOffset, const uint64_t totalBufferLength, const QUIC_BUFFER* buffers, const uint32_t bufferCount)
{
    for (uint32_t i = 0; i < bufferCount; i++)
    {
        OnReceived(buffers[i].Buffer, buffers[i].Length);
    }
}

void QuicClient::OnStreamSendComplete(void* clientContext, const bool isCanceled)
{
    std::cout << "OnStreamSendComplete called" << std::endl;

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

QuicClient::QuicClient(HQUIC Configuration)
    : lastQuicError(EQuicError::Success)
    , Configuration(Configuration)
    , onConnected(nullptr)
    , onClosed(nullptr)
    , onReceived(nullptr)
{
    bIsConnected.store(false);
    QuicWrapper::CreateConnection(ConnectionCallback, this, &connection);
    QuicWrapper::OpenStream(connection, &stream, this, StreamCallback);
}

QuicClient::~QuicClient()
{
    Close();
}

bool QuicClient::Connect(const std::string& ipAddr, uint16_t port)
{
    bIsConnecting.store(true);
    QuicWrapper::Connect(connection, Configuration, ipAddr.c_str(), port);

    while (bIsConnecting.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return bIsConnected.load();
}

bool QuicClient::ConnectAsync(const std::string& ipAddr, uint16_t port)
{
    return QuicWrapper::Connect(connection, Configuration, ipAddr.c_str(), port);
}

void QuicClient::Close()
{
    if (IsConnected() == false)
    {
        return;
    }

    QuicWrapper::ShutdownConnection(connection);

    while (IsConnected())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void QuicClient::CloseAsync()
{
    if (IsConnected() == false)
    {
        return;
    }

    QuicWrapper::CloseConnection(connection);
}

bool QuicClient::Send(const uint8_t* data, const uint32_t count)
{
    bool isSendCompleted = false;

    QuicSendContext* context = new QuicSendContext;
    context->Buffer.Buffer = const_cast<uint8_t*>(data);
    context->Buffer.Length = count;
    context->IsSendCompleted = &isSendCompleted;

    if (false == QuicWrapper::Send(stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
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

    if (false == QuicWrapper::Send(stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
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

    if (false == QuicWrapper::Send(stream, reinterpret_cast<QUIC_BUFFER*>(context), context))
    {
        delete context;
        delete data;
        return false;
    }

    return true;
}

void QuicClient::OnRemoteCertificateReceived(QUIC_CERTIFICATE* certificate, uint32_t deferredErrorFlags, HRESULT deferredStatus, QUIC_CERTIFICATE_CHAIN* chain)
{
    std::cout << "OnRemoteCertificateReceived called" << std::endl;
}

EQuicError QuicClient::ConvertQuicStatus(HRESULT status)
{
    switch (status)
    {
    case QUIC_STATUS_SUCCESS:               return EQuicError::Success;
    case QUIC_STATUS_OUT_OF_MEMORY:         return EQuicError::OutOfMemory;
    case QUIC_STATUS_INVALID_PARAMETER:     return EQuicError::InvalidParameter;
    case QUIC_STATUS_INVALID_STATE:         return EQuicError::InvalidState;
    case QUIC_STATUS_NOT_SUPPORTED:         return EQuicError::NotSupported;
    case QUIC_STATUS_NOT_FOUND:             return EQuicError::NotFound;
    case QUIC_STATUS_BUFFER_TOO_SMALL:      return EQuicError::BufferTooSmall;
    case QUIC_STATUS_HANDSHAKE_FAILURE:     return EQuicError::HandshakeFailure;
    case QUIC_STATUS_ABORTED:               return EQuicError::Aborted;
    case QUIC_STATUS_ADDRESS_IN_USE:        return EQuicError::AddressInUse;
    case QUIC_STATUS_INVALID_ADDRESS:       return EQuicError::InvalidAddress;
    case QUIC_STATUS_CONNECTION_TIMEOUT:    return EQuicError::ConnectionTimeout;
    case QUIC_STATUS_CONNECTION_IDLE:       return EQuicError::ConnectionIdle;
    case QUIC_STATUS_INTERNAL_ERROR:        return EQuicError::InternalError;
    case QUIC_STATUS_UNREACHABLE:           return EQuicError::Unreachable;
    case QUIC_STATUS_CONNECTION_REFUSED:    return EQuicError::ConnectionRefused;
    case QUIC_STATUS_PROTOCOL_ERROR:        return EQuicError::ProtocolError;
    case QUIC_STATUS_VER_NEG_ERROR:         return EQuicError::VersionNegotiation;
    case QUIC_STATUS_USER_CANCELED:         return EQuicError::UserCanceled;
    case QUIC_STATUS_ALPN_NEG_FAILURE:      return EQuicError::AlpnNegotiationFailure;
    case QUIC_STATUS_STREAM_LIMIT_REACHED:  return EQuicError::StreamLimitReached;
    default:                                return EQuicError::Unknown;
    }
}
