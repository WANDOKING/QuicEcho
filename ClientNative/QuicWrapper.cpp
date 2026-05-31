#include "QuicWrapper.h"
#include "Assert.h"

constexpr QUIC_UINT62 defaultStreamErrorCode = 0x0A;
constexpr QUIC_UINT62 DefaultCloseErrorCode = 0x0B;

const QUIC_BUFFER QuicWrapper::SLApplicationProtocol =
{
    sizeof("h3") - 1,
    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("h3"))
};

EQuicError QuicWrapper::ConvertQuicStatus(QUIC_STATUS status)
{
    switch (status)
    {
    case QUIC_STATUS_SUCCESS:               return EQuicError::Success;
    case QUIC_STATUS_PENDING:               return EQuicError::Pending;
    case QUIC_STATUS_CONTINUE:              return EQuicError::Continue;
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

void QuicWrapper::Startup()
{
    OpenMsQuic();
    OpenRegistration();
}

void QuicWrapper::Cleanup()
{
    CloseRegistration();
    CloseMsQuic();
}

bool QuicWrapper::UseOpenSSL()
{
    QUIC_TLS_PROVIDER TlsProvider = QUIC_TLS_PROVIDER_SCHANNEL;

    uint32_t BufferLength = sizeof(TlsProvider);
    QUIC_STATUS retGetParam = QuicApiTable->GetParam(nullptr, QUIC_PARAM_GLOBAL_TLS_PROVIDER, &BufferLength, &TlsProvider);
    if (QUIC_FAILED(retGetParam))
    {
        LIVE_ASSERT(false, "GetParam Failed");
    }

    if (TlsProvider == QUIC_TLS_PROVIDER_OPENSSL)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool QuicWrapper::CreateConnection(QUIC_CONNECTION_CALLBACK_HANDLER handler, void* context, HQUIC* outConnection)
{
    QUIC_STATUS retConnectionOpen = QuicApiTable->ConnectionOpen(Registration, handler, context, outConnection);
    if (QUIC_FAILED(retConnectionOpen))
    {
        LIVE_ASSERT(false, "MsQuic ConnectionOpen Failed");
        return false;
    }

    return true;
}

void QuicWrapper::ShutdownConnection(HQUIC connection)
{
    if (connection != nullptr)
    {
        QuicApiTable->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, DefaultCloseErrorCode);
    }
}

void QuicWrapper::CloseConnection(HQUIC connection)
{
    if (connection != nullptr)
    {
        QuicApiTable->ConnectionClose(connection);
    }
}

bool QuicWrapper::OpenStream(HQUIC connection, HQUIC* outStream, void* context, QUIC_STREAM_CALLBACK callback)
{
    if (connection == nullptr)
    {
        return false;
    }

    QUIC_STATUS retStreamOpen = QuicApiTable->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, callback, context, outStream);
    if (QUIC_FAILED(retStreamOpen))
    {
        LIVE_ASSERT(false, "MsQuic StreamOpen Failed");
        return false;
    }

    QUIC_STATUS retStreamStart = QuicApiTable->StreamStart(*outStream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(retStreamStart))
    {
        CloseStream(*outStream);
        ShutdownConnection(connection);
        return false;
    }

    return true;
}

void QuicWrapper::ShutdownStream(HQUIC stream)
{
    if (stream != nullptr)
    {
        QuicApiTable->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, defaultStreamErrorCode);
    }
}

bool QuicWrapper::Connect(HQUIC connection, HQUIC Configuration, const char* ip, uint16_t port)
{
    if (connection == nullptr)
    {
        return false;
    }

    QUIC_STATUS retConnectionStart = QuicApiTable->ConnectionStart(connection, Configuration, QUIC_ADDRESS_FAMILY_INET, ip, port);
    if (QUIC_FAILED(retConnectionStart))
    {
        return false;
    }

    return true;
}

bool QuicWrapper::Send(HQUIC stream, QUIC_BUFFER* buffer, void* sendContext)
{
    if (stream == nullptr || buffer == nullptr)
    {
        return false;
    }

    if (buffer->Length <= 0)
    {
        return false;
    }

    if (buffer->Buffer == nullptr)
    {
        return false;
    }

    QUIC_STATUS retStreamSend = QuicApiTable->StreamSend(stream, buffer, 1, QUIC_SEND_FLAG_NONE, sendContext);
    if (QUIC_FAILED(retStreamSend))
    {
        return false;
    }

    return true;
}

void QuicWrapper::CloseStream(HQUIC stream)
{
    QuicApiTable->StreamClose(stream);
}

std::string QuicWrapper::QuicErrorToString(const EQuicError Error)
{
    switch (Error)
    {
    case EQuicError::Success:                    return "Success";
    case EQuicError::OutOfMemory:                return "OutOfMemory";
    case EQuicError::InvalidParameter:           return "InvalidParameter";
    case EQuicError::InvalidState:               return "InvalidState";
    case EQuicError::NotSupported:               return "NotSupported";
    case EQuicError::NotFound:                   return "NotFound";
    case EQuicError::BufferTooSmall:            return "BufferTooSmall";
    case EQuicError::HandshakeFailure:           return "HandshakeFailure";
    case EQuicError::Aborted:                    return "Aborted";
    case EQuicError::AddressInUse:               return "AddressInUse";
    case EQuicError::InvalidAddress:             return "InvalidAddress";
    case EQuicError::ConnectionTimeout:          return "ConnectionTimeout";
    case EQuicError::ConnectionIdle:             return "ConnectionIdle";
    case EQuicError::InternalError:              return "InternalError";
    case EQuicError::Unreachable:                 return "Unreachable";
    case EQuicError::ConnectionRefused:          return "ConnectionRefused";
    case EQuicError::ProtocolError:              return "ProtocolError";
    case EQuicError::VersionNegotiation:         return "VersionNegotiation";
    case EQuicError::UserCanceled:               return "UserCanceled";
    case EQuicError::AlpnNegotiationFailure:     return "AlpnNegotiationFailure";
    case EQuicError::StreamLimitReached:         return "StreamLimitReached";
    case EQuicError::Unknown:                    return "Unknown";
    default:                                    return "InvalidQuicErrorValue";
    }
}

void QuicWrapper::OpenMsQuic()
{
    QUIC_STATUS retMsQuicOpen = ::MsQuicOpen2(&QuicApiTable);
    if (QUIC_FAILED(retMsQuicOpen))
    {
        LIVE_ASSERT(false, "MsQuic Open Failed");
    }
}

void QuicWrapper::CloseMsQuic()
{
    if (QuicApiTable != nullptr)
    {
        ::MsQuicClose(QuicApiTable);
        QuicApiTable = nullptr;
    }
}

void QuicWrapper::OpenRegistration(QUIC_EXECUTION_PROFILE ExecutionProfile)
{
    QUIC_REGISTRATION_CONFIG registrationConfig = {};
    registrationConfig.AppName = "SL";
    registrationConfig.ExecutionProfile = ExecutionProfile;

    QUIC_STATUS retRegistrationOpen = QuicApiTable->RegistrationOpen(&registrationConfig, &Registration);
    if (QUIC_FAILED(retRegistrationOpen))
    {
        LIVE_ASSERT(false, "MsQuic RegistrationOpen Failed");
    }
}

void QuicWrapper::CloseRegistration()
{
    if (Registration != nullptr)
    {
        QuicApiTable->RegistrationClose(Registration);
        Registration = nullptr;
    }
}

HQUIC QuicWrapper::OpenConfigurationOrNull(
    const uint64_t idleTimeoutMs,
    const uint64_t handshakeIdleTimeoutMs,
    const uint32_t disconnectTimeoutMs,
    bool bUseCertificateValidation)
{
    QUIC_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));

    settings.IdleTimeoutMs = idleTimeoutMs;
    settings.IsSet.IdleTimeoutMs = 1;

    settings.HandshakeIdleTimeoutMs = handshakeIdleTimeoutMs;
    settings.IsSet.HandshakeIdleTimeoutMs = 1;

    settings.DisconnectTimeoutMs = disconnectTimeoutMs;
    settings.IsSet.DisconnectTimeoutMs = 1;

    HQUIC Configuration = nullptr;

    QUIC_STATUS retConfigurationOpen = QuicApiTable->ConfigurationOpen(Registration, &SLApplicationProtocol, 1, &settings, sizeof(settings), nullptr, &Configuration);
    if (QUIC_FAILED(retConfigurationOpen))
    {
        LIVE_ASSERT(false, "MsQuic ConfigurationOpen Failed");
        return nullptr;
    }

    LoadConfigurationCredential(Configuration, bUseCertificateValidation);
    return Configuration;
}

void QuicWrapper::CloseConfiguration(HQUIC Configuration)
{
    if (Configuration != nullptr)
    {
        QuicApiTable->ConfigurationClose(Configuration);
    }
}

void QuicWrapper::LoadConfigurationCredential(HQUIC Configuration, bool bUseCertificateValidation)
{
    QUIC_CREDENTIAL_CONFIG credentialConfig;
    memset(&credentialConfig, 0, sizeof(credentialConfig));

    credentialConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;

    credentialConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

    if (bUseCertificateValidation)
    {
        // QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED 이벤트를 호출받도록 설정합니다.
        credentialConfig.Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;

        // 최종 인증서 검증을 Applicaiton에서 수행하도록 합니다.
        credentialConfig.Flags |= QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION;

        // 인증서 검증을 OpenSSL이 수행합니다.
        credentialConfig.Flags |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
    }
    else
    {
        credentialConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    QUIC_STATUS retConfigurationLoadCredential = QuicApiTable->ConfigurationLoadCredential(Configuration, &credentialConfig);
    if (QUIC_FAILED(retConfigurationLoadCredential))
    {
        LIVE_ASSERT(false, "MsQuic ConfigurationLoadCredential Failed");
        return;
    }
}