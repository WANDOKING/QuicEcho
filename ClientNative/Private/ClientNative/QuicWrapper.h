#pragma once

#include "ClientNative/include/msquic.h"

#include <string>

enum class EQuicError
{
    Success,
    OutOfMemory,
    InvalidParameter,
    InvalidState,
    NotSupported,
    NotFound,
    BufferTooSmall,
    HandshakeFailure,
    Aborted,
    AddressInUse,
    InvalidAddress,
    ConnectionTimeout,
    ConnectionIdle,
    InternalError,
    Unreachable,
    ConnectionRefused,
    ProtocolError,
    VersionNegotiation,
    UserCanceled,
    AlpnNegotiationFailure,
    StreamLimitReached,
    Unknown
};

class QuicWrapper final
{
public:
    QuicWrapper() = delete;
    QuicWrapper(const QuicWrapper&) = delete;
    QuicWrapper(const QuicWrapper&&) = delete;
    QuicWrapper& operator=(const QuicWrapper&) = delete;
    QuicWrapper& operator=(QuicWrapper&&) = delete;

public:

    /// <summary>
    /// MsQuic 초기화를 수행합니다.
    /// </summary>
    static void Startup();

    /// <summary>
    /// MsQuic 자원 정리를 수행합니다.
    /// 주의: 이 함수는 다른 MsQuic 관련 자원이 모두 해제되었을 때만 호출해야 합니다.
    /// 다른 모든 자원이 해제될 때까지 스레드를 차단시킵니다.
    /// </summary>
    static void Cleanup();

    /// <summary>
    /// 커넥션을 생성합니다.
    /// </summary>
    static bool CreateConnection(QUIC_CONNECTION_CALLBACK_HANDLER handler, void* context, HQUIC* outConnection);

    /// <summary>
    /// 커넥션 종료를 시작합니다.
    /// 피어에게 종료를 알립니다.
    /// </summary>
    static void ShutdownConnection(HQUIC connection);

    /// <summary>
    /// 커넥션을 종료를 완료합니다.
    /// Shutdown 전에 호출하면 피어에게 종료를 알리지 않습니다.
    /// </summary>
    static void CloseConnection(HQUIC connection);

    /// <summary>
    /// 연결을 시작합니다.
    /// </summary>
    static bool Connect(HQUIC connection, HQUIC Configuration, const char* ip, uint16_t port);

    /// <summary>
    /// 스트림을 생성합니다.
    /// </summary>
    static bool OpenStream(HQUIC connection, HQUIC* outStream, void* context, QUIC_STREAM_CALLBACK callback);

    /// <summary>
    /// 스트림 종료를 시작합니다.
    /// </summary>
    static void ShutdownStream(HQUIC stream);

    /// <summary>
    /// 스트림을 종료를 완료합니다.
    /// </summary>
    static void CloseStream(HQUIC stream);

    /// <summary>
    /// 데이터를 송신합니다.
    /// 송신이 완료될 때까지 버퍼를 수정해서는 안됩니다.
    /// </summary>
    static bool Send(HQUIC stream, QUIC_BUFFER* buffer, void* sendContext);

    /// <summary>
    /// 설정을 엽니다.
    /// </summary>
    static HQUIC OpenConfigurationOrNull(
        const uint64_t idleTimeoutMs = 0, 
        const uint64_t handshakeIdleTimeoutMs = 10'000, 
        const uint32_t disconnectTimeoutMs = 5'000,
        bool bUseCertificateValidation = false);

    /// <summary>
    /// 설정을 닫습니다.
    /// </summary>
    static void CloseConfiguration(HQUIC Configuration);

public:
    static std::string QuicErrorToString(const EQuicError Error);

private:
    static void OpenMsQuic();
    static void CloseMsQuic();
    static void OpenRegistration();
    static void CloseRegistration();
    static void LoadConfigurationCredential(HQUIC Configuration, bool useCertificateValidation);

private:
    /// <summary>
    /// QUIC 함수 테이블로, 모든 MsQuic 함수 호출은 해당 객체를 통해서 이루어집니다.
    /// </summary>
    inline static const QUIC_API_TABLE* QuicApiTable;

    /// <summary>
    /// MsQuic의 실행 컨텍스트를 나타내는 최상위 레벨 API 객체입니다.
    /// 스레드 구성과 관련된 실행 프로파일이 포함됩니다.
    /// </summary>
    inline static HQUIC Registration;

    /// <summary>
    /// ALPN
    /// </summary>
    static const QUIC_BUFFER SLApplicationProtocol;
};