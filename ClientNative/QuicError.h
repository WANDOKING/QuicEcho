#pragma once

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
