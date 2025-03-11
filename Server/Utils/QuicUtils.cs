namespace Server.Utils;

using System;
using System.Net.Quic;

public static class QuicUtils
{
    /// <summary>
    /// 시스템의 QUIC 지원 여부를 체크합니다.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">QUIC을 지원하지 않으면 발생합니다.</exception>
    public static void CheckSupportQuic()
    {
        if (QuicListener.IsSupported is false || QuicConnection.IsSupported is false)
        {
            throw new PlatformNotSupportedException("QUIC is not supported on this system.");
        }
    }
}
