namespace Client;

using System.Net.Quic;
using System.Net.Security;
using System.Net;
using System.Buffers;
using System.Text;
using ConsoleKeyUtils;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;

internal class Client
{
    private static bool shouldForceDenyCertificate;
    private static QuicStream? ClientStream;

    private static async Task Main(string[] args)
    {
        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            Console.WriteLine($"UnobservedTaskException= {e.Exception}");
        };

        ConsoleKeyDispatcher.BindHandler(ConsoleKey.D1, async () =>
        {
            var clientConnectionOptions = new QuicClientConnectionOptions()
            {
                // 접속할 IP 주소와 포트 번호를 지정
                RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 23456),

                DefaultStreamErrorCode = 0x0A,
                DefaultCloseErrorCode = 0x0B,

                MaxInboundUnidirectionalStreams = 0,
                MaxInboundBidirectionalStreams = 1,

                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",

                    ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },

                    // 서버측 인증서 검증 콜백
                    RemoteCertificateValidationCallback = QuicRemoteCertificateValidationCallback,
                }
            };

            try
            {
                QuicConnection connection = await QuicConnection.ConnectAsync(clientConnectionOptions);
                Console.WriteLine($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

                // 스트림을 생성하고 Receive 루프 수행
                _ = ClientLoop(connection, clientConnectionOptions);
            }
            catch (AuthenticationException ex)
            {
                Console.WriteLine($"{nameof(AuthenticationException)} occured. ex={ex}");
            }
        }, "QuicConnection 연결");

        int number = 0;
        ConsoleKeyDispatcher.BindAsyncHandler(ConsoleKey.D2, async () =>
        {
            if (ClientStream is null)
            {
                return;
            }

            byte[] helloWorldToBytes = Encoding.UTF8.GetBytes($"Hello, World! ({number++})");

            await ClientStream.WriteAsync(helloWorldToBytes, 0, helloWorldToBytes.Length);
        }, "Hello, World Send");

        ConsoleKeyDispatcher.BindHandler(ConsoleKey.P, () =>
        {
            shouldForceDenyCertificate = !shouldForceDenyCertificate;
            Console.WriteLine($"shouldForceDenyCertificate: {shouldForceDenyCertificate}");
        }, "인증서 검증 결과 반전");

        // 사용법 출력
        foreach ((ConsoleKey key, string? handlerName) in ConsoleKeyDispatcher.HandlerNames)
        {
            Console.WriteLine($"[{key}]: {handlerName}");
        }

        ConsoleKeyDispatcher.BindExitHandler();
        ConsoleKeyDispatcher.KeepDispatching();
    }

    private static bool QuicRemoteCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        Console.WriteLine($"{nameof(QuicRemoteCertificateValidationCallback)} called.");

        if (shouldForceDenyCertificate)
        {
            return false;
        }

        if (sslPolicyErrors is SslPolicyErrors.None)
        {
            return true;
        }

        if (chain is not null)
        {
            chain.ChainStatus.ToList().ForEach(status =>
            {
                Console.WriteLine($"ChainStatus: {status.Status} | {status.StatusInformation}");
            });
        }

        Console.WriteLine($"RemoteCertificateValidation will be failed. SSL Policy Errors: {sslPolicyErrors}");
        return false;
    }

    private static async Task ClientLoop(QuicConnection connection, QuicClientConnectionOptions options)
    {
        try
        {
            Memory<byte> receiveBuffer = new byte[1024];

            ClientStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

            while (true)
            {
                int readBytesCounts = await ClientStream.ReadAsync(receiveBuffer);
                string receivedString = Encoding.UTF8.GetString(receiveBuffer.ToArray(), 0, readBytesCounts);

                Console.WriteLine(receivedString);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}
