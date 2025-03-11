namespace Client;

using System.Net.Quic;
using System.Net.Security;
using System.Net;
using System.Buffers;
using System.Text;
using ConsoleKeyUtils;

internal class Client
{
    private static QuicStream? ClientStream;

    private static async Task Main(string[] args)
    {
        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            Console.WriteLine(e);
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
                    ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
                    RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true,
                }
            };

            QuicConnection connection = await QuicConnection.ConnectAsync(clientConnectionOptions);
            Console.WriteLine($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

            _ = ClientLoop(connection, clientConnectionOptions);
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

        // 사용법 출력
        foreach ((ConsoleKey key, string? handlerName) in ConsoleKeyDispatcher.HandlerNames)
        {
            Console.WriteLine($"[{key}]: {handlerName}");
        }

        ConsoleKeyDispatcher.BindExitHandler();
        ConsoleKeyDispatcher.KeepDispatching();
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
