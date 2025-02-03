using System.Net.Quic;
using System.Net.Security;
using System.Net;
using System.Buffers;
using System.Text;

namespace Client;

internal class Client
{
    private static async Task Main(string[] args)
    {
        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            Console.WriteLine(e);
        };

        await Task.Delay(1000);

        var clientConnectionOptions = new QuicClientConnectionOptions()
        {
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

        for (int i = 0; i < 1000; ++i)
        {
            _ = ClientLoop(clientConnectionOptions);
            await Task.Delay(5);
        }

        await Task.Delay(Timeout.Infinite);
    }

    private static async Task ClientLoop(QuicClientConnectionOptions options)
    {
        QuicConnection connection = await QuicConnection.ConnectAsync(options);
        Console.WriteLine($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

        byte[] receiveBuffer = ArrayPool<byte>.Shared.Rent(1024);
        int number = 0;
        using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        while (true)
        {
            byte[] helloWorldToBytes = Encoding.UTF8.GetBytes($"Hello, World! ({number++})");

            if (Random.Shared.Next() % 10 == 0)
            {
                await connection.CloseAsync(0x0B);
                return;
            }

            await stream.WriteAsync(helloWorldToBytes, 0, helloWorldToBytes.Length);
            await stream.ReadExactlyAsync(receiveBuffer, 0, helloWorldToBytes.Length);
            string receivedString = Encoding.UTF8.GetString(receiveBuffer);

            Console.WriteLine(receivedString);

            await Task.Delay(10);
        }
    }
}
