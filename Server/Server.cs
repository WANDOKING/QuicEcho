using System.Buffers;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Server;

internal class Server
{
    private static async Task Main(string[] args)
    {
        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            if (e.Exception is AggregateException ex)
            {
                // UnobservedTaskException = System.Net.Quic.QuicException: Connection aborted by peer (11).
                //   at System.Net.Quic.QuicConnection.HandleEventShutdownInitiatedByPeer(_SHUTDOWN_INITIATED_BY_PEER_e__Struct & data)
                //   at System.Net.Quic.QuicConnection.HandleConnectionEvent(QUIC_CONNECTION_EVENT & connectionEvent)
                //   at System.Net.Quic.QuicConnection.NativeCallback(QUIC_HANDLE * connection, Void * context, QUIC_CONNECTION_EVENT * connectionEvent)
                // --- End of stack trace from previous location ---
                foreach (Exception exception in ex.InnerExceptions)
                {
                    Console.WriteLine($"UnobservedTaskException = {exception}");
                }
            }
        };

        var serverConnectionOptions = new QuicServerConnectionOptions()
        {
            DefaultStreamErrorCode = 0x0A,
            DefaultCloseErrorCode = 0x0B,
            IdleTimeout = TimeSpan.FromSeconds(60),
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
                ServerCertificate = X509CertificateLoader.LoadPkcs12FromFile(@"server.pfx", "test"),
            }
        };

        var quicListenerOptions = new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Any, 23456),
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverConnectionOptions),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(quicListenerOptions);

        int clientId = 0;
        while (true)
        {
            try
            {
                QuicConnection connection = await listener.AcceptConnectionAsync();
                //Console.WriteLine($"connection = {connection.RemoteEndPoint} | {connection.NegotiatedApplicationProtocol}");
                _ = StartReceive(++clientId, connection);
            }
            catch (Exception)
            {
                Console.WriteLine("Exception at Accept");
            }
        }
    }

    private static async Task StartReceive(int clientId, QuicConnection client)
    {
        byte[] receiveBuffer = ArrayPool<byte>.Shared.Rent(4096);

        try
        {
            await using var stream = await client.AcceptInboundStreamAsync().ConfigureAwait(false);

            while (true)
            {
                int receivedBytesCount = await stream.ReadAsync(receiveBuffer).ConfigureAwait(false);

                //Console.WriteLine($"Received Count = {receivedBytesCount}, Data = {Encoding.UTF8.GetString(receiveBuffer)}");

                // Echo for test
                await stream.WriteAsync(receiveBuffer, 0, receivedBytesCount).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"ID {clientId} : {ex}");
        }
        finally
        {
            Console.WriteLine($"ID {clientId} | Disconnected.");

            // I know calling DisposeAsync in this part is the correct code,
            // but I'm wondering if it's the intended behavior
            // to throw an UnobservedTaskException because I missed calling DisposeAsync.
            await client.CloseAsync(0x0B).ConfigureAwait(false);

            ArrayPool<byte>.Shared.Return(receiveBuffer);
        }
    }
}
