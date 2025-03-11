namespace Server;

using CommandLine;
using NLog;
using Server.Utils;
using System.Buffers;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal class Program
{
    private static ILogger Logger = LogManager.GetCurrentClassLogger();
    private static ILogger AcceptLogger = LogManager.GetLogger("AcceptLogger");
    private static ILogger ReceiveLogger = LogManager.GetLogger("ReceiveLogger");

    private static int HandleParseError(IEnumerable<Error> errors)
    {
        Logger.Error($"{nameof(HandleParseError)}");

        foreach (var error in errors)
        {
            Logger.Error(error);
        }

        return 0;
    }

    private static async Task Main(string[] args)
    {
        // QUIC 지원 여부 확인
        QuicUtils.CheckSupportQuic();

        // UnobservedTaskException 핸들러 등록
        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            if (e.Exception is AggregateException ex)
            {
                foreach (Exception exception in ex.InnerExceptions)
                {
                    Logger.Fatal($"UnobservedTaskException = {exception}");
                }
            }
        };

        Parser.Default.ParseArguments<CommandLineOptions>(args)
            .MapResult(
                options => Launch(options).Result,
                errors => HandleParseError(errors));
    }

    private static async Task<int> Launch(CommandLineOptions options)
    {
        Logger.Debug($"[{nameof(CommandLineOptions)}]");

        foreach (var property in options.GetType().GetProperties())
        {
            Logger.Debug($"{property.Name}: {property.GetValue(options)}");
        }

        var listenerOptions = new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Any, 23456),

            // 일단 HTTP3를 사용한다 (h3)
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },

            ConnectionOptionsCallback = (_, _, _) =>
            {
                var serverConnectionOptions = new QuicServerConnectionOptions()
                {
                    DefaultStreamErrorCode = 0x0A,
                    DefaultCloseErrorCode = 0x0B,

                    IdleTimeout = TimeSpan.FromSeconds(5),

                    ServerAuthenticationOptions = new SslServerAuthenticationOptions
                    {
                        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
                        ServerCertificate = string.IsNullOrWhiteSpace(options.CertificatePath) ? TlsUtils.CreateSelfSignedCertificate() : X509CertificateLoader.LoadPkcs12FromFile(@"server.pfx", "test"),
                    }
                };

                return ValueTask.FromResult(serverConnectionOptions);
            },
        };

        Logger.Debug($"[{nameof(QuicListenerOptions)}] {nameof(listenerOptions.ListenEndPoint)}: {listenerOptions.ListenEndPoint}");
        Logger.Debug($"[{nameof(QuicListenerOptions)}] {nameof(listenerOptions.ListenBacklog)}: {listenerOptions.ListenBacklog}");
        Logger.Debug($"[{nameof(QuicListenerOptions)}] {nameof(listenerOptions.ApplicationProtocols)}: {string.Join(", ", listenerOptions.ApplicationProtocols)}");

        await using (QuicListener listener = await QuicListener.ListenAsync(listenerOptions))
        {
            Logger.Info($"Listening Start as {listener.LocalEndPoint}");

            int clientId = 0;
            while (true)
            {
                try
                {
                    QuicConnection connection = await listener.AcceptConnectionAsync();
                    AcceptLogger.Debug($"connection = {connection.RemoteEndPoint} | {connection.NegotiatedApplicationProtocol}");

                    _ = Task.Run(() => StartReceive(++clientId, connection));
                }
                catch (Exception ex)
                {
                    AcceptLogger.Error("Exception at Accept, ");
                }
            }
        }

        Logger.Info($"{nameof(QuicListener)} closed.");
        return 0;
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
                ReceiveLogger.Debug($"Received Count = {receivedBytesCount}, Data = {Encoding.UTF8.GetString(receiveBuffer)}");

                // Echo for test
                await stream.WriteAsync(receiveBuffer, 0, receivedBytesCount).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            ReceiveLogger.Debug($"ID {clientId} : {ex}");
        }
        finally
        {
            ReceiveLogger.Debug($"ID {clientId} | Disconnected.");

            await client.CloseAsync(0x0B).ConfigureAwait(false);

            ArrayPool<byte>.Shared.Return(receiveBuffer);
        }
    }
}
