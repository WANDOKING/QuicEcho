namespace Server;

using CommandLine;

public sealed class CommandLineOptions
{
    [Option('c', "cert", Required = false, HelpText = "Certificate file path. Default is server.pfx")]
    public string CertificatePath { get; set; } = string.Empty;
}
