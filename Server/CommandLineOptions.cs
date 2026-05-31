namespace Server;

using CommandLine;

public sealed class CommandLineOptions
{
    [Option('c', "certPath", Required = false, HelpText = "Certificate file path. Default is server.pfx")]
    public string CertificatePath { get; set; } = string.Empty;

    [Option('p', "certPassword", Required = false, HelpText = "Certificate password. Default is empty string")]
    public string CertificatePassword { get; set; } = string.Empty;
}
