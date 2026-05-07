namespace Server.Utils;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class TlsUtils
{
    public static X509Certificate2 CreateSelfSignedCertificate(string? password = default)
    {
        // 1. 임시 RSA-2048 키를 생성
        using var ephemeralRsaKey = RSA.Create(2048);

        // 2. 인증서 서명 요청을 생성 (RSA-2048이므로 SHA256 + PKCS#1)
        var request = new CertificateRequest("CN=localhost", ephemeralRsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // 3. 유효기간이 30일인 Self-Signed Certificate을 생성합니다.
        var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddDays(30));

        // 4. 인증서를 PFX(PKCS#12) 형식으로 내보내고, X509Certificate2 객체로 로드합니다.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, password), password);
    }

    public static X509Certificate2 LoadFromPfxFile(string path, string? password = default)
    {
        return X509CertificateLoader.LoadPkcs12FromFile(path, password);
    }
}
