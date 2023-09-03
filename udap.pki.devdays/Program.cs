// See https://aka.ms/new-console-template for more information
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using udap.pki.devdays;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

Console.WriteLine("Generating PKI for UDAP DevDays");

string staticCertPort = "5034";
string certificateStore = $"CertificateStore";
string certificateStoreFullPath = $"{BaseDir()}/{certificateStore}";

MakeUdapPki(
    $"{certificateStore}/Community1",                                       //communityStorePath
    "DevDaysCA_1",                                                          //anchorName
    "DevDaysSubCA_1",                                                       //intermediateName
    "DevDaysRSAClient",                                                     //issuedName
    "CN=localhost, OU=DevDays-Community1, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
    new List<string>
    {
        "https://localhost:7017/fhir/r4",
        "https://host.docker.internal:7017/fhir/r4",
        "http://localhost/fhir/r4",
    },                                                                      //SubjAltNames (Demonstrate multiple)
    "RSA"
);

MakeUdapPki(
    $"{certificateStore}/Community2",                                       //communityStorePath
    "DevDaysCA_2",                                                          //anchorName
    "DevDaysSubCA_2",                                                       //intermediateName
    "DevDaysECDSAClient",                                                   //issuedName
    "CN=localhost, OU=DevDays-Community2, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
    new List<string>
    {
        "https://localhost:7017/fhir/r4",
        "https://host.docker.internal:7017/fhir/r4",
        "http://localhost/fhir/r4",
    },                                                                      //SubjAltNames (Demonstrate multiple)
    "ECDSA"
);

//
// Let's revoke a certificate
//
// Add another Community and certificate to revoke
//

MakeUdapPki(
    $"{certificateStore}/Community3",                                       //communityStorePath
    "DevDaysCA_3",                                                          //anchorName
    "DevDaysSubCA_3",                                                       //intermediateName
    "DevDaysRevokedClient",                                                 //issuedName
    "CN=localhost, OU=DevDays-Community3, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
    new List<string>
    {
        "https://localhost:7017/fhir/r4",
        "https://host.docker.internal:7017/fhir/r4",
        "http://localhost/fhir/r4",
    },                                                                      //SubjAltNames (Demonstrate multiple)
    "RSA"
);

// Revoke

var subCA = new X509Certificate2($"{certificateStoreFullPath}/Community3/intermediates/DevDaysSubCA_3.pfx", "udap-test", X509KeyStorageFlags.Exportable);
var revokeCertificate = new X509Certificate2($"{certificateStoreFullPath}/Community3/issued/DevDaysRevokedClient.pfx", "udap-test");

RevokeCertificate(subCA, revokeCertificate, $"{certificateStoreFullPath}/Community3/crl/DevDaysSubCA_3.crl");




void MakeUdapPki(
            string communityStorePath,
            string anchorName,
            string intermediateName,
            string issuedName,
            string issuedDistinguishedName,
            List<string> issuedSubjectAltNames,
            string cryptoAlgorithm)
{
    var communityStoreFullPath = $"{BaseDir()}/{communityStorePath}";
    var crlStorePath = $"{communityStorePath}/crl";
    var crlStoreFullPath = $"{BaseDir()}/{crlStorePath}";
    crlStoreFullPath.EnsureDirectoryExists();
    var anchorCrlFile = $"{crlStorePath}/{anchorName}.crl";
    var anchorCrlFullPath = $"{BaseDir()}/{anchorCrlFile}";
    var intermediateCrlFile = $"{crlStorePath}/{intermediateName}.crl";
    var intermediateCrlFullPath = $"{BaseDir()}/{intermediateCrlFile}";

    var intermediateCdp = $"http://host.docker.internal:{staticCertPort}/crl/{anchorName}.crl";
    var clientCdp = $"http://host.docker.internal:{staticCertPort}/crl/{intermediateName}.crl";

    string anchorHostedUrl = $"http://host.docker.internal:{staticCertPort}/certs/{anchorName}.crt";
    string intermediateHostedUrl = $"http://host.docker.internal:{staticCertPort}/certs/{intermediateName}.crt";

    var intermediateStorePath = $"{communityStorePath}/intermediates";
    var intermediateStoreFullPath = $"{BaseDir()}/{intermediateStorePath}";
    var issuedStorePath = $"{communityStorePath}/issued";
    var issuedStoreFullPath = $"{BaseDir()}/{issuedStorePath}";

    using (RSA parent = RSA.Create(4096))
    using (RSA intermediate = RSA.Create(4096))
    {
        var parentReq = new CertificateRequest(
            $"CN={anchorName}, OU=DevDays, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            parent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        parentReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        parentReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                false));

        parentReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

        using (var caCert = parentReq.CreateSelfSigned(
                   DateTimeOffset.UtcNow.AddDays(-1),
                   DateTimeOffset.UtcNow.AddYears(10)))
        {

            var parentBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");
            communityStoreFullPath.EnsureDirectoryExists();
            File.WriteAllBytes($"{communityStoreFullPath}/{anchorName}.pfx", parentBytes);
            var caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
            var caFilePath = $"{communityStoreFullPath}/{anchorName}.crt";
            File.WriteAllBytes(caFilePath, caPem.Select(c => (byte)c).ToArray());

            //Distribute
            var caAiaFile = $"{BaseDir()}/../udap.certificates.server.devdays/wwwroot/certs/{new FileInfo(caFilePath).Name}";
            caAiaFile.EnsureDirectoryExistFromFilePath();
            File.Copy(caFilePath, caAiaFile, true);

            var caAuthServerFile = $"{BaseDir()}/../udap.authserver.devdays/{communityStorePath}/{new FileInfo(caFilePath).Name}";
            caAuthServerFile.EnsureDirectoryExistFromFilePath();
            File.Copy(caFilePath, caAuthServerFile, true);

            CreateCertificateRevocationList(caCert, anchorCrlFullPath);
            
            var intermediateReq = new CertificateRequest(
                $"CN={intermediateName}, OU=DevDays, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                intermediate,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Referred to as intermediate Cert or Intermediate
            intermediateReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));

            intermediateReq.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign |
                    X509KeyUsageFlags.DigitalSignature,
                    false));

            intermediateReq.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(intermediateReq.PublicKey, false));

            AddAuthorityKeyIdentifier(caCert, intermediateReq);
            intermediateReq.CertificateExtensions.Add(
                MakeCdp(intermediateCdp));

            var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
            authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(anchorHostedUrl));
            var aiaExtension = authorityInfoAccessBuilder.Build();
            intermediateReq.CertificateExtensions.Add(aiaExtension);

            using var intermediateCert = intermediateReq.Create(
                caCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(5),
                new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
            var intermediateCertWithKey = intermediateCert.CopyWithPrivateKey(intermediate);
            var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
            intermediateStoreFullPath.EnsureDirectoryExists();
            File.WriteAllBytes($"{intermediateStoreFullPath}/{intermediateName}.pfx", intermediateBytes);
            var intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCert.RawData);
            var subCaFilePath = $"{intermediateStoreFullPath}/{intermediateName}.crt";
            File.WriteAllBytes(subCaFilePath, intermediatePem.Select(c => (byte)c).ToArray());

            //Distribute
            var subCaCopyToFilePath = $"{BaseDir()}/../udap.certificates.server.devdays/wwwroot/certs/{new FileInfo(subCaFilePath).Name}";
            subCaCopyToFilePath.EnsureDirectoryExistFromFilePath();
            File.Copy(subCaFilePath, subCaCopyToFilePath, true);

            CreateCertificateRevocationList(intermediateCertWithKey, intermediateCrlFullPath);

            $"{issuedStoreFullPath}".EnsureDirectoryExists();

            if (cryptoAlgorithm is "ECDSA")
            {
                BuildClientCertificateECDSA(
                    communityStorePath,
                    intermediateCert,
                    caCert,
                    intermediate,
                    issuedDistinguishedName,
                    issuedSubjectAltNames,
                    $"{issuedStorePath}/{issuedName}",
                    intermediateHostedUrl,
                    clientCdp
                );
            }
            else
            {
                BuildClientCertificate(
                    communityStorePath,
                    intermediateCert,
                    caCert,
                    intermediate,
                    issuedDistinguishedName,
                    issuedSubjectAltNames,
                    $"{issuedStorePath}/{issuedName}",
                    intermediateHostedUrl,
                    clientCdp
                );
            }
        }
    }
}



X509Certificate2 BuildClientCertificate(
            string communityStorePath,
            X509Certificate2 intermediateCert,
            X509Certificate2 caCert,
            RSA intermediateKey,
            string distinguishedName,
            List<string> subjectAltNames,
            string clientCertFilePath,
            string intermediateHostedUrl,
            string? crl,
            DateTimeOffset notBefore = default,
            DateTimeOffset notAfter = default)
{
    var clientCertFullFilePath = $"{BaseDir()}/{clientCertFilePath}";

    if (notBefore == default)
    {
        notBefore = DateTimeOffset.UtcNow;
    }

    if (notAfter == default)
    {
        notAfter = DateTimeOffset.UtcNow.AddYears(2);
    }


    var intermediateCertWithKey = intermediateCert.HasPrivateKey ?
        intermediateCert :
        intermediateCert.CopyWithPrivateKey(intermediateKey);

    using RSA rsaKey = RSA.Create(2048);

    var clientCertRequest = new CertificateRequest(
        distinguishedName,
        rsaKey,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    clientCertRequest.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));

    clientCertRequest.CertificateExtensions.Add(
        new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            true));

    clientCertRequest.CertificateExtensions.Add(
        new X509SubjectKeyIdentifierExtension(clientCertRequest.PublicKey, false));

    AddAuthorityKeyIdentifier(intermediateCert, clientCertRequest);

    if (crl != null)
    {
        clientCertRequest.CertificateExtensions.Add(MakeCdp(crl));
    }

    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
    foreach (var subjectAltName in subjectAltNames)
    {
        subAltNameBuilder.AddUri(new Uri(subjectAltName)); //Same as iss claim
    }

    var x509Extension = subAltNameBuilder.Build();
    clientCertRequest.CertificateExtensions.Add(x509Extension);

    var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
    authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(intermediateHostedUrl));
    var aiaExtension = authorityInfoAccessBuilder.Build();
    clientCertRequest.CertificateExtensions.Add(aiaExtension);
    

    var clientCert = clientCertRequest.Create(
        intermediateCertWithKey,
        notBefore,
        notAfter,
        new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
    // Do something with these certs, like export them to PFX,
    // or add them to an X509Store, or whatever.
    var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);


    var certPackage = new X509Certificate2Collection();
    certPackage.Add(clientCertWithKey);
    certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
    certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));

    var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
    File.WriteAllBytes($"{clientCertFullFilePath}.pfx", clientBytes!);
    var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
    File.WriteAllBytes($"{clientCertFullFilePath}.crt", clientPem.Select(c => (byte)c).ToArray());


    //Distribute
    var fileName = new FileInfo(clientCertFilePath + ".pfx").Name;
    var clientP12File = $"{BaseDir()}/../udap.fhirserver.devdays/{clientCertFilePath}.pfx";
    clientP12File.EnsureDirectoryExistFromFilePath();
    File.Copy($"{clientCertFullFilePath}.pfx", clientP12File,
        true);

    return clientCert;
}

X509Certificate2 BuildClientCertificateECDSA(
    string communityStorePath,
    X509Certificate2 intermediateCert,
    X509Certificate2 caCert,
    RSA intermediateKey,
    string distinguishedName,
    List<string> subjectAltNames,
    string clientCertFilePath,
    string intermediateHostedUrl,
    string? crl,
    DateTimeOffset notBefore = default,
    DateTimeOffset notAfter = default)
{
    var clientCertFullFilePath = $"{BaseDir()}/{clientCertFilePath}";

    if (notBefore == default)
    {
        notBefore = DateTimeOffset.UtcNow;
    }

    if (notAfter == default)
    {
        notAfter = DateTimeOffset.UtcNow.AddYears(2);
    }


    var intermediateCertWithKey = intermediateCert.HasPrivateKey ?
        intermediateCert :
        intermediateCert.CopyWithPrivateKey(intermediateKey);

    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

    var clientCertRequest = new CertificateRequest(
        distinguishedName,
        ecdsa,
        HashAlgorithmName.SHA256);

    clientCertRequest.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));

    clientCertRequest.CertificateExtensions.Add(
        new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            true));

    clientCertRequest.CertificateExtensions.Add(
        new X509SubjectKeyIdentifierExtension(clientCertRequest.PublicKey, false));

    AddAuthorityKeyIdentifier(intermediateCert, clientCertRequest);

    if (crl != null)
    {
        clientCertRequest.CertificateExtensions.Add(MakeCdp(crl));
    }

    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
    foreach (var subjectAltName in subjectAltNames)
    {
        subAltNameBuilder.AddUri(new Uri(subjectAltName)); //Same as iss claim
    }

    var x509Extension = subAltNameBuilder.Build();
    clientCertRequest.CertificateExtensions.Add(x509Extension);

   
        var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
        authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(intermediateHostedUrl));
        var aiaExtension = authorityInfoAccessBuilder.Build();
        clientCertRequest.CertificateExtensions.Add(aiaExtension);
    

    var clientCert = clientCertRequest.Create(
        intermediateCertWithKey.SubjectName,
        X509SignatureGenerator.CreateForRSA(intermediateKey, RSASignaturePadding.Pkcs1),
        notBefore,
        notAfter,
        new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
    // Do something with these certs, like export them to PFX,
    // or add them to an X509Store, or whatever.
    var clientCertWithKey = clientCert.CopyWithPrivateKey(ecdsa);


    var certPackage = new X509Certificate2Collection();
    certPackage.Add(clientCertWithKey);
    certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
    certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));


    var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
    File.WriteAllBytes($"{clientCertFullFilePath}.pfx", clientBytes!);
    var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
    File.WriteAllBytes($"{clientCertFullFilePath}.crt", clientPem.Select(c => (byte)c).ToArray());

    //Distribute
    var fileName = new FileInfo(clientCertFilePath + ".pfx").Name;
    var clientP12File = $"{BaseDir()}/../udap.fhirserver.devdays/{clientCertFilePath}.pfx";
    clientP12File.EnsureDirectoryExistFromFilePath();
    File.Copy($"{clientCertFullFilePath}.pfx", clientP12File,
        true);
    
    return clientCert;
}


void CreateCertificateRevocationList(X509Certificate2 certificate, string crlFilePath){
    // Certificate Revocation
    var bouncyCaCert = DotNetUtilities.FromX509Certificate(certificate);

    var crlGen = new X509V2CrlGenerator();
    var intermediateNow = DateTime.UtcNow;
    crlGen.SetIssuerDN(bouncyCaCert.SubjectDN);
    crlGen.SetThisUpdate(intermediateNow);
    crlGen.SetNextUpdate(intermediateNow.AddYears(1));

    crlGen.AddCrlEntry(BigInteger.One, intermediateNow, CrlReason.PrivilegeWithdrawn);

    crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
        false,
        new AuthorityKeyIdentifierStructure(bouncyCaCert.GetPublicKey()));

    var nextCrlNum = GetNextCrlNumber(crlFilePath);

    crlGen.AddExtension(X509Extensions.CrlNumber, false, nextCrlNum);
    
    var akp = DotNetUtilities.GetKeyPair(certificate.GetRSAPrivateKey()).Private;
    var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", akp));
    
    File.WriteAllBytes(crlFilePath, crl.GetEncoded());

    //Distribute
    var crlFile = $"{BaseDir()}/../udap.certificates.server.devdays/wwwroot/crl/{new FileInfo(crlFilePath).Name}";
    crlFile.EnsureDirectoryExistFromFilePath();
    File.Copy(crlFilePath, crlFile, true);

}


void RevokeCertificate(X509Certificate2 signingCertificate, X509Certificate2 certificateToRevoke, string crlFilePath)
{
    var bouncyIntermediateCert = DotNetUtilities.FromX509Certificate(signingCertificate);

    var crlGen = new X509V2CrlGenerator();
    var now = DateTime.UtcNow;
    crlGen.SetIssuerDN(bouncyIntermediateCert.SubjectDN);
    crlGen.SetThisUpdate(now);
    crlGen.SetNextUpdate(now.AddMonths(1));
    // crlGen.SetSignatureAlgorithm("SHA256withRSA");

    //
    // revokeCertificate.SerialNumberBytes requires target framework net7.0
    //
    crlGen.AddCrlEntry(new BigInteger(certificateToRevoke.SerialNumberBytes.ToArray()), now,
        CrlReason.PrivilegeWithdrawn);

    crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
        false,
        new AuthorityKeyIdentifierStructure(bouncyIntermediateCert.GetPublicKey()));

    var nextSureFhirClientCrlNum = GetNextCrlNumber(crlFilePath);

    crlGen.AddExtension(X509Extensions.CrlNumber, false, nextSureFhirClientCrlNum);

    var key = signingCertificate.GetRSAPrivateKey();
    using var rsa = RSA.Create(4096);

#if Windows
    //
    // Windows work around.  Otherwise works on Linux
    // Short answer: Windows behaves in such a way when importing the pfx
    // it creates the CNG key so it can only be exported encrypted
    // https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
    // https://stackoverflow.com/a/57330499/6115838
    //
        byte[] encryptedPrivKeyBytes = key!.ExportEncryptedPkcs8PrivateKey(
            "ILikePasswords",
            new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100_000));

        rsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivKeyBytes.AsSpan(), out int bytesRead);
#else
    rsa.ImportECPrivateKey(key?.ExportECPrivateKey(), out _);
#endif
    
    var akp = DotNetUtilities.GetKeyPair(rsa).Private;
    var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", akp));

    File.WriteAllBytes(crlFilePath, crl.GetEncoded());

    //Distribute
    var crlFile = $"{BaseDir()}/../udap.certificates.server.devdays/wwwroot/crl/{new FileInfo(crlFilePath).Name}";
    crlFile.EnsureDirectoryExistFromFilePath();
    File.Copy(crlFilePath, crlFile, true);
}



static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest intermediateReq)
{
    //
    // Found way to generate intermediate below
    //
    // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
    // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
    //


    var issuerSubjectKey = caCert.Extensions?["2.5.29.14"]!.RawData;
    var segment = new ArraySegment<byte>(issuerSubjectKey!, 2, issuerSubjectKey!.Length - 2);
    var authorityKeyIdentifier = new byte[segment.Count + 4];
    // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
    authorityKeyIdentifier[0] = 0x30;
    authorityKeyIdentifier[1] = 0x16;
    authorityKeyIdentifier[2] = 0x80;
    authorityKeyIdentifier[3] = 0x14;
    segment.CopyTo(authorityKeyIdentifier, 4);
    intermediateReq.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
}

static X509Extension MakeCdp(string url)
{
    //
    // urls less than 119 char solution.
    // From Bartonjs of course.
    //
    // https://stackoverflow.com/questions/60742814/add-crl-distribution-points-cdp-extension-to-x509certificate2-certificate
    //
    // From Crypt32:  .NET doesn't support CDP extension. You have to use 3rd party libraries for that. BC is ok if it works for you.
    // Otherwise write you own. :)
    //

    byte[] encodedUrl = Encoding.ASCII.GetBytes(url);

    if (encodedUrl.Length > 119)
    {
        throw new NotSupportedException();
    }

    byte[] payload = new byte[encodedUrl.Length + 10];
    int offset = 0;
    payload[offset++] = 0x30;
    payload[offset++] = (byte)(encodedUrl.Length + 8);
    payload[offset++] = 0x30;
    payload[offset++] = (byte)(encodedUrl.Length + 6);
    payload[offset++] = 0xA0;
    payload[offset++] = (byte)(encodedUrl.Length + 4);
    payload[offset++] = 0xA0;
    payload[offset++] = (byte)(encodedUrl.Length + 2);
    payload[offset++] = 0x86;
    payload[offset++] = (byte)(encodedUrl.Length);
    Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

    return new X509Extension("2.5.29.31", payload, critical: false);
}

static CrlNumber GetNextCrlNumber(string fileName)
{
    CrlNumber nextCrlNum = new CrlNumber(BigInteger.One);

    if (File.Exists(fileName))
    {
        byte[] buf = File.ReadAllBytes(fileName);
        var crlParser = new X509CrlParser();
        var prevCrl = crlParser.ReadCrl(buf);
        var prevCrlNum = prevCrl.GetExtensionValue(X509Extensions.CrlNumber);
        var asn1Object = X509ExtensionUtilities.FromExtensionValue(prevCrlNum);
        var prevCrlNumVal = DerInteger.GetInstance(asn1Object).PositiveValue;
        nextCrlNum = new CrlNumber(prevCrlNumVal.Add(BigInteger.One));
    }

    return nextCrlNum;
}

static string BaseDir()
{
    var assembly = Assembly.GetExecutingAssembly();
    var resourcePath = String.Format(
        $"{Regex.Replace(assembly.ManifestModule.Name, @"\.(exe|dll)$", string.Empty, RegexOptions.IgnoreCase)}" +
        $".Resources.ProjectDirectory.txt");

    var rm = new ResourceManager("Resources", assembly);
    using var stream = assembly.GetManifestResourceStream(resourcePath);
    using var streamReader = new StreamReader(stream!);

    return streamReader.ReadToEnd().Trim();
}
