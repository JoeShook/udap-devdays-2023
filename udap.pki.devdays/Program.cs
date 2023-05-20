// See https://aka.ms/new-console-template for more information
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using udap.pki.devdays;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

Console.WriteLine("Generating PKI for UDAP DevDays");

string staticCertPort = "5033";
string certificateStore = "CertificateStore";

MakeUdapPki(
    $"{certificateStore}/Community1",                                       //communityStorePath
    "DevDaysCA_1",                                                          //anchorName
    "DevDaysSubCA_1",                                                       //intermediateName
    "DevDaysRsaClient",                                                     //issuedName
    "CN=localhost, OU=DevDays, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
    new List<string>
    {
        "https://localhost:7016/fhir/r4",
        "http://localhost/fhir/r4",
    },                                                                      //SubjAltNames (Demonstrate multiple)
    "RSA"
);

MakeUdapPki(
    $"{certificateStore}/Community2",                                       //communityStorePath
    "DevDaysCA_2",                                                          //anchorName
    "DevDaysSubCA_2",                                                       //intermediateName
    "DevDaysRsaClient",                                                     //issuedName
    "CN=localhost, OU=DevDays, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
    new List<string>
    {
        "https://localhost:7016/fhir/r4",
        "http://localhost/fhir/r4",
    },                                                                      //SubjAltNames (Demonstrate multiple)
    "ECDSA"
);

void MakeUdapPki(
            string communityStorePath,
            string anchorName,
            string intermediateName,
            string issuedName,
            string issuedDistinguishedName,
            List<string> issuedSubjectAltNames,
            string cryptoAlgorithm)
{
    var crlFolder = $"{communityStorePath}/crl";
    crlFolder.EnsureDirectoryExists();
    var anchorCrlFile = $"{crlFolder}/{anchorName}.crl";
    var intermediateCrlFile = $"{crlFolder}/{intermediateName}.crl";


    var intermediateCdp = $"http://localhost:{staticCertPort}/crl/{anchorName}.crl";
    var clientCdp = $"http://localhost:{staticCertPort}/crl/{intermediateName}.crl";

    string intermediateHostedUrl = $"https://localhost:{staticCertPort}/{intermediateName}.crt";

    var localhostUdapIntermediateFolder = $"{communityStorePath}/intermediates";
    var localhostUdapIssuedFolder = $"{communityStorePath}/issued";
    

    using (RSA parent = RSA.Create(4096))
    using (RSA intermediate = RSA.Create(4096))
    {
        var parentReq = new CertificateRequest(
            $"CN={anchorName}, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
            communityStorePath.EnsureDirectoryExists();
            File.WriteAllBytes($"{communityStorePath}/{anchorName}.pfx", parentBytes);
            var caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
            File.WriteAllBytes($"{communityStorePath}/{anchorName}.crt",
                caPem.Select(c => (byte)c).ToArray());

            CreateCertificateRevocationList(caCert, anchorCrlFile);

            var intermediateReq = new CertificateRequest(
                $"CN={intermediateName}, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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

            
            using var intermediateCert = intermediateReq.Create(
                caCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(5),
                new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
            var intermediateCertWithKey = intermediateCert.CopyWithPrivateKey(intermediate);
            var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
            localhostUdapIntermediateFolder.EnsureDirectoryExists();
            File.WriteAllBytes($"{localhostUdapIntermediateFolder}/{intermediateName}.pfx",
                intermediateBytes);
            char[] intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCert.RawData);
            File.WriteAllBytes($"{localhostUdapIntermediateFolder}/{intermediateName}.crt",
                intermediatePem.Select(c => (byte)c).ToArray());

            CreateCertificateRevocationList(intermediateCertWithKey, intermediateCrlFile);

            communityStorePath.EnsureDirectoryExists();
            $"{localhostUdapIssuedFolder}".EnsureDirectoryExists();

            X509Certificate2? clientCertificate = null;

            if (cryptoAlgorithm is "ECDSA")
            {
                BuildClientCertificateECDSA(
                    intermediateCert,
                    caCert,
                    intermediate,
                    issuedDistinguishedName,
                    issuedSubjectAltNames,
                    $"{localhostUdapIssuedFolder}/{issuedName}",
                    intermediateHostedUrl,
                    clientCdp
                );
            }
            else
            {
                BuildClientCertificate(
                    intermediateCert,
                    caCert,
                    intermediate,
                    issuedDistinguishedName,
                    issuedSubjectAltNames,
                    $"{localhostUdapIssuedFolder}/{issuedName}",
                    intermediateHostedUrl,
                    clientCdp
                );
            }
        }
    }
}



X509Certificate2 BuildClientCertificate(
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
    File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes);
    var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
    File.WriteAllBytes($"{clientCertFilePath}.crt", clientPem.Select(c => (byte)c).ToArray());


    //Distribute
    File.Copy($"{clientCertFilePath}.pfx", $"{BaseDir()}/../udap.fhirserver.devdays/{clientCertFilePath}.pfx",
        true);

    return clientCert;
}

X509Certificate2 BuildClientCertificateECDSA(
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
    File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes);
    var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
    File.WriteAllBytes($"{clientCertFilePath}.crt", clientPem.Select(c => (byte)c).ToArray());

    return clientCert;
}


void CreateCertificateRevocationList(X509Certificate2 certificate, string crlFilePath){
    // Certificate Revocation
    var bouncyCaCert = DotNetUtilities.FromX509Certificate(certificate);

    var crlIntermediateGen = new X509V2CrlGenerator();
    var intermediateNow = DateTime.UtcNow;
    crlIntermediateGen.SetIssuerDN(bouncyCaCert.SubjectDN);
    crlIntermediateGen.SetThisUpdate(intermediateNow);
    crlIntermediateGen.SetNextUpdate(intermediateNow.AddYears(1));

    crlIntermediateGen.AddCrlEntry(BigInteger.One, intermediateNow, CrlReason.PrivilegeWithdrawn);

    crlIntermediateGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
        false,
        new AuthorityKeyIdentifierStructure(bouncyCaCert.GetPublicKey()));

    var nextsureFhirIntermediateCrlNum = GetNextCrlNumber(crlFilePath);

    crlIntermediateGen.AddExtension(X509Extensions.CrlNumber, false, nextsureFhirIntermediateCrlNum);

    // var intermediateRandomGenerator = new CryptoApiRandomGenerator();
    // var intermediateRandom = new SecureRandom(intermediateRandomGenerator);

    var intermediateAkp = DotNetUtilities.GetKeyPair(certificate.GetRSAPrivateKey()).Private;

    // var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp, intermediateRandom));
    var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp));
    
    File.WriteAllBytes(crlFilePath, intermediateCrl.GetEncoded());
}

static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest intermediateReq)
{
    //
    // Found way to generate intermediate below
    //
    // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
    // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
    //


    var issuerSubjectKey = caCert.Extensions?["2.5.29.14"].RawData;
    var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
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
    using var streamReader = new StreamReader(stream);

    return streamReader.ReadToEnd().Trim();
}
