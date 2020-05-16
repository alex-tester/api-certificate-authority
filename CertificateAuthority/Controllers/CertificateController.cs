using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateAuthority.Models;
using CertificateAuthority.Models.DatabaseModels;
using Microsoft.AspNetCore.Mvc;

namespace CertificateAuthority.Controllers
{
    public class CertificateController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }




        #region Asn Encoding Functions
        public string GetAsnFormattedData()
        {
            CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
            Oid oidObj = new Oid("2.5.29.31");
            byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes1.txt");
            return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        }

        // WORKING ASN1 FUNCTIONS
        [HttpPost]
        //public string AsnFormattedDataFromByteArray(string Oid, byte[] RawExtensionData)
        public string AsnFormattedDataFromBase64String([FromBody] AsnEncodedDataClass A)
        {
            Oid oidObj = new Oid(A.Oid);
            CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
            byte[] rawExtensionData = System.Convert.FromBase64String(A.Base64ExtensionData);
            //byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes1.txt");
            return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        }

        [HttpPost]
        //public string AsnFormattedDataFromByteArray(string Oid, byte[] RawExtensionData)
        public string AsnFormattedDataFromFile([FromBody] AsnEncodedFileLocation F)
        {
            Oid oidObj = new Oid(F.Oid);
            CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();

            byte[] rawExtensionData = System.IO.File.ReadAllBytes($@"{F.FilePath}");
            return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        }

        [HttpPost]
        public string ConvertToBase64X509CrlExtensionData([FromBody] X509CrlExtensionInputData D)
        {
            CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
            return asnFnc.EncodeCrlExtensionData(D.CrlLocations);

        }

        #endregion




        #region database methods
        private IssuedCertificates GetBase64CertificateFromDb(string certificateThumbprint)
        {
            CertificateAuthorityContext db = new CertificateAuthorityContext();

            var crt = (from c in db.IssuedCertificates
                       where c.CertificateThumbprint == certificateThumbprint
                       select c).First();
            return crt;
        }

        public async Task<string> WriteCertificateToDb_ReturnBase64Pfx(X509Certificate2 cert, string PfxPass)
        {


            bool isRoot = false;
            bool isIntermediate = false;
            bool isClient = true;
            
            if (cert.Issuer == cert.Subject)
            {
                //root cert
                isRoot = true;
                isClient = false;
            }


            var certBytes = cert.Export(X509ContentType.Pfx, PfxPass); //export as pfx to test
            //System.IO.File.WriteAllBytes(fileName, certBytes);
            var base64Cert = System.Convert.ToBase64String(certBytes);
            IssuedCertificates newRecord = new IssuedCertificates();
            newRecord.CertificateThumbprint = cert.Thumbprint;
            newRecord.Base64Pfx = base64Cert;
            newRecord.FriendlyName = cert.FriendlyName;
            newRecord.Subject = cert.Subject;
            newRecord.ValidTo = cert.NotAfter;
            newRecord.ValidFrom = cert.NotBefore;
            newRecord.SerialNumber = cert.SerialNumber;
            newRecord.HasPk = true;
            newRecord.PkSecret = PfxPass; //bad practice right here
            newRecord.SignatureAlgorithmId = 1;
            newRecord.Version = cert.Version;
            newRecord.IsRootCa = isRoot;
            newRecord.IsIntermediateCa = isIntermediate;
            newRecord.IsClientCert = isClient;

            CertificateAuthorityContext db = new CertificateAuthorityContext();
            try
            {
                await db.IssuedCertificates.AddAsync(newRecord);
                await db.SaveChangesAsync();
            }
            catch
            { } //meh
            return base64Cert;
        }

        #endregion



        #region ROOT CA Generation

        public async Task<string> TestCreateRoot()
        {
            string pfxPass = "1234";
            string filePath = @"F:\Devgit\certs\testroot\testroot2.pfx";
            string cn = "csharp-root";
            
            
            var newCert = CreateRootCA(cn, certSignatureAlgorithm.RSA, HashAlgorithmName.SHA512,
                2048, 365, pfxPass);
            string base64Cert = await WriteCertificateToDb_ReturnBase64Pfx(newCert, pfxPass);

            return base64Cert;

            //System.Security.Cryptography.RSAOpenSsl
        }

        //include filename in export path if exportpfx option is chosen
        public X509Certificate2 CreateRootCA(string certName, certSignatureAlgorithm algorithm,
            HashAlgorithmName hash, int keySize, int validDays, string keyPassword)
        {
            //need to make these params
            bool useCrl = true; //should i do this on ca cert?
       

            X509Certificate2 newRoot = new X509Certificate2();
            CertificateRequest request;// = new CertificateRequest();


            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            //sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddDnsName("dev-11.observicing.net");
            //sanBuilder.AddUserPrincipalName("tester");
            //sanBuilder.AddDnsName(Environment.MachineName);
            //sanBuilder.AddEmailAddress();
            //sanBuilder.AddUri();

            //OidCollection enhancedUsage = new OidCollection();

            X500DistinguishedName dn = new X500DistinguishedName($"CN={certName}"); //($"CN=test-cert"); //($"CN={}");
            if (algorithm == certSignatureAlgorithm.RSA)
            {
                var key = GenerateRsaKey(keySize);
                request = CreateRsaCertificateRequest(dn, hash, key);


                newRoot = CompleteRootCaRequest(certName, request, sanBuilder, validDays,
                    keyPassword, useCrl);
                return newRoot; //.CopyWithPrivateKey(key);
                //key.Dispose();
                //newRoot = CreateRootCaRSA(certificateName, sanBuilder, hash, keySize, validDays, keyPassword, useCRL, addRootCaToComputerRootStore, addRootCaToComputerPersonalStore);
            }
            else //edcsa
            {

            }


            return newRoot;//.CopyWithPrivateKey(key);

        }

        public X509Certificate2 CompleteRootCaRequest(string certName, CertificateRequest request,
            SubjectAlternativeNameBuilder sanBuilder, int validDays, string PfxPassword, bool useCrl)
        {

            var sanExtension = sanBuilder.Build();

            // set this cert as a CA
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));

            request.CertificateExtensions.Add(sanExtension);

            var newRoot = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(validDays)));

            // System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            newRoot.FriendlyName = certName;

            return newRoot;
            //return new X509Certificate2(newRoot.Export(X509ContentType.Pfx, PfxPassword), PfxPassword, X509KeyStorageFlags.Exportable);
        }




        public void AddRootCaToStore(X509Certificate2 rootCert, StoreLocation storeLocation, StoreName storeName)
        {
            X509Store store = new X509Store(storeName, storeLocation);

            store.Open(OpenFlags.ReadWrite);
            store.Add(rootCert);

            store.Close();
            store.Dispose();
        }


        internal RSA GenerateRsaKey(int keySize)
        {
            return RSA.Create(keySize);
        }

        internal CertificateRequest CreateRsaCertificateRequest(X500DistinguishedName dn, HashAlgorithmName hash, RSA key)
        {
            var request = new CertificateRequest(dn, key, hash, RSASignaturePadding.Pkcs1);

            return request;
        }




        #endregion




        #region INTERMEDIATE CA GENERATION



        #endregion




        #region CLIENT CERT GENERATION

        public async Task<string> testrequestclienttobase64bytespfx()
        {
            string exportPass = "1234";
            string fileName = @"F:\DevGit\certs\csharptest\encodingusinglib\client-WITH-crl.crt";
            string thumnprint = "8F75B0762106AB61581F6E12EC1DA62501CA2DDD";
            var hash = HashAlgorithmName.SHA512;
            var keySize = 2048;
            int validDays = 100;
            string certDn = "issuedtoclient";
            string friendlyName = "csharp auto test - pfxmethod";

            //string crlUri = "http://dev-11.observicing.net/crl/new-auto-root-ca.crl";
            string[] crlUri =
                                {
                                    "http://automatedtestfromcsharp/root-ca.crl",
                                    "http://thisisgoingtowork/right.crl"
                                };

            var cert = RequestClientCertificateUsingDb(certDn, friendlyName, thumnprint, true, crlUri, hash, keySize, validDays);
            //var certBytes = cert.Export(X509ContentType.Pkcs12, exportPass);
            //var certBytes = cert.Export(X509ContentType.Cert, exportPass);


            //var certBytes = cert.Export(X509ContentType.Pfx, exportPass); //export as pfx to test
            //System.IO.File.WriteAllBytes(fileName, certBytes);
            //var base64Cert = System.Convert.ToBase64String(certBytes);

            var base64Cert = await WriteCertificateToDb_ReturnBase64Pfx(cert, exportPass);



            return base64Cert;
        }

        public string testrequestclienttobase64bytescrt()
        {
            string exportPass = "1234";
            string fileName = @"F:\DevGit\certs\csharptest\encodingusinglib\client-WITH-crl.crt";
            string thumnprint = "3407a90ef0de2618c6568ff46ce4e8126dc907d0";
            var hash = HashAlgorithmName.SHA512;
            var keySize = 2048;
            int validDays = 100;
            string certDn = "issuedtoclient";
            string friendlyName = "csharp auto test - crtmethod";

            //string crlUri = "http://dev-11.observicing.net/crl/new-auto-root-ca.crl";
            string[] crlUri =
                                {
                                    "http://automatedtestfromcsharp/root-ca.crl",
                                    "http://thisisgoingtowork/right.crl"
                                };

            var cert = RequestClientCertificateUsingDb(certDn, friendlyName, thumnprint, true, crlUri, hash, keySize, validDays);
            //var certBytes = cert.Export(X509ContentType.Pkcs12, exportPass);
            //var certBytes = cert.Export(X509ContentType.Cert, exportPass);
            var certBytes = cert.Export(X509ContentType.Cert, exportPass); //export as pfx to test
            //System.IO.File.WriteAllBytes(fileName, certBytes);
            return System.Convert.ToBase64String(certBytes);
        }

        //mine
        public X509Certificate2 RequestClientCertificate(string certName, string rootCertificateThumbprint, bool useCrl, string[] crlUri, HashAlgorithmName hash, int keySize, int validDays)
        {

            //X509Store store = new X509Store(StoreLocation.LocalMachine);
            //X509Certificate2 newCert = new X509Certificate2();
            X509Certificate2 rootCert; // = new X509Certificate2();

            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);

            store.Open(OpenFlags.ReadOnly);

            //X509Certificate2 rootCertificate = (store.Certificates.Find(X509FindType.FindByThumbprint, "6272237b5079bf4bb57194f841dc01508fadbc50", false))[0]; //client.obs
            X509Certificate2Collection storeCerts = store.Certificates.Find(X509FindType.FindByThumbprint, rootCertificateThumbprint, false);

            //living dangerously
            rootCert = storeCerts[0];

            //if (storeCerts.Count > 0) { rootCert = storeCerts[0]; }
            //else
            //{
            //    throw; // new ArgumentException($"{nameof(rootCertificateThumbprint)} was not found in the computer trusted root store", nameof(rootCertificateThumbprint));
            //    //return newCert; 
            //}


            return CreateAndSignClientCert(certName, rootCert, keySize, hash, validDays, useCrl, crlUri);

        }

        public X509Certificate2 RequestClientCertificateUsingDb(string baseDn, string FriendlyName, string rootCertificateThumbprint, bool useCrl, string[] crlUri, HashAlgorithmName hash, int keySize, int validDays)
        {

            var PfxFromDb = GetBase64CertificateFromDb(rootCertificateThumbprint);
            var rootCert = new X509Certificate2(Convert.FromBase64String(PfxFromDb.Base64Pfx), PfxFromDb.PkSecret);
            var newCert = CreateAndSignClientCert(baseDn, rootCert, keySize, hash, validDays, useCrl, crlUri);
            newCert.FriendlyName = FriendlyName; //is this really how i set this?
            return newCert;

        }


        public X509Certificate2 CreateAndSignClientCert(string subjectName, X509Certificate2 signingCertificate,
            int keySize, HashAlgorithmName hash, int validDays, bool useCrl, string[] crlUri)
        {
            if (signingCertificate == null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }
            if (!signingCertificate.HasPrivateKey)
            {
                throw new Exception("Signing cert must have private key");
            }
            if (string.IsNullOrEmpty(subjectName))
            {
                throw new ArgumentException($"{nameof(subjectName)} must be a valid DNS name", nameof(subjectName));
            }
            //if (UriHostNameType.Unknown == Uri.CheckHostName(subjectName))
            //{
            //    throw new ArgumentException("Must be a valid DNS name", nameof(subjectName));
            //}

            X500DistinguishedName dn = new X500DistinguishedName($"CN={subjectName}");

            RSA key = GenerateRsaKey(keySize);


            CertificateRequest request = CreateRsaCertificateRequest(dn, hash, key);


            //using (var ecdsa = ECDsa.Create("ECDsa"))
            //{
            //ecdsa.KeySize = 256;
            //var request = new CertificateRequest(
            //    $"CN={subjectName}",
            //    ecdsa,
            //    HashAlgorithmName.SHA256);

            // set basic certificate contraints
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));

            // key usage: Digital Signature and Key Encipherment
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    true));

            // set the AuthorityKeyIdentifier. There is no built-in 
            // support, so it needs to be copied from the Subject Key 
            // Identifier of the signing certificate and massaged slightly.
            // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"

            //x509

            // TEMPORARILY REMOVING - PLAN TO ADD BACK
            //var issuerSubjectKey = signingCertificate.Extensions["Subject Key Identifier"].RawData;
            //var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
            //var authorityKeyIdentifer = new byte[segment.Count + 4];
            //// these bytes define the "KeyID" part of the AuthorityKeyIdentifer
            //authorityKeyIdentifer[0] = 0x30;
            //authorityKeyIdentifer[1] = 0x16;
            //authorityKeyIdentifer[2] = 0x80;
            //authorityKeyIdentifer[3] = 0x14;
            //segment.CopyTo(authorityKeyIdentifer, 4);
            //request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifer, false));

            //request.CertificateExtensions.Add(new X509Extension //X509Extension("2.5.29.31", crlUri, false));

            //string crlUri = "http://dev-11.observicing.net/crl/new-auto-root-ca.crl";

            // add oid for cert revocation list
            if (useCrl)
            {
                //byte[] crlBytes = Encoding.ASCII.GetBytes(crlUri);
                //byte[] oidBytes = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\crloid.txt"); // WORKS!
                //byte[] oidBytes = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\crloid-modified.txt");
                CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();

                Oid crlOid = new Oid("2.5.29.31");
                byte[] oidBytes = System.Convert.FromBase64String(asnFnc.EncodeCrlExtensionData(crlUri));
                AsnEncodedData enc = new AsnEncodedData(crlOid, oidBytes);

                //request.CertificateExtensions.Add(new X509Extension(enc, false));

                //X509CrlExtensionInputData crlExt = new X509CrlExtensionInputData();
                //crlExt.CrlLocations = crlUri;
                request.CertificateExtensions.Add(new X509Extension(enc, false));
            }



            //AsnEncodedData

            // DPS samples create certs with the device name as a SAN name 
            // in addition to the subject name
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(subjectName);
            var sanExtension = sanBuilder.Build();
            request.CertificateExtensions.Add(sanExtension);

            // Enhanced key usages
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                    },
                    false));

            // add this subject key identifier
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            // certificate expiry: Valid from Yesterday to Now+365 days
            // Unless the signing cert's validity is less. It's not possible
            // to create a cert with longer validity than the signing cert.
            var notbefore = DateTimeOffset.UtcNow.AddDays(-1);
            if (notbefore < signingCertificate.NotBefore)
            {
                notbefore = new DateTimeOffset(signingCertificate.NotBefore);
            }
            var notafter = DateTimeOffset.UtcNow.AddDays(validDays);
            if (notafter > signingCertificate.NotAfter)
            {
                notafter = new DateTimeOffset(signingCertificate.NotAfter);
            }

            // cert serial is the epoch/unix timestamp
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
            var serial = BitConverter.GetBytes(unixTime);

            // create and return the generated and signed
            using (var cert = request.Create(
                signingCertificate,
                notbefore,
                notafter,
                serial))
            {
                return cert.CopyWithPrivateKey(key);
            }
            //}
        }



        #endregion




        public enum certSignatureAlgorithm
        {
            RSA = 0,
            ECDsa = 1
        }
    }
}