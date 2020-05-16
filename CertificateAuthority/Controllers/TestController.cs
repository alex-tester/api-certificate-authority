using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
//using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CertificateAuthority.Models;
//using CERTENROLLLib;
using Microsoft.AspNetCore.Mvc;
using CertificateAuthority.Models.DatabaseModels;
//using Org.BouncyCastle;

namespace CertificateAuthority.Controllers
{
    public class TestController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public X509Certificate2 cert2file()
        {
            string certificateName = "root-cert";
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);
            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={certificateName}"); //($"CN=test-cert"); //($"CN={}");
            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));


                request.CertificateExtensions.Add(
                   new X509EnhancedKeyUsageExtension(
                       new OidCollection
                       {
                           new Oid("1.3.6.1.5.5.7.3.1"), // server authentication
                           new Oid("1.3.6.1.5.5.7.3.2")  // client authentication
                       }, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
                certificate.FriendlyName = certificateName;
                byte[] certData = certificate.Export(X509ContentType.Pfx, "1234");
                System.IO.File.WriteAllBytes(@"F:\DevGit\certs\csharptest\cert1.pfx", certData);
                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "WeNeedASaf3rPassword"), "WeNeedASaf3rPassword", X509KeyStorageFlags.MachineKeySet);

            }
        }




        public X509Certificate2 TestCreateRoot()
        {
            string pass = "1234";
            string filePath = @"F:\Devgit\certs\testroot\testroot2.pfx";
            return CreateRootCA("new-auto-root2", certSignatureAlgorithm.RSA, HashAlgorithmName.SHA512,
                2048, 365, pass, true, filePath);

            //System.Security.Cryptography.RSAOpenSsl
        }


        #region migrated to certificatecontroller
        public enum certSignatureAlgorithm
        {
            RSA = 0,
            ECDsa = 1
        }
        //include filename in export path if exportpfx option is chosen
        public X509Certificate2 CreateRootCA(string certName, certSignatureAlgorithm algorithm,
            HashAlgorithmName hash, int keySize, int validDays, string keyPassword, bool exportPfx, string exportPath)
        {
            //need to make these params
            bool useCrl = true;
            bool addRootCaToComputerRootStore = true;
            bool addRootCaToComputerPersonalStore = true;

            //string filePath = @"F:\Devgit\certs\testroot\testroot.pfx";
            //end

            X509Certificate2 newRoot = new X509Certificate2();
            CertificateRequest request;// = new CertificateRequest();

            //string certificateName = "root-ca-csharp2";
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            //sanBuilder.AddIpAddress(IPAddress.Loopback);
            //sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("dev-11.observicing.net");
            //sanBuilder.AddUserPrincipalName("tester");
            //sanBuilder.AddDnsName(Environment.MachineName);

            //OidCollection enhancedUsage = new OidCollection();

            X500DistinguishedName dn = new X500DistinguishedName($"CN={certName}"); //($"CN=test-cert"); //($"CN={}");
            if (algorithm == certSignatureAlgorithm.RSA)
            {
                var key = GenerateRsaKey(keySize);
                request = CreateRsaCertificateRequest(dn, hash, key);


                newRoot = CompleteRootCaRequest(certName, request, sanBuilder, validDays,
                    keyPassword, useCrl, exportPfx, exportPath,
                    addRootCaToComputerRootStore, addRootCaToComputerPersonalStore);
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
            SubjectAlternativeNameBuilder sanBuilder, int validDays, string keyPassword, bool useCrl,
            bool exportPfx, string exportPath, bool addRootCaToComputerRootStore, bool addRootCaToComputerPersonalStore)
        {

            var sanExtension = sanBuilder.Build();

            // set this cert as a CA
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));

            request.CertificateExtensions.Add(sanExtension);
            //request.CertificateExtensions
            var newRoot = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(validDays)));
           
               // System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            newRoot.FriendlyName = certName;

            if (exportPfx) { ExportCaPfx(newRoot, exportPath, keyPassword); }
            if (addRootCaToComputerRootStore) { AddRootCaToStore(newRoot, StoreLocation.LocalMachine, StoreName.Root); }
            if (addRootCaToComputerPersonalStore) { AddRootCaToStore(newRoot, StoreLocation.LocalMachine, StoreName.My); }


            return new X509Certificate2(newRoot.Export(X509ContentType.Pfx, keyPassword), keyPassword, X509KeyStorageFlags.MachineKeySet);
        }


        public void ExportCaPfx(X509Certificate rootCert, string filePath, string keyPassword)
        {
            //bool exported = false;
            try
            {
                byte[] certData = rootCert.Export(X509ContentType.Pfx, keyPassword);
                System.IO.File.WriteAllBytes(filePath, certData);
                //exported = true;
            }
            catch { }
            //return exported;
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

        internal CertificateRequest GenerateCertificateRequest(X500DistinguishedName dn,
            HashAlgorithmName hash, int keySize)//, int validDays, string keyPassword,bool useCRL, bool addRootCaToComputerRootStore, bool addRootCaToComputerPersonalStore)
        {
            //X500DistinguishedName dn = new X500DistinguishedName($"CN={certificateName}");

            RSA key = RSA.Create(keySize);

            var request = new CertificateRequest(dn, key, hash, RSASignaturePadding.Pkcs1);

            key.Dispose();

            return request;
            //var sanExtension = sanBuilder.Build();

            //request.CertificateExtensions.Add(sanExtension);

            //var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(validDays)));
            //certificate.FriendlyName = certificateName;

            //key.Dispose();

            //return new X509Certificate2(certificate.Export(X509ContentType.Pfx, keyPassword), keyPassword, X509KeyStorageFlags.MachineKeySet);


        }



        internal static X509Certificate2 ExportCertificatePublicKey(X509Certificate2 certificate)
        {
            var publicKeyBytes = certificate.Export(X509ContentType.Cert);
            var signingCertWithoutPrivateKey = new X509Certificate2(publicKeyBytes);
            return signingCertWithoutPrivateKey;
        }

        internal static void SaveCertificateToPfxFile(string filename, string password,
    X509Certificate2 certificate, X509Certificate2 signingCert,
    X509Certificate2Collection chain)
        {
            var certCollection = new X509Certificate2Collection(certificate);
            if (chain != null)
            {
                certCollection.AddRange(chain);
            }
            if (signingCert != null)
            {
                var signingCertWithoutPrivateKey = ExportCertificatePublicKey(signingCert);
                certCollection.Add(signingCertWithoutPrivateKey);

            }
            var certBytes = certCollection.Export(X509ContentType.Pkcs12, password);
            System.IO.File.WriteAllBytes(filename, certBytes);
        }

        //public X509Certificate2 testreq()
        //{
        //    string thumbprint = "6272237b5079bf4bb57194f841dc01508fadbc50"; //root-ca.observicing.net
        //    string subject = "autocsharptest";
        //    string exportPassword = "1234";
        //    string fileName = @"F:\devgit\certs\csharptest\autocsharptest.pfx";

        //    X509Certificate2 newCert = RequestClientCertificate(subject, thumbprint);
        //    var certBytes = newCert.Export(X509ContentType.Pkcs12, exportPassword);
        //    System.IO.File.WriteAllBytes(fileName, certBytes);
        //    return newCert;
        //}

        public int testchain()
        {
            CreateCertChain certChain = new CreateCertChain();
            certChain.IntermediateCount = 5;
            certChain.Password = "1234";
            certChain.RootName = "chaintest";
            certChain.filePath = @"F:\DevGit\certs\testchain\";
            return certChain.OnExecute();
        }

        public X509Certificate2 testrequestclient()
        {
            string exportPass = "1234";
            string fileName = @"F:\DevGit\certs\csharptest\encodingusinglib\client-WITH-crl.crt";
            string thumnprint = "3407a90ef0de2618c6568ff46ce4e8126dc907d0";
            var hash = HashAlgorithmName.SHA512;
            var keySize = 2048;
            int validDays = 100;
            //string crlUri = "http://dev-11.observicing.net/crl/new-auto-root-ca.crl";
            string[] crlUri =
                                {
                                    "http://automatedtestfromcsharp/root-ca.crl",
                                    "http://thisisgoingtowork/right.crl"
                                };

            var cert = RequestClientCertificate("client-auto-test", thumnprint, true, crlUri, hash, keySize, validDays);
            //var certBytes = cert.Export(X509ContentType.Pkcs12, exportPass);
            var certBytes = cert.Export(X509ContentType.Cert, exportPass); //export as crt to test
            System.IO.File.WriteAllBytes(fileName, certBytes);
            return cert;
        }

     

        private IssuedCertificates GetBase64CertificateFromDb(string certificateThumbprint)
        {
            CertificateAuthorityContext db = new CertificateAuthorityContext();

            var crt = (from c in db.IssuedCertificates
                       where c.CertificateThumbprint == certificateThumbprint
                       select c).First();
            return crt;
        }

        public class CertFromDbClass
        {
            public string data { get; set; }
            public string secret { get; set; }
        }


        #region migrated db function
        private string WriteCertificateToDb_ReturnBase64Pfx(X509Certificate2 cert, string PfxPass)
        {

            //var cert = RequestClientCertificateFromPfxFile("client-auto-test", thumnprint, true, crlUri, hash, keySize, validDays);
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
            newRecord.IsRootCa = false;
            newRecord.IsIntermediateCa = false;
            newRecord.IsClientCert = true;

            CertificateAuthorityContext db = new CertificateAuthorityContext();
            try
            {
                db.IssuedCertificates.AddAsync(newRecord);
            }
            catch
            { } //meh
            return base64Cert;
        }

        #endregion
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

            #region noop - removing this
            //X509Store store = new X509Store(StoreLocation.LocalMachine);
            //X509Certificate2 newCert = new X509Certificate2();
            //X509Certificate2 rootCert; // = new X509Certificate2();

            //X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);

            //store.Open(OpenFlags.ReadOnly);

            //X509Certificate2 rootCertificate = (store.Certificates.Find(X509FindType.FindByThumbprint, "6272237b5079bf4bb57194f841dc01508fadbc50", false))[0]; //client.obs
            //X509Certificate2Collection storeCerts = store.Certificates.Find(X509FindType.FindByThumbprint, rootCertificateThumbprint, false);
            //if (storeCerts.Count > 0) { rootCert = storeCerts[0]; }
            //else
            //{
            //    throw new ArgumentException($"{nameof(rootCertificateThumbprint)} was not found in the computer trusted root store", nameof(rootCertificateThumbprint));
            //    //return newCert; 
            //}


            //var currentDir = Directory.GetCurrentDirectory();

            ////testing using pfx file
            //string certFileName = "ca.pfx";

            //var certPath = Path.Combine(currentDir, certFileName);

            //X509Certificate2 rootCert;
            //try
            //{


            //    //rootCert = new X509Certificate2($@"{currentDir}\ca.pfx", "hmm");

            //    rootCert = new X509Certificate2(certPath, "hmm");
            //    
            //}
            //catch
            //{
            //    throw; //add message
            //}


            //rootCert = new X509Certificate2($@"{currentDir}/ca.pfx", "hmm");
            //return CreateAndSignClientCert(certName, rootCert, keySize, hash, validDays, useCrl, crlUri);

            #endregion

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


        public async Task<string> testcrlgen()
        {
            var hmm = testcrl();
            var hmmCrt = Convert.ToBase64String(hmm.Export(X509ContentType., "1234"));
            var base64Pfx = WriteCertificateToDb_ReturnBase64Pfx(hmm, "1234");
            return hmmCrt;
        }


        public X509Certificate2 testcrl()
        {
            string subjectName = "crltest";
            X500DistinguishedName dn = new X500DistinguishedName($"CN={subjectName}");
            CERTENROLLLib.CX509CertificateRevocationList newCrl = new CERTENROLLLib.CX509CertificateRevocationList();

            string rootThumbprint = "8F75B0762106AB61581F6E12EC1DA62501CA2DDD";

            var PfxFromDb = GetBase64CertificateFromDb(rootThumbprint);

            var signingCertificate = new X509Certificate2(Convert.FromBase64String(PfxFromDb.Base64Pfx), PfxFromDb.PkSecret);

            var rsaKey = GenerateRsaKey(2048);

            var crlReq = CreateRsaCertificateRequest(dn, HashAlgorithmName.SHA512, rsaKey);


            // set basic certificate contraints
            //crlReq.CertificateExtensions.Add(
            //    new X509BasicConstraintsExtension(false, false, 0, true));

            //// key usage: Digital Signature and Key Encipherment
            //crlReq.CertificateExtensions.Add(
            //    new X509KeyUsageExtension(
            //         X509KeyUsageFlags.CrlSign,
            //        true));

            string[] crlNumArr =
            {
                "01"
            };

            Models.Asn1Functions.Asn1Functions asnFnc = new Models.Asn1Functions.Asn1Functions();
            string base64CrlNumber = asnFnc.EncodeCrlNumberExtensionData(crlNumArr);

            Oid crlNumberOid = new Oid("2.5.29.20");

            byte[] crlNumberBytes = Convert.FromBase64String(base64CrlNumber);
            AsnEncodedData crlNumberEnc = new AsnEncodedData(crlNumberOid, crlNumberBytes);
            crlReq.CertificateExtensions.Add(new X509Extension(crlNumberEnc, false));


            //        crlReq.CertificateExtensions.Add(
            //new X509EnhancedKeyUsageExtension(
            //    new OidCollection {
            //                        new Oid("2.5.29.20") // TLS Client auth

            //    },
            //    false));

            //var PfxFromDb = GetBase64CertificateFromDb(rootThumbprint);
            //var rootCert = new X509Certificate2(Convert.FromBase64String(PfxFromDb.Base64Pfx), PfxFromDb.PkSecret);

            //var rootCert = new CERTENROLLLib.X509CertificateEnrollmentContext CX509Certificate2(Convert.FromBase64String(PfxFromDb.Base64Pfx), PfxFromDb.PkSecret);

            //newCrl.Initialize
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
            var serial = BitConverter.GetBytes(unixTime);
            using (var crlCrt = crlReq.Create(
                signingCertificate,
                DateTime.Now.AddDays(-1),
                DateTime.Now.AddDays(100),
                serial))
            {
                return crlCrt.CopyWithPrivateKey(rsaKey);
            }
        }

        //public string GetAsnFormattedData()
        //{
        //    CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
        //    Oid oidObj = new Oid("2.5.29.31");
        //    byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes1.txt");
        //    return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        //}






      


        //// WORKING ASN1 FUNCTIONS
        //[HttpPost]
        ////public string AsnFormattedDataFromByteArray(string Oid, byte[] RawExtensionData)
        //public string AsnFormattedDataFromBase64String([FromBody] AsnEncodedDataClass A)
        //{
        //    Oid oidObj = new Oid(A.Oid);
        //    CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
        //    byte[] rawExtensionData = System.Convert.FromBase64String(A.Base64ExtensionData);
        //    //byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes1.txt");
        //    return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        //}

        //[HttpPost]
        ////public string AsnFormattedDataFromByteArray(string Oid, byte[] RawExtensionData)
        //public string AsnFormattedDataFromFile([FromBody] AsnEncodedFileLocation F)
        //{
        //    Oid oidObj = new Oid(F.Oid);
        //    CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();

        //    byte[] rawExtensionData = System.IO.File.ReadAllBytes($@"{F.FilePath}");
        //    return asnFnc.FormatNative(oidObj, rawExtensionData, true);

        //}

        //[HttpPost]
        //public string ConvertToBase64X509CrlExtensionData([FromBody] X509CrlExtensionInputData D)
        //{
        //    CertificateAuthority.Models.Asn1Functions.Asn1Functions asnFnc = new CertificateAuthority.Models.Asn1Functions.Asn1Functions();
        //    return asnFnc.EncodeCrlExtensionData(D.CrlLocations);

        //}

        //public class X509CrlExtensionInputData
        //{
        //    public string Oid { get; set; }
        //    public string[] CrlLocations { get; set; }
        //}

        //public class AsnEncodedDataClass
        //{
        //    public string Base64ExtensionData { get; set; }
        //    public string Oid { get; set; }
        //}

        //public class AsnEncodedFileLocation
        //{
        //    public string Oid { get; set; }
        //    public string FilePath { get; set; }
        //}
    }
}