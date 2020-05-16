using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertificateAuthority
{

    public class CreateCertChain
    {
        //[LegalFilePath]
        //[Option("-s", LongName = "Subject", Description = "The generated root CA's certificate subject name. This will also be the base of the generated filenames.")]
        public string RootName { get; set; }

        //[Option("-p", LongName = "Password", Description = "The password of the PFX file(s) that are output.")]
        public string Password { get; set; }

        //[Range(0, 5)]
        //[Option("-i", LongName = "Intermediates", Description = "The number of intermediate CAs to create in a chain.")]
        public int IntermediateCount { get; set; }
        public string filePath { get; set; } // = @"F:\DevGit\certs\testchain\";
        public int OnExecute()
        {
            //string filePath = @"F:\DevGit\certs\testchain\";
            var rootCaCert = CertificateUtil.CreateCaCertificate(RootName, Password, null);
            CertificateUtil.SaveCertificateToPfxFile($"{filePath}{RootName}.pfx", Password, rootCaCert, null, null);
            var rootPublicKey = CertificateUtil.ExportCertificatePublicKey(rootCaCert);
            var rootPublicKeyBytes = rootPublicKey.Export(X509ContentType.Cert);
            File.WriteAllBytes($"{filePath}{RootName}.cer", rootPublicKeyBytes);
            var previousCaCert = rootCaCert;
            var chain = new X509Certificate2Collection();
            for (var i = 1; i <= IntermediateCount; i++)
            {
                var intermediateCert = CertificateUtil.CreateCaCertificate($"{filePath}{RootName} - Intermediate {i}", Password, previousCaCert);
                var previousCaCertPublicKey = CertificateUtil.ExportCertificatePublicKey(previousCaCert);
                CertificateUtil.SaveCertificateToPfxFile($"{filePath}Intermediate {i}.pfx", Password, intermediateCert, previousCaCertPublicKey, chain);

                var intermediatePublicKey = CertificateUtil.ExportCertificatePublicKey(intermediateCert);
                var intermediatePublicKeyBytes = intermediatePublicKey.Export(X509ContentType.Cert);
                File.WriteAllBytes($"{filePath}{RootName}Intermediate {i}.cer", intermediatePublicKeyBytes);
                
                
                chain.Add(previousCaCertPublicKey);
                previousCaCert = intermediateCert;
            }
            return 0;
        }
    }
}

