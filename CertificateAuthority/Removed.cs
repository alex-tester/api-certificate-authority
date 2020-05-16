using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertificateAuthority
{
    public class Removed
    {

        //deprecating
        public X509Certificate2 CreateRootCaRSA(string certificateName, SubjectAlternativeNameBuilder sanBuilder,
            HashAlgorithmName hash, int keySize, int validDays, string keyPassword,
            bool useCRL, bool addRootCaToComputerRootStore, bool addRootCaToComputerPersonalStore)
        {
            X500DistinguishedName dn = new X500DistinguishedName($"CN={certificateName}");

            RSA key = RSA.Create(keySize);

            var request = new CertificateRequest(dn, key, hash, RSASignaturePadding.Pkcs1);

            var sanExtension = sanBuilder.Build();

            request.CertificateExtensions.Add(sanExtension);

            var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(validDays)));
            certificate.FriendlyName = certificateName;

            key.Dispose();

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, keyPassword), keyPassword, X509KeyStorageFlags.MachineKeySet);


        }



    }
}
