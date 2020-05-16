using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateParsing
{
    class Program
    {
        static void Main(string[] args)
        {

            int option = 3;
            if (option == 1)
            {
                Console.WriteLine("Hello World!");
                X509Certificate2 cert = new X509Certificate2();
                //string certificateThumbprint = "c6a24a08eb419a70980ba0ab3b174e92c8cf743e"; //clientauth root-ca.observicing.net
                string certificateThumbprint = "8782c6c304353bcfd29692d2593e7d44d934ff11";

                X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);

                store.Open(OpenFlags.ReadOnly);

                //X509Certificate2 rootCertificate = (store.Certificates.Find(X509FindType.FindByThumbprint, "6272237b5079bf4bb57194f841dc01508fadbc50", false))[0]; //client.obs
                X509Certificate2Collection storeCerts = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
                if (storeCerts.Count > 0) { cert = storeCerts[0]; }
                else
                {
                    throw new ArgumentException($"{nameof(certificateThumbprint)} was not found in the computer trusted root store", nameof(certificateThumbprint));
                    //return newCert; 
                }


                //X509Certificate2 cert = /* your code here */;

                foreach (X509Extension extension in cert.Extensions)
                {
                    if (extension.Oid.Value == "2.5.29.31")
                    {
                        Console.WriteLine("yeet");

                        var rawExtensionData = extension.RawData;
                        AsnEncodedData asnExtensionData = new AsnEncodedData(extension.Oid, extension.RawData);
                        //var hmm = extension. //CopyFrom(asnExtensionData);
                        
                        System.IO.File.WriteAllBytes(@"F:\DevGit\certs\csharptest\crloid.txt", rawExtensionData);

                        //asnExtensionData.
                    }
                    //var rawExtensionData = extension.RawData;
                    //AsnEncodedData asnExtensionData = new AsnEncodedData(extension.Oid, extension.RawData);
                    //System.IO.File.WriteAllBytes(@"F:\DevGit\certs\csharptest\compare\" + extension.Oid.Value + ".txt", rawExtensionData);
                    // Create an AsnEncodedData object using the extensions information.
                    AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                    Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                    Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                    Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                    Console.WriteLine(asndata.Format(true));

                }
            }
            if (option == 2)
            {

                // Create a CryptoConfig object to store configuration information.
                CryptoConfig cryptoConfig = new CryptoConfig();

                // Retrieve the class path for CryptoConfig.
                string classDescription = cryptoConfig.ToString();

                // Create a new SHA1 provider.
                //SHA256CryptoServiceProvider SHA1alg =
                //    (SHA256CryptoServiceProvider)CryptoConfig.CreateFromName("SHA256");

                // Create an RSAParameters with the TestContainer key container.
                CspParameters parameters = new CspParameters();
                parameters.KeyContainerName = "http://dev-11.observicing.net/crl/root-ca.crl";
                Object[] argsArray = new Object[] { parameters };

                //string[] tst = new string[0];
                List<string> strlst = new List<string>();
                string tst = "http://dev-11.observicing.net/crl/root-ca.crl";
                var strarr = strlst.ToArray();
                // Instantiate the RSA provider instance accessing the TestContainer
                // key container.
                RSACryptoServiceProvider rsaProvider = (RSACryptoServiceProvider)
                        CryptoConfig.CreateFromName("RSA", argsArray);


                //parameters.
                // Use the MapNameToOID method to get an object identifier  
                // (OID) from the string name of the SHA1 algorithm.
                string sha1Oid = CryptoConfig.MapNameToOID("SHA256RSA");

                // Encode the specified object identifier.
                byte[] encodedMessage = CryptoConfig.EncodeOID(sha1Oid);



                CryptoConfig.AddOID("2.5.29.31", strarr);
                byte[] encodetest = CryptoConfig.EncodeOID(sha1Oid); //.EncodeOID("2.5.29.31");

                System.IO.File.WriteAllBytes(@"F:\DevGit\certs\csharptest\encodedsha256.txt", encodetest);
                // Display the results to the console.
                Console.WriteLine("** " + classDescription + " **");
                Console.WriteLine("Created an RSA provider " +
                    "with a KeyContainerName called " + parameters.KeyContainerName +
                    ".");
                Console.WriteLine("Object identifier from the SHA1 name:" + sha1Oid);
                Console.WriteLine("The object identifier encoded: " +
                    System.Text.Encoding.ASCII.GetString(encodedMessage));
                Console.WriteLine("This sample completed successfully; " +
                    "press Enter to exit.");
                Console.ReadLine();
                //byte[] oidBytes = File.ReadAllBytes(@"F:\DevGit\certs\csharptest\crloid.txt");
                //X509SignatureGenerator hmm = new X509SignatureGenerator();

                //string s = "30353033a031a02f862d687474703a2f2f6465762d31312e6f62736572766963696e672e6e65742f63726c2f726f6f742d63612e63726c";
                //    int len = s.Length;

                //    byte[] data = new byte[len / 2];
                //    for (int i = 0; i < len; i += 2)
                //    {
                //        data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)
                //                             + Character.digit(s.charAt(i + 1), 16));
                //    }

                //    return data;


            }
            if (option == 3)
            {
                // WORKING EXAMPLE TO DECODE X509 EXTENSION BYTE ARRAY
                //Oid oidObj = new Oid("2.5.29.31"); // CRL distribution points


                List<string> files = new List<string>();
                files.Add("2.5.29.37.txt");
                files.Add("2.5.29.14.txt");
                files.Add("2.5.29.15.txt");
                files.Add("2.5.29.17.txt");
                files.Add("2.5.29.19.txt");
                files.Add("2.5.29.31.txt");
                files.Add("2.5.29.35.txt");

                //WOW
                //files.Add("crltext-base64decode-bytes1.txt");

                //var hmm = extension. //CopyFrom(asnExtensionData);2.5.29.14.txt
                //WORKS!
                //byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\crloid.txt"); //WriteAllBytes(@"F:\DevGit\certs\csharptest\crloid.txt", rawExtensionData);


                foreach (var f in files)
                {
                    // testing loop
                    Oid oidObj = new Oid(f.Replace(".txt", ""));
                    //Oid oidObj = new Oid("2.5.29.31");
                    byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\" + f);
                    //byte[] rawExtensionData = System.IO.File.ReadAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\" + f);

                    //decode base64
                    //string base64Decoded;
                    //byte[] data = System.Convert.FromBase64String(base64Encoded);
                   // base64Decoded = System.Text.ASCIIEncoding.ASCII.GetString(data);



                    //srcref_test testencode = new srcref_test();
                    srcref_test testencode = new srcref_test();


                    //AsnEncodedData asnExtensionData = new AsnEncodedData(oidObj, rawExtensionData);


                    var hmm = testencode.FormatNative(oidObj, rawExtensionData, true);
                    Console.WriteLine("------------------------");
                    Console.WriteLine(oidObj.FriendlyName);
                    Console.WriteLine(hmm);
                    Console.WriteLine("------------------------");

                    //var encfunction = testencode.Srcref_test();// Srcref_test Srcref_test.for
                }
                Console.ReadKey();
            }

            if (option == 4)
            {
                //WORKING EXAMPLE OF ENCODING CRL
                
                
                string testnumber = "3";
                var urisStr = new string[]
                  {
                "http://dev-11.observicing.net/crl/root-ca.crl"
                  };
                var uris = urisStr.Select(u => Encoding.UTF8.GetBytes(u));
                var zero = new byte[] { 48 }; //"0", delimiter ?
                var nbsp = new byte[] { 160 }; //"&nbsp;", separator ?
                var dagger = new byte[] { 134 }; //"dagger", separator ?

                var zeroSize = zero.Length + 1;
                var nbspSize = nbsp.Length + 1;
                var daggerSize = dagger.Length + 1;

                var col = new List<byte>();
                col.AddRange(zero); //delimiter
                int totalBytes = uris.Sum(u => u.Length);
                totalBytes += (zeroSize + (nbspSize * 2) + daggerSize) * uris.Count();
                col.Add((byte)totalBytes); //size of everything it contains

                foreach (var uri in uris)
                {
                    var uriSize = uri.Length;
                    col.AddRange(zero); //delimiter
                    col.Add((byte)(nbspSize + nbspSize + uriSize + daggerSize)); //size of everything it contains
                    col.AddRange(nbsp);
                    col.Add((byte)(nbspSize + uriSize + daggerSize)); //size of everything it contains
                    col.AddRange(nbsp);
                    col.Add((byte)(uriSize + daggerSize)); //size of everything it contains
                    col.AddRange(dagger); //separator ?
                    col.Add((byte)uriSize);
                    col.AddRange(uri);
                }
                var bytes = col.ToArray();
                var base64 = Convert.ToBase64String(bytes);

                var oidCDP = new CObjectId();
                oidCDP.InitializeFromName(CERTENROLL_OBJECTID.XCN_OID_CRL_DIST_POINTS);

                // There is no specific class to CDPs, so we use the CX509Extension
                var crlList = new CX509Extension();
                crlList.Initialize(oidCDP, EncodingType.XCN_CRYPT_STRING_BASE64, base64);
                //certRequest.X509Extensions.Add(crlList);
                //crlList.RawData
                ASCIIEncoding asc = new ASCIIEncoding();
                System.IO.File.WriteAllText(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-hexascii" + testnumber + ".txt", crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEXASCII]);

                System.IO.File.WriteAllText(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-hexraw" + testnumber + ".txt", crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEXRAW]);

                System.IO.File.WriteAllText(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64string" + testnumber + ".txt", crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]);

                System.IO.File.WriteAllText(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64string" + testnumber + ".txt", crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]);
                
                
                
                byte[] data = System.Convert.FromBase64String(crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]);

                System.IO.File.WriteAllBytes(@"F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes" + testnumber + ".txt", data);
                //crlList.RawData System.Text.Encoding.ASCII
                //x509extensions

            }
        }
    }
}
