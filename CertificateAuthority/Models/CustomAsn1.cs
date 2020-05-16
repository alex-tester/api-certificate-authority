using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CertificateAuthority.Models
{
    public class CustomAsn1
    {
    }

    public class X509CrlExtensionInputData
    {
        public string Oid { get; set; }
        public string[] CrlLocations { get; set; }
    }

    public class AsnEncodedDataClass
    {
        public string Base64ExtensionData { get; set; }
        public string Oid { get; set; }
    }

    public class AsnEncodedFileLocation
    {
        public string Oid { get; set; }
        public string FilePath { get; set; }
    }

    public class OidTable
    {
       
    }
}
