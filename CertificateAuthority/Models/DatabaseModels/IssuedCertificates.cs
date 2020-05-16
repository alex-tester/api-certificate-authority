using System;
using System.Collections.Generic;

namespace CertificateAuthority.Models.DatabaseModels
{
    public partial class IssuedCertificates
    {
        public int Id { get; set; }
        public string CertificateThumbprint { get; set; }
        public string Base64Pfx { get; set; }
        public string FriendlyName { get; set; }
        public string Subject { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string SerialNumber { get; set; }
        public bool HasPk { get; set; }
        public string PkSecret { get; set; }
        public int SignatureAlgorithmId { get; set; }
        public int Version { get; set; }
        public bool IsRootCa { get; set; }
        public bool IsIntermediateCa { get; set; }
        public bool IsClientCert { get; set; }
    }
}
