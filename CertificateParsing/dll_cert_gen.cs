using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;


// USAGE:
//var certificate = X509Certificate2Helper.GenerateSelfSignedCertificate("CN = localhost");
//File.WriteAllBytes(@"C:\Users\User\Desktop\Certificate.pfx", certificate.Export(X509ContentType.Pfx, "password"));


namespace CertificateParsing
{
    //class dll_cert_gen
    //{
    public struct SystemTime
    {
        public Int16 Year;
        public Int16 Month;
        public Int16 DayOfWeek;
        public Int16 Day;
        public Int16 Hour;
        public Int16 Minute;
        public Int16 Second;
        public Int16 Milliseconds;
    }

    public static class MarshalHelper
    {
        public static void CheckReturnValue(Boolean nativeCallSucceeded)
        {
            if (!nativeCallSucceeded)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
        }
    }

    public static class DateTimeExtensions
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern Boolean FileTimeToSystemTime(ref Int64 fileTime, out SystemTime systemTime);

        public static SystemTime ToSystemTime(this DateTime dateTime)
        {
            Int64 fileTime = dateTime.ToFileTime();
            SystemTime systemTime;
            MarshalHelper.CheckReturnValue(FileTimeToSystemTime(ref fileTime, out systemTime));
            return systemTime;
        }
    }

    class X509Certificate2Helper
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern Boolean CryptAcquireContextW(out IntPtr providerContext, String container, String provider, UInt32 providerType, UInt32 flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Boolean CryptReleaseContext(IntPtr providerContext, Int32 flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Boolean CryptGenKey(IntPtr providerContext, Int32 algorithmId, Int32 flags, out IntPtr cryptKeyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Boolean CryptDestroyKey(IntPtr cryptKeyHandle);

        [DllImport("crypt32.dll", SetLastError = true)]
        static extern Boolean CertStrToNameW(Int32 certificateEncodingType, IntPtr x500, Int32 strType, IntPtr reserved, Byte[] encoded, ref Int32 encodedLength, out IntPtr errorString);

        [DllImport("crypt32.dll", SetLastError = true)]
        static extern IntPtr CertCreateSelfSignCertificate(IntPtr providerHandle, ref CryptoApiBlob subjectIssuerBlob, Int32 flags, ref CryptKeyProviderInformation keyProviderInformation, IntPtr signatureAlgorithm, ref SystemTime startTime, ref SystemTime endTime, IntPtr extensions);

        [DllImport("crypt32.dll", SetLastError = true)]
        static extern Boolean CertFreeCertificateContext(IntPtr certificateContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        static extern Boolean CertSetCertificateContextProperty(IntPtr certificateContext, Int32 propertyId, Int32 flags, ref CryptKeyProviderInformation data);

        public static X509Certificate2 GenerateSelfSignedCertificate(String name = "", DateTime? startTime = null, DateTime? endTime = null)
        {
            if (startTime == null || (DateTime)startTime < DateTime.FromFileTimeUtc(0))
                startTime = DateTime.FromFileTimeUtc(0);
            var startSystemTime = ((DateTime)startTime).ToSystemTime();
            if (endTime == null)
                endTime = DateTime.MaxValue;
            var endSystemTime = ((DateTime)endTime).ToSystemTime();
            String containerName = Guid.NewGuid().ToString();
            GCHandle dataHandle = new GCHandle();
            IntPtr providerContext = IntPtr.Zero;
            IntPtr cryptKey = IntPtr.Zero;
            IntPtr certificateContext = IntPtr.Zero;
            IntPtr algorithmPoInt32er = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                MarshalHelper.CheckReturnValue(CryptAcquireContextW(out providerContext, containerName, null, 0x1, 0x8));
                MarshalHelper.CheckReturnValue(CryptGenKey(providerContext, 0x1, 0x20000001, out cryptKey));
                IntPtr errorStringPtr;
                Int32 nameDataLength = 0;
                Byte[] nameData;
                dataHandle = GCHandle.Alloc(name, GCHandleType.Pinned);
                if (!CertStrToNameW(0x10001, dataHandle.AddrOfPinnedObject(), 3, IntPtr.Zero, null, ref nameDataLength, out errorStringPtr))
                {
                    String error = Marshal.PtrToStringUni(errorStringPtr);
                    throw new ArgumentException(error);
                }
                nameData = new Byte[nameDataLength];
                if (!CertStrToNameW(0x10001, dataHandle.AddrOfPinnedObject(), 3, IntPtr.Zero, nameData, ref nameDataLength, out errorStringPtr))
                {
                    String error = Marshal.PtrToStringUni(errorStringPtr);
                    throw new ArgumentException(error);
                }
                dataHandle.Free();
                dataHandle = GCHandle.Alloc(nameData, GCHandleType.Pinned);
                CryptoApiBlob nameBlob = new CryptoApiBlob { cbData = (UInt32)nameData.Length, pbData = dataHandle.AddrOfPinnedObject() };
                dataHandle.Free();
                CryptKeyProviderInformation keyProvider = new CryptKeyProviderInformation { pwszContainerName = containerName, dwProvType = 1, dwKeySpec = 1 };
                CryptAlgorithmIdentifier algorithm = new CryptAlgorithmIdentifier { pszObjId = "1.2.840.113549.1.1.13", Parameters = new CryptoApiBlob() };
                algorithmPoInt32er = Marshal.AllocHGlobal(Marshal.SizeOf(algorithm));
                Marshal.StructureToPtr(algorithm, algorithmPoInt32er, false);
                certificateContext = CertCreateSelfSignCertificate(providerContext, ref nameBlob, 0, ref keyProvider, algorithmPoInt32er, ref startSystemTime, ref endSystemTime, IntPtr.Zero);
                MarshalHelper.CheckReturnValue(certificateContext != IntPtr.Zero);
                return new X509Certificate2(certificateContext);
            }
            finally
            {
                if (dataHandle.IsAllocated)
                    dataHandle.Free();
                if (certificateContext != IntPtr.Zero)
                    CertFreeCertificateContext(certificateContext);
                if (cryptKey != IntPtr.Zero)
                    CryptDestroyKey(cryptKey);
                if (providerContext != IntPtr.Zero)
                    CryptReleaseContext(providerContext, 0);
                if (algorithmPoInt32er != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(algorithmPoInt32er, typeof(CryptAlgorithmIdentifier));
                    Marshal.FreeHGlobal(algorithmPoInt32er);
                }
            }
        }

        struct CryptoApiBlob
        {
            public UInt32 cbData;
            public IntPtr pbData;
        }

        struct CryptAlgorithmIdentifier
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public CryptoApiBlob Parameters;
        }

        struct CryptKeyProviderInformation
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pwszProvName;
            public UInt32 dwProvType;
            public UInt32 dwFlags;
            public UInt32 cProvParam;
            public IntPtr rgProvParam;
            public UInt32 dwKeySpec;
        }
    }
    //}
}
