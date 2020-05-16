using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CertificateAuthority.Models.Asn1Functions
{
    public class Interop
    {
        internal partial class Crypt32
        {
            internal const int CRYPT_FORMAT_STR_NONE = 0;
            internal const int CRYPT_FORMAT_STR_MULTI_LINE = 0x00000001;
            internal const int CRYPT_FORMAT_STR_NO_HEX = 0x00000010;

            [DllImport(Libraries.Crypt32, SetLastError = true, BestFitMapping = false)]
            internal static extern unsafe bool CryptFormatObject(
                [In]      int dwCertEncodingType,   // only valid value is X509_ASN_ENCODING
                [In]      int dwFormatType,         // unused - pass 0.
                [In]      int dwFormatStrType,      // select multiline
                [In]      IntPtr pFormatStruct,     // unused - pass IntPtr.Zero
                [In]      byte* lpszStructType,     // OID value
                [In]      byte[] pbEncoded,         // Data to be formatted
                [In]      int cbEncoded,            // Length of data to be formatted
                [Out]     void* pbFormat,           // Receives formatted string.
                [In, Out] ref int pcbFormat);       // Sends/receives length of formatted string in bytes
        }

        internal static partial class Libraries
        {
            internal const string Advapi32 = "advapi32.dll";
            internal const string BCrypt = "BCrypt.dll";
            internal const string CoreComm_L1_1_1 = "api-ms-win-core-comm-l1-1-1.dll";
            internal const string CoreComm_L1_1_2 = "api-ms-win-core-comm-l1-1-2.dll";
            internal const string Crypt32 = "crypt32.dll";
            internal const string CryptUI = "cryptui.dll";
            internal const string Error_L1 = "api-ms-win-core-winrt-error-l1-1-0.dll";
            internal const string Gdi32 = "gdi32.dll";
            internal const string HttpApi = "httpapi.dll";
            internal const string IpHlpApi = "iphlpapi.dll";
            internal const string Kernel32 = "kernel32.dll";
            internal const string Memory_L1_3 = "api-ms-win-core-memory-l1-1-3.dll";
            internal const string Mswsock = "mswsock.dll";
            internal const string NCrypt = "ncrypt.dll";
            internal const string NtDll = "ntdll.dll";
            internal const string Odbc32 = "odbc32.dll";
            internal const string Ole32 = "ole32.dll";
            internal const string OleAut32 = "oleaut32.dll";
            internal const string PerfCounter = "perfcounter.dll";
            internal const string RoBuffer = "api-ms-win-core-winrt-robuffer-l1-1-0.dll";
            internal const string Secur32 = "secur32.dll";
            internal const string Shell32 = "shell32.dll";
            internal const string SspiCli = "sspicli.dll";
            internal const string User32 = "user32.dll";
            internal const string Version = "version.dll";
            internal const string WebSocket = "websocket.dll";
            internal const string WinHttp = "winhttp.dll";
            internal const string WinMM = "winmm.dll";
            internal const string Ws2_32 = "ws2_32.dll";
            internal const string Wtsapi32 = "wtsapi32.dll";
            internal const string CompressionNative = "clrcompression.dll";
            internal const string CoreWinRT = "api-ms-win-core-winrt-l1-1-0.dll";
        }
    }
    //public class Asn1Functions
    //{
    //}

    public class Asn1Functions
    {
        //public void Srcref_test()
        //{
        //    Oid oidObj = new Oid("2.5.29.31");
        //    string oidVal = oidObj.Value;


        //    string managedString = "test";


        //    IntPtr stringPointer = (IntPtr)Marshal.StringToHGlobalAnsi(oidVal);
        //}

        public string FormatNative(Oid oid, byte[] rawData, bool multiLine)
        {
            // If OID is not present, then we can force CryptFormatObject
            // to use hex formatting by providing an empty OID string.
            string oidValue = string.Empty;
            if (oid != null && oid.Value != null)
            {
                oidValue = oid.Value;
            }


            // values found at https://github.com/microsoft/referencesource/blob/master/System/security/system/security/cryptography/cryptoapi.cs

            int dwFormatStrType = multiLine ? Interop.Crypt32.CRYPT_FORMAT_STR_MULTI_LINE : Interop.Crypt32.CRYPT_FORMAT_STR_NONE;

            int cbFormat = 0;
            const int X509_ASN_ENCODING = 0x00000001;
            unsafe
            {
                IntPtr oidValuePtr = Marshal.StringToHGlobalAnsi(oidValue);
                char[] pooledarray = null;
                try
                {
                    if (Interop.Crypt32.CryptFormatObject(X509_ASN_ENCODING, 0, dwFormatStrType, IntPtr.Zero, (byte*)oidValuePtr, rawData, rawData.Length, null, ref cbFormat))
                    {
                        int charLength = (cbFormat + 1) / 2;
                        Span<char> buffer = charLength <= 256 ?
                            stackalloc char[256] :
                            (pooledarray = ArrayPool<char>.Shared.Rent(charLength));
                        fixed (char* bufferPtr = buffer)
                        {
                            if (Interop.Crypt32.CryptFormatObject(X509_ASN_ENCODING, 0, dwFormatStrType, IntPtr.Zero, (byte*)oidValuePtr, rawData, rawData.Length, bufferPtr, ref cbFormat))
                            {
                                return new string(bufferPtr);
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(oidValuePtr);
                    if (pooledarray != null)
                    {
                        ArrayPool<char>.Shared.Return(pooledarray);
                    }
                }
            }

            return null;
        }

        public string EncodeCrlExtensionData(string[] urisStr)
        {
            //var urisStr = D.CrlLocations;
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

            var oidCDP = new CERTENROLLLib.CObjectId();
            oidCDP.InitializeFromName(CERTENROLLLib.CERTENROLL_OBJECTID.XCN_OID_CRL_DIST_POINTS);

            // There is no specific class to CDPs, so we use the CX509Extension
            var crlList = new CERTENROLLLib.CX509Extension();
            crlList.Initialize(oidCDP, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, base64);
            //certRequest.X509Extensions.Add(crlList);

            return crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64];
        }



        public string EncodeCrlNumberExtensionData(string[] crlNumber)
        {
            //var urisStr = D.CrlLocations;
            var uris = crlNumber.Select(u => Encoding.UTF8.GetBytes(u));
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

            var oidCDP = new CERTENROLLLib.CObjectId();
            //oidCDP.InitializeFromName(CERTENROLLLib.CERTENROLL_OBJECTID.XCN_OID_CRL_DIST_POINTS);
            oidCDP.InitializeFromName(CERTENROLLLib.CERTENROLL_OBJECTID.XCN_OID_CRL_NUMBER);
            // There is no specific class to CDPs, so we use the CX509Extension
            var crlList = new CERTENROLLLib.CX509Extension();
            crlList.Initialize(oidCDP, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, base64);
            //certRequest.X509Extensions.Add(crlList);

            return crlList.RawData[CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64];
        }
    }
}
