using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


//custom
//using System.Security.Cryptography.capi;
using System.Buffers;



// WORKING EXAMPLE TO DECODE X509 EXTENSION BYTE ARRAY

namespace CertificateParsing
{
    //internal partial class Interop
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


    //}

    //internal static partial class Interop
    //{
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
    public class srcref_test
    {
        public void Srcref_test()
        {
            Oid oidObj = new Oid("2.5.29.31");
            string oidVal = oidObj.Value;


            string managedString = "test";


            IntPtr stringPointer = (IntPtr)Marshal.StringToHGlobalAnsi(oidVal);
        }

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

        public string hmm()
        {



            
            return "hmm";
        }
    } 


}

