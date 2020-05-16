//using System;
//using System.Collections.Generic;
//using System.Diagnostics.Contracts;
//using System.Runtime.CompilerServices;
//using System.Runtime.InteropServices;
//using System.Runtime.Versioning;
//using System.Security;
//using System.Security.Cryptography;
////using System.Security.Cryptography.capi;
//using System.Text;

//using CertificateParsing;
////using CertificateParsing.Interop;

//namespace CertificateParsing
//{
//    public class encodeextension
//    {

//        internal const uint CRYPT_ASN_ENCODING = 0x00000001;
//        internal const uint CRYPT_NDR_ENCODING = 0x00000002;
//        internal const uint X509_ASN_ENCODING = 0x00000001;
//        internal const uint X509_NDR_ENCODING = 0x00000002;
//        internal const uint PKCS_7_ASN_ENCODING = 0x00010000;
//        internal const uint PKCS_7_NDR_ENCODING = 0x00020000;
//        internal const uint PKCS_7_OR_X509_ASN_ENCODING = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);

//        [DllImport(Libraries.Crypt32, SetLastError = true, BestFitMapping = false)]
//        internal static extern unsafe bool CryptFormatObject(
//    [In]      int dwCertEncodingType,   // only valid value is X509_ASN_ENCODING
//    [In]      int dwFormatType,         // unused - pass 0.
//    [In]      int dwFormatStrType,      // select multiline
//    [In]      IntPtr pFormatStruct,     // unused - pass IntPtr.Zero
//    [In]      byte* lpszStructType,     // OID value
//    [In]      byte[] pbEncoded,         // Data to be formatted
//    [In]      int cbEncoded,            // Length of data to be formatted
//    [Out]     void* pbFormat,           // Receives formatted string.
//    [In, Out] ref int pcbFormat);       // Sends/receives length of formatted string in bytes

//        internal static partial class Libraries
//        {
//            internal const string Advapi32 = "advapi32.dll";
//            internal const string BCrypt = "BCrypt.dll";
//            internal const string CoreComm_L1_1_1 = "api-ms-win-core-comm-l1-1-1.dll";
//            internal const string CoreComm_L1_1_2 = "api-ms-win-core-comm-l1-1-2.dll";
//            internal const string Crypt32 = "crypt32.dll";
//            internal const string CryptUI = "cryptui.dll";
//            internal const string Error_L1 = "api-ms-win-core-winrt-error-l1-1-0.dll";
//            internal const string Gdi32 = "gdi32.dll";
//            internal const string HttpApi = "httpapi.dll";
//            internal const string IpHlpApi = "iphlpapi.dll";
//            internal const string Kernel32 = "kernel32.dll";
//            internal const string Memory_L1_3 = "api-ms-win-core-memory-l1-1-3.dll";
//            internal const string Mswsock = "mswsock.dll";
//            internal const string NCrypt = "ncrypt.dll";
//            internal const string NtDll = "ntdll.dll";
//            internal const string Odbc32 = "odbc32.dll";
//            internal const string Ole32 = "ole32.dll";
//            internal const string OleAut32 = "oleaut32.dll";
//            internal const string PerfCounter = "perfcounter.dll";
//            internal const string RoBuffer = "api-ms-win-core-winrt-robuffer-l1-1-0.dll";
//            internal const string Secur32 = "secur32.dll";
//            internal const string Shell32 = "shell32.dll";
//            internal const string SspiCli = "sspicli.dll";
//            internal const string User32 = "user32.dll";
//            internal const string Version = "version.dll";
//            internal const string WebSocket = "websocket.dll";
//            internal const string WinHttp = "winhttp.dll";
//            internal const string WinMM = "winmm.dll";
//            internal const string Ws2_32 = "ws2_32.dll";
//            internal const string Wtsapi32 = "wtsapi32.dll";
//            internal const string CompressionNative = "clrcompression.dll";
//            internal const string CoreWinRT = "api-ms-win-core-winrt-l1-1-0.dll";
//        }


//        internal enum OidKeyType
//        {
//            Oid = 1,                                        // CRYPT_OID_INFO_OID_KEY
//            Name = 2,                                       // CRYPT_OID_INFO_NAME_KEY
//            AlgorithmID = 3,                                // CRYPT_OID_INFO_ALGID_KEY
//            SignatureID = 4,                                // CRYPT_OID_INFO_SIGN_KEY
//            CngAlgorithmID = 5,                             // CRYPT_OID_INFO_CNG_ALGID_KEY
//            CngSignatureID = 6,                             // CRYPT_OID_INFO_CNG_SIGN_KEY
//        }


//        internal static class X509Utils
//        {
//            //#if FEATURE_CRYPTO || FEATURE_LEGACYNETCFCRYPTO
//            private static bool OidGroupWillNotUseActiveDirectory(OidGroup group)
//            {
//                // These groups will never cause an Active Directory query
//                return group == OidGroup.HashAlgorithm ||
//                       group == OidGroup.EncryptionAlgorithm ||
//                       group == OidGroup.PublicKeyAlgorithm ||
//                       group == OidGroup.SignatureAlgorithm ||
//                       group == OidGroup.Attribute ||
//                       group == OidGroup.ExtensionOrAttribute ||
//                       group == OidGroup.KeyDerivationFunction;
//            }

//            [SecurityCritical]
//            private static CRYPT_OID_INFO FindOidInfo(OidKeyType keyType, string key, OidGroup group)
//            {
//                Contract.Requires(key != null);

//                IntPtr rawKey = IntPtr.Zero;

//                RuntimeHelpers.PrepareConstrainedRegions();
//                try
//                {
//                    if (keyType == OidKeyType.Oid)
//                    {
//                        rawKey = Marshal.StringToCoTaskMemAnsi(key);
//                    }
//                    else
//                    {
//                        rawKey = Marshal.StringToCoTaskMemUni(key);
//                    }

//                    // If the group alone isn't sufficient to suppress an active directory lookup, then our
//                    // first attempt should also include the suppression flag
//                    if (!OidGroupWillNotUseActiveDirectory(group))
//                    {
//                        OidGroup localGroup = group | OidGroup.DisableSearchDS;
//                        IntPtr localOidInfo = CryptFindOIDInfo(keyType, rawKey, localGroup);
//                        if (localOidInfo != IntPtr.Zero)
//                        {
//                            return (CRYPT_OID_INFO)Marshal.PtrToStructure(localOidInfo, typeof(CRYPT_OID_INFO));
//                        }
//                    }

//                    // Attempt to query with a specific group, to make try to avoid an AD lookup if possible
//                    IntPtr fullOidInfo = CryptFindOIDInfo(keyType, rawKey, group);
//                    if (fullOidInfo != IntPtr.Zero)
//                    {
//                        return (CRYPT_OID_INFO)Marshal.PtrToStructure(fullOidInfo, typeof(CRYPT_OID_INFO));
//                    }

//                    // Finally, for compatibility with previous runtimes, if we have a group specified retry the
//                    // query with no group
//                    if (group != OidGroup.AllGroups)
//                    {
//                        IntPtr allGroupOidInfo = CryptFindOIDInfo(keyType, rawKey, OidGroup.AllGroups);
//                        if (allGroupOidInfo != IntPtr.Zero)
//                        {
//                            return (CRYPT_OID_INFO)Marshal.PtrToStructure(allGroupOidInfo, typeof(CRYPT_OID_INFO));
//                        }
//                    }

//                    // Otherwise the lookup failed
//                    return new CRYPT_OID_INFO();
//                }
//                finally
//                {
//                    if (rawKey != IntPtr.Zero)
//                    {
//                        Marshal.FreeCoTaskMem(rawKey);
//                    }
//                }
//            }



//        }

//        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
//        internal struct CRYPTOAPI_BLOB
//        {
//            internal uint cbData;
//            internal IntPtr pbData;
//        }

//        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
//        internal struct CERT_EXTENSION
//        {
//            [MarshalAs(UnmanagedType.LPStr)]
//            internal string pszObjId;
//            internal bool fCritical;
//            internal CRYPTOAPI_BLOB Value;
//        }


//        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
//        internal struct CRYPT_OID_INFO
//        {
//            internal CRYPT_OID_INFO(int size)
//            {
//                cbSize = (uint)size;
//                pszOID = null;
//                pwszName = null;
//                dwGroupId = 0;
//                Algid = 0;
//                ExtraInfo = new CRYPTOAPI_BLOB();
//            }
//            internal uint cbSize;
//            [MarshalAs(UnmanagedType.LPStr)]
//            internal string pszOID;
//            internal string pwszName;
//            internal uint dwGroupId;
//            internal uint Algid;
//            internal CRYPTOAPI_BLOB ExtraInfo;
//        }



//        //[SuppressMessage("Microsoft.Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "by design; fixing requires changing class hierarchy")]
//        //internal sealed class CAPI : CAPIMethods
//        //{
//        internal static
//        byte[] BlobToByteArray(IntPtr pBlob)
//        {
//            //CAPI.CRYPTOAPI_BLOB blob = (CAPI.CRYPTOAPI_BLOB)Marshal.PtrToStructure(pBlob, typeof(CAPI.CRYPTOAPI_BLOB));
//            CRYPTOAPI_BLOB blob = (CRYPTOAPI_BLOB)Marshal.PtrToStructure(pBlob, typeof(CRYPTOAPI_BLOB));
//            if (blob.cbData == 0)
//                return new byte[0];
//            return BlobToByteArray(blob);
//        }


//        internal static
//        byte[] BlobToByteArray(CRYPTOAPI_BLOB blob)
//        {
//            if (blob.cbData == 0)
//                return new byte[0];
//            byte[] data = new byte[blob.cbData];
//            Marshal.Copy(blob.pbData, data, 0, data.Length);
//            return data;
//        }


//        public abstract class SafeHandleZeroOrMinusOneIsInvalid : SafeHandle
//        {
//            protected SafeHandleZeroOrMinusOneIsInvalid(bool ownsHandle) : base(IntPtr.Zero, ownsHandle)
//            {
//            }

//            public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);
//        }


//        internal static SafeLocalAllocHandle InvalidHandle
//        {
//            get
//            {
//                SafeLocalAllocHandle invalidHandle = new SafeLocalAllocHandle(IntPtr.Zero);
//                // This is valid since we don't expose any way to replace the handle value
//                GC.SuppressFinalize(invalidHandle);
//                return invalidHandle;
//            }
//        }


//        [DllImport(Libraries.Kernel32, CharSet = CharSet.Auto, SetLastError = true)]
//        [ResourceExposure(ResourceScope.None)]
//        internal static extern
//SafeLocalAllocHandle LocalAlloc(
//[In] uint uFlags,
//[In] IntPtr sizetdwBytes);


//        [DllImport(Libraries.Kernel32, SetLastError = true)]
//        [ResourceExposure(ResourceScope.None)]
//        internal static extern
// IntPtr LocalFree(IntPtr hMem);


//        [DllImport(Libraries.Kernel32, CharSet = CharSet.Auto, SetLastError = true, BestFitMapping = false, EntryPoint = "LoadLibraryA")]
//        [ResourceExposure(ResourceScope.Machine)]
//        internal static extern
//        IntPtr LoadLibrary(
//            [In] [MarshalAs(UnmanagedType.LPStr)] string lpFileName);


//        private void DecodeExtension()
//        {
//            uint cbDecoded = 0;
//            SafeLocalAllocHandle decoded = null;

//            SafeLocalAllocHandle pb = X509Utils.StringToAnsiPtr(CAPI.szOID_SUBJECT_KEY_IDENTIFIER);
//            bool result = DecodeObject(pb.DangerousGetHandle(),
//                                            m_rawData,
//                                            out decoded,
//                                            out cbDecoded);
//            if (!result)
//                throw new CryptographicException(Marshal.GetLastWin32Error());

//            CRYPTOAPI_BLOB pSubjectKeyIdentifier = (CRYPTOAPI_BLOB)Marshal.PtrToStructure(decoded.DangerousGetHandle(), typeof(CRYPTOAPI_BLOB));
//            byte[] hexArray = CAPI.BlobToByteArray(pSubjectKeyIdentifier);
//            m_subjectKeyIdentifier = X509Utils.EncodeHexString(hexArray);

//            m_decoded = true;
//            decoded.Dispose();
//            pb.Dispose();
//        }



//        //[SecurityCritical]
//        //#endif
//        //internal sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
//        //{
//        //    private SafeLocalAllocHandle() : base(true) { }

//        //    // 0 is an Invalid Handle
//        //    internal SafeLocalAllocHandle(IntPtr handle) : base(true)
//        //    {
//        //        SetHandle(handle);
//        //    }

//        //    [SecurityCritical]
//        //    override protected bool ReleaseHandle()
//        //    {
//        //        return LocalFree(handle) == IntPtr.Zero;
//        //    }
//        //}
//        internal sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
//        {
//            private SafeLocalAllocHandle() : base(true) { }

//            // 0 is an Invalid Handle
//            internal SafeLocalAllocHandle(IntPtr handle) : base(true)
//            {
//                SetHandle(handle);
//            }

//            internal static SafeLocalAllocHandle InvalidHandle
//            {
//                get
//                {
//                    SafeLocalAllocHandle invalidHandle = new SafeLocalAllocHandle(IntPtr.Zero);
//                    // This is valid since we don't expose any way to replace the handle value
//                    GC.SuppressFinalize(invalidHandle);
//                    return invalidHandle;
//                }
//            }

//            [DllImport(Libraries.Kernel32, SetLastError = true),
//             SuppressUnmanagedCodeSecurity]
//            //#if !FEATURE_CORESYSTEM
//            //[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
//            //#endif
//            [ResourceExposure(ResourceScope.None)]
//            private static extern IntPtr LocalFree(IntPtr handle);

//            //#if FEATURE_CORESYSTEM
//            [SecurityCritical]
//            //#endif
//            override protected bool ReleaseHandle()
//            {
//                return LocalFree(handle) == IntPtr.Zero;
//            }
//        }


//        [SecurityCritical]
//        [DllImport(Libraries.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
//        [ResourceExposure(ResourceScope.None)]
//        internal static extern
//bool CryptDecodeObject(
//    [In]     uint dwCertEncodingType,
//    [In]     IntPtr lpszStructType,
//    [In]     IntPtr pbEncoded,
//    [In]     uint cbEncoded,
//    [In]     uint dwFlags,
//    [In, Out] SafeLocalAllocHandle pvStructInfo,
//    [In, Out] IntPtr pcbStructInfo);

//        internal static unsafe
//        bool DecodeObject(IntPtr pszStructType,
//                          IntPtr pbEncoded,
//                          uint cbEncoded,
//                          out SafeLocalAllocHandle decodedValue,
//                          out uint cbDecodedValue)
//        {
//            // Initialize out parameters
//            decodedValue = SafeLocalAllocHandle.InvalidHandle;
//            cbDecodedValue = 0;

//            // Decode
//            uint cbDecoded = 0;
//            SafeLocalAllocHandle ptr = SafeLocalAllocHandle.InvalidHandle;
//            bool result = CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//                                                        pszStructType,
//                                                        pbEncoded,
//                                                        cbEncoded,
//                                                        0,
//                                                        ptr,
//                                                        new IntPtr(&cbDecoded));
//            if (result == false)
//                return false;

//            ptr = CAPI.LocalAlloc(CAPI.LMEM_FIXED, new IntPtr(cbDecoded));
//            result = CAPIMethods.CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//                                                   pszStructType,
//                                                   pbEncoded,
//                                                   cbEncoded,
//                                                   0,
//                                                   ptr,
//                                                   new IntPtr(&cbDecoded));
//            if (result == false)
//                return false;

//            // Return decoded values
//            decodedValue = ptr;
//            cbDecodedValue = cbDecoded;

//            return true;
//        }



//        private static unsafe byte[] EncodeExtension(string subjectKeyIdentifier)
//        {
//            if (subjectKeyIdentifier == null)
//                throw new ArgumentNullException("subjectKeyIdentifier");

//            return EncodeExtension(X509Utils.DecodeHexString(subjectKeyIdentifier));
//        }

//        private static unsafe byte[] EncodeExtension(byte[] subjectKeyIdentifier)
//        {
//            if (subjectKeyIdentifier == null)
//                throw new ArgumentNullException("subjectKeyIdentifier");
//            if (subjectKeyIdentifier.Length == 0)
//                throw new ArgumentException("subjectKeyIdentifier");

//            byte[] encodedSubjectKeyIdentifier = null;
//            fixed (byte* pb = subjectKeyIdentifier)
//            {
//                CAPI.CRYPTOAPI_BLOB pSubjectKeyIdentifier = new CAPI.CRYPTOAPI_BLOB();
//                pSubjectKeyIdentifier.pbData = new IntPtr(pb);
//                pSubjectKeyIdentifier.cbData = (uint)subjectKeyIdentifier.Length;

//                if (!CAPI.EncodeObject(CAPI.szOID_SUBJECT_KEY_IDENTIFIER, new IntPtr(&pSubjectKeyIdentifier), out encodedSubjectKeyIdentifier))
//                    throw new CryptographicException(Marshal.GetLastWin32Error());
//            }

//            return encodedSubjectKeyIdentifier;
//        }
//        //  }


//    }
//}