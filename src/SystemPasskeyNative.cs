using System;
namespace WinUp.SystemPasskeyNative {
// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;



// =============================================================================
// Complete managed transcription of webauthn.h (Windows SDK, WEBAUTHN_API_VERSION_9):
// the WebAuthN data structures, constants, and client API entry points.
//
// The CTAP-CBOR structures and encode/decode entry points from webauthnplugin.h
// live in WebAuthnPluginNative.cs; the IPluginAuthenticator contract from
// pluginauthenticator.h lives in PluginAuthenticatorNative.cs.
//
// Source: https://github.com/microsoft/webauthn (webauthn.h).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// ABI notes (x64):
//   * All structs use LayoutKind.Sequential with default packing (Pack = 0),
//     which reproduces MSVC's natural alignment for these blittable types. The
//     CLR inserts the same implicit padding the C compiler does, so no explicit
//     padding fields are required.
//   * DWORD -> uint, LONG/BOOL -> int, WORD -> ushort, PBYTE/byte* -> byte*,
//     PCWSTR/LPCWSTR -> char*, PVOID -> void*, HWND -> IntPtr, GUID -> System.Guid.
//   * BOOL is a 4-byte int; never use managed bool inside these structs.
// =============================================================================

#region Constants

/// <summary>
/// Version, algorithm, transport, and option constants from webauthn.h.
/// </summary>
internal static class WebAuthnConstants
{
	// API versions ----------------------------------------------------------
	public const uint ApiVersion1 = 1;
	public const uint ApiVersion2 = 2;
	public const uint ApiVersion3 = 3;
	public const uint ApiVersion4 = 4;
	public const uint ApiVersion5 = 5;
	public const uint ApiVersion6 = 6;
	public const uint ApiVersion7 = 7;
	public const uint ApiVersion8 = 8;
	public const uint ApiVersion9 = 9;
	public const uint ApiCurrentVersion = ApiVersion9;

	// Structure versions ----------------------------------------------------
	public const uint RpEntityInformationCurrentVersion = 1; // WEBAUTHN_RP_ENTITY_INFORMATION
	public const uint UserEntityVersion = 1; // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1 (kept name: used by callers)
	public const uint ClientDataCurrentVersion = 1;
	public const uint CoseCredentialParameterCurrentVersion = 1;
	public const uint CredentialVersion = 1; // WEBAUTHN_CREDENTIAL_CURRENT_VERSION (kept name: used by callers)
	public const uint CredentialExCurrentVersion = 1;
	public const uint AuthenticatorDetailsOptionsCurrentVersion = 1;
	public const uint AuthenticatorDetailsCurrentVersion = 1;
	public const uint CredentialDetailsCurrentVersion = 4;
	public const uint GetCredentialsOptionsCurrentVersion = 1;
	public const uint MakeCredentialOptionsCurrentVersion = 9;
	public const uint GetAssertionOptionsCurrentVersion = 9;
	public const uint CommonAttestationCurrentVersion = 1;
	public const uint AttestationCurrentVersion = 8; // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION (kept name)
	public const uint AssertionCurrentVersion = 6; // WEBAUTHN_ASSERTION_CURRENT_VERSION (kept name)

	public const uint MaxUserIdLength = 64;

	// Credential type -------------------------------------------------------
	public const string CredentialTypePublicKey = "public-key"; // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY (kept name)

	// Hash algorithm identifiers --------------------------------------------
	public const string HashAlgorithmSha256 = "SHA-256";
	public const string HashAlgorithmSha384 = "SHA-384";
	public const string HashAlgorithmSha512 = "SHA-512";

	// COSE algorithm identifiers --------------------------------------------
	public const int CoseAlgorithmEcdsaP256WithSha256 = -7;
	public const int CoseAlgorithmEcdsaP384WithSha384 = -35;
	public const int CoseAlgorithmEcdsaP521WithSha512 = -36;
	public const int CoseAlgorithmRsassaPkcs1V15WithSha256 = -257;
	public const int CoseAlgorithmRsassaPkcs1V15WithSha384 = -258;
	public const int CoseAlgorithmRsassaPkcs1V15WithSha512 = -259;
	public const int CoseAlgorithmRsaPssWithSha256 = -37;
	public const int CoseAlgorithmRsaPssWithSha384 = -38;
	public const int CoseAlgorithmRsaPssWithSha512 = -39;

	// CTAP transports -------------------------------------------------------
	public const uint CtapTransportUsb = 0x00000001;
	public const uint CtapTransportNfc = 0x00000002;
	public const uint CtapTransportBle = 0x00000004;
	public const uint CtapTransportTest = 0x00000008;
	public const uint CtapTransportInternal = 0x00000010;
	public const uint CtapTransportHybrid = 0x00000020;
	public const uint CtapTransportSmartCard = 0x00000040;
	public const uint CtapTransportFlagsMask = 0x0000007F;

	// Authenticator attachment ----------------------------------------------
	public const uint AuthenticatorAttachmentAny = 0;
	public const uint AuthenticatorAttachmentPlatform = 1;
	public const uint AuthenticatorAttachmentCrossPlatform = 2;
	public const uint AuthenticatorAttachmentCrossPlatformU2fV2 = 3;

	// User verification requirement -----------------------------------------
	public const uint UserVerificationRequirementAny = 0;
	public const uint UserVerificationRequirementRequired = 1;
	public const uint UserVerificationRequirementPreferred = 2;
	public const uint UserVerificationRequirementDiscouraged = 3;

	// credProtect user verification -----------------------------------------
	public const uint UserVerificationAny = 0;
	public const uint UserVerificationOptional = 1;
	public const uint UserVerificationOptionalWithCredentialIdList = 2;
	public const uint UserVerificationRequired = 3;

	// Attestation conveyance preference -------------------------------------
	public const uint AttestationConveyancePreferenceAny = 0;
	public const uint AttestationConveyancePreferenceNone = 1;
	public const uint AttestationConveyancePreferenceIndirect = 2;
	public const uint AttestationConveyancePreferenceDirect = 3;

	// Enterprise attestation ------------------------------------------------
	public const uint EnterpriseAttestationNone = 0;
	public const uint EnterpriseAttestationVendorFacilitated = 1;
	public const uint EnterpriseAttestationPlatformManaged = 2;

	// Large blob support ----------------------------------------------------
	public const uint LargeBlobSupportNone = 0;
	public const uint LargeBlobSupportRequired = 1;
	public const uint LargeBlobSupportPreferred = 2;

	// Large blob operation --------------------------------------------------
	public const uint CredLargeBlobOperationNone = 0;
	public const uint CredLargeBlobOperationGet = 1;
	public const uint CredLargeBlobOperationSet = 2;
	public const uint CredLargeBlobOperationDelete = 3;

	// Large blob status -----------------------------------------------------
	public const uint CredLargeBlobStatusNone = 0;
	public const uint CredLargeBlobStatusSuccess = 1;
	public const uint CredLargeBlobStatusNotSupported = 2;
	public const uint CredLargeBlobStatusInvalidData = 3;
	public const uint CredLargeBlobStatusInvalidParameter = 4;
	public const uint CredLargeBlobStatusNotFound = 5;
	public const uint CredLargeBlobStatusMultipleCredentials = 6;
	public const uint CredLargeBlobStatusLackOfSpace = 7;
	public const uint CredLargeBlobStatusPlatformError = 8;
	public const uint CredLargeBlobStatusAuthenticatorError = 9;

	// Attestation decode type -----------------------------------------------
	public const uint AttestationDecodeNone = 0;
	public const uint AttestationDecodeCommon = 1;

	// Attestation format types ----------------------------------------------
	public const string AttestationTypePacked = "packed";
	public const string AttestationTypeU2f = "fido-u2f";
	public const string AttestationTypeTpm = "tpm";
	public const string AttestationTypeNone = "none";

	// Credential hints ------------------------------------------------------
	public const string CredentialHintSecurityKey = "security-key";
	public const string CredentialHintClientDevice = "client-device";
	public const string CredentialHintHybrid = "hybrid";

	// Extension identifiers -------------------------------------------------
	public const string ExtensionsIdentifierHmacSecret = "hmac-secret";
	public const string ExtensionsIdentifierCredProtect = "credProtect";
	public const string ExtensionsIdentifierCredBlob = "credBlob";
	public const string ExtensionsIdentifierMinPinLength = "minPinLength";

	// PRF / HMAC-secret -----------------------------------------------------
	public const uint CtapOneHmacSecretLength = 32;
	public const uint AuthenticatorHmacSecretValuesFlag = 0x00100000;
}

#endregion

#region Core structures

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnRpEntityInformation
{
	public uint dwVersion; // WEBAUTHN_RP_ENTITY_INFORMATION_VERSION_1 = 1
	public char* pwszId;
	public char* pwszName;
	public char* pwszIcon;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnUserEntityInformation
{
	public uint dwVersion; // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1 = 1
	public uint cbId;
	public byte* pbId;
	public char* pwszName;
	public char* pwszIcon;
	public char* pwszDisplayName;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnClientData
{
	public uint dwVersion; // WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1
	public uint cbClientDataJSON;
	public byte* pbClientDataJSON;
	public char* pwszHashAlgId; // L"SHA-256" etc.
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameter
{
	public uint dwVersion;
	public char* pwszCredentialType;
	public int lAlg;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameters
{
	public uint cCredentialParameters;
	public WebAuthnCoseCredentialParameter* pCredentialParameters; // array of cCredentialParameters
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredential
{
	public uint dwVersion;   // WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1
	public uint cbId;
	public byte* pbId;
	public char* pwszCredentialType; // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = L"public-key"
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentials
{
	public uint cCredentials;
	public WebAuthnCredential* pCredentials; // array of cCredentials
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialEx
{
	public uint dwVersion;   // WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1
	public uint cbId;
	public byte* pbId;
	public char* pwszCredentialType;
	public uint dwTransports;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialList
{
	public uint cCredentials;
	public WebAuthnCredentialEx** ppCredentials; // array of pointers
}

/// <summary>CTAPCBOR_HYBRID_STORAGE_LINKED_DATA (deprecated).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CtapCborHybridStorageLinkedData
{
	public uint dwVersion;
	public uint cbContactId;
	public byte* pbContactId;
	public uint cbLinkId;
	public byte* pbLinkId;
	public uint cbLinkSecret;
	public byte* pbLinkSecret;
	public uint cbPublicKey;
	public byte* pbPublicKey;
	public char* pwszAuthenticatorName;
	public ushort wEncodedTunnelServerDomain;
}

#endregion

#region Authenticator list / credential details

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetailsOptions
{
	public uint dwVersion;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetails
{
	public uint dwVersion;
	public uint cbAuthenticatorId;
	public byte* pbAuthenticatorId;
	public char* pwszAuthenticatorName;
	public uint cbAuthenticatorLogo;
	public byte* pbAuthenticatorLogo;
	public int bLocked; // BOOL
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetailsList
{
	public uint cAuthenticatorDetails;
	public WebAuthnAuthenticatorDetails** ppAuthenticatorDetails;
}

/// <summary>WEBAUTHN_CREDENTIAL_DETAILS (version 4).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialDetails
{
	public uint dwVersion;
	public uint cbCredentialID;
	public byte* pbCredentialID;
	public WebAuthnRpEntityInformation* pRpInformation;
	public WebAuthnUserEntityInformation* pUserInformation;
	public int bRemovable;          // BOOL
									// Version 2:
	public int bBackedUp;           // BOOL
									// Version 3:
	public char* pwszAuthenticatorName;
	public uint cbAuthenticatorLogo;
	public byte* pbAuthenticatorLogo;
	public int bThirdPartyPayment;  // BOOL
									// Version 4:
	public uint dwTransports;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialDetailsList
{
	public uint cCredentialDetails;
	public WebAuthnCredentialDetails** ppCredentialDetails;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnGetCredentialsOptions
{
	public uint dwVersion;
	public char* pwszRpId;            // optional
	public int bBrowserInPrivateMode; // BOOL
}

#endregion

#region PRF / HMAC-secret salt values

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnHmacSecretSalt
{
	public uint cbFirst;
	public byte* pbFirst;
	public uint cbSecond;
	public byte* pbSecond;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredWithHmacSecretSalt
{
	public uint cbCredID;
	public byte* pbCredID;
	public WebAuthnHmacSecretSalt* pHmacSecretSalt;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnHmacSecretSaltValues
{
	public WebAuthnHmacSecretSalt* pGlobalHmacSalt;
	public uint cCredWithHmacSecretSaltList;
	public WebAuthnCredWithHmacSecretSalt* pCredWithHmacSecretSaltList;
}

#endregion

#region Extensions

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredProtectExtensionIn
{
	public uint dwCredProtect; // one of WEBAUTHN_USER_VERIFICATION_*
	public int bRequireCredProtect; // BOOL
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredBlobExtension
{
	public uint cbCredBlob;
	public byte* pbCredBlob;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnExtension
{
	public char* pwszExtensionIdentifier; // LPCWSTR
	public uint cbExtension;
	public void* pvExtension;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnExtensions
{
	public uint cExtensions;
	public WebAuthnExtension* pExtensions;
}

#endregion

#region MakeCredential / GetAssertion options

/// <summary>WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (version 9).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorMakeCredentialOptions
{
	// Version 1:
	public uint dwVersion;
	public uint dwTimeoutMilliseconds;
	public WebAuthnCredentials CredentialList;
	public WebAuthnExtensions Extensions;
	public uint dwAuthenticatorAttachment;
	public int bRequireResidentKey; // BOOL
	public uint dwUserVerificationRequirement;
	public uint dwAttestationConveyancePreference;
	public uint dwFlags;
	// Version 2:
	public Guid* pCancellationId;
	// Version 3:
	public WebAuthnCredentialList* pExcludeCredentialList;
	// Version 4:
	public uint dwEnterpriseAttestation;
	public uint dwLargeBlobSupport;
	public int bPreferResidentKey;     // BOOL
									   // Version 5:
	public int bBrowserInPrivateMode;  // BOOL
									   // Version 6:
	public int bEnablePrf;             // BOOL
									   // Version 7:
	public CtapCborHybridStorageLinkedData* pLinkedDevice; // deprecated
	public uint cbJsonExt;
	public byte* pbJsonExt;
	// Version 8:
	public WebAuthnHmacSecretSalt* pPRFGlobalEval;
	public uint cCredentialHints;
	public char** ppwszCredentialHints; // LPCWSTR*
	public int bThirdPartyPayment;      // BOOL
										// Version 9:
	public char* pwszRemoteWebOrigin;
	public uint cbPublicKeyCredentialCreationOptionsJSON;
	public byte* pbPublicKeyCredentialCreationOptionsJSON;
	public uint cbAuthenticatorId;
	public byte* pbAuthenticatorId;
}

/// <summary>WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (version 9).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorGetAssertionOptions
{
	// Version 1:
	public uint dwVersion;
	public uint dwTimeoutMilliseconds;
	public WebAuthnCredentials CredentialList;
	public WebAuthnExtensions Extensions;
	public uint dwAuthenticatorAttachment;
	public uint dwUserVerificationRequirement;
	public uint dwFlags;
	// Version 2:
	public char* pwszU2fAppId;
	public int* pbU2fAppId; // BOOL*
							// Version 3:
	public Guid* pCancellationId;
	// Version 4:
	public WebAuthnCredentialList* pAllowCredentialList;
	// Version 5:
	public uint dwCredLargeBlobOperation;
	public uint cbCredLargeBlob;
	public byte* pbCredLargeBlob;
	// Version 6:
	public WebAuthnHmacSecretSaltValues* pHmacSecretSaltValues;
	public int bBrowserInPrivateMode; // BOOL
									  // Version 7:
	public CtapCborHybridStorageLinkedData* pLinkedDevice; // deprecated
	public int bAutoFill;             // BOOL
	public uint cbJsonExt;
	public byte* pbJsonExt;
	// Version 8:
	public uint cCredentialHints;
	public char** ppwszCredentialHints; // LPCWSTR*
										// Version 9:
	public char* pwszRemoteWebOrigin;
	public uint cbPublicKeyCredentialRequestOptionsJSON;
	public byte* pbPublicKeyCredentialRequestOptionsJSON;
	public uint cbAuthenticatorId;
	public byte* pbAuthenticatorId;
}

#endregion

#region Attestation / Assertion output

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnX5c
{
	public uint cbData;
	public byte* pbData;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCommonAttestation
{
	public uint dwVersion;
	public char* pwszAlg;
	public int lAlg; // COSE algorithm
	public uint cbSignature;
	public byte* pbSignature;
	public uint cX5c;
	public WebAuthnX5c* pX5c;
	public char* pwszVer; // L"2.0"
	public uint cbCertInfo;
	public byte* pbCertInfo;
	public uint cbPubArea;
	public byte* pbPubArea;
}

/// <summary>
/// WEBAUTHN_CREDENTIAL_ATTESTATION - version 8 (CURRENT_VERSION), 192 bytes on x64.
/// All fields are declared so WebAuthNEncodeMakeCredentialResponse reads the correct
/// offsets when dwVersion = CURRENT_VERSION.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialAttestation
{
	// Version 1:
	public uint dwVersion;           // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = 8
	public char* pwszFormatType;     // PCWSTR; e.g. L"none"
	public uint cbAuthenticatorData;
	public byte* pbAuthenticatorData;
	public uint cbAttestation;
	public byte* pbAttestation;
	public uint dwAttestationDecodeType;
	public void* pvAttestationDecode; // PWEBAUTHN_COMMON_ATTESTATION when decoded
	public uint cbAttestationObject;
	public byte* pbAttestationObject;
	public uint cbCredentialId;
	public byte* pbCredentialId;
	// Version 2:
	public WebAuthnExtensions Extensions;
	// Version 3:
	public uint dwUsedTransport;
	// Version 4:
	public int bEpAtt;            // BOOL
	public int bLargeBlobSupported; // BOOL
	public int bResidentKey;      // BOOL
								  // Version 5:
	public int bPrfEnabled;       // BOOL
								  // Version 6:
	public uint cbUnsignedExtensionOutputs;
	public byte* pbUnsignedExtensionOutputs;
	// Version 7:
	public WebAuthnHmacSecretSalt* pHmacSecret;
	public int bThirdPartyPayment; // BOOL
								   // Version 8:
	public uint dwTransports;
	public uint cbClientDataJSON;
	public byte* pbClientDataJSON;
	public uint cbRegistrationResponseJSON;
	public byte* pbRegistrationResponseJSON;
}

/// <summary>
/// WEBAUTHN_ASSERTION - version 6 (CURRENT_VERSION), 176 bytes on x64.
/// All fields through v6 are declared so the embedded layout inside
/// WebAuthnCtapCborGetAssertionResponse (WebAuthnPluginNative.cs) is correct.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAssertion
{
	// Version 1:
	public uint dwVersion;           // WEBAUTHN_ASSERTION_CURRENT_VERSION = 6
	public uint cbAuthenticatorData;
	public byte* pbAuthenticatorData;
	public uint cbSignature;
	public byte* pbSignature;
	public WebAuthnCredential Credential;
	public uint cbUserId;
	public byte* pbUserId;
	// Version 2:
	public WebAuthnExtensions Extensions;
	public uint cbCredLargeBlob;
	public byte* pbCredLargeBlob;
	public uint dwCredLargeBlobStatus;
	// Version 3:
	public WebAuthnHmacSecretSalt* pHmacSecret;
	// Version 4:
	public uint dwUsedTransport;
	// Version 5:
	public uint cbUnsignedExtensionOutputs;
	public byte* pbUnsignedExtensionOutputs;
	// Version 6:
	public uint cbClientDataJSON;
	public byte* pbClientDataJSON;
	public uint cbAuthenticationResponseJSON;
	public byte* pbAuthenticationResponseJSON;
}

#endregion

#region P/Invoke - webauthn.dll (WebAuthN client API)

/// <summary>
/// Complete P/Invoke surface for the WebAuthN client APIs declared in webauthn.h.
/// The CTAP-CBOR encode/decode helpers from webauthnplugin.h live in
/// <see cref="WebAuthnPluginApi"/>. All entry points resolve lazily from
/// webauthn.dll at first call.
/// </summary>
internal static unsafe class WebAuthnApi
{
	private const string WebAuthnDll = "webauthn.dll";

	// --- Version / availability -------------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern uint WebAuthNGetApiVersionNumber();

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
		int* pbIsUserVerifyingPlatformAuthenticatorAvailable);

	// --- MakeCredential / GetAssertion ------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNAuthenticatorMakeCredential(
		IntPtr hWnd,
		WebAuthnRpEntityInformation* pRpInformation,
		WebAuthnUserEntityInformation* pUserInformation,
		WebAuthnCoseCredentialParameters* pPubKeyCredParams,
		WebAuthnClientData* pWebAuthNClientData,
		WebAuthnAuthenticatorMakeCredentialOptions* pWebAuthNMakeCredentialOptions,
		WebAuthnCredentialAttestation** ppWebAuthNCredentialAttestation);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNAuthenticatorGetAssertion(
		IntPtr hWnd,
		char* pwszRpId,
		WebAuthnClientData* pWebAuthNClientData,
		WebAuthnAuthenticatorGetAssertionOptions* pWebAuthNGetAssertionOptions,
		WebAuthnAssertion** ppWebAuthNAssertion);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreeCredentialAttestation(
		WebAuthnCredentialAttestation* pWebAuthNCredentialAttestation);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreeAssertion(
		WebAuthnAssertion* pWebAuthNAssertion);

	// --- Cancellation ------------------------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNGetCancellationId(
		Guid* pCancellationId);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNCancelCurrentOperation(
		Guid* pCancellationId);

	// --- Platform credential list (API v4+) -------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNGetPlatformCredentialList(
		WebAuthnGetCredentialsOptions* pGetCredentialsOptions,
		WebAuthnCredentialDetailsList** ppCredentialDetailsList);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreePlatformCredentialList(
		WebAuthnCredentialDetailsList* pCredentialDetailsList);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNDeletePlatformCredential(
		uint cbCredentialId,
		byte* pbCredentialId);

	// --- Authenticator list (API v9+) -------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNGetAuthenticatorList(
		WebAuthnAuthenticatorDetailsOptions* pWebAuthNGetAuthenticatorListOptions,
		WebAuthnAuthenticatorDetailsList** ppAuthenticatorDetailsList);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreeAuthenticatorList(
		WebAuthnAuthenticatorDetailsList* pAuthenticatorDetailsList);

	// --- Error helpers -----------------------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern char* WebAuthNGetErrorName(int hr);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNGetW3CExceptionDOMError(int hr);
}

#endregion

}
namespace WinUp.SystemPasskeyNative {
// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;



// =============================================================================
// Complete managed transcription of webauthnplugin.h: the CTAP-CBOR request/
// response structures and their encode/decode entry points, plus the
// WebAuthNPlugin* authenticator-management / autofill-cache / user-verification
// APIs. These types are NOT in the shipped Win32 winmd, so they are bound by hand.
//
// The core WebAuthN data types these structures reuse (WEBAUTHN_RP_ENTITY_INFORMATION,
// WEBAUTHN_ASSERTION, WEBAUTHN_CREDENTIAL_ATTESTATION, ...) live in WebAuthnNative.cs.
// The IPluginAuthenticator COM contract from pluginauthenticator.h lives in
// PluginAuthenticatorNative.cs.
//
// Source: https://github.com/microsoft/webauthn (webauthnplugin.h).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// Same ABI conventions as WebAuthnNative.cs (x64, natural alignment, DWORD->uint,
// LONG/BOOL->int, REFCLSID/REFGUID->Guid*, HWND->IntPtr).
// =============================================================================

#region Enums / constants



/// <summary>AUTHENTICATOR_STATE (PLUGIN_AUTHENTICATOR_STATE).</summary>
internal enum AuthenticatorState : int
{
	AuthenticatorState_Disabled = 0,
	AuthenticatorState_Enabled = 1,
}


/// <summary>WEBAUTHN_PLUGIN_PERFORM_UV_OPERATION_TYPE.</summary>
internal enum WebAuthnPluginPerformUvOperationType : int
{
	PerformUserVerification = 1,
	GetUserVerificationCount = 2,
	GetPublicKey = 3,
}

/// <summary>Structure version constants from webauthnplugin.h.</summary>
internal static class WebAuthnPluginConstants
{
	public const uint CtapCborAuthenticatorOptionsCurrentVersion = 1;
	public const uint CtapCborEccPublicKeyCurrentVersion = 1;
	public const uint CtapCborHmacSaltExtensionCurrentVersion = 1;
	public const uint CtapCborMakeCredentialRequestCurrentVersion = 1;
	public const uint CtapCborGetAssertionRequestCurrentVersion = 1;
}

#endregion

#region CTAP-CBOR request/response structures

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborAuthenticatorOptions
{
	public uint dwVersion;
	public int lUp;                 // +1 true / 0 undefined / -1 false
	public int lUv;
	public int lRequireResidentKey;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborEccPublicKey
{
	public uint dwVersion;
	public int lKty;
	public int lAlg;
	public int lCrv;
	public uint cbX;
	public byte* pbX;
	public uint cbY;
	public byte* pbY;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborHmacSaltExtension
{
	public uint dwVersion;
	public WebAuthnCtapCborEccPublicKey* pKeyAgreement;
	public uint cbEncryptedSalt;
	public byte* pbEncryptedSalt;
	public uint cbSaltAuth;
	public byte* pbSaltAuth;
}

/// <summary>WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST (full declaration).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborMakeCredentialRequest
{
	public uint dwVersion;
	public uint cbRpId;
	public byte* pbRpId;
	public uint cbClientDataHash;
	public byte* pbClientDataHash;
	public WebAuthnRpEntityInformation* pRpInformation;
	public WebAuthnUserEntityInformation* pUserInformation;
	public WebAuthnCoseCredentialParameters WebAuthNCredentialParameters;
	public WebAuthnCredentialList CredentialList;
	public uint cbCborExtensionsMap;
	public byte* pbCborExtensionsMap;
	public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
	public int fEmptyPinAuth; // BOOL
	public uint cbPinAuth;
	public byte* pbPinAuth;
	public int lHmacSecretExt;
	public WebAuthnCtapCborHmacSaltExtension* pHmacSecretMcExtension;
	public int lPrfExt;
	public uint cbHmacSecretSaltValues;
	public byte* pbHmacSecretSaltValues;
	public uint dwCredProtect;
	public uint dwPinProtocol;
	public uint dwEnterpriseAttestation;
	public uint cbCredBlobExt;
	public byte* pbCredBlobExt;
	public int lLargeBlobKeyExt;
	public uint dwLargeBlobSupport;
	public int lMinPinLengthExt;
	public uint cbJsonExt;
	public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST (full declaration).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionRequest
{
	public uint dwVersion;
	public char* pwszRpId;
	public uint cbRpId;
	public byte* pbRpId;
	public uint cbClientDataHash;
	public byte* pbClientDataHash;
	public WebAuthnCredentialList CredentialList;
	public uint cbCborExtensionsMap;
	public byte* pbCborExtensionsMap;
	public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
	public int fEmptyPinAuth; // BOOL
	public uint cbPinAuth;
	public byte* pbPinAuth;
	public WebAuthnCtapCborHmacSaltExtension* pHmacSaltExtension;
	public uint cbHmacSecretSaltValues;
	public byte* pbHmacSecretSaltValues;
	public uint dwPinProtocol;
	public int lCredBlobExt;
	public int lLargeBlobKeyExt;
	public uint dwCredLargeBlobOperation;
	public uint cbCredLargeBlobCompressed;
	public byte* pbCredLargeBlobCompressed;
	public uint dwCredLargeBlobOriginalSize;
	public uint cbJsonExt;
	public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionResponse
{
	public WebAuthnAssertion WebAuthNAssertion;          // 176 bytes
	public WebAuthnUserEntityInformation* pUserInformation;
	public uint dwNumberOfCredentials;
	public int lUserSelected;                            // LONG
	public uint cbLargeBlobKey;
	public byte* pbLargeBlobKey;
	public uint cbUnsignedExtensionOutputs;
	public byte* pbUnsignedExtensionOutputs;
}

#endregion

#region Plugin-management structures

/// <summary>
/// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS - passed to WebAuthNPluginAddAuthenticator.
/// rclsid is REFCLSID = const CLSID* (pointer on x64).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions
{
	public char* pwszAuthenticatorName;  // LPCWSTR
	public Guid* rclsid;                 // REFCLSID
	public char* pwszPluginRpId;         // LPCWSTR (required for a nested WebAuthN call originating from a plugin)
	public char* pwszLightThemeLogoSvg;  // LPCWSTR (optional)
	public char* pwszDarkThemeLogoSvg;   // LPCWSTR (optional)
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;    // CTAP CBOR authenticatorGetInfo
	public uint cSupportedRpIds;         // 0 => all RPs supported
	public char** ppwszSupportedRpIds;   // const LPCWSTR*
}

/// <summary>WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorResponse
{
	public uint cbOpSignPubKey;
	public byte* pbOpSignPubKey;
}

/// <summary>WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUpdateAuthenticatorDetails
{
	public char* pwszAuthenticatorName;
	public Guid* rclsid;                 // REFCLSID
	public Guid* rclsidNew;              // REFCLSID
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
}

/// <summary>
/// WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS - one entry in the Windows autofill cache.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCredentialDetails
{
	public uint cbCredentialId;
	public byte* pbCredentialId;
	public char* pwszRpId;               // LPCWSTR
	public char* pwszRpName;             // LPCWSTR
	public uint cbUserId;
	public byte* pbUserId;
	public char* pwszUserName;           // LPCWSTR
	public char* pwszUserDisplayName;    // LPCWSTR
}

/// <summary>
/// WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST - passed to WebAuthNPluginPerformUserVerification.
/// rguidTransactionId is REFGUID = const GUID* (pointer, not inline value).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUserVerificationRequest
{
	public IntPtr hwnd;                 // HWND
	public Guid* rguidTransactionId;  // REFGUID
	public char* pwszUsername;        // LPCWSTR (optional)
	public char* pwszDisplayHint;     // LPCWSTR (optional)
}

#endregion

#region Plugin-management structures (v2 - finalized in KB5089573, OS builds 26200.8524 / 26100.8524)

/// <summary>WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions2
{
	public char* pwszAuthenticatorName;
	public Guid* pClsid;                 // const CLSID*
	public char* pwszPluginRpId;         // required for a nested WebAuthN call originating from a plugin
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
	public char* pwszUserVerificationKeyName; // name for KeyCredentialManager.RequestCreateAsync (optional)
}

/// <summary>WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUpdateAuthenticatorDetails2
{
	public char* pwszAuthenticatorName;
	public Guid* pClsid;                 // const CLSID*
	public Guid* pClsidNew;              // const CLSID*
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
	public char* pwszUserVerificationKeyName; // name for KeyCredentialManager.RequestCreateAsync (optional, NULL removes this)
}

/// <summary>WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUserVerificationRequest2
{
	public IntPtr hwnd;                 // HWND
	public Guid* pGuidTransactionId;  // const GUID*
	public char* pwszUsername;
	public char* pwszDisplayHint;
	public uint cbBufferToSign;
	public byte* pbBufferToSign;      // custom buffer signed by the UV key (optional; not hashed by the API)
}

#endregion

#region P/Invoke - webauthn.dll (plugin APIs + CTAP-CBOR encode/decode)

/// <summary>
/// Complete P/Invoke surface for webauthnplugin.h: the WebAuthNPlugin* management,
/// autofill-cache and user-verification APIs, plus the CTAP-CBOR encode/decode
/// helpers. All entry points resolve lazily from webauthn.dll at first call.
///
/// The *2 entry points (finalized in KB5089573) require recent Windows builds
/// (26200.8524 / 26100.8524); because P/Invoke resolves entry points lazily at
/// first call, declaring them is harmless on older builds until actually invoked.
/// </summary>
internal static unsafe class WebAuthnPluginApi
{
	private const string WebAuthnDll = "webauthn.dll";

	// --- CTAP-CBOR encode / decode ----------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNDecodeMakeCredentialRequest(
		uint cbEncoded,
		byte* pbEncoded,
		WebAuthnCtapCborMakeCredentialRequest** ppRequest);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreeDecodedMakeCredentialRequest(
		WebAuthnCtapCborMakeCredentialRequest* pRequest);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNDecodeGetAssertionRequest(
		uint cbEncoded,
		byte* pbEncoded,
		WebAuthnCtapCborGetAssertionRequest** ppRequest);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNFreeDecodedGetAssertionRequest(
		WebAuthnCtapCborGetAssertionRequest* pRequest);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNEncodeMakeCredentialResponse(
		WebAuthnCredentialAttestation* pAttestation,
		uint* pcbResp,
		byte** ppbResp);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNEncodeGetAssertionResponse(
		WebAuthnCtapCborGetAssertionResponse* pResponse,
		uint* pcbResp,
		byte** ppbResp);

	// --- Authenticator registration ---------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetAuthenticatorState(
		ref Guid rclsid,
		AuthenticatorState* pluginAuthenticatorState);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAddAuthenticator(
		WebAuthnPluginAddAuthenticatorOptions* pPluginAddAuthenticatorOptions,
		WebAuthnPluginAddAuthenticatorResponse** ppPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAddAuthenticator2(
		WebAuthnPluginAddAuthenticatorOptions2* pPluginAddAuthenticatorOptions,
		WebAuthnPluginAddAuthenticatorResponse** ppPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreeAddAuthenticatorResponse(
		WebAuthnPluginAddAuthenticatorResponse* pPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginRemoveAuthenticator(ref Guid rclsid);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUpdateAuthenticatorDetails(
		WebAuthnPluginUpdateAuthenticatorDetails* pPluginUpdateAuthenticatorDetails);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUpdateAuthenticatorDetails2(
		WebAuthnPluginUpdateAuthenticatorDetails2* pPluginUpdateAuthenticatorDetails);

	// --- Autofill credential cache ----------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAuthenticatorAddCredentials(
		ref Guid rclsid,
		uint cCredentialDetails,
		WebAuthnPluginCredentialDetails* pCredentialDetails);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAuthenticatorRemoveCredentials(
		ref Guid rclsid,
		uint cCredentialDetails,
		WebAuthnPluginCredentialDetails* pCredentialDetails);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAuthenticatorRemoveAllCredentials(ref Guid rclsid);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAuthenticatorGetAllCredentials(
		ref Guid rclsid,
		uint* pcCredentialDetails,
		WebAuthnPluginCredentialDetails** ppCredentialDetailsArray);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(
		uint cCredentialDetails,
		WebAuthnPluginCredentialDetails* pCredentialDetailsArray);

	// --- Windows Hello user verification ----------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginPerformUserVerification(
		WebAuthnPluginUserVerificationRequest* pPluginUserVerification,
		uint* pcbResponse,
		byte** ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginPerformUserVerification2(
		WebAuthnPluginUserVerificationRequest2* pPluginUserVerification,
		uint* pcbResponse,
		byte** ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreeUserVerificationResponse(byte* ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetUserVerificationCount(
		ref Guid rclsid,
		uint* pdwVerificationCount);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetUserVerificationPublicKey(
		ref Guid rclsid,
		uint* pcbPublicKey,
		byte** ppbPublicKey); // free with WebAuthNPluginFreePublicKeyResponse

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetOperationSigningPublicKey(
		ref Guid rclsid,
		uint* pcbOpSignPubKey,
		byte** ppbOpSignPubKey); // free with WebAuthNPluginFreePublicKeyResponse

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreePublicKeyResponse(byte* pbOpSignPubKey);

	// --- Status-change notifications --------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginRegisterStatusChangeCallback(
		IntPtr callback,
		void* context,
		ref Guid rclsid,
		uint* pdwRegister);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUnregisterStatusChangeCallback(uint* pdwRegister);
}

#endregion

}
namespace WinUp.SystemPasskeyNative {
// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;



// =============================================================================
// Complete managed transcription of pluginauthenticator.h: the IPluginAuthenticator
// COM interface contract and its operation request/response structures. These types
// are NOT in the shipped Win32 winmd, so they are bound by hand.
//
// pluginauthenticator.h declares no exported C functions - only the COM interface
// (consumed via vtable in PluginAuthenticator.cs) and its supporting structs/enums.
// The WebAuthNPlugin* management APIs live in WebAuthnPluginNative.cs; the WebAuthN
// data types live in WebAuthnNative.cs.
//
// Source: https://github.com/microsoft/webauthn (pluginauthenticator.h, pluginauthenticator.idl).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// Same ABI conventions as WebAuthnNative.cs (x64, natural alignment, DWORD->uint,
// GUID inline, HWND->IntPtr).
// =============================================================================

#region Enums

/// <summary>PLUGIN_LOCK_STATUS.</summary>
internal enum PluginLockStatus : int
{
	PluginLocked = 0,
	PluginUnlocked = 1,
}

/// <summary>WEBAUTHN_PLUGIN_REQUEST_TYPE.</summary>
internal enum WebAuthnPluginRequestType : uint
{
	Ctap2Cbor = 1, // WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR
}

#endregion

#region Operation structures

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_REQUEST - passed in by the platform (read only).
/// Layout (x64): HWND(8) + GUID(16) + DWORD(4)+[pad] + ptr(8) + DWORD(4) + DWORD(4) + ptr(8) = 56 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationRequest
{
	public IntPtr hWnd;                              // HWND
	public Guid transactionId;                     // 16 bytes
	public uint cbRequestSignature;
	public byte* pbRequestSignature;
	public WebAuthnPluginRequestType requestType;  // enum = DWORD
	public uint cbEncodedRequest;
	public byte* pbEncodedRequest;
}

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_RESPONSE - written by the authenticator.
/// pbEncodedResponse is allocated by WebAuthNEncode*, owned and freed by the platform.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationResponse
{
	public uint cbEncodedResponse;
	public byte* pbEncodedResponse;
}

/// <summary>WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST - passed in by the platform.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCancelOperationRequest
{
	public Guid transactionId;
	public uint cbRequestSignature;
	public byte* pbRequestSignature;
}

#endregion

#region COM interface identifiers

/// <summary>COM interface IIDs from pluginauthenticator.h and the COM standard.</summary>
internal static class ComIids
{
	/// <summary>IPluginAuthenticator IID (pluginauthenticator.h MIDL_INTERFACE).</summary>
	public static readonly Guid IID_IPluginAuthenticator = new Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7");

	/// <summary>IClassFactory IID (standard COM).</summary>
	public static readonly Guid IID_IClassFactory = new Guid("00000001-0000-0000-C000-000000000046");

	/// <summary>IUnknown IID (standard COM).</summary>
	public static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");
}

#endregion

}