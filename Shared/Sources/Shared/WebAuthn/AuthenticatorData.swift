// AuthenticatorData.swift
// Shared
//
// WebAuthn Authenticator Data encoding.
// Based on W3C WebAuthn Level 3 Specification.
// See: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data

import Foundation
import CryptoKit

// MARK: - Authenticator Flags

/// Authenticator data flags as defined in WebAuthn Level 3 § 6.1.
///
/// The flags byte indicates the results of authenticator data processing.
/// Each bit has a specific meaning as defined in the specification.
///
/// ## Topics
///
/// ### Presence and Verification
/// - ``userPresent``
/// - ``userVerified``
///
/// ### Credential Backup (§ 6.1.3)
/// - ``backupEligible``
/// - ``backedUp``
///
/// ### Data Inclusion
/// - ``attestedCredentialData``
/// - ``extensionData``
///
/// - SeeAlso: [WebAuthn § 6.1 - Authenticator Data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
public struct AuthenticatorFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// User Present (UP) - Bit 0.
    ///
    /// Set if the user performed a test of user presence (e.g., touched the authenticator).
    /// - SeeAlso: [WebAuthn § 6.1](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
    public static let userPresent = AuthenticatorFlags(rawValue: 1 << 0)

    /// User Verified (UV) - Bit 2.
    ///
    /// Set if the user was verified (e.g., via PIN, biometric, or other method).
    /// - SeeAlso: [WebAuthn § 6.1](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
    public static let userVerified = AuthenticatorFlags(rawValue: 1 << 2)

    /// Backup Eligibility (BE) - Bit 3.
    ///
    /// Indicates the credential is eligible for backup (multi-device credential).
    /// - SeeAlso: [WebAuthn § 6.1.3 - Credential Backup State](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)
    public static let backupEligible = AuthenticatorFlags(rawValue: 1 << 3)

    /// Backup State (BS) - Bit 4.
    ///
    /// Indicates the credential is currently backed up.
    /// - SeeAlso: [WebAuthn § 6.1.3 - Credential Backup State](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)
    public static let backedUp = AuthenticatorFlags(rawValue: 1 << 4)

    /// Attested Credential Data included (AT) - Bit 6.
    ///
    /// Set if the authenticator data contains attested credential data.
    /// This is set during registration, not during assertion.
    /// - SeeAlso: [WebAuthn § 6.5.1 - Attested Credential Data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data)
    public static let attestedCredentialData = AuthenticatorFlags(rawValue: 1 << 6)

    /// Extension Data included (ED) - Bit 7.
    ///
    /// Set if the authenticator data contains extension data.
    /// - SeeAlso: [WebAuthn § 9 - WebAuthn Extensions](https://www.w3.org/TR/webauthn-3/#sctn-extensions)
    public static let extensionData = AuthenticatorFlags(rawValue: 1 << 7)

    /// Standard flags for passkey registration (with user verification).
    ///
    /// Includes: UP, UV, BE, BS, AT
    public static let registration: AuthenticatorFlags = [
        .userPresent,
        .userVerified,
        .backupEligible,
        .backedUp,
        .attestedCredentialData
    ]

    /// Standard flags for passkey assertion (with user verification).
    ///
    /// Includes: UP, UV, BE, BS (no AT since attestation data is not included in assertions)
    public static let assertion: AuthenticatorFlags = [
        .userPresent,
        .userVerified,
        .backupEligible,
        .backedUp
    ]
}

// MARK: - AAGUID

/// Authenticator Attestation GUID (AAGUID).
///
/// A 16-byte identifier that indicates the type (model) of the authenticator.
/// Each authenticator model has a unique AAGUID assigned by FIDO Alliance.
///
/// For software authenticators without formal FIDO certification,
/// an all-zero AAGUID is typically used.
///
/// - SeeAlso: [WebAuthn § 6.5.1 - Attested Credential Data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data)
public struct AAGUID: Sendable {
    public let bytes: [UInt8]

    /// Creates an AAGUID with all zeros (default for software authenticators).
    public static let zero = AAGUID(bytes: [UInt8](repeating: 0, count: 16))

    public init(bytes: [UInt8]) {
        precondition(bytes.count == 16, "AAGUID must be 16 bytes")
        self.bytes = bytes
    }
}

// MARK: - Attested Credential Data

/// Attested Credential Data as defined in WebAuthn Level 3 § 6.5.1.
///
/// This structure is included in authenticator data during credential registration.
/// It contains the AAGUID, credential ID, and the credential public key in COSE format.
///
/// ## Binary Format
///
/// | Field | Length | Description |
/// |-------|--------|-------------|
/// | aaguid | 16 bytes | Authenticator model identifier |
/// | credentialIdLength | 2 bytes | Big-endian length of credential ID |
/// | credentialId | L bytes | Unique credential identifier |
/// | credentialPublicKey | variable | COSE-encoded public key |
///
/// - SeeAlso: [WebAuthn § 6.5.1 - Attested Credential Data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data)
public struct AttestedCredentialData: Sendable {
    public let aaguid: AAGUID
    public let credentialId: Data
    public let publicKey: EC2PublicKey

    public init(aaguid: AAGUID = .zero, credentialId: Data, publicKey: EC2PublicKey) {
        self.aaguid = aaguid
        self.credentialId = credentialId
        self.publicKey = publicKey
    }

    /// Encodes the attested credential data as bytes per WebAuthn § 6.5.1.
    ///
    /// - Returns: Binary representation of the attested credential data
    public func toBytes() -> [UInt8] {
        var result = [UInt8]()

        // AAGUID (16 bytes)
        result.append(contentsOf: aaguid.bytes)

        // Credential ID length (2 bytes, big-endian)
        let idLength = UInt16(credentialId.count)
        result.append(UInt8((idLength >> 8) & 0xFF))
        result.append(UInt8(idLength & 0xFF))

        // Credential ID
        result.append(contentsOf: credentialId)

        // Public key (COSE format per RFC 9052)
        result.append(contentsOf: publicKey.toCBOR())

        return result
    }
}

// MARK: - Authenticator Data

/// Authenticator Data structure as defined in WebAuthn Level 3 § 6.1.
///
/// This structure encapsulates the authenticator's response during
/// both registration (attestation) and authentication (assertion) ceremonies.
///
/// ## Binary Format
///
/// | Field | Length | Description |
/// |-------|--------|-------------|
/// | rpIdHash | 32 bytes | SHA-256 hash of the RP ID |
/// | flags | 1 byte | Bit field (see ``AuthenticatorFlags``) |
/// | signCount | 4 bytes | Big-endian signature counter |
/// | attestedCredentialData | variable | Present only if AT flag is set |
/// | extensions | variable | Present only if ED flag is set |
///
/// - SeeAlso: [WebAuthn § 6.1 - Authenticator Data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
public struct AuthenticatorData: Sendable {
    public let relyingPartyId: String
    public let flags: AuthenticatorFlags
    public let signCount: UInt32
    public let attestedCredentialData: AttestedCredentialData?

    /// Creates authenticator data for registration (includes attested credential data).
    ///
    /// - Parameters:
    ///   - relyingPartyId: The relying party identifier (domain)
    ///   - flags: Authenticator flags (should include `.attestedCredentialData`)
    ///   - signCount: Initial signature counter value
    ///   - attestedCredentialData: The attested credential data containing the public key
    public init(
        relyingPartyId: String,
        flags: AuthenticatorFlags,
        signCount: UInt32,
        attestedCredentialData: AttestedCredentialData
    ) {
        self.relyingPartyId = relyingPartyId
        self.flags = flags
        self.signCount = signCount
        self.attestedCredentialData = attestedCredentialData
    }

    /// Creates authenticator data for assertion (no attested credential data).
    ///
    /// - Parameters:
    ///   - relyingPartyId: The relying party identifier (domain)
    ///   - flags: Authenticator flags (should not include `.attestedCredentialData`)
    ///   - signCount: Current signature counter value (incremented from last use)
    public init(
        relyingPartyId: String,
        flags: AuthenticatorFlags,
        signCount: UInt32
    ) {
        self.relyingPartyId = relyingPartyId
        self.flags = flags
        self.signCount = signCount
        self.attestedCredentialData = nil
    }

    /// Encodes the authenticator data as bytes per WebAuthn § 6.1.
    ///
    /// The signature counter helps relying parties detect cloned authenticators.
    /// See [WebAuthn § 6.1.1](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter) for details.
    ///
    /// - Returns: Binary representation of the authenticator data
    public func toBytes() -> [UInt8] {
        var result = [UInt8]()

        // RP ID Hash (SHA-256 of RP ID string)
        let rpIdData = Data(relyingPartyId.utf8)
        let rpIdHash = SHA256.hash(data: rpIdData)
        result.append(contentsOf: rpIdHash)

        // Flags (1 byte)
        result.append(flags.rawValue)

        // Sign Count (4 bytes, big-endian)
        result.append(UInt8((signCount >> 24) & 0xFF))
        result.append(UInt8((signCount >> 16) & 0xFF))
        result.append(UInt8((signCount >> 8) & 0xFF))
        result.append(UInt8(signCount & 0xFF))

        // Attested Credential Data (if present)
        if let attestedData = attestedCredentialData {
            result.append(contentsOf: attestedData.toBytes())
        }

        return result
    }
}
