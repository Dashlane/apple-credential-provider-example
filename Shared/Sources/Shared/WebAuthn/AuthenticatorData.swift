// AuthenticatorData.swift
// Shared
//
// WebAuthn Authenticator Data encoding.
// Based on W3C WebAuthn Specification Section 6.1.

import Foundation
import CryptoKit

// MARK: - Authenticator Flags

/// Authenticator data flags (WebAuthn Section 6.1)
/// Bit positions in the flags byte.
public struct AuthenticatorFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// User Present (UP) - Bit 0
    public static let userPresent = AuthenticatorFlags(rawValue: 1 << 0)

    /// User Verified (UV) - Bit 2
    public static let userVerified = AuthenticatorFlags(rawValue: 1 << 2)

    /// Backup Eligibility (BE) - Bit 3
    public static let backupEligible = AuthenticatorFlags(rawValue: 1 << 3)

    /// Backup State (BS) - Bit 4
    public static let backedUp = AuthenticatorFlags(rawValue: 1 << 4)

    /// Attested Credential Data included (AT) - Bit 6
    public static let attestedCredentialData = AuthenticatorFlags(rawValue: 1 << 6)

    /// Extension Data included (ED) - Bit 7
    public static let extensionData = AuthenticatorFlags(rawValue: 1 << 7)

    /// Standard flags for passkey registration (with user verification)
    public static let registration: AuthenticatorFlags = [
        .userPresent,
        .userVerified,
        .backupEligible,
        .backedUp,
        .attestedCredentialData
    ]

    /// Standard flags for passkey assertion (with user verification)
    public static let assertion: AuthenticatorFlags = [
        .userPresent,
        .userVerified,
        .backupEligible,
        .backedUp
    ]
}

// MARK: - AAGUID

/// Authenticator Attestation GUID.
/// 16-byte identifier for the authenticator model.
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

/// Attested Credential Data structure (WebAuthn Section 6.5.1).
/// Included in authenticator data during registration.
public struct AttestedCredentialData: Sendable {
    public let aaguid: AAGUID
    public let credentialId: Data
    public let publicKey: EC2PublicKey

    public init(aaguid: AAGUID = .zero, credentialId: Data, publicKey: EC2PublicKey) {
        self.aaguid = aaguid
        self.credentialId = credentialId
        self.publicKey = publicKey
    }

    /// Encodes the attested credential data as bytes.
    ///
    /// Format:
    /// - AAGUID (16 bytes)
    /// - Credential ID length (2 bytes, big-endian)
    /// - Credential ID (variable)
    /// - Public key in COSE format (variable)
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

        // Public key (COSE format)
        result.append(contentsOf: publicKey.toCBOR())

        return result
    }
}

// MARK: - Authenticator Data

/// Authenticator Data structure (WebAuthn Section 6.1).
/// Contains the cryptographic attestation of a credential operation.
public struct AuthenticatorData: Sendable {
    public let relyingPartyId: String
    public let flags: AuthenticatorFlags
    public let signCount: UInt32
    public let attestedCredentialData: AttestedCredentialData?

    /// Creates authenticator data for registration (includes attested credential data).
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

    /// Encodes the authenticator data as bytes.
    ///
    /// Format:
    /// - RP ID Hash (32 bytes) - SHA-256 of relying party ID
    /// - Flags (1 byte)
    /// - Sign Count (4 bytes, big-endian)
    /// - Attested Credential Data (variable, if present)
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
