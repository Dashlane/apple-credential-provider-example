// StoredPasskey.swift
// Shared
//
// Model representing a stored passkey credential.

import Foundation
import CryptoKit

/// Represents a stored passkey credential.
///
/// Contains all metadata needed for passkey operations including
/// credential ID, relying party info, user info, and usage counters.
///
/// This type is `Sendable` to support Swift's strict concurrency model.
public struct StoredPasskey: Codable, Identifiable, Equatable, Sendable {

    /// Unique identifier for this passkey (same as credentialId)
    public var id: String { credentialIdBase64 }

    /// Base64URL-encoded credential ID
    public let credentialIdBase64: String

    /// Relying party identifier (domain)
    public let relyingPartyId: String

    /// Relying party display name
    public let relyingPartyName: String

    /// Base64URL-encoded user handle
    public let userHandleBase64: String

    /// User display name
    public let userName: String

    /// Signature counter (incremented on each use)
    public var signCount: UInt32

    /// Creation timestamp
    public let createdAt: Date

    /// Last used timestamp
    public var lastUsedAt: Date?

    public init(
        credentialId: Data,
        relyingPartyId: String,
        relyingPartyName: String,
        userHandle: Data,
        userName: String,
        signCount: UInt32 = 0
    ) {
        self.credentialIdBase64 = credentialId.base64URLEncodedString()
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
        self.userHandleBase64 = userHandle.base64URLEncodedString()
        self.userName = userName
        self.signCount = signCount
        self.createdAt = Date()
        self.lastUsedAt = nil
    }

    /// Returns the credential ID as Data
    public var credentialId: Data? {
        Data(base64URLEncoded: credentialIdBase64)
    }

    /// Returns the user handle as Data
    public var userHandle: Data? {
        Data(base64URLEncoded: userHandleBase64)
    }
}

// MARK: - Base64URL Encoding

public extension Data {
    /// Encodes data as Base64URL (URL-safe Base64 without padding).
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Creates Data from a Base64URL-encoded string.
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        self.init(base64Encoded: base64)
    }
}

// MARK: - Credential ID Generation

public extension StoredPasskey {
    /// Generates a random 16-byte credential ID.
    static func generateCredentialId() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}
