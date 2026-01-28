// AssertionBuilder.swift
// Shared
//
// WebAuthn Assertion (authentication) response builder.
// Based on W3C WebAuthn Specification Section 6.3.3.

import Foundation
import CryptoKit

/// Builds WebAuthn assertion responses for credential authentication.
///
/// An assertion proves possession of a credential's private key
/// by signing a challenge from the relying party.
public struct AssertionBuilder {

    /// Creates the signature base for an assertion.
    ///
    /// The signature is computed over: authenticatorData || clientDataHash
    ///
    /// - Parameters:
    ///   - authenticatorData: The authenticator data bytes
    ///   - clientDataHash: SHA-256 hash of the client data JSON
    /// - Returns: Data to be signed
    public static func buildSignatureBase(
        authenticatorData: [UInt8],
        clientDataHash: Data
    ) -> Data {
        var signatureBase = Data(authenticatorData)
        signatureBase.append(clientDataHash)
        return signatureBase
    }

    /// Signs the assertion data with a P-256 private key.
    ///
    /// - Parameters:
    ///   - signatureBase: Data to sign (authenticatorData || clientDataHash)
    ///   - privateKey: The credential's P-256 private key
    /// - Returns: DER-encoded ECDSA signature
    /// - Throws: If signing fails
    public static func sign(
        _ signatureBase: Data,
        with privateKey: P256.Signing.PrivateKey
    ) throws -> Data {
        let signature = try privateKey.signature(for: signatureBase)
        return signature.derRepresentation
    }

    /// Creates a complete assertion response.
    ///
    /// - Parameters:
    ///   - relyingPartyId: The relying party identifier
    ///   - clientDataHash: SHA-256 hash of client data JSON
    ///   - signCount: Current signature counter value
    ///   - privateKey: The credential's private key
    /// - Returns: Tuple of (authenticatorData, signature)
    /// - Throws: If signing fails
    public static func buildAssertion(
        relyingPartyId: String,
        clientDataHash: Data,
        signCount: UInt32,
        privateKey: P256.Signing.PrivateKey
    ) throws -> (authenticatorData: Data, signature: Data) {
        // Build authenticator data (no attested credential data for assertions)
        let authData = AuthenticatorData(
            relyingPartyId: relyingPartyId,
            flags: .assertion,
            signCount: signCount
        )
        let authDataBytes = authData.toBytes()

        // Build signature base and sign
        let signatureBase = buildSignatureBase(
            authenticatorData: authDataBytes,
            clientDataHash: clientDataHash
        )
        let signature = try sign(signatureBase, with: privateKey)

        return (Data(authDataBytes), signature)
    }
}
