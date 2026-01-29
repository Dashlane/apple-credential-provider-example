// AssertionBuilder.swift
// Shared
//
// WebAuthn Assertion (authentication) response builder.
// Based on W3C WebAuthn Level 3 Specification.
// See: https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion

import Foundation
import CryptoKit

/// Builds WebAuthn assertion responses for credential authentication.
///
/// An assertion proves possession of a credential's private key
/// by signing a challenge from the relying party. The signature is computed
/// over `authenticatorData || clientDataHash`.
///
/// - SeeAlso: [WebAuthn § 6.3.3 - The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion)
public struct AssertionBuilder {

    /// Creates the signature base for an assertion.
    ///
    /// Per WebAuthn § 6.3.3, the assertion signature is computed over the concatenation
    /// of the authenticator data and the hash of the client data JSON.
    ///
    /// - Parameters:
    ///   - authenticatorData: The authenticator data bytes
    ///   - clientDataHash: SHA-256 hash of the client data JSON
    /// - Returns: Data to be signed (`authenticatorData || clientDataHash`)
    /// - SeeAlso: [WebAuthn § 6.3.3 - The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion)
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
    /// Uses ECDSA with SHA-256 (ES256) as required by WebAuthn for P-256 keys.
    /// The signature is returned in DER format.
    ///
    /// - Parameters:
    ///   - signatureBase: Data to sign (`authenticatorData || clientDataHash`)
    ///   - privateKey: The credential's P-256 private key
    /// - Returns: DER-encoded ECDSA signature
    /// - Throws: If signing fails
    /// - SeeAlso: [WebAuthn § 5.8.5 - Cryptographic Algorithm Identifier](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier)
    public static func sign(
        _ signatureBase: Data,
        with privateKey: P256.Signing.PrivateKey
    ) throws -> Data {
        let signature = try privateKey.signature(for: signatureBase)
        return signature.derRepresentation
    }

    /// Creates a complete assertion response.
    ///
    /// This method builds the authenticator data for an assertion (without
    /// attested credential data) and signs it with the credential's private key.
    ///
    /// - Parameters:
    ///   - relyingPartyId: The relying party identifier (must match registration)
    ///   - clientDataHash: SHA-256 hash of client data JSON from the browser
    ///   - signCount: Current signature counter value (should be incremented)
    ///   - privateKey: The credential's private key
    /// - Returns: Tuple of (`authenticatorData`, `signature`)
    /// - Throws: If signing fails
    /// - SeeAlso: [WebAuthn § 6.3.3 - The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion)
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
