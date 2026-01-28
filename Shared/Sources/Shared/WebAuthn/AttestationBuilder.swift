// AttestationBuilder.swift
// Shared
//
// WebAuthn Attestation Object builder.
// Based on W3C WebAuthn Specification Section 6.5.4.

import Foundation
import SwiftCBOR

/// Attestation format types (WebAuthn Section 8).
public enum AttestationFormat: String, Sendable {
    case none = "none"          // Self-attestation (no attestation statement)
    case packed = "packed"      // Packed attestation
    case tpm = "tpm"            // TPM attestation
    case androidKey = "android-key"
    case androidSafetyNet = "android-safetynet"
    case fidoU2F = "fido-u2f"
    case apple = "apple"
}

/// Builds WebAuthn attestation objects for credential registration.
///
/// The attestation object is a CBOR-encoded structure containing:
/// - fmt: attestation format (e.g., "none")
/// - attStmt: attestation statement (empty for "none" format)
/// - authData: authenticator data bytes
public struct AttestationBuilder {

    /// Creates an attestation object with "none" format (self-attestation).
    ///
    /// This is the simplest attestation type, suitable for software authenticators.
    /// The relying party trusts the credential without cryptographic attestation.
    ///
    /// - Parameters:
    ///   - authenticatorData: The authenticator data containing the credential
    /// - Returns: CBOR-encoded attestation object as Data
    public static func buildNoneAttestation(authenticatorData: AuthenticatorData) -> Data {
        let authDataBytes = authenticatorData.toBytes()

        // Build the attestation object map with ordered keys
        // Order matters for CBOR deterministic encoding
        let attestationObject = CBOR.orderedMap([
            (CBOR.utf8String("fmt"), CBOR.utf8String(AttestationFormat.none.rawValue)),
            (CBOR.utf8String("attStmt"), CBOR.map([:])),  // Empty map for "none" format
            (CBOR.utf8String("authData"), CBOR.byteString(authDataBytes))
        ])

        return Data(attestationObject)
    }

    /// Creates an attestation object with the specified format.
    ///
    /// - Parameters:
    ///   - format: The attestation format
    ///   - statement: The attestation statement (format-specific)
    ///   - authenticatorData: The authenticator data
    /// - Returns: CBOR-encoded attestation object as Data
    public static func buildAttestation(
        format: AttestationFormat,
        statement: CBOR,
        authenticatorData: AuthenticatorData
    ) -> Data {
        let authDataBytes = authenticatorData.toBytes()

        let attestationObject = CBOR.orderedMap([
            (CBOR.utf8String("fmt"), CBOR.utf8String(format.rawValue)),
            (CBOR.utf8String("attStmt"), statement),
            (CBOR.utf8String("authData"), CBOR.byteString(authDataBytes))
        ])

        return Data(attestationObject)
    }
}
