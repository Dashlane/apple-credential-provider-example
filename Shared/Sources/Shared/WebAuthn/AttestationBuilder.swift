// AttestationBuilder.swift
// Shared
//
// WebAuthn Attestation Object builder.
// Based on W3C WebAuthn Level 3 Specification.
// See: https://www.w3.org/TR/webauthn-3/#sctn-attestation

import Foundation
import SwiftCBOR

/// Attestation statement format identifiers as defined in WebAuthn Level 3 § 8.
///
/// The attestation statement format determines how the authenticator's
/// attestation is conveyed to the relying party.
///
/// - SeeAlso: [WebAuthn § 8 - Defined Attestation Statement Formats](https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats)
public enum AttestationFormat: String, Sendable {
    /// No attestation statement. The RP trusts the credential without attestation.
    /// - SeeAlso: [WebAuthn § 8.7 - None Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation)
    case none = "none"

    /// Packed attestation, a WebAuthn-optimized format.
    /// - SeeAlso: [WebAuthn § 8.2 - Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
    case packed = "packed"

    /// TPM attestation for hardware TPM-based authenticators.
    /// - SeeAlso: [WebAuthn § 8.3 - TPM Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation)
    case tpm = "tpm"

    /// Android Key Attestation.
    /// - SeeAlso: [WebAuthn § 8.4 - Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation)
    case androidKey = "android-key"

    /// Android SafetyNet Attestation.
    /// - SeeAlso: [WebAuthn § 8.5 - Android SafetyNet Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation)
    case androidSafetyNet = "android-safetynet"

    /// FIDO U2F Attestation for backward compatibility.
    /// - SeeAlso: [WebAuthn § 8.6 - FIDO U2F Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation)
    case fidoU2F = "fido-u2f"

    /// Apple Anonymous Attestation.
    /// - SeeAlso: [WebAuthn § 8.8 - Apple Anonymous Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation)
    case apple = "apple"
}

/// Builds WebAuthn attestation objects for credential registration.
///
/// The attestation object is a CBOR-encoded map containing:
/// - `fmt`: Attestation statement format identifier
/// - `attStmt`: Attestation statement (format-specific)
/// - `authData`: Authenticator data bytes
///
/// - SeeAlso: [WebAuthn § 6.5.4 - Generating an Attestation Object](https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object)
public struct AttestationBuilder {

    /// Creates an attestation object with "none" format.
    ///
    /// This is the simplest attestation type, suitable for software authenticators.
    /// The relying party trusts the credential without any attestation statement.
    ///
    /// > Note: "None" attestation is distinct from *self-attestation*, where the
    /// > credential private key signs the attestation (using "packed" format without
    /// > a certificate chain). With "none", the `attStmt` is simply an empty map.
    ///
    /// - Parameter authenticatorData: The authenticator data containing the credential
    /// - Returns: CBOR-encoded attestation object as Data
    /// - SeeAlso: [WebAuthn § 8.7 - None Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation)
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
    ///   - statement: The attestation statement (format-specific CBOR)
    ///   - authenticatorData: The authenticator data
    /// - Returns: CBOR-encoded attestation object as Data
    /// - SeeAlso: [WebAuthn § 6.5.4 - Generating an Attestation Object](https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object)
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
