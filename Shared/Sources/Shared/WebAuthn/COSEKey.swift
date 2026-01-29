// COSEKey.swift
// Shared
//
// COSE (CBOR Object Signing and Encryption) key encoding for WebAuthn.
// Based on RFC 9052 (COSE) and referenced by WebAuthn Level 3 § 5.8.5.
// See: https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier

import Foundation
import CryptoKit
import SwiftCBOR

// MARK: - COSE Constants

/// COSE Key Types as registered in the IANA COSE Key Types registry.
///
/// - SeeAlso: [IANA COSE Key Types Registry](https://www.iana.org/assignments/cose/cose.xhtml#key-type)
/// - SeeAlso: [RFC 9053 § 7 - Key Type Parameters](https://datatracker.ietf.org/doc/html/rfc9053#section-7)
public enum COSEKeyType: UInt64, Sendable {
    /// Octet Key Pair (OKP) - Used for Ed25519, X25519, etc.
    case okp = 1
    /// Elliptic Curve with x and y coordinates (EC2) - Used for P-256, P-384, P-521
    case ec2 = 2
    /// Symmetric key
    case symmetric = 4
}

/// COSE Algorithm identifiers as referenced by WebAuthn Level 3 § 5.8.5.
///
/// WebAuthn uses a subset of COSE algorithms. ES256 (-7) is the most commonly
/// used algorithm for passkeys.
///
/// - SeeAlso: [WebAuthn § 5.8.5 - COSEAlgorithmIdentifier](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier)
/// - SeeAlso: [IANA COSE Algorithms Registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
public enum COSEAlgorithm: Int, Sendable {
    /// ECDSA with SHA-256 using P-256 curve
    case es256 = -7
    /// ECDSA with SHA-384 using P-384 curve
    case es384 = -35
    /// ECDSA with SHA-512 using P-521 curve
    case es512 = -36
}

/// COSE Elliptic Curves as registered in the IANA COSE Elliptic Curves registry.
///
/// - SeeAlso: [IANA COSE Elliptic Curves Registry](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves)
/// - SeeAlso: [RFC 9053 § 2.1 - Elliptic Curve Keys](https://datatracker.ietf.org/doc/html/rfc9053#section-2.1)
public enum COSECurve: UInt64, Sendable {
    /// NIST P-256 (secp256r1) - 32-byte coordinates
    case p256 = 1
    /// NIST P-384 (secp384r1) - 48-byte coordinates
    case p384 = 2
    /// NIST P-521 (secp521r1) - 66-byte coordinates
    case p521 = 3
}

/// COSE Key map labels for EC2 keys.
///
/// These integer labels are used as keys in the CBOR map representing a COSE Key.
/// Common parameters (1, 3) are defined in RFC 9052 § 7.1; EC2-specific parameters
/// (-1, -2, -3) are defined in RFC 9053 § 7.1.1.
///
/// - SeeAlso: [RFC 9052 § 7.1 - COSE Key Common Parameters](https://datatracker.ietf.org/doc/html/rfc9052#section-7.1)
/// - SeeAlso: [RFC 9053 § 7.1.1 - EC2 Key Type Parameters](https://datatracker.ietf.org/doc/html/rfc9053#section-7.1.1)
public enum COSEKeyLabel: Int, Sendable {
    /// Key type (kty) - identifies the cryptographic algorithm family
    case keyType = 1
    /// Algorithm (alg) - identifies the algorithm to use with the key
    case algorithm = 3
    /// Curve (crv) - for EC2 keys, identifies the elliptic curve
    case curve = -1
    /// X coordinate - for EC2 keys, the x-coordinate as a byte string
    case xCoord = -2
    /// Y coordinate - for EC2 keys, the y-coordinate as a byte string
    case yCoord = -3
}

// MARK: - EC2PublicKey

/// Represents an EC2 (Elliptic Curve) public key in COSE format.
///
/// This structure is used for encoding the credential public key in WebAuthn
/// attestation objects. The key is encoded as a CBOR map with integer labels.
///
/// ## COSE Key Structure for EC2
///
/// ```
/// {
///   1: 2,           // kty: EC2
///   3: -7,          // alg: ES256
///   -1: 1,          // crv: P-256
///   -2: x_coord,    // x coordinate (32 bytes for P-256)
///   -3: y_coord     // y coordinate (32 bytes for P-256)
/// }
/// ```
///
/// - SeeAlso: [RFC 9053 - COSE EC2 Key Type](https://datatracker.ietf.org/doc/html/rfc9053#section-7.1.1)
/// - SeeAlso: [WebAuthn § 6.5.1 - Attested Credential Data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data)
public struct EC2PublicKey: Sendable {
    public let algorithm: COSEAlgorithm
    public let curve: COSECurve
    public let xCoordinate: Data
    public let yCoordinate: Data

    /// Creates an EC2PublicKey from a CryptoKit P256 public key.
    ///
    /// - Parameter publicKey: A P-256 public key from CryptoKit
    public init(from publicKey: P256.Signing.PublicKey) {
        self.algorithm = .es256
        self.curve = .p256

        // P256 public key raw representation is x || y (32 bytes each)
        let rawKey = publicKey.rawRepresentation
        self.xCoordinate = rawKey.prefix(32)
        self.yCoordinate = rawKey.suffix(32)
    }

    /// Creates an EC2PublicKey with explicit coordinates.
    ///
    /// - Parameters:
    ///   - algorithm: The COSE algorithm identifier
    ///   - curve: The elliptic curve
    ///   - x: The x-coordinate as raw bytes
    ///   - y: The y-coordinate as raw bytes
    public init(algorithm: COSEAlgorithm, curve: COSECurve, x: Data, y: Data) {
        self.algorithm = algorithm
        self.curve = curve
        self.xCoordinate = x
        self.yCoordinate = y
    }

    /// Encodes the public key as a COSE Key in CBOR format.
    ///
    /// The keys are encoded in the canonical order required by CTAP2.
    ///
    /// - Returns: CBOR-encoded bytes suitable for inclusion in authenticator data
    /// - SeeAlso: [RFC 9052 - COSE Key Object](https://datatracker.ietf.org/doc/html/rfc9052#section-7)
    public func toCBOR() -> [UInt8] {
        return CBOR.orderedMapWithIntKeys([
            (COSEKeyLabel.keyType.rawValue, .unsignedInt(COSEKeyType.ec2.rawValue)),
            (COSEKeyLabel.algorithm.rawValue, .negativeInt(UInt64(-1 - algorithm.rawValue))),
            (COSEKeyLabel.curve.rawValue, .unsignedInt(curve.rawValue)),
            (COSEKeyLabel.xCoord.rawValue, .byteString([UInt8](xCoordinate))),
            (COSEKeyLabel.yCoord.rawValue, .byteString([UInt8](yCoordinate)))
        ])
    }
}
