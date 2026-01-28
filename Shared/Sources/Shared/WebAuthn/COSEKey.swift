// COSEKey.swift
// Shared
//
// COSE (CBOR Object Signing and Encryption) key encoding for WebAuthn.
// Based on RFC 8152 Section 13.1 (Elliptic Curve Keys).

import Foundation
import CryptoKit
import SwiftCBOR

// MARK: - COSE Constants

/// COSE Key Types (RFC 8152 Section 13)
public enum COSEKeyType: UInt64, Sendable {
    case okp = 1        // Octet Key Pair (Ed25519, etc.)
    case ec2 = 2        // Elliptic Curve with x and y coordinates
    case symmetric = 4  // Symmetric key
}

/// COSE Algorithms (RFC 8152 Section 8.1)
public enum COSEAlgorithm: Int, Sendable {
    case es256 = -7     // ECDSA w/ SHA-256 (P-256)
    case es384 = -35    // ECDSA w/ SHA-384 (P-384)
    case es512 = -36    // ECDSA w/ SHA-512 (P-521)
}

/// COSE Elliptic Curves (RFC 8152 Section 13.1)
public enum COSECurve: UInt64, Sendable {
    case p256 = 1       // NIST P-256 (secp256r1)
    case p384 = 2       // NIST P-384 (secp384r1)
    case p521 = 3       // NIST P-521 (secp521r1)
}

/// COSE Key Map Labels (RFC 8152)
public enum COSEKeyLabel: Int, Sendable {
    case keyType = 1    // kty
    case algorithm = 3  // alg
    case curve = -1     // crv (EC2)
    case xCoord = -2    // x coordinate
    case yCoord = -3    // y coordinate
}

// MARK: - EC2PublicKey

/// Represents an EC2 public key in COSE format.
/// Used for encoding the credential public key in WebAuthn attestation.
public struct EC2PublicKey: Sendable {
    public let algorithm: COSEAlgorithm
    public let curve: COSECurve
    public let xCoordinate: Data
    public let yCoordinate: Data

    /// Creates an EC2PublicKey from a CryptoKit P256 public key.
    public init(from publicKey: P256.Signing.PublicKey) {
        self.algorithm = .es256
        self.curve = .p256

        // P256 public key raw representation is x || y (32 bytes each)
        let rawKey = publicKey.rawRepresentation
        self.xCoordinate = rawKey.prefix(32)
        self.yCoordinate = rawKey.suffix(32)
    }

    /// Creates an EC2PublicKey with explicit coordinates.
    public init(algorithm: COSEAlgorithm, curve: COSECurve, x: Data, y: Data) {
        self.algorithm = algorithm
        self.curve = curve
        self.xCoordinate = x
        self.yCoordinate = y
    }

    /// Encodes the public key as a COSE Key in CBOR format.
    /// Returns bytes suitable for inclusion in authenticator data.
    ///
    /// COSE Key structure for EC2:
    /// {
    ///   1: 2,           // kty: EC2
    ///   3: -7,          // alg: ES256
    ///   -1: 1,          // crv: P-256
    ///   -2: x_coord,    // x coordinate (32 bytes)
    ///   -3: y_coord     // y coordinate (32 bytes)
    /// }
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
