// CBORHelpers.swift
// Shared
//
// CBOR ordered map helpers for WebAuthn attestation objects.
// Based on RFC 8949 (CBOR) deterministic encoding requirements.
// See: https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c

import Foundation
import SwiftCBOR

public extension CBOR {

    /// Creates a CBOR map with keys in the specified order.
    ///
    /// WebAuthn and CTAP2 require deterministic CBOR encoding where map keys
    /// appear in a specific order. Standard CBOR implementations may not
    /// guarantee key ordering, so this helper ensures correct encoding.
    ///
    /// WebAuthn attestation objects require keys in a specific order
    /// (`fmt`, `attStmt`, `authData`) for interoperability.
    ///
    /// - Parameter pairs: Array of (key, value) tuples in desired order
    /// - Returns: CBOR-encoded bytes representing the ordered map
    /// - SeeAlso: [RFC 8949 § 4.2 - Deterministically Encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c)
    /// - SeeAlso: [WebAuthn § 6.5.4 - Generating an Attestation Object](https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object)
    static func orderedMap(_ pairs: [(key: CBOREncodable, value: CBOR)]) -> [UInt8] {
        // Encode map header: major type 5 (0xa0) + count
        var result: [UInt8] = pairs.count.encode()
        result[0] = result[0] | 0b1010_0000  // Set major type to 5 (map)

        // Encode each key-value pair in order
        for (key, value) in pairs {
            result.append(contentsOf: key.encode(options: CBOROptions()))
            result.append(contentsOf: value.encode())
        }

        return result
    }

    /// Creates a CBOR map with integer keys in the specified order.
    ///
    /// Used for COSE key encoding where keys are integers (positive and negative).
    /// COSE keys use integer labels like 1 (kty), 3 (alg), -1 (crv), etc.
    ///
    /// This ensures deterministic encoding as required by CTAP2 and WebAuthn.
    ///
    /// - Parameter pairs: Array of (Int, CBOR) tuples in desired order
    /// - Returns: CBOR-encoded bytes
    /// - SeeAlso: [RFC 8949 § 4.2 - Deterministically Encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c)
    /// - SeeAlso: [RFC 9052 § 7 - COSE Key Objects](https://datatracker.ietf.org/doc/html/rfc9052#section-7)
    static func orderedMapWithIntKeys(_ pairs: [(key: Int, value: CBOR)]) -> [UInt8] {
        var result: [UInt8] = pairs.count.encode()
        result[0] = result[0] | 0b1010_0000

        for (key, value) in pairs {
            // Encode integer key (handles negative integers for COSE)
            if key >= 0 {
                result.append(contentsOf: CBOR.unsignedInt(UInt64(key)).encode())
            } else {
                result.append(contentsOf: CBOR.negativeInt(UInt64(-1 - key)).encode())
            }
            result.append(contentsOf: value.encode())
        }

        return result
    }
}
