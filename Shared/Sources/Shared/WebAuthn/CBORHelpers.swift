// CBORHelpers.swift
// Shared
//
// CBOR ordered map helper for WebAuthn attestation objects.
// Based on RFC 8949 (CBOR) and WebAuthn specification requirements.

import Foundation
import SwiftCBOR

/// Extension to create ordered CBOR maps.
/// WebAuthn requires deterministic CBOR encoding with keys in a specific order.
public extension CBOR {

    /// Creates a CBOR map with keys in the specified order.
    /// Standard CBOR.map() doesn't guarantee order, but WebAuthn attestation objects
    /// require specific key ordering for interoperability.
    ///
    /// - Parameter pairs: Array of (key, value) tuples in desired order
        /// - Returns: CBOR-encoded bytes representing the ordered map
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
    /// Used for COSE key encoding where keys are integers.
    ///
    /// - Parameter pairs: Array of (Int, CBOR) tuples
    /// - Returns: CBOR-encoded bytes
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
