// PasskeyStore.swift
// Shared
//
// Secure storage for passkey credentials.
// Uses Keychain for private keys and App Group UserDefaults for metadata.

import Foundation
import CryptoKit
import Security
import AuthenticationServices

/// Manages secure storage of passkey credentials.
///
/// - Private keys are stored in the Keychain with `kSecAttrAccessibleAfterFirstUnlock`
/// - Passkey metadata is stored in App Group UserDefaults for sharing between app and extension
/// - Credential identities are synced to `ASCredentialIdentityStore` for AutoFill support
public final class PasskeyStore {

    // MARK: - Constants

    /// App Group identifier for sharing data between app and extension.
    /// Must match the App Group configured in entitlements.
    public static let appGroupId = "group.dashlane.PasskeyProviderDemo"

    /// UserDefaults key for storing passkey metadata
    private static let passkeyMetadataKey = "storedPasskeys"

    /// Keychain service identifier
    private static let keychainService = "com.dashlane.PasskeyProviderDemo.passkeys"

    // MARK: - Properties

    private let userDefaults: UserDefaults
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    /// Manager for syncing credentials to the identity store
    private let identityStoreManager = CredentialIdentityStoreManager.shared

    // MARK: - Initialization

    public init() {
        guard let defaults = UserDefaults(suiteName: Self.appGroupId) else {
            fatalError("Failed to access App Group UserDefaults: \(Self.appGroupId)")
        }
        self.userDefaults = defaults
    }

    // MARK: - Passkey Metadata Operations

    /// Returns all stored passkeys.
    public func getAllPasskeys() -> [StoredPasskey] {
        guard let data = userDefaults.data(forKey: Self.passkeyMetadataKey),
              let passkeys = try? decoder.decode([StoredPasskey].self, from: data) else {
            return []
        }
        return passkeys
    }

    /// Saves a passkey with its private key.
    ///
    /// This method also adds the passkey to `ASCredentialIdentityStore` so it appears
    /// as an AutoFill suggestion in iOS.
    ///
    /// - Parameters:
    ///   - passkey: The passkey metadata to store
    ///   - privateKey: The P-256 private key for this passkey
    /// - Throws: If storage fails
    public func save(passkey: StoredPasskey, privateKey: P256.Signing.PrivateKey) throws {
        // Save private key to Keychain
        try savePrivateKey(privateKey, forCredentialId: passkey.credentialIdBase64)

        // Save metadata to UserDefaults
        var passkeys = getAllPasskeys()

        // Remove existing passkey with same ID if present
        passkeys.removeAll { $0.credentialIdBase64 == passkey.credentialIdBase64 }
        passkeys.append(passkey)

        let data = try encoder.encode(passkeys)
        userDefaults.set(data, forKey: Self.passkeyMetadataKey)

        // Add to credential identity store for AutoFill support
        let manager = identityStoreManager
        Task {
            try? await manager.addCredentialIdentity(for: passkey)
        }
    }

    /// Finds a passkey by credential ID.
    public func findPasskey(credentialId: Data) -> StoredPasskey? {
        let base64Id = credentialId.base64URLEncodedString()
        return getAllPasskeys().first { $0.credentialIdBase64 == base64Id }
    }

    /// Finds a passkey by Base64URL-encoded credential ID.
    public func findPasskey(credentialIdBase64: String) -> StoredPasskey? {
        getAllPasskeys().first { $0.credentialIdBase64 == credentialIdBase64 }
    }

    /// Finds all passkeys for a relying party.
    public func findPasskeys(forRelyingParty rpId: String) -> [StoredPasskey] {
        getAllPasskeys().filter { $0.relyingPartyId == rpId }
    }

    /// Updates a passkey's metadata (e.g., sign count, last used).
    public func updatePasskey(_ passkey: StoredPasskey) throws {
        var passkeys = getAllPasskeys()

        guard let index = passkeys.firstIndex(where: { $0.credentialIdBase64 == passkey.credentialIdBase64 }) else {
            throw PasskeyStoreError.passkeyNotFound
        }

        passkeys[index] = passkey
        let data = try encoder.encode(passkeys)
        userDefaults.set(data, forKey: Self.passkeyMetadataKey)
    }

    /// Deletes a passkey and its private key.
    ///
    /// This method also removes the passkey from `ASCredentialIdentityStore` so it
    /// no longer appears as an AutoFill suggestion.
    public func deletePasskey(credentialIdBase64: String) throws {
        // Get the passkey before deletion (for identity store removal)
        let passkeyToDelete = findPasskey(credentialIdBase64: credentialIdBase64)

        // Delete private key from Keychain
        try deletePrivateKey(forCredentialId: credentialIdBase64)

        // Remove from UserDefaults
        var passkeys = getAllPasskeys()
        passkeys.removeAll { $0.credentialIdBase64 == credentialIdBase64 }

        let data = try encoder.encode(passkeys)
        userDefaults.set(data, forKey: Self.passkeyMetadataKey)

        // Remove from credential identity store
        if let passkey = passkeyToDelete {
            let manager = identityStoreManager
            Task {
                try? await manager.removeCredentialIdentity(for: passkey)
            }
        }
    }

    // MARK: - Credential Identity Store Sync

    /// Synchronizes all stored passkeys to the credential identity store.
    ///
    /// This performs a full replacement of all credential identities in
    /// `ASCredentialIdentityStore` with the passkeys stored in this store.
    /// Call this on app launch to ensure the identity store is up to date.
    ///
    /// - Throws: If the sync operation fails
    public func syncCredentialsToIdentityStore() async throws {
        let passkeys = getAllPasskeys()
        try await identityStoreManager.syncAllCredentials(passkeys)
    }

    /// Returns whether the credential identity store is enabled.
    ///
    /// The store is enabled when the user has selected this app as a credential provider
    /// in Settings > Passwords > Password Options.
    public func isIdentityStoreEnabled() async -> Bool {
        await identityStoreManager.isEnabled()
    }

    // MARK: - Private Key Operations (Keychain)

    /// Retrieves the private key for a passkey.
    public func getPrivateKey(forCredentialId credentialIdBase64: String) throws -> P256.Signing.PrivateKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: credentialIdBase64,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let keyData = result as? Data else {
            throw PasskeyStoreError.privateKeyNotFound
        }

        return try P256.Signing.PrivateKey(rawRepresentation: keyData)
    }

    /// Saves a private key to the Keychain.
    private func savePrivateKey(_ privateKey: P256.Signing.PrivateKey, forCredentialId credentialIdBase64: String) throws {
        // Delete existing key if present
        try? deletePrivateKey(forCredentialId: credentialIdBase64)

        let keyData = privateKey.rawRepresentation

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: credentialIdBase64,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw PasskeyStoreError.keychainError(status)
        }
    }

    /// Deletes a private key from the Keychain.
    private func deletePrivateKey(forCredentialId credentialIdBase64: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: credentialIdBase64
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PasskeyStoreError.keychainError(status)
        }
    }
}

// MARK: - Errors

public enum PasskeyStoreError: Error, LocalizedError, Sendable {
    case passkeyNotFound
    case privateKeyNotFound
    case keychainError(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .passkeyNotFound:
            return "Passkey not found"
        case .privateKeyNotFound:
            return "Private key not found in Keychain"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        }
    }
}
