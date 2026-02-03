// CredentialIdentityStoreManager.swift
// Shared
//
// Manages synchronization of passkey credentials with ASCredentialIdentityStore.
// This allows passkeys to appear as AutoFill suggestions in iOS.

import Foundation
@preconcurrency import AuthenticationServices

/// Manages the synchronization of passkey credentials with the system's credential identity store.
///
/// By adding credentials to `ASCredentialIdentityStore`, passkeys become available as
/// AutoFill suggestions directly in password fields, without requiring the user to
/// open the credential provider extension UI.
///
/// ## Usage
///
/// ```swift
/// let manager = CredentialIdentityStoreManager()
///
/// // Add a single passkey
/// await manager.addCredentialIdentity(for: passkey)
///
/// // Remove a passkey
/// await manager.removeCredentialIdentity(for: passkey)
///
/// // Sync all passkeys
/// await manager.syncAllCredentials(passkeys)
/// ```
///
/// ## Thread Safety
///
/// All methods are async and safe to call from any context.
public final class CredentialIdentityStoreManager: Sendable {

    // MARK: - Shared Instance

    /// Shared instance for convenience
    public static let shared = CredentialIdentityStoreManager()

    // MARK: - Properties

    /// The system credential identity store
    private let store = ASCredentialIdentityStore.shared

    // MARK: - Initialization

    public init() {}

    // MARK: - State

    /// Returns the current state of the credential identity store.
    ///
    /// Use this to check if the store is enabled before attempting operations.
    public func getState() async -> ASCredentialIdentityStoreState {
        await withCheckedContinuation { continuation in
            store.getState { state in
                continuation.resume(returning: state)
            }
        }
    }

    /// Returns whether the credential identity store is enabled.
    ///
    /// The store is enabled when the user has selected this app as a credential provider
    /// in Settings > Passwords > Password Options.
    public func isEnabled() async -> Bool {
        let state = await getState()
        return state.isEnabled
    }

    // MARK: - Add Credentials

    /// Adds a single passkey credential identity to the store.
    ///
    /// This makes the passkey available as an AutoFill suggestion when the user
    /// interacts with a password field on the matching relying party's website or app.
    ///
    /// - Parameter passkey: The passkey to add to the identity store
    /// - Throws: If the operation fails
    public func addCredentialIdentity(for passkey: StoredPasskey) async throws {
        guard let identity = createPasskeyIdentity(from: passkey) else {
            return
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            store.saveCredentialIdentities([identity]) { success, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    /// Adds multiple passkey credential identities to the store.
    ///
    /// - Parameter passkeys: The passkeys to add
    /// - Throws: If the operation fails
    public func addCredentialIdentities(for passkeys: [StoredPasskey]) async throws {
        let identities = passkeys.compactMap { createPasskeyIdentity(from: $0) }

        guard !identities.isEmpty else { return }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            store.saveCredentialIdentities(identities) { success, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    // MARK: - Remove Credentials

    /// Removes a single passkey credential identity from the store.
    ///
    /// - Parameter passkey: The passkey to remove
    /// - Throws: If the operation fails
    public func removeCredentialIdentity(for passkey: StoredPasskey) async throws {
        guard let identity = createPasskeyIdentity(from: passkey) else {
            return
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            store.removeCredentialIdentities([identity]) { success, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    /// Removes multiple passkey credential identities from the store.
    ///
    /// - Parameter passkeys: The passkeys to remove
    /// - Throws: If the operation fails
    public func removeCredentialIdentities(for passkeys: [StoredPasskey]) async throws {
        let identities = passkeys.compactMap { createPasskeyIdentity(from: $0) }

        guard !identities.isEmpty else { return }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            store.removeCredentialIdentities(identities) { success, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    // MARK: - Sync All Credentials

    /// Replaces all credential identities in the store with the provided passkeys.
    ///
    /// This performs a full synchronization, removing any identities that are no longer
    /// in the passkey list and adding any new ones. Use this when you need to ensure
    /// the identity store is in sync with your passkey storage.
    ///
    /// - Parameter passkeys: The complete list of passkeys to sync
    /// - Throws: If the operation fails
    public func syncAllCredentials(_ passkeys: [StoredPasskey]) async throws {
        let identities = passkeys.compactMap { createPasskeyIdentity(from: $0) }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            store.replaceCredentialIdentities(identities) { success, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    /// Removes all credential identities from the store.
    ///
    /// - Throws: If the operation fails
    public func removeAllCredentials() async throws {
        try await syncAllCredentials([])
    }

    // MARK: - Private Helpers

    /// Creates an ASPasskeyCredentialIdentity from a StoredPasskey.
    ///
    /// - Parameter passkey: The passkey to convert
    /// - Returns: The credential identity, or nil if the passkey data is invalid
    private func createPasskeyIdentity(from passkey: StoredPasskey) -> ASPasskeyCredentialIdentity? {
        guard let credentialId = passkey.credentialId,
              let userHandle = passkey.userHandle else {
            return nil
        }

        return ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: passkey.relyingPartyId,
            userName: passkey.userName,
            credentialID: credentialId,
            userHandle: userHandle,
            recordIdentifier: passkey.credentialIdBase64
        )
    }
}
