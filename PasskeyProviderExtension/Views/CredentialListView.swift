//
//  CredentialListView.swift
//  PasskeyProviderExtension
//
//  SwiftUI view for selecting a passkey from a list.
//

import SwiftUI
import Shared

/// A view that displays a list of available passkeys for selection.
///
/// This view is shown when multiple passkeys are available for a website,
/// allowing the user to choose which one to use for authentication.
///
/// ## Usage
///
/// ```swift
/// CredentialListView(
///     passkeys: [passkey1, passkey2],
///     relyingParty: "example.com",
///     onSelect: { selectedPasskey in /* use passkey */ },
///     onCancel: { /* cancel request */ }
/// )
/// ```
struct CredentialListView: View {

    /// The list of available passkeys
    let passkeys: [StoredPasskey]

    /// The relying party identifier (website domain)
    let relyingParty: String

    /// Called when the user selects a passkey
    let onSelect: (StoredPasskey) -> Void

    /// Called when the user cancels the operation
    let onCancel: () -> Void

    var body: some View {
        NavigationView {
            List {
                Section {
                    ForEach(passkeys) { passkey in
                        PasskeyRow(passkey: passkey)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                onSelect(passkey)
                            }
                    }
                } header: {
                    Text("Select a passkey for \(relyingParty)")
                }
            }
            .navigationTitle("Passkeys")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }
}

/// A row displaying a single passkey.
private struct PasskeyRow: View {
    let passkey: StoredPasskey

    var body: some View {
        HStack(spacing: 12) {
            // Icon
            Image(systemName: "person.badge.key.fill")
                .font(.title2)
                .foregroundColor(.blue)
                .frame(width: 40)

            // User info
            VStack(alignment: .leading, spacing: 4) {
                Text(passkey.userName)
                    .font(.body)
                    .fontWeight(.medium)

                if let lastUsed = passkey.lastUsedAt {
                    Text("Last used: \(lastUsed.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else {
                    Text("Created: \(passkey.createdAt.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // Chevron
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Preview

#Preview {
    CredentialListView(
        passkeys: [
            StoredPasskey(
                credentialId: Data([1, 2, 3, 4]),
                relyingPartyId: "webauthn.io",
                relyingPartyName: "WebAuthn.io",
                userHandle: Data([5, 6, 7, 8]),
                userName: "demo@example.com"
            ),
            StoredPasskey(
                credentialId: Data([9, 10, 11, 12]),
                relyingPartyId: "webauthn.io",
                relyingPartyName: "WebAuthn.io",
                userHandle: Data([13, 14, 15, 16]),
                userName: "test@example.com"
            )
        ],
        relyingParty: "webauthn.io",
        onSelect: { print("Selected: \($0.userName)") },
        onCancel: { print("Cancelled") }
    )
}
