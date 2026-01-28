//
//  ContentView.swift
//  PasskeyProviderDemo
//
//  Main view displaying stored passkeys and setup instructions.
//

import SwiftUI
import UIKit
import Shared

/// The main content view of the Passkey Provider Demo app.
///
/// This view displays:
/// - A list of stored passkeys with the ability to delete them
/// - Navigation to setup instructions
/// - A link to test passkey functionality on webauthn.io
///
/// ## Overview
///
/// The app serves as a companion to the Passkey Provider Extension,
/// allowing users to view and manage their stored passkeys.
struct ContentView: View {

    /// Storage for passkey credentials
    @State private var passkeyStore = PasskeyStore()

    /// List of stored passkeys
    @State private var passkeys: [StoredPasskey] = []

    /// Controls display of the setup instructions sheet
    @State private var showingSetup = false

    /// Controls display of delete confirmation alert
    @State private var passkeyToDelete: StoredPasskey?

    var body: some View {
        NavigationStack {
            Group {
                if passkeys.isEmpty {
                    emptyStateView
                } else {
                    passkeyListView
                }
            }
            .navigationTitle("Passkeys")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showingSetup = true
                    } label: {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showingSetup) {
                SetupInstructionsView()
            }
            .alert("Delete Passkey?", isPresented: .init(
                get: { passkeyToDelete != nil },
                set: { if !$0 { passkeyToDelete = nil } }
            )) {
                Button("Cancel", role: .cancel) {
                    passkeyToDelete = nil
                }
                Button("Delete", role: .destructive) {
                    if let passkey = passkeyToDelete {
                        deletePasskey(passkey)
                    }
                }
            } message: {
                if let passkey = passkeyToDelete {
                    Text("This will permanently delete the passkey for \(passkey.userName) on \(passkey.relyingPartyId).")
                }
            }
            .onAppear {
                refreshPasskeys()
            }
        }
    }

    // MARK: - Subviews

    /// View shown when no passkeys are stored.
    private var emptyStateView: some View {
        VStack(spacing: 20) {
            Image(systemName: "key.fill")
                .font(.system(size: 60))
                .foregroundColor(.secondary)

            Text("No Passkeys Yet")
                .font(.title2)
                .fontWeight(.semibold)

            Text("Passkeys you create will appear here. Visit webauthn.io in Safari to test creating a passkey.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            VStack(spacing: 12) {
                Button {
                    showingSetup = true
                } label: {
                    Label("Setup Instructions", systemImage: "gear")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }

                Link(destination: URL(string: "https://webauthn.io")!) {
                    Label("Test on webauthn.io", systemImage: "safari")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color(uiColor: .secondarySystemBackground))
                        .foregroundColor(.primary)
                        .cornerRadius(12)
                }
            }
            .padding(.horizontal, 40)
            .padding(.top, 20)
        }
    }

    /// View showing the list of stored passkeys.
    private var passkeyListView: some View {
        List {
            Section {
                ForEach(passkeys) { passkey in
                    PasskeyRowView(passkey: passkey)
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                passkeyToDelete = passkey
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
            } header: {
                Text("\(passkeys.count) passkey\(passkeys.count == 1 ? "" : "s")")
            } footer: {
                Link("Test passkeys on webauthn.io", destination: URL(string: "https://webauthn.io")!)
                    .font(.footnote)
            }
        }
        .refreshable {
            refreshPasskeys()
        }
    }

    // MARK: - Actions

    /// Refreshes the list of passkeys from storage.
    private func refreshPasskeys() {
        passkeys = passkeyStore.getAllPasskeys()
            .sorted { $0.createdAt > $1.createdAt }
    }

    /// Deletes a passkey from storage.
    private func deletePasskey(_ passkey: StoredPasskey) {
        do {
            try passkeyStore.deletePasskey(credentialIdBase64: passkey.credentialIdBase64)
            refreshPasskeys()
        } catch {
            print("Failed to delete passkey: \(error)")
        }
        passkeyToDelete = nil
    }
}

// MARK: - Passkey Row View

/// A row displaying information about a single passkey.
private struct PasskeyRowView: View {
    let passkey: StoredPasskey

    var body: some View {
        HStack(spacing: 12) {
            // Icon
            Image(systemName: "person.badge.key.fill")
                .font(.title2)
                .foregroundColor(.blue)
                .frame(width: 44, height: 44)
                .background(Color.blue.opacity(0.1))
                .cornerRadius(10)

            // Info
            VStack(alignment: .leading, spacing: 4) {
                Text(passkey.relyingPartyId)
                    .font(.headline)

                Text(passkey.userName)
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                HStack(spacing: 8) {
                    Label("\(passkey.signCount)", systemImage: "arrow.counterclockwise")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    if let lastUsed = passkey.lastUsedAt {
                        Text("Used \(lastUsed.formatted(date: .abbreviated, time: .omitted))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Preview

#Preview {
    ContentView()
}
