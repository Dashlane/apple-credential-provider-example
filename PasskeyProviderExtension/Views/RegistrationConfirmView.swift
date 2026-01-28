//
//  RegistrationConfirmView.swift
//  PasskeyProviderExtension
//
//  SwiftUI view for confirming passkey creation.
//

import SwiftUI
import UIKit

/// A view that confirms passkey creation with the user.
///
/// This view is displayed when a website requests creation of a new passkey.
/// It shows the relying party (website) and user information, and provides
/// buttons to confirm or cancel the operation.
///
/// ## Usage
///
/// ```swift
/// RegistrationConfirmView(
///     relyingParty: "example.com",
///     userName: "john@example.com",
///     onConfirm: { /* create passkey */ },
///     onCancel: { /* cancel request */ }
/// )
/// ```
struct RegistrationConfirmView: View {

    /// The relying party identifier (website domain)
    let relyingParty: String

    /// The user's display name or username
    let userName: String

    /// Called when the user confirms passkey creation
    let onConfirm: () -> Void

    /// Called when the user cancels the operation
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            // Icon
            Image(systemName: "key.fill")
                .font(.system(size: 60))
                .foregroundColor(.blue)
                .padding(.top, 40)

            // Title
            Text("Create Passkey")
                .font(.title)
                .fontWeight(.bold)

            // Description
            Text("A passkey will be created for signing in to this website.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            // Website and user info
            VStack(spacing: 16) {
                InfoRow(title: "Website", value: relyingParty)
                InfoRow(title: "Account", value: userName)
            }
            .padding()
            .background(Color(uiColor: .secondarySystemBackground))
            .cornerRadius(12)
            .padding(.horizontal)

            Spacer()

            // Action buttons
            VStack(spacing: 12) {
                Button(action: onConfirm) {
                    HStack {
                        Image(systemName: "key.fill")
                        Text("Create Passkey")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                    .font(.headline)
                }

                Button(action: onCancel) {
                    Text("Cancel")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .foregroundColor(.primary)
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 20)
        }
        .background(Color(uiColor: .systemBackground))
    }
}

/// A row displaying a title-value pair.
private struct InfoRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
    }
}

// MARK: - Preview

#Preview {
    RegistrationConfirmView(
        relyingParty: "webauthn.io",
        userName: "demo@example.com",
        onConfirm: { print("Confirmed") },
        onCancel: { print("Cancelled") }
    )
}
