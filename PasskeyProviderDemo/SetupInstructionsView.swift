//
//  SetupInstructionsView.swift
//  PasskeyProviderDemo
//
//  Instructions for enabling the passkey provider extension.
//

import SwiftUI
import UIKit

/// A view displaying instructions for enabling the Passkey Provider Extension.
///
/// This view guides users through the process of enabling the credential
/// provider in iOS Settings so that it can be used for passkey operations.
///
/// ## Overview
///
/// Users must manually enable credential provider extensions in iOS Settings.
/// This view provides step-by-step instructions for doing so.
struct SetupInstructionsView: View {

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    // Header
                    headerSection

                    // Steps
                    stepsSection

                    // Testing section
                    testingSection
                }
                .padding()
            }
            .navigationTitle("Setup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }

    // MARK: - Sections

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Image(systemName: "key.fill")
                .font(.system(size: 50))
                .foregroundColor(.blue)

            Text("Enable Passkey Provider")
                .font(.title)
                .fontWeight(.bold)

            Text("Follow these steps to enable PasskeyProviderDemo as your passkey provider.")
                .font(.body)
                .foregroundColor(.secondary)
        }
    }

    private var stepsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Setup Steps")
                .font(.headline)

            SetupStepView(
                number: 1,
                title: "Open Settings",
                description: "Go to the Settings app on your device."
            )

            SetupStepView(
                number: 2,
                title: "Navigate to Passwords",
                description: "Tap \"Passwords\" in the Settings menu."
            )

            SetupStepView(
                number: 3,
                title: "Open Password Options",
                description: "Tap \"Password Options\" at the top of the screen."
            )

            SetupStepView(
                number: 4,
                title: "Enable AutoFill",
                description: "Make sure \"AutoFill Passwords and Passkeys\" is turned on."
            )

            SetupStepView(
                number: 5,
                title: "Select Provider",
                description: "Under \"Use Passwords and Passkeys From:\", enable \"PasskeyProviderDemo\"."
            )

            // Settings link button
            if let settingsURL = URL(string: UIApplication.openSettingsURLString) {
                Link(destination: settingsURL) {
                    HStack {
                        Image(systemName: "gear")
                        Text("Open Settings")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                }
                .padding(.top, 8)
            }
        }
        .padding()
        .background(Color(uiColor: .secondarySystemBackground))
        .cornerRadius(16)
    }

    private var testingSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Testing")
                .font(.headline)

            Text("After enabling the provider, you can test passkey creation and authentication:")
                .font(.body)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                BulletPoint(text: "Open Safari and visit webauthn.io")
                BulletPoint(text: "Enter a username and tap \"Register\"")
                BulletPoint(text: "Select \"PasskeyProviderDemo\" when prompted")
                BulletPoint(text: "Confirm the passkey creation")
                BulletPoint(text: "Return to this app to see your stored passkey")
            }

            Link(destination: URL(string: "https://webauthn.io")!) {
                HStack {
                    Image(systemName: "safari")
                    Text("Open webauthn.io")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color(uiColor: .tertiarySystemBackground))
                .foregroundColor(.primary)
                .cornerRadius(12)
            }
            .padding(.top, 8)
        }
        .padding()
        .background(Color(uiColor: .secondarySystemBackground))
        .cornerRadius(16)
    }
}

// MARK: - Setup Step View

/// A single step in the setup instructions.
private struct SetupStepView: View {
    let number: Int
    let title: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Step number
            Text("\(number)")
                .font(.headline)
                .foregroundColor(.white)
                .frame(width: 28, height: 28)
                .background(Color.blue)
                .clipShape(Circle())

            // Content
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)

                Text(description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Bullet Point

/// A bullet point for listing items.
private struct BulletPoint: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("•")
                .foregroundColor(.secondary)
            Text(text)
                .font(.subheadline)
        }
    }
}

// MARK: - Preview

#Preview {
    SetupInstructionsView()
}
