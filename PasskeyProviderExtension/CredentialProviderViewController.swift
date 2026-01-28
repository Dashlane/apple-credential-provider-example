//
//  CredentialProviderViewController.swift
//  PasskeyProviderExtension
//
//  A credential provider extension that handles passkey (WebAuthn) operations.
//  This is the main entry point for the AutoFill Credential Provider Extension.
//

import AuthenticationServices
import CryptoKit
import SwiftUI
import Shared

/// Main view controller for the Passkey Provider Extension.
///
/// This controller handles three main operations:
/// 1. **Registration**: Creating new passkeys when websites request them
/// 2. **Assertion**: Authenticating with existing passkeys
/// 3. **Credential List**: Showing available passkeys for a service
///
/// ## Overview
///
/// When a website or app requests a passkey operation, iOS calls the appropriate
/// method on this controller. The controller then either completes the request
/// directly or shows UI for user confirmation.
///
/// ## Topics
///
/// ### Registration
/// - ``prepareInterface(forPasskeyRegistration:)``
///
/// ### Assertion
/// - ``prepareInterfaceToProvideCredential(for:)``
/// - ``provideCredentialWithoutUserInteraction(for:)``
///
/// ### Credential Selection
/// - ``prepareCredentialList(for:requestParameters:)``
///
class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: - Properties

    /// Storage for passkey credentials
    private let passkeyStore = PasskeyStore()

    // MARK: - Passkey Registration

    /// Called when a website requests creation of a new passkey.
    ///
    /// This method is invoked when the user chooses this credential provider
    /// to create a passkey for a website. The extension should:
    ///
    /// 1. Show UI to confirm the passkey creation
    /// 2. Generate a new key pair
    /// 3. Build the attestation object
    /// 4. Store the credential
    /// 5. Complete the request with the registration credential
    ///
    /// - Parameter registrationRequest: The passkey registration request from the system
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancelWithError(.failed)
            return
        }

        // Show registration confirmation UI
        let registrationView = RegistrationConfirmView(
            relyingParty: identity.relyingPartyIdentifier,
            userName: identity.userName,
            onConfirm: { [weak self] in
                self?.completeRegistration(request: request, identity: identity)
            },
            onCancel: { [weak self] in
                self?.cancelWithError(.userCanceled)
            }
        )

        let hostingController = UIHostingController(rootView: registrationView)
        presentViewController(hostingController)
    }

    /// Completes the passkey registration by generating keys and building the attestation.
    private func completeRegistration(request: ASPasskeyCredentialRequest, identity: ASPasskeyCredentialIdentity) {
        do {
            // 1. Generate a new P-256 key pair
            let privateKey = P256.Signing.PrivateKey()
            let publicKey = EC2PublicKey(from: privateKey.publicKey)

            // 2. Generate a random credential ID
            let credentialId = StoredPasskey.generateCredentialId()

            // 3. Build attested credential data
            let attestedCredentialData = AttestedCredentialData(
                aaguid: .zero,
                credentialId: credentialId,
                publicKey: publicKey
            )

            // 4. Build authenticator data
            let authenticatorData = AuthenticatorData(
                relyingPartyId: identity.relyingPartyIdentifier,
                flags: .registration,
                signCount: 0,
                attestedCredentialData: attestedCredentialData
            )

            // 5. Build attestation object
            let attestationObject = AttestationBuilder.buildNoneAttestation(
                authenticatorData: authenticatorData
            )

            // 6. Store the passkey
            let storedPasskey = StoredPasskey(
                credentialId: credentialId,
                relyingPartyId: identity.relyingPartyIdentifier,
                relyingPartyName: identity.relyingPartyIdentifier,  // Use RP ID as name
                userHandle: identity.userHandle,
                userName: identity.userName,
                signCount: 0
            )
            try passkeyStore.save(passkey: storedPasskey, privateKey: privateKey)

            // 7. Complete the registration request
            let registrationCredential = ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                credentialID: credentialId,
                attestationObject: attestationObject
            )

            extensionContext.completeRegistrationRequest(using: registrationCredential) { success in
                if success {
                    print("Passkey registration completed successfully")
                }
            }

        } catch {
            print("Registration failed: \(error)")
            cancelWithError(.failed)
        }
    }

    // MARK: - Passkey Assertion

    /// Called to provide a passkey assertion without showing UI.
    ///
    /// If the passkey is available and the app is unlocked, this method
    /// should complete the assertion immediately. Otherwise, it should
    /// fail with `userInteractionRequired` to show UI.
    ///
    /// - Parameter credentialRequest: The assertion request
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancelWithError(.failed)
            return
        }

        // Try to complete assertion without UI
        do {
            try completeAssertion(request: request, identity: identity)
        } catch {
            // Need user interaction to unlock or select credential
            cancelWithError(.userInteractionRequired)
        }
    }

    /// Called when UI is needed to provide a passkey assertion.
    ///
    /// Shows UI for the user to confirm the passkey usage.
    ///
    /// - Parameter credentialRequest: The assertion request
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancelWithError(.failed)
            return
        }

        // Find the passkey
        guard let passkey = passkeyStore.findPasskey(credentialId: identity.credentialID) else {
            cancelWithError(.credentialIdentityNotFound)
            return
        }

        // Show assertion confirmation UI
        let assertionView = AssertionConfirmView(
            relyingParty: identity.relyingPartyIdentifier,
            userName: passkey.userName,
            onConfirm: { [weak self] in
                do {
                    try self?.completeAssertion(request: request, identity: identity)
                } catch {
                    self?.cancelWithError(.failed)
                }
            },
            onCancel: { [weak self] in
                self?.cancelWithError(.userCanceled)
            }
        )

        let hostingController = UIHostingController(rootView: assertionView)
        presentViewController(hostingController)
    }

    /// Completes the passkey assertion by signing the challenge.
    private func completeAssertion(request: ASPasskeyCredentialRequest, identity: ASPasskeyCredentialIdentity) throws {
        // 1. Find the stored passkey
        guard var passkey = passkeyStore.findPasskey(credentialId: identity.credentialID) else {
            throw PasskeyStoreError.passkeyNotFound
        }

        // 2. Get the private key
        let privateKey = try passkeyStore.getPrivateKey(forCredentialId: passkey.credentialIdBase64)

        // 3. Increment sign count
        passkey.signCount += 1
        passkey.lastUsedAt = Date()

        // 4. Build assertion
        let (authenticatorData, signature) = try AssertionBuilder.buildAssertion(
            relyingPartyId: identity.relyingPartyIdentifier,
            clientDataHash: request.clientDataHash,
            signCount: passkey.signCount,
            privateKey: privateKey
        )

        // 5. Update stored passkey with new sign count
        try passkeyStore.updatePasskey(passkey)

        // 6. Complete the assertion request
        guard let credentialId = passkey.credentialId,
              let userHandle = passkey.userHandle else {
            throw PasskeyStoreError.passkeyNotFound
        }

        let assertionCredential = ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: identity.relyingPartyIdentifier,
            signature: signature,
            clientDataHash: request.clientDataHash,
            authenticatorData: authenticatorData,
            credentialID: credentialId
        )

        extensionContext.completeAssertionRequest(using: assertionCredential) { success in
            if success {
                print("Passkey assertion completed successfully")
            }
        }
    }

    // MARK: - Credential List

    /// Called to show a list of available passkeys for the service.
    ///
    /// This method is called when the user taps on the password field
    /// and the system shows available credentials from all providers.
    ///
    /// - Parameters:
    ///   - serviceIdentifiers: Identifiers for the service (website/app)
    ///   - requestParameters: Additional parameters for the passkey request
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        // Find passkeys matching the relying party
        let rpId = requestParameters.relyingPartyIdentifier
        let matchingPasskeys = passkeyStore.findPasskeys(forRelyingParty: rpId)

        if matchingPasskeys.isEmpty {
            // No passkeys found, show empty state or cancel
            cancelWithError(.credentialIdentityNotFound)
            return
        }

        // Show credential selection UI
        let selectionView = CredentialListView(
            passkeys: matchingPasskeys,
            relyingParty: rpId,
            onSelect: { [weak self] selectedPasskey in
                self?.selectPasskeyForAssertion(selectedPasskey, requestParameters: requestParameters)
            },
            onCancel: { [weak self] in
                self?.cancelWithError(.userCanceled)
            }
        )

        let hostingController = UIHostingController(rootView: selectionView)
        presentViewController(hostingController)
    }

    /// Legacy credential list method for password-only requests.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // This extension only supports passkeys, not passwords
        cancelWithError(.credentialIdentityNotFound)
    }

    /// Handles passkey selection from the credential list.
    private func selectPasskeyForAssertion(_ passkey: StoredPasskey, requestParameters: ASPasskeyCredentialRequestParameters) {
        do {
            // Get the private key
            let privateKey = try passkeyStore.getPrivateKey(forCredentialId: passkey.credentialIdBase64)

            // Build assertion
            var mutablePasskey = passkey
            mutablePasskey.signCount += 1
            mutablePasskey.lastUsedAt = Date()

            let (authenticatorData, signature) = try AssertionBuilder.buildAssertion(
                relyingPartyId: requestParameters.relyingPartyIdentifier,
                clientDataHash: requestParameters.clientDataHash,
                signCount: mutablePasskey.signCount,
                privateKey: privateKey
            )

            // Update stored passkey
            try passkeyStore.updatePasskey(mutablePasskey)

            // Complete assertion
            guard let credentialId = passkey.credentialId,
                  let userHandle = passkey.userHandle else {
                throw PasskeyStoreError.passkeyNotFound
            }

            let assertionCredential = ASPasskeyAssertionCredential(
                userHandle: userHandle,
                relyingParty: requestParameters.relyingPartyIdentifier,
                signature: signature,
                clientDataHash: requestParameters.clientDataHash,
                authenticatorData: authenticatorData,
                credentialID: credentialId
            )

            extensionContext.completeAssertionRequest(using: assertionCredential) { success in
                if success {
                    print("Passkey assertion completed successfully")
                }
            }

        } catch {
            print("Assertion failed: \(error)")
            cancelWithError(.failed)
        }
    }

    // MARK: - Helper Methods

    /// Cancels the current request with the specified error.
    private func cancelWithError(_ error: ASExtensionError.Code) {
        let nsError = NSError(
            domain: ASExtensionErrorDomain,
            code: error.rawValue
        )
        extensionContext.cancelRequest(withError: nsError)
    }

    /// Presents a view controller as the root content.
    private func presentViewController(_ viewController: UIViewController) {
        // Remove any existing child view controllers
        children.forEach { child in
            child.willMove(toParent: nil)
            child.view.removeFromSuperview()
            child.removeFromParent()
        }

        // Add the new view controller
        addChild(viewController)
        view.addSubview(viewController.view)
        viewController.view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            viewController.view.topAnchor.constraint(equalTo: view.topAnchor),
            viewController.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            viewController.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            viewController.view.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
        viewController.didMove(toParent: self)
    }
}

// MARK: - Assertion Confirm View

/// SwiftUI view for confirming passkey assertion.
struct AssertionConfirmView: View {
    let relyingParty: String
    let userName: String
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "person.badge.key.fill")
                .font(.system(size: 60))
                .foregroundColor(.blue)

            Text("Sign In with Passkey")
                .font(.title2)
                .fontWeight(.semibold)

            VStack(spacing: 8) {
                Text(relyingParty)
                    .font(.headline)
                Text(userName)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            VStack(spacing: 12) {
                Button(action: onConfirm) {
                    Text("Continue")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }

                Button(action: onCancel) {
                    Text("Cancel")
                        .frame(maxWidth: .infinity)
                        .padding()
                }
            }
        }
        .padding()
    }
}
