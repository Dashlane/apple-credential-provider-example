# Passkey Provider Demo

A "hello world" style iOS Credential Provider Extension demonstrating how third-party password managers can handle passkey (WebAuthn) creation and authentication on iOS.

## Overview

This sample app shows how to build a credential provider extension that:
- **Registers passkeys** when websites request them
- **Authenticates** users with stored passkeys
- **Lists available passkeys** for a relying party

Similar in concept to the [Windows PasskeyManager sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager), but for iOS.

## Requirements

- iOS 18.0+
- Xcode 16+
- Physical iOS device (credential provider extensions don't work in the Simulator)

## Project Structure

```
PasskeyProviderDemo/
├── PasskeyProviderDemo/           # Host app
│   ├── ContentView.swift          # Lists stored passkeys
│   └── SetupInstructionsView.swift
├── PasskeyProviderExtension/      # Credential Provider Extension
│   ├── CredentialProviderViewController.swift
│   ├── Views/
│   │   ├── RegistrationConfirmView.swift
│   │   └── CredentialListView.swift
│   └── Info.plist
└── Shared/                        # Swift Package (shared code)
    └── Sources/Shared/
        ├── Models/
        │   └── StoredPasskey.swift
        ├── Storage/
        │   └── PasskeyStore.swift
        └── WebAuthn/
            ├── AuthenticatorData.swift
            ├── AttestationBuilder.swift
            ├── AssertionBuilder.swift
            ├── COSEKey.swift
            └── CBORHelpers.swift
```

## Setup

1. **Clone the repository**

2. **Open in Xcode**
   ```
   open PasskeyProviderDemo.xcodeproj
   ```

3. **Configure signing**
   - Select the project in the navigator
   - For both targets (PasskeyProviderDemo and PasskeyProviderExtension):
     - Set your Development Team
     - Update the Bundle Identifier to use your own prefix

4. **Configure App Group**
   - In Xcode, select each target → Signing & Capabilities
   - Update the App Group identifier if needed
   - Update `PasskeyStore.appGroupId` in `Shared/Sources/Shared/Storage/PasskeyStore.swift` to match

5. **Build and run** on a physical device

## Enable the Extension

After installing, enable the credential provider in Settings:

Settings → General → AutoFill & Passwords → Enable "Passkey Provider Demo"

## Testing

1. Open Safari on your device
2. Navigate to [webauthn.io](https://webauthn.io)
3. Enter a username and tap "Register"
4. Select "Passkey Provider Demo" when prompted
5. Confirm passkey creation in the extension UI
6. Tap "Authenticate" to test sign-in with the passkey

## How It Works

### Registration Flow

1. Website calls `navigator.credentials.create()`
2. iOS invokes `prepareInterface(forPasskeyRegistration:)`
3. Extension generates P-256 key pair using CryptoKit
4. Builds authenticator data with attested credential data
5. Creates attestation object (CBOR encoded, "none" format)
6. Stores private key in Keychain, metadata in App Group UserDefaults
7. Returns `ASPasskeyRegistrationCredential` to the system

### Authentication Flow

1. Website calls `navigator.credentials.get()`
2. iOS invokes `prepareInterfaceToProvideCredential(for:)`
3. Extension retrieves private key from Keychain
4. Builds authenticator data and signs `authData || clientDataHash`
5. Returns `ASPasskeyAssertionCredential` to the system

## Key Components

### WebAuthn Implementation

Based on [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) specification:

- **AuthenticatorData** - RP ID hash, flags (UP, UV, BE, BS, AT), sign counter, attested credential data
- **COSEKey** - EC2 public key encoding per [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)
- **AttestationBuilder** - Creates attestation objects with "none" format
- **AssertionBuilder** - Signs challenges for authentication

### Storage

- **Private keys**: Keychain with `kSecAttrAccessibleAfterFirstUnlock`
- **Passkey metadata**: App Group UserDefaults (shared between app and extension)

## Dependencies

- [SwiftCBOR](https://github.com/valpackett/SwiftCBOR) - CBOR encoding (required by WebAuthn spec)

## License

MIT License

## References

- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [RFC 8152: COSE](https://datatracker.ietf.org/doc/html/rfc8152)
- [Apple: Supporting Passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
- [ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [WWDC24: Streamline sign-in with passkey upgrades](https://developer.apple.com/videos/play/wwdc2024/10125/)
