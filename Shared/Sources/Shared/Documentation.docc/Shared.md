# ``Shared``

WebAuthn data structures and utilities for passkey credential management.

## Overview

The Shared framework provides the core WebAuthn implementation for the
Passkey Provider Demo app. It includes data structures for authenticator data,
attestation objects, and COSE key encoding, all based on the
[W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) specification.

If you're new to WebAuthn and passkeys, start with <doc:WebAuthnOverview>.

## Topics

### Essentials

- <doc:WebAuthnOverview>

### Authenticator Data

- ``AuthenticatorData``
- ``AuthenticatorFlags``
- ``AttestedCredentialData``
- ``AAGUID``

### Attestation

- ``AttestationBuilder``
- ``AttestationFormat``

### Assertion

- ``AssertionBuilder``

### COSE Key Encoding

- ``EC2PublicKey``
- ``COSEAlgorithm``
- ``COSEKeyType``
- ``COSECurve``
- ``COSEKeyLabel``

### Credential Storage

- ``StoredPasskey``
- ``PasskeyStore``
- ``PasskeyStoreError``
