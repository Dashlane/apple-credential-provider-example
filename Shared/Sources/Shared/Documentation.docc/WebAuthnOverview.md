# Understanding WebAuthn and Passkeys

Learn the key concepts behind passkeys, WebAuthn, and FIDO authentication.

## Overview

This guide explains the terminology and processes involved in passkey authentication
for developers who are new to WebAuthn. It covers the key concepts, data structures,
and cryptographic operations used in this implementation, with emphasis on how
these pieces fit together.

## What Are Passkeys?

**Passkeys** are a modern, phishing-resistant replacement for passwords. They use
public-key cryptography to authenticate users without transmitting secrets over the network.

- **No shared secrets**: Unlike passwords, the private key is never sent to the relying party—only the public key (during registration) and signatures (during authentication)
- **Phishing-resistant**: Credentials are bound to specific websites (relying parties)
- **Multi-device**: Can sync across devices via encrypted cloud backup (iCloud Keychain, Google Password Manager)

Passkeys are built on the **WebAuthn** standard and the **FIDO2** protocols.

## The Standards Landscape

When working with passkeys, you'll encounter several overlapping terms. Here's how
they relate:

| Term | What It Is | Role |
|------|------------|------|
| **FIDO Alliance** | Industry consortium | Creates the standards |
| **FIDO2** | Protocol suite | The umbrella containing WebAuthn + CTAP2 |
| **WebAuthn** | W3C specification | Defines the browser/server API |
| **CTAP2** | FIDO specification | Defines how browsers talk to authenticators |

Think of it as layers: **FIDO2** is the overall framework, **WebAuthn** handles the
web-facing API, and **CTAP2** handles the low-level authenticator communication.
As an iOS credential provider, you implement the authenticator side—iOS handles
the CTAP2 communication for you via `ASCredentialProviderViewController`.

- SeeAlso: [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- SeeAlso: [FIDO CTAP 2.2 Proposed Standard (July 2025)](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html) — For the latest version, see [FIDO Alliance Specifications](https://fidoalliance.org/specifications/)

## Participants in WebAuthn

Three parties participate in every WebAuthn ceremony:

### Relying Party (RP)

The **Relying Party** is the website or app that wants to authenticate users.
It's called "relying" because it relies on the authenticator's assertions to
verify user identity.

- Identified by its **RP ID** (typically the domain, e.g., `example.com`)
- Generates challenges and verifies responses
- Stores the user's public key after registration

### Client

The **Client** mediates between the RP and authenticator. On the web, this is
the browser; on iOS, it's the system credential manager.

- Receives WebAuthn API calls from the RP
- Creates the **Client Data JSON** containing:
  - `type`: The operation (`"webauthn.create"` or `"webauthn.get"`)
  - `challenge`: The RP's challenge, Base64URL-encoded
  - `origin`: The origin that requested the operation (e.g., `"https://example.com"`)
  - `crossOrigin`: Whether the request is cross-origin (optional)
- Routes requests to the appropriate authenticator

> Note: As a credential provider, you receive the SHA-256 hash of the client
> data JSON (`clientDataHash`), not the raw JSON. The system constructs the
> client data JSON and provides only its hash for signing.

- SeeAlso: [WebAuthn § 5.8.1 - Client Data Used in WebAuthn Signatures](https://www.w3.org/TR/webauthn-3/#dictdef-collectedclientdata)

### Authenticator

The **Authenticator** generates and protects credentials. This can be:

- **Platform authenticators**: Built into the device (Touch ID, Face ID)
- **Roaming authenticators**: External devices (YubiKey, security keys)
- **Software authenticators**: Apps like this credential provider extension

Each authenticator model has an **AAGUID** (Authenticator Attestation GUID)—a
16-byte identifier that uniquely identifies the authenticator make and model.
When an authenticator does not have a meaningful AAGUID to report (e.g., for
self-attestation or software authenticators without FIDO certification), it
SHOULD be set to 16 zero bytes per the specification.

- SeeAlso: [WebAuthn § 6.5.1 - Attested Credential Data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data) (includes AAGUID definition)

## How WebAuthn Maps to iOS

The abstract WebAuthn roles map to concrete components on iOS. Understanding
which component handles what is essential for credential provider developers.

### Component Responsibilities

| Component | WebAuthn Role | Key Responsibilities |
|-----------|---------------|----------------------|
| **Website Server** | Relying Party | Generate challenges, verify attestations/assertions, store public keys |
| **Safari** | Client (web) | Receive `navigator.credentials` API calls, construct clientDataJSON, invoke system UI |
| **Native App** | Client (native) | Use `ASAuthorizationController` to request credentials, construct clientDataJSON |
| **iOS System** | Platform Broker | Present credential picker, route requests to extensions, enforce origin binding |
| **Your Extension** | Authenticator | Generate/store keys, sign assertions, build attestation objects |

### The Request Flow on iOS

Here's how a passkey authentication request flows through the system:

```
┌─────────────────┐
│  Website/App    │  ← Relying Party: generates challenge
│    (Server)     │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│ Safari or App   │  ← Client: calls navigator.credentials.get()
│                 │     or ASAuthorizationController
└────────┬────────┘
         │ System API
         ▼
┌─────────────────┐
│    iOS System   │  ← Broker: shows credential picker,
│  (AuthServices) │     builds clientDataJSON, computes clientDataHash
└────────┬────────┘
         │ Extension Launch
         ▼
┌─────────────────┐
│  Your Extension │  ← Authenticator: receives clientDataHash,
│ (ASCredential-  │     signs assertion, returns response
│  Provider)      │
└─────────────────┘
```

### What Each Component Does

#### Website or Native App (Relying Party)

The server-side component initiates WebAuthn ceremonies:

- **Registration**: Sends `PublicKeyCredentialCreationOptions` containing user info,
  RP info, challenge, and supported algorithms
- **Authentication**: Sends `PublicKeyCredentialRequestOptions` containing challenge
  and optionally a list of allowed credential IDs
- **Verification**: Validates the attestation or assertion response, checking
  signatures, origins, and counters

For web contexts, the JavaScript calls `navigator.credentials.create()` or
`navigator.credentials.get()`. Native apps use `ASAuthorizationController`.

- SeeAlso: [WebAuthn § 5.1 - PublicKeyCredential](https://www.w3.org/TR/webauthn-3/#iface-pkcredential)

#### Safari (Web Client)

When a website calls the WebAuthn API, Safari:

1. Validates the request comes from a secure context (HTTPS)
2. Constructs the **clientDataJSON** with the challenge, origin, and operation type
3. Invokes the iOS credential manager via system APIs
4. Returns the authenticator's response to the website

Safari enforces origin binding—the origin in clientDataJSON is set by the browser,
not the website, preventing phishing attacks.

> Important: Safari constructs clientDataJSON. Your extension never sees this
> JSON directly—you receive only its SHA-256 hash (`clientDataHash`).

- SeeAlso: [WebAuthn § 5.1.3 - Create a New Credential](https://www.w3.org/TR/webauthn-3/#sctn-createCredential)

#### Native Apps (Native Client)

Native iOS apps use `ASAuthorizationController` to request passkeys:

```swift
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: "example.com"
)
let request = provider.createCredentialAssertionRequest(
    challenge: challengeData
)
let controller = ASAuthorizationController(authorizationRequests: [request])
```

The app must be associated with the RP's domain via the
`apple-app-site-association` file for the system to permit the request.

- SeeAlso: [Supporting Associated Domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- SeeAlso: [ASAuthorizationController](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller)

#### iOS System (Platform Broker)

The iOS system credential manager orchestrates the entire flow:

1. **Displays the credential picker UI** — Users see available passkeys from all
   credential providers (iCloud Keychain, third-party apps)
2. **Constructs clientDataJSON** — The system builds this structure; your extension
   cannot influence its contents
3. **Computes clientDataHash** — SHA-256 of clientDataJSON, provided to your extension
4. **Enforces security policies** — Origin validation, user presence/verification
5. **Routes to your extension** — Launches your `ASCredentialProviderViewController`
   subclass with the request parameters
6. **Returns the response** — Delivers your attestation/assertion back to the client

Your extension runs in a **separate process** with limited communication:
you receive request parameters and return a credential response. The system
handles everything else.

- SeeAlso: [About the Password AutoFill Workflow](https://developer.apple.com/documentation/authenticationservices/connecting-to-a-service-with-passkeys#About-the-Password-AutoFill-workflow)

#### Your Credential Provider Extension (Authenticator)

Your extension implements `ASCredentialProviderViewController` and handles:

**Registration** (`prepareInterface(forPasskeyRegistration:)` and `performPasskeyRegistration(with:)`):
- Generate a new P-256 key pair
- Create a unique credential ID
- Store the private key securely (Keychain)
- Store metadata (RP ID, user info, counter) for discovery
- Build and return an `ASPasskeyRegistrationCredential` containing the attestation object

**Authentication** (`provideCredentialWithoutUserInteraction(for:)` or after user selection):
- Look up the credential by RP ID (and credential ID if provided)
- Sign `authenticatorData || clientDataHash` with the private key
- Increment the sign counter
- Return an `ASPasskeyAssertionCredential` containing the signature

> Important: Your extension does **not**:
> - Construct clientDataJSON (the system does this)
> - See the raw challenge (only the hash)
> - Control the credential picker UI (the system presents it)
> - Handle CTAP2 protocol details (abstracted by iOS)

- SeeAlso: [ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- SeeAlso: [ASPasskeyCredentialRequest](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialrequest)

### Security Boundaries

Understanding what your extension *cannot* do clarifies the security model:

| Boundary | Enforced By | Purpose |
|----------|-------------|---------|
| Origin binding | iOS/Safari | Prevents phishing—credentials only work for their registered origin |
| clientDataJSON construction | iOS | Extension cannot forge the challenge or origin |
| User presence | iOS UI | System confirms user intent before invoking extension |
| Process isolation | iOS sandbox | Extension runs separately from the host app |

This architecture means even a compromised credential provider cannot:
- Use credentials for origins the user didn't intend
- Bypass user presence checks
- Access credentials from other providers

- SeeAlso: [WebAuthn § 13 - Security Considerations](https://www.w3.org/TR/webauthn-3/#sctn-security-considerations)

## How the Cryptography Fits Together

WebAuthn's cryptographic components can seem like alphabet soup: ES256, P-256,
SHA-256, ECDSA, COSE, DER. Here's how they connect—each layer builds on the previous:

### Layer 1: The Curve (P-256)

**P-256** (also called secp256r1 or prime256v1) is an *elliptic curve*—a
mathematical structure that enables public-key cryptography.

Think of it as the foundation: P-256 defines the "shape" of the mathematical
space where keys live. It determines:
- Key size: 256 bits for private keys; public keys are points with two 256-bit
  coordinates (x, y)—64 bytes as raw coordinates (32-byte X + 32-byte Y)
- Security strength (roughly equivalent to 128-bit symmetric encryption)

> Note: In generic cryptographic contexts, public keys often use SEC 1 uncompressed
> format (65 bytes with a `0x04` prefix). However, COSE keys in WebAuthn encode the
> X and Y coordinates directly as byte strings without this prefix.

P-256 was standardized by **NIST** (National Institute of Standards and Technology),
a U.S. government agency that develops cryptographic standards used worldwide.
The curve is widely supported across platforms and cryptographic libraries.

### Layer 2: The Signature Algorithm (ECDSA)

**ECDSA** (Elliptic Curve Digital Signature Algorithm) is the *process* for
creating and verifying signatures using elliptic curve keys.

If P-256 defines the playing field, ECDSA defines the rules of the game.
Given a private key and a message, ECDSA produces a signature that anyone
with the corresponding public key can verify.

ECDSA signatures prove two things:
1. The signer possesses the private key
2. The message hasn't been modified

### Layer 3: The Hash Function (SHA-256)

Before signing, you need to condense your data into a fixed-size fingerprint.
**SHA-256** produces a 256-bit (32-byte) hash that's:
- Deterministic: Same input always produces the same hash
- One-way: You can't reverse a hash to get the original data
- Collision-resistant: It's practically impossible to find two inputs with the same hash

Why hash before signing? ECDSA can only sign fixed-size data efficiently.
By hashing first, you can sign messages of any length while maintaining security.

### Layer 4: The Label (ES256)

**ES256** is simply a label that bundles all the above choices together.
When a system declares "ES256", it means:
- Curve: P-256
- Signature algorithm: ECDSA
- Hash function: SHA-256

Instead of specifying three separate parameters, ES256 is a convenient shorthand
registered in the IANA COSE Algorithms registry as algorithm identifier **-7**.

### Other Supported Algorithms

WebAuthn algorithm identifiers are registered in the IANA COSE Algorithms
registry. The most commonly supported algorithms are:

| Algorithm | COSE ID | Key Type | Curve | Description |
|-----------|---------|----------|-------|-------------|
| **ES256** | -7 | EC2 (kty: 2) | P-256 (crv: 1) | ECDSA with SHA-256—default, universal support |
| **ES384** | -35 | EC2 (kty: 2) | P-384 (crv: 2) | ECDSA with SHA-384 |
| **ES512** | -36 | EC2 (kty: 2) | P-521 (crv: 3) | ECDSA with SHA-512 |
| **EdDSA** | -8 | OKP (kty: 1) | Ed25519 (crv: 6) | Edwards-curve signatures |
| **RS256** | -257 | RSA (kty: 3) | N/A | RSASSA-PKCS1-v1_5 with SHA-256 |

> Note: The IANA COSE Algorithms registry (referenced by WebAuthn § 5.8.5) specifies
> required curves for each algorithm. For example, ES256 keys MUST use P-256.
> RFC 9053 supports both uncompressed and compressed point encodings for EC2 keys,
> but WebAuthn implementations conventionally use uncompressed form (separate x and
> y coordinates) for broad interoperability. RFC 9864 deprecates these algorithm
> identifiers in favor of fully-specified variants (e.g., ESP256), but **for WebAuthn
> purposes, ES256 (-7) remains the universal standard** and is required by all
> conforming relying parties.

**EdDSA with Ed25519** is gaining adoption due to its simplicity and performance.
Unlike ECDSA, EdDSA is deterministic (no random nonce required) and resistant
to certain implementation pitfalls. However, ES256 remains the recommended
default for maximum interoperability.

> Note: This implementation supports **ES256 only**, which provides universal
> compatibility with all WebAuthn relying parties. EdDSA and RSA support could
> be added if specific relying parties require them.

- SeeAlso: [IANA COSE Algorithms Registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
- SeeAlso: [WebAuthn § 5.8.5 - COSEAlgorithmIdentifier](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier)
- SeeAlso: [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032.html)

### Putting It Together: Signing Flow

Here's how these layers work together when creating an assertion signature:

```
1. INPUT: authenticatorData + clientDataHash
         ↓
2. CONCATENATE: authData || clientDataHash (variable length)
         ↓
3. SIGN with ES256:
   ┌─────────────────────────────────────┐
   │  CryptoKit handles internally:      │
   │  • SHA-256 hash of concatenation    │
   │  • ECDSA signature with P-256 key   │
   └─────────────────────────────────────┘
         ↓
4. ENCODE: DER format for transmission
         ↓
5. OUTPUT: Signature ready for relying party
```

> Note: High-level APIs like Apple's CryptoKit perform the SHA-256 hashing internally
> as part of the signing operation. You pass the raw concatenation to `signature(for:)`,
> not a pre-hashed digest. The "ES256" label identifies the complete algorithm bundle
> (P-256 curve + ECDSA + SHA-256).

The relying party verifies by reconstructing the same digest and checking the signature:

```
1. INPUT: authenticatorData + clientDataJSON (received from client)
         ↓
2. HASH clientDataJSON: SHA-256 produces clientDataHash
         ↓
3. CONCATENATE: authData || clientDataHash
         ↓
4. HASH: SHA-256 produces a 32-byte digest
         ↓
5. VERIFY: ECDSA with stored public key + received signature
         ↓
6. OUTPUT: Valid or Invalid
```

## Encoding Formats: How Data Is Packaged

WebAuthn uses specific binary formats to ensure interoperability. Each format
serves a distinct purpose:

### CBOR: The Binary Container

**CBOR** (Concise Binary Object Representation) is a binary encoding format—think
of it as "binary JSON." WebAuthn uses CBOR for:
- Attestation objects
- COSE keys

CBOR was chosen over JSON because it's more compact and supports binary data
natively (important for cryptographic material).

- SeeAlso: [RFC 8949 - CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)

### COSE: Keys and Signatures

**COSE** (CBOR Object Signing and Encryption) defines how to represent
cryptographic keys and signatures in CBOR format.

A COSE key is a CBOR map with standardized integer labels:
- `1` → Key type (e.g., `2` for elliptic curve)
- `3` → Algorithm (e.g., `-7` for ES256)
- `-1` → Curve (e.g., `1` for P-256)
- `-2` → X coordinate
- `-3` → Y coordinate

Using integer labels instead of strings keeps the encoding compact—important
when every byte counts in authenticator storage.

- SeeAlso: [RFC 9052 - COSE Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- SeeAlso: [RFC 9053 - COSE Algorithms (EC2 key parameters)](https://datatracker.ietf.org/doc/html/rfc9053)
- SeeAlso: ``EC2PublicKey``

### DER: Signature Encoding

**DER** (Distinguished Encoding Rules) is used to encode ECDSA signatures.
An ECDSA signature consists of two large integers (r and s); DER provides
a standardized, unambiguous way to serialize them as an ASN.1 SEQUENCE.

WebAuthn uses DER-encoded signatures for compatibility with existing
cryptographic libraries. In Swift, CryptoKit handles this automatically
via `signature.derRepresentation` for encoding and
`ECDSASignature(derRepresentation:)` for decoding.

- SeeAlso: [ITU-T X.690 - ASN.1 Encoding Rules (DER)](https://www.itu.int/rec/T-REC-X.690)
- SeeAlso: [RFC 3279 § 2.2.3 - ECDSA Signature Algorithm](https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3)

### Base64URL: Text-Safe Binary

**Base64URL** is used when binary data must travel through text-based channels
(like JSON). It's a URL-safe variant of Base64 that replaces `+` with `-`,
`/` with `_`, and omits padding `=` characters.

Credential IDs and user handles are typically represented as Base64URL strings
in WebAuthn APIs.

- SeeAlso: [RFC 4648 § 5 - Base64 Encoding with URL and Filename Safe Alphabet](https://www.rfc-editor.org/rfc/rfc4648#section-5)

## The Registration Ceremony (Attestation)

Registration creates a new credential. Here's the complete flow:

```
┌──────────────┐     ┌──────────┐     ┌───────────────┐
│ Relying Party│     │  Client  │     │ Authenticator │
└──────┬───────┘     └────┬─────┘     └───────┬───────┘
       │                  │                   │
       │ 1. Challenge +   │                   │
       │    user info     │                   │
       │─────────────────>│                   │
       │                  │                   │
       │                  │ 2. Create request │
       │                  │──────────────────>│
       │                  │                   │
       │                  │    3. Generate P-256 key pair
       │                  │    4. Create credential ID
       │                  │    5. Build authenticator data
       │                  │    6. Build attestation object
       │                  │                   │
       │                  │ 7. Attestation    │
       │                  │    response       │
       │                  │<──────────────────│
       │                  │                   │
       │ 8. Attestation   │                   │
       │    object +      │                   │
       │    client data   │                   │
       │<─────────────────│                   │
       │                  │                   │
       │ 9. Verify attestation                │
       │ 10. Store public key + credential ID │
```

**In this implementation:**

| Step | Implementation |
|------|----------------|
| 3. Generate key pair | `SecKeyCreateRandomKey` / CryptoKit |
| 4. Create credential ID | Random bytes via `SecRandomCopyBytes` |
| 5. Build authenticator data | ``AuthenticatorData`` |
| 6. Build attestation object | ``AttestationBuilder`` |

### What the Authenticator Builds

During registration, the authenticator constructs several nested structures:

**Authenticator Data** contains:
- RP ID hash (32 bytes): SHA-256 of the relying party identifier
- Flags (1 byte): Indicates user presence, verification, and what data follows
- Sign count (4 bytes): Counter to detect cloned authenticators
- Attested credential data: The new credential's ID and public key

**Attestation Object** wraps the authenticator data:
- `fmt`: Format identifier (e.g., `"none"` for no attestation)
- `attStmt`: Attestation statement (empty map for `"none"`)
- `authData`: The authenticator data bytes

The `"none"` format means no attestation statement is provided—the relying
party trusts the credential without cryptographic proof of the authenticator's
identity. This is appropriate for software authenticators without FIDO certification.
Note that `"none"` is distinct from *self-attestation*, where the credential
private key signs the attestation statement (using `"packed"` format without
a certificate chain). Other attestation formats (`"packed"`, `"tpm"`, `"android-key"`)
exist for hardware authenticators that can cryptographically prove their provenance,
but these are not applicable to iOS credential provider extensions.

> Note: Relying parties can request different **attestation conveyance preferences**
> via `PublicKeyCredentialCreationOptions.attestation`: `"none"` (default),
> `"indirect"`, `"direct"`, or `"enterprise"`. Most passkey deployments use
> `"none"` since attestation verification adds complexity without significant
> security benefit for typical consumer scenarios.

- SeeAlso: ``AuthenticatorData``
- SeeAlso: ``AttestationBuilder``
- SeeAlso: [WebAuthn § 6.5.4 - Generating an Attestation Object](https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object)

## The Authentication Ceremony (Assertion)

Authentication proves the user possesses a registered credential:

```
┌──────────────┐     ┌──────────┐     ┌───────────────┐
│ Relying Party│     │  Client  │     │ Authenticator │
└──────┬───────┘     └────┬─────┘     └───────┬───────┘
       │                  │                   │
       │ 1. Challenge +   │                   │
       │    allowed       │                   │
       │    credentials   │                   │
       │─────────────────>│                   │
       │                  │                   │
       │                  │ 2. Get assertion  │
       │                  │──────────────────>│
       │                  │                   │
       │                  │    3. Find matching credential
       │                  │    4. Verify user (biometric/PIN)
       │                  │    5. Build authenticator data
       │                  │    6. Sign authData || clientDataHash
       │                  │    7. Increment sign counter
       │                  │                   │
       │                  │ 8. Assertion      │
       │                  │    response       │
       │                  │<──────────────────│
       │                  │                   │
       │ 9. Signature +   │                   │
       │    authData +    │                   │
       │    client data   │                   │
       │<─────────────────│                   │
       │                  │                   │
       │ 10. Verify signature with stored public key
       │ 11. Check sign counter increased     │
```

**In this implementation:**

| Step | Implementation |
|------|----------------|
| 3. Find credential | ``PasskeyStore`` |
| 5. Build authenticator data | ``AuthenticatorData`` |
| 6. Sign | ``AssertionBuilder`` |
| 7. Increment counter | ``StoredPasskey`` / ``PasskeyStore`` |

### The Signature: What Gets Signed

The authenticator signs the concatenation of two pieces:

```
signatureBase = authenticatorData || clientDataHash
```

- **authenticatorData**: Fresh data for this assertion (RP ID hash, flags, counter)
- **clientDataHash**: SHA-256 of the client data JSON (contains the challenge)

This binding is crucial for security:
- The RP ID hash ensures the credential is used only for the correct site
- The client data hash includes the challenge, preventing replay attacks
- The counter helps detect if a credential was cloned

- SeeAlso: ``AssertionBuilder``
- SeeAlso: [WebAuthn § 6.3.3 - authenticatorGetAssertion](https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion)

## Discoverable Credentials (Resident Keys)

WebAuthn credentials come in two flavors based on where credential metadata is stored:

### Server-Side Credentials (Non-Discoverable)

With **server-side credentials**, the relying party stores the credential ID and provides
it during authentication. The authenticator only needs to store the private key, indexed
by credential ID.

- RP must know which credentials belong to the user (requires username-first flow)
- Authenticator storage requirements are minimal
- Legacy behavior, common with security keys

### Client-Side Discoverable Credentials (Resident Keys)

With **discoverable credentials** (historically called "resident keys"), the authenticator
stores enough metadata to identify credentials without RP assistance. This enables
"usernameless" authentication—the user simply selects from available passkeys.

- RP sends an empty `allowCredentials` list
- Authenticator searches its storage for credentials matching the RP ID
- User selects which credential to use (if multiple exist)
- Requires more authenticator storage (RP ID, user ID, username, display name)

**Passkeys are always discoverable.** The passkey UX model assumes users can authenticate
by selecting their account from a system-presented list, without typing a username first.
When implementing a credential provider, you must store sufficient metadata to:
1. Match credentials by RP ID
2. Display meaningful account information to the user

- SeeAlso: [WebAuthn § 4 - Terminology (Client-side Discoverable Credential)](https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential)
- SeeAlso: [WebAuthn § 5.4.4 - Authenticator Selection Criteria (residentKey)](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey)

## Authenticator Flags

The flags byte is a compact way to communicate the authenticator's state:

| Bit | Name | Abbr | Meaning |
|-----|------|------|---------|
| 0 | User Present | UP | User performed a presence test (touched sensor) |
| 2 | User Verified | UV | User identity was verified (biometric, PIN) |
| 3 | Backup Eligible | BE | Credential can be synced to other devices |
| 4 | Backup State | BS | Credential has been backed up |
| 6 | Attested Credential Data | AT | Response includes attested credential data (AAGUID + credential ID + public key) |
| 7 | Extension Data | ED | Response includes extension data |

> Note: Bits 1 and 5 are reserved for future use (RFU) and MUST be zero.

**UP vs UV**: User *presence* just confirms someone is there (like touching a
button). User *verification* confirms *who* is there (like Face ID or a PIN).
Passkeys typically require both.

**BE and BS**: These flags indicate whether a credential is a "multi-device
credential" (can sync via iCloud/Google) or a "single-device credential"
(bound to one authenticator). A synced passkey has both BE and BS set.

- SeeAlso: ``AuthenticatorFlags``
- SeeAlso: [WebAuthn § 6.1 - Authenticator Data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
- SeeAlso: [WebAuthn § 6.1.3 - Credential Backup State](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)

## Credential Storage in This Implementation

This credential provider stores data in two locations:

| Data | Storage | Why |
|------|---------|-----|
| Private keys | Keychain | Hardware-backed secure storage |
| Metadata | App Group UserDefaults | Shared between app and extension |

**Why two locations?** The Keychain provides secure, hardware-backed storage
for sensitive cryptographic keys. However, the app and extension run as
separate processes—they need a shared container (App Group) to coordinate
which credentials exist and their metadata (RP ID, username, counter).

The **sign counter** is particularly important: it must persist across
assertions and increment each time. If a relying party sees a counter go
*backwards*, it knows something is wrong (possibly a cloned credential).

> Note: Some modern passkey implementations (particularly those with cloud sync)
> use a constant counter of `0` and rely on other mechanisms for clone detection,
> since synchronized credentials make traditional counter-based detection less
> meaningful. This implementation increments the counter for compatibility with
> relying parties that enforce counter validation.

- SeeAlso: ``PasskeyStore``
- SeeAlso: [WebAuthn § 6.1.1 - Signature Counter](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter)

## Further Reading

### Specifications
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) — The core web authentication specification
- [FIDO CTAP 2.2 (July 2025)](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html) — Client to Authenticator Protocol (check [FIDO specs page](https://fidoalliance.org/specifications/) for updates)
- [RFC 9052 - COSE Structures](https://datatracker.ietf.org/doc/html/rfc9052) — CBOR Object Signing and Encryption
- [RFC 8949 - CBOR](https://www.rfc-editor.org/rfc/rfc8949.html) — Concise Binary Object Representation

### Apple Documentation
- [Supporting Passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
- [ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)

### Community Resources
- [WebAuthn Guide](https://webauthn.guide/) — Introduction to WebAuthn
- [passkeys.dev](https://passkeys.dev/) — Passkey implementation resources
