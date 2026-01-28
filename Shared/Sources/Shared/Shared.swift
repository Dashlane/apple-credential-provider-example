// Shared.swift
// Shared
//
// Main module file - exports all public types from the Shared package.

import Foundation

// Re-export SwiftCBOR for consumers
@_exported import SwiftCBOR

// WebAuthn types are automatically available as they're in the same module.
// This file can be used for any top-level module utilities if needed.
