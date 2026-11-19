//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A public key of a kind that ``NIOSSH`` does not have built in.
///
/// ``NIOSSH`` has built-in support for Ed25519 and ECDSA keys. A type that conforms to this protocol describes
/// the public half of a key of any other kind, such as RSA, well enough for ``NIOSSH`` to send it to a peer. It
/// can be wrapped in a ``NIOSSHPublicKey`` using ``NIOSSHPublicKey/init(custom:)``.
///
/// Two keys of a custom kind are equal when they have the same ``publicKeyPrefix`` and write the same bytes. A
/// key of a custom kind is never equal to a key of a built-in kind.
public protocol NIOSSHPublicKeyProtocol: Sendable {
    /// The name of the key format, such as `ssh-rsa`. This is the string that begins the encoding of the key.
    static var publicKeyPrefix: String { get }

    /// Writes the key in its format-specific encoding: the bytes that follow the name of the key format in the
    /// encoding of a public key (RFC 4253 § 6.6).
    ///
    /// - returns: The number of bytes written.
    func write(to buffer: inout ByteBuffer) -> Int
}

/// A private key of a kind that ``NIOSSH`` does not have built in.
///
/// A type that conforms to this protocol signs on behalf of a ``NIOSSHPrivateKey`` created with
/// ``NIOSSHPrivateKey/init(custom:)``. It does not need to hold any key material itself: the private key may be
/// kept by the operating system, in a secure element, or by some other party, so long as it can be asked to sign.
///
/// - Important: ``signature(for:)`` is called synchronously on the event loop of the connection. Implementations
///     should not block.
public protocol NIOSSHPrivateKeyProtocol: Sendable {
    /// The public half of this key.
    var publicKey: any NIOSSHPublicKeyProtocol { get }

    /// The name of the public key algorithm that this key signs with, such as `rsa-sha2-512`.
    ///
    /// This is the name sent to the peer alongside the key, and it is part of the data that is signed. It is
    /// distinct from ``NIOSSHPublicKeyProtocol/publicKeyPrefix`` because one key format may be used with several
    /// algorithms: an `ssh-rsa` key signs as `rsa-sha2-256` or `rsa-sha2-512` (RFC 8332). The default
    /// implementation returns the public key's ``NIOSSHPublicKeyProtocol/publicKeyPrefix``.
    var signatureAlgorithm: String { get }

    /// Signs `data` with the algorithm named by ``signatureAlgorithm``.
    ///
    /// - parameters:
    ///     - data: The data to sign. It has not been hashed.
    /// - returns: The signature blob: the bytes that follow the name of the algorithm in the encoding of a
    ///     signature (RFC 4253 § 6.6). For `rsa-sha2-256` and `rsa-sha2-512` that is the signature as an SSH
    ///     string.
    func signature<D: DataProtocol>(for data: D) throws -> ByteBuffer
}

extension NIOSSHPrivateKeyProtocol {
    public var signatureAlgorithm: String {
        type(of: self.publicKey).publicKeyPrefix
    }
}

extension NIOSSHPublicKeyProtocol {
    /// The encoding of this key without the name of its format, used to compare and to hash keys.
    internal var writtenBytes: ByteBuffer {
        var buffer = ByteBuffer()
        _ = self.write(to: &buffer)
        return buffer
    }
}
